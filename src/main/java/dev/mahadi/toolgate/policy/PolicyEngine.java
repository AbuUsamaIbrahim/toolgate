package dev.mahadi.toolgate.policy;

import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.protocol.HeaderMirror;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.scanner.InjectionScanner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Decides whether a tool may be advertised to the model and whether a call may proceed.
 *
 * <p>Ordering is deliberate and worth stating, because it is the whole design:
 *
 * <ol>
 *   <li><b>Allowlist</b> — cheapest check, and the only one that is not a heuristic. A
 *       tool nobody authorised is refused before anything else is considered.</li>
 *   <li><b>Integrity</b> — did this definition change since it was approved?</li>
 *   <li><b>Content</b> — does it look adversarial on its face?</li>
 *   <li><b>Human gate</b> — is this operation destructive enough to require a person?</li>
 * </ol>
 *
 * <p>The first three are evaluated for every tool at {@code tools/list} time, so a
 * poisoned definition never reaches the model's context at all. Filtering at call time
 * alone would be too late: by then the model has already read the injected instructions
 * and may be acting on them through some entirely different tool.
 */
@Component
public class PolicyEngine {

    private final ToolPolicyProperties props;
    private final ToolPinStore pins;
    private final InjectionScanner scanner;
    private final DriftStore drifts;

    public PolicyEngine(ToolPolicyProperties props, ToolPinStore pins,
                        InjectionScanner scanner, DriftStore drifts) {
        this.props = props;
        this.pins = pins;
        this.scanner = scanner;
        this.drifts = drifts;
    }

    /** What the gateway decided, and why. The reason is carried so it can be audited. */
    public sealed interface Decision {
        String reason();

        record Allow(String reason) implements Decision {}

        /** Refused outright. The tool is hidden from the model or the call is rejected. */
        record Deny(String reason, List<String> evidence) implements Decision {}

        /** Permitted only with explicit human approval. */
        record NeedsApproval(String reason) implements Decision {}
    }

    /**
     * Evaluates a tool at advertisement time.
     *
     * @param serverId which upstream advertised it; tool names are only unique per server
     */
    public Decision evaluateAdvertisement(String serverId, Mcp.Tool tool) {
        // 1. Allowlist — deny by default.
        if (!props.isAllowed(serverId, tool.name())) {
            return new Decision.Deny(
                    "tool not in allowlist",
                    List.of("%s/%s".formatted(serverId, tool.name())));
        }

        // 2. Integrity.
        var verdict = pins.check(serverId, tool);
        if (verdict instanceof ToolPinStore.Verdict.Drifted d) {
            // Keep both definitions so an operator can be shown what actually changed.
            drifts.record(d.pin(), tool, d.actualFingerprint());
            return new Decision.Deny(
                    "tool definition changed since it was pinned",
                    List.of(
                            "pinned=" + abbreviate(d.pin().fingerprint()),
                            "actual=" + abbreviate(d.actualFingerprint()),
                            "pinnedAt=" + d.pin().pinnedAt()));
        }
        boolean firstSighting = verdict instanceof ToolPinStore.Verdict.FirstSighting;

        // 3. Header mirroring. Unlike everything else in a definition this is an
        // instruction to the transport rather than text for the model, so it is checked
        // separately and refused outright — there is no benign reason for a tool to name
        // a header outside the reserved namespace, so there is nothing for a human to
        // weigh up and no reason to escalate rather than deny.
        var headerProblems = HeaderMirror.validate(tool);
        if (!headerProblems.isEmpty()) {
            return refuse(serverId, tool, firstSighting,
                    "tool declares an unacceptable x-mcp-header mirror",
                    List.copyOf(headerProblems));
        }

        // 4. Content.
        var scan = scanner.scan(tool);
        if (!scan.clean()) {
            List<String> evidence = new ArrayList<>();
            scan.findings().forEach(f ->
                    evidence.add("%s in %s: %s".formatted(f.rule(), f.field(), f.evidence())));

            if (scan.score() >= props.getBlockThreshold()) {
                return refuse(serverId, tool, firstSighting,
                        "tool metadata contains adversarial content (score %d)".formatted(scan.score()),
                        List.copyOf(evidence));
            }
            return new Decision.NeedsApproval(
                    "tool metadata is suspicious (score %d): %s".formatted(scan.score(), evidence));
        }

        // Back to matching its pin: the upstream reverted, so the alert is stale.
        drifts.clear(serverId, tool.name());

        // A clean, allowlisted tool seen for the first time is still a change to the
        // agent's capability surface. Operators who want to review that set
        // approve-first-sighting; those who trust their supply chain do not.
        if (firstSighting && props.isApproveFirstSighting()) {
            return new Decision.NeedsApproval("first sighting of this tool definition");
        }

        return new Decision.Allow("allowlisted, pinned and clean");
    }

    /**
     * Evaluates an actual invocation.
     *
     * <p>Re-checks the allowlist rather than trusting that advertisement filtering
     * happened: a client may call a tool it was never offered, and a gateway that assumes
     * otherwise is trusting the caller to enforce its own restrictions.
     */
    public Decision evaluateCall(String serverId, String toolName) {
        if (!props.isAllowed(serverId, toolName)) {
            return new Decision.Deny(
                    "tool not in allowlist",
                    List.of("%s/%s".formatted(serverId, toolName)));
        }
        if (pins.get(serverId, toolName).isEmpty()) {
            return new Decision.Deny(
                    "tool was never advertised through this gateway",
                    List.of("%s/%s".formatted(serverId, toolName)));
        }
        if (props.requiresApproval(serverId, toolName)) {
            return new Decision.NeedsApproval("tool is marked as requiring human approval");
        }
        return new Decision.Allow("allowlisted and pinned");
    }

    /**
     * Headers to mirror for a call, derived from the pinned definition.
     *
     * <p>Reading the pin rather than the live definition matters: it means a tool must
     * have been advertised and accepted before it can influence a header at all, and the
     * instruction being followed is the one that was reviewed.
     */
    public java.util.Map<String, String> mirroredHeaders(
            String serverId, String toolName, java.util.Map<String, Object> arguments) {
        return pins.get(serverId, toolName)
                .map(ToolPinStore.Pin::definition)
                .map(def -> HeaderMirror.headersFor(def, arguments))
                .orElse(java.util.Map.of());
    }

    /**
     * Denies a tool, and drops the pin if this sighting is what created it.
     *
     * <p>The integrity check runs before the content and header checks — deliberately,
     * because it is the one control that is not a heuristic — and it pins whatever it sees
     * for the first time. Leaving that pin behind for a definition the gateway then
     * refused would mean the upstream's eventual fix arrives as drift, and a server
     * repairing itself would sit blocked waiting for a human to approve the repair.
     */
    private Decision refuse(String serverId, Mcp.Tool tool, boolean firstSighting,
                            String reason, List<String> evidence) {
        if (firstSighting) {
            pins.forget(serverId, tool.name());
        }
        return new Decision.Deny(reason, evidence);
    }

    private static String abbreviate(String hash) {
        return hash.length() <= 12 ? hash : hash.substring(0, 12);
    }
}
