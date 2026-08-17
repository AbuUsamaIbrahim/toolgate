package dev.mahadi.toolgate.policy;

import dev.mahadi.toolgate.integrity.ToolPinStore;
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

    public PolicyEngine(ToolPolicyProperties props, ToolPinStore pins, InjectionScanner scanner) {
        this.props = props;
        this.pins = pins;
        this.scanner = scanner;
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
            return new Decision.Deny(
                    "tool definition changed since it was pinned",
                    List.of(
                            "pinned=" + abbreviate(d.pin().fingerprint()),
                            "actual=" + abbreviate(d.actualFingerprint()),
                            "pinnedAt=" + d.pin().pinnedAt()));
        }
        boolean firstSighting = verdict instanceof ToolPinStore.Verdict.FirstSighting;

        // 3. Content.
        var scan = scanner.scan(tool);
        if (!scan.clean()) {
            List<String> evidence = new ArrayList<>();
            scan.findings().forEach(f ->
                    evidence.add("%s in %s: %s".formatted(f.rule(), f.field(), f.evidence())));

            if (scan.score() >= props.getBlockThreshold()) {
                return new Decision.Deny(
                        "tool metadata contains adversarial content (score %d)".formatted(scan.score()),
                        List.copyOf(evidence));
            }
            return new Decision.NeedsApproval(
                    "tool metadata is suspicious (score %d): %s".formatted(scan.score(), evidence));
        }

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

    private static String abbreviate(String hash) {
        return hash.length() <= 12 ? hash : hash.substring(0, 12);
    }
}
