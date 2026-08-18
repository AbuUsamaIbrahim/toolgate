package dev.mahadi.toolgate.telemetry;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.bundle.BundleStore;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Prometheus metrics for the gateway.
 *
 * <h2>The label-cardinality trap, which here is a security problem</h2>
 * The obvious design labels every decision with the tool it concerned:
 * {@code toolgate_decisions_total{server="files", tool="read_file", outcome="DENIED"}}.
 * That reads beautifully and is exactly wrong, because <em>tool names come from the
 * upstream server</em> — the untrusted party this whole gateway exists to defend against.
 *
 * <p>A hostile upstream advertising ten thousand randomly named tools would mint ten
 * thousand time series in the registry, each held in memory for the lifetime of the
 * process, and ship them to Prometheus on every scrape. The gateway correctly refuses every
 * one of those tools and is destroyed by the monitoring it did about them. Attacker-
 * controlled label values are a denial of service aimed at your own observability, and the
 * fact that the request was <em>denied</em> does not help.
 *
 * <p>So the labels here are drawn only from sets the operator controls: the outcome enum,
 * the action, the server id from configuration, and a small fixed set of reason categories.
 * Which specific tool was involved is a question for the audit trail, which is designed to
 * hold unbounded strings and is not indexed by them.
 */
@Component
public class GatewayMetrics {

    private final MeterRegistry registry;

    public GatewayMetrics(MeterRegistry registry, BundleStore bundles, DriftStore drifts,
                          ApprovalStore approvals, ToolPinStore pins) {
        this.registry = registry;

        registry.gauge("toolgate.drift.outstanding", drifts, d -> d.all().size());
        registry.gauge("toolgate.approvals.pending", approvals, a -> a.outstanding().size());
        registry.gauge("toolgate.pins.total", pins, p -> p.all().size());

        // Health as a number so it can be alerted on: 0 disabled, 1 fresh, 2 stale, 3 failed.
        // An alert on >= 2 catches a fleet drifting out of policy before anyone notices
        // that their agent has quietly stopped being governed.
        registry.gauge("toolgate.bundle.health", bundles, b -> switch (b.health()) {
            case DISABLED -> 0;
            case FRESH -> 1;
            case STALE -> 2;
            case FAILED -> 3;
        });
        registry.gauge("toolgate.bundle.sequence", bundles,
                b -> b.current().map(c -> (double) c.sequence()).orElse(-1d));
        registry.gauge("toolgate.bundle.age.seconds", bundles,
                b -> b.active()
                        .map(a -> (double) Duration.between(a.loadedAt(), Instant.now()).toSeconds())
                        .orElse(-1d));
    }

    /**
     * Records a decision.
     *
     * <p>{@code reason} is deliberately not a label — it is free text written by whoever
     * added the check. It is folded into a small fixed category instead.
     */
    public void decision(AuditLog.Entry entry) {
        Counter.builder("toolgate.decisions")
                .description("Policy decisions, by outcome")
                .tags(Tags.of(
                        "outcome", entry.outcome().name(),
                        "action", normaliseAction(entry.action()),
                        "server", entry.serverId() == null ? "unknown" : entry.serverId(),
                        "reason", category(entry.outcome(), entry.reason())))
                .register(registry)
                .increment();
    }

    /** Actions are internal strings; pin them to a known set rather than trusting the caller. */
    private static String normaliseAction(String action) {
        if (action == null) return "unknown";
        return switch (action) {
            case "advertise", "tools/call", "tools/call result", "tools/list" -> action;
            default -> "other";
        };
    }

    /**
     * Folds a free-text reason into a category an alert can be written against.
     *
     * <p>Matching on substrings of a message is fragile, and it is fragile in the right
     * direction: an unrecognised reason becomes {@code other} rather than a new time
     * series. Rewording a message degrades a dashboard; it cannot exhaust memory.
     */
    private static String category(AuditLog.Outcome outcome, String reason) {
        // An allowed decision has no interesting category, and trying to give it one goes
        // wrong immediately: "allowlisted, pinned and clean" contains the word "allowlist"
        // and lands in not_allowlisted, producing a metric that says the gateway allowed
        // something because it was not on the allowlist.
        if (outcome == AuditLog.Outcome.ALLOWED || outcome == AuditLog.Outcome.APPROVED) {
            return "ok";
        }
        if (reason == null) return "other";
        String r = reason.toLowerCase();
        if (r.contains("not in allowlist")) return "not_allowlisted";
        if (r.contains("changed since it was pinned")) return "drift";
        if (r.contains("centrally reviewed")) return "review_mismatch";
        if (r.contains("no reviewed definition")) return "unreviewed";
        if (r.contains("adversarial content")) return "injection";
        if (r.contains("suspicious")) return "suspicious";
        if (r.contains("x-mcp-header")) return "header_mirror";
        if (r.contains("human approval") || r.contains("requiring human")) return "approval_required";
        if (r.contains("policy bundle")) return "no_policy";
        if (r.contains("never advertised")) return "unadvertised";
        if (r.contains("authentication failed")) return "auth_failed";
        if (r.contains("insufficient scope")) return "insufficient_scope";
        if (r.contains("upstream error")) return "upstream_error";
        return "other";
    }
}
