package dev.mahadi.toolgate.telemetry;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.bundle.BundleProperties;
import dev.mahadi.toolgate.bundle.BundleStore;
import dev.mahadi.toolgate.gateway.ApprovalProperties;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.InMemoryPinStorage;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tool names come from the upstream server — the untrusted party. Using one as a metric
 * label hands an attacker a memory-growth primitive aimed at the gateway's own monitoring,
 * and refusing the tool does not help, because the refusal is what gets counted.
 */
class MetricsCardinalityTest {

    private SimpleMeterRegistry registry;
    private GatewayMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        metrics = new GatewayMetrics(
                registry,
                new BundleStore(new BundleProperties(), mapper),
                new DriftStore(),
                new ApprovalStore(new ApprovalProperties(), mapper),
                new ToolPinStore(new InMemoryPinStorage()));
    }

    private AuditLog.Entry denied(String tool, String reason) {
        return new AuditLog.Entry(Instant.now(), "someone@example.com", "files", tool,
                "advertise", AuditLog.Outcome.DENIED, reason, List.of());
    }

    @Test
    @DisplayName("ten thousand hostile tool names produce one time series, not ten thousand")
    void toolNamesDoNotExplodeCardinality() {
        for (int i = 0; i < 10_000; i++) {
            metrics.decision(denied("tool-" + java.util.UUID.randomUUID(), "tool not in allowlist"));
        }

        var series = registry.find("toolgate.decisions").counters();

        assertThat(series).hasSize(1);
        assertThat(series.iterator().next().count()).isEqualTo(10_000);
    }

    @Test
    @DisplayName("a reworded reason degrades the dashboard rather than minting a series")
    void unknownReasonsFoldIntoOther() {
        metrics.decision(denied("read_file", "some brand new reason nobody categorised"));
        metrics.decision(denied("read_file", "another entirely different message"));

        var series = registry.find("toolgate.decisions").counters();

        assertThat(series).hasSize(1);
        assertThat(series.iterator().next().getId().getTag("reason")).isEqualTo("other");
    }

    @Test
    @DisplayName("distinct reasons are still distinguishable, so alerts can be specific")
    void knownReasonsAreCategorised() {
        metrics.decision(denied("a", "tool not in allowlist"));
        metrics.decision(denied("b", "tool definition changed since it was pinned"));
        metrics.decision(denied("c", "tool metadata contains adversarial content (score 70)"));
        metrics.decision(denied("d", "tool declares an unacceptable x-mcp-header mirror"));

        var reasons = registry.find("toolgate.decisions").counters().stream()
                .map(c -> c.getId().getTag("reason")).toList();

        assertThat(reasons).containsExactlyInAnyOrder(
                "not_allowlisted", "drift", "injection", "header_mirror");
    }

    @Test
    @DisplayName("an unrecognised action does not become a label of its own")
    void unknownActionsAreNormalised() {
        var entry = new AuditLog.Entry(Instant.now(), "x", "files", "read_file",
                "something/unexpected", AuditLog.Outcome.ALLOWED, "fine", List.of());

        metrics.decision(entry);

        assertThat(registry.find("toolgate.decisions").counters().iterator().next()
                .getId().getTag("action")).isEqualTo("other");
    }

    @Test
    @DisplayName("an allowed decision is not categorised by a word its reason happens to contain")
    void allowedIsNotMiscategorised() {
        // "allowlisted, pinned and clean" contains "allowlist". Substring matching on a
        // free-text reason produced a metric claiming the gateway allowed a call because
        // it was not on the allowlist.
        var allowed = new AuditLog.Entry(Instant.now(), "x", "files", "read_file",
                "advertise", AuditLog.Outcome.ALLOWED, "allowlisted, pinned and clean", List.of());

        metrics.decision(allowed);

        assertThat(registry.find("toolgate.decisions").counters().iterator().next()
                .getId().getTag("reason")).isEqualTo("ok");
    }

    @Test
    @DisplayName("bundle health is exported as a number an alert can compare against")
    void bundleHealthIsAGauge() {
        var gauge = registry.find("toolgate.bundle.health").gauge();

        assertThat(gauge).isNotNull();
        // No bundle configured, so local config is authoritative: 0, not a failure.
        assertThat(gauge.value()).isEqualTo(0);
    }
}
