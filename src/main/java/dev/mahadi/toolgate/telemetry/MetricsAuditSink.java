package dev.mahadi.toolgate.telemetry;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import org.springframework.stereotype.Component;

/**
 * Feeds the audit stream into the metrics registry.
 *
 * <p>Every decision already flows through one place, so counting them belongs here rather
 * than scattered through the policy engine — the alternative is a new counter increment
 * that someone forgets to add next to a new {@code audit.record} call, and a dashboard that
 * is quietly wrong about what the gateway did.
 */
@Component
public class MetricsAuditSink implements AuditSink {

    private final GatewayMetrics metrics;

    public MetricsAuditSink(GatewayMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public void append(AuditLog.Entry entry) {
        metrics.decision(entry);
    }
}
