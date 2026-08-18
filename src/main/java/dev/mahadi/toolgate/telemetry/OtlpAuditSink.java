package dev.mahadi.toolgate.telemetry;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor;
import io.opentelemetry.sdk.resources.Resource;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.InetAddress;

/**
 * Ships the audit trail to an OpenTelemetry collector.
 *
 * <h2>Why this exists when there is already a file</h2>
 * The JSON Lines file is append-only from the gateway's side, and it lives on the machine
 * being defended. Anyone who can write that disk can rewrite the record of what they did.
 * A copy in a sink the caller does not control is the difference between a log and
 * evidence — and on a fleet of laptops, the machine that most needs auditing is exactly the
 * one you cannot trust to keep its own audit.
 *
 * <h2>Why OTLP rather than a bespoke shipper</h2>
 * Whatever the company already runs — Splunk, Elastic, Loki, a cloud vendor — has an OTLP
 * ingest path or a collector in front of it. Inventing a wire format for a control whose
 * entire value is that somebody else's system can read it would be a strange choice.
 *
 * <p>Note that tailing the file with Fluent Bit or Vector is a perfectly good alternative
 * and needs no code at all. This exists for deployments that already run a collector, not
 * because the file is inadequate.
 *
 * <p>Export is batched and asynchronous. A slow collector must never add latency to a tool
 * call, and a dead one must never fail one — a gateway that stops working because its
 * telemetry backend is down has made itself the outage.
 */
@Component
public class OtlpAuditSink implements AuditSink {

    private static final Logger log = LoggerFactory.getLogger(OtlpAuditSink.class);

    private static final AttributeKey<String> CALLER = AttributeKey.stringKey("toolgate.caller");
    private static final AttributeKey<String> SERVER = AttributeKey.stringKey("toolgate.server");
    private static final AttributeKey<String> TOOL = AttributeKey.stringKey("toolgate.tool");
    private static final AttributeKey<String> ACTION = AttributeKey.stringKey("toolgate.action");
    private static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("toolgate.outcome");
    private static final AttributeKey<String> REASON = AttributeKey.stringKey("toolgate.reason");
    private static final AttributeKey<java.util.List<String>> EVIDENCE =
            AttributeKey.stringArrayKey("toolgate.evidence");

    private final SdkLoggerProvider provider;
    private final io.opentelemetry.api.logs.Logger otel;

    public OtlpAuditSink(OtlpProperties props) {
        if (!props.enabled()) {
            this.provider = null;
            this.otel = null;
            return;
        }

        Resource resource = Resource.getDefault().merge(Resource.builder()
                .put("service.name", props.getServiceName())
                .put("service.instance.id", instanceId(props))
                .build());

        this.provider = SdkLoggerProvider.builder()
                .setResource(resource)
                .addLogRecordProcessor(BatchLogRecordProcessor.builder(
                        OtlpHttpLogRecordExporter.builder()
                                .setEndpoint(props.getEndpoint())
                                .setTimeout(props.getTimeout())
                                .build()).build())
                .build();
        this.otel = provider.get("toolgate.audit");

        log.info("Audit trail exporting to {} as service.name={}",
                props.getEndpoint(), props.getServiceName());
    }

    /**
     * Which machine this is. On a fleet of sidecars the hostname is the only thing that
     * makes "who did this" answerable — the caller identity says who, and this says where.
     */
    private static String instanceId(OtlpProperties props) {
        if (props.getServiceInstanceId() != null && !props.getServiceInstanceId().isBlank()) {
            return props.getServiceInstanceId();
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }

    @Override
    public void append(AuditLog.Entry entry) {
        if (otel == null) return;

        otel.logRecordBuilder()
                .setTimestamp(entry.at())
                .setSeverity(severityOf(entry))
                .setBody("%s %s %s/%s: %s".formatted(
                        entry.outcome(), entry.action(), entry.serverId(), entry.tool(),
                        entry.reason()))
                .setAllAttributes(Attributes.builder()
                        .put(CALLER, nullSafe(entry.caller()))
                        .put(SERVER, nullSafe(entry.serverId()))
                        .put(TOOL, nullSafe(entry.tool()))
                        .put(ACTION, nullSafe(entry.action()))
                        .put(OUTCOME, entry.outcome().name())
                        .put(REASON, nullSafe(entry.reason()))
                        .put(EVIDENCE, entry.evidence())
                        .build())
                .emit();
    }

    /**
     * Denials and approval requests are the interesting records, so they arrive at a
     * severity a SIEM will route on. A trail where a refused attack and a routine read
     * look identical makes the consumer do the triage the producer already knew how to do.
     */
    private static Severity severityOf(AuditLog.Entry entry) {
        return switch (entry.outcome()) {
            case DENIED -> Severity.WARN;
            case APPROVAL_REQUIRED -> Severity.WARN;
            case FAILED -> Severity.ERROR;
            default -> Severity.INFO;
        };
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    @PreDestroy
    void flush() {
        if (provider == null) return;
        // Give the batch a chance to leave. Records held in a buffer at shutdown are
        // exactly the ones written just before something went wrong.
        CompletableResultCode result = provider.shutdown();
        result.join(5, java.util.concurrent.TimeUnit.SECONDS);
    }
}
