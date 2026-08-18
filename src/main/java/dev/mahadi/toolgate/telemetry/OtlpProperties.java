package dev.mahadi.toolgate.telemetry;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@ConfigurationProperties(prefix = "toolgate.otlp")
@Component
public class OtlpProperties {

    /** Collector endpoint, e.g. http://otel-collector:4318/v1/logs. Empty disables export. */
    private String endpoint = "";

    /** Value of {@code service.name} on exported records. */
    private String serviceName = "toolgate";

    /** Identifies which machine's gateway a record came from. */
    private String serviceInstanceId = "";

    private Duration timeout = Duration.ofSeconds(10);

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }
    public String getServiceInstanceId() { return serviceInstanceId; }
    public void setServiceInstanceId(String serviceInstanceId) { this.serviceInstanceId = serviceInstanceId; }
    public Duration getTimeout() { return timeout; }
    public void setTimeout(Duration timeout) { this.timeout = timeout; }

    public boolean enabled() {
        return endpoint != null && !endpoint.isBlank();
    }
}
