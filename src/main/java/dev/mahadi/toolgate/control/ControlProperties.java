package dev.mahadi.toolgate.control;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@ConfigurationProperties(prefix = "toolgate.control")
@Component
public class ControlProperties {

    /**
     * Sidecar side: where the control plane lives. Empty means this gateway reports to
     * nobody, which is the correct default for someone running it on their own machine.
     */
    private String url = "";

    /** Sidecar side: how often to report in. */
    private Duration checkInInterval = Duration.ofMinutes(5);

    /**
     * Sidecar side: identifies this machine in the fleet view. Defaults to the hostname.
     * It is scoped to the caller's token subject, so it need only be unique per person.
     */
    private String instanceId = "";

    /** Server side: the signed bundle this control plane serves. */
    private String bundleFile = "";

    /**
     * Server side: how long without a check-in before a gateway is considered silent.
     *
     * <p>Comfortably more than the check-in interval. Too tight and a laptop that closed
     * its lid for lunch shows up as a coverage gap, which trains people to ignore the
     * report — the specific failure that makes a monitoring control worthless.
     */
    private Duration silentAfter = Duration.ofMinutes(30);

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public Duration getCheckInInterval() { return checkInInterval; }
    public void setCheckInInterval(Duration checkInInterval) { this.checkInInterval = checkInInterval; }
    public String getInstanceId() { return instanceId; }
    public void setInstanceId(String instanceId) { this.instanceId = instanceId; }
    public String getBundleFile() { return bundleFile; }
    public void setBundleFile(String bundleFile) { this.bundleFile = bundleFile; }
    public Duration getSilentAfter() { return silentAfter; }
    public void setSilentAfter(Duration silentAfter) { this.silentAfter = silentAfter; }

    public boolean reportingEnabled() {
        return url != null && !url.isBlank();
    }
}
