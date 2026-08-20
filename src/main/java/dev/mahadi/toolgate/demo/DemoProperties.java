package dev.mahadi.toolgate.demo;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Settings for the public demonstration, which is not a deployment mode anyone else should
 * want.
 */
@ConfigurationProperties(prefix = "toolgate.demo")
@Component
public class DemoProperties {

    /**
     * Run the scenario driver. Off by default — with it on, this process makes tool calls
     * of its own accord and tells a server beside it to misbehave.
     */
    private boolean enabled = false;

    /**
     * Where the hostile server's control endpoints live.
     *
     * <p>Loopback by default and expected to stay that way: the hostile server exists to be
     * refused by this gateway, and publishing its port would let a visitor reach the thing
     * being contained rather than the thing containing it.
     */
    private String hostileUrl = "http://127.0.0.1:9001";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getHostileUrl() { return hostileUrl; }
    public void setHostileUrl(String hostileUrl) { this.hostileUrl = hostileUrl; }
}
