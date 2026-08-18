package dev.mahadi.toolgate.bundle;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "toolgate.bundle")
@Component
public class BundleProperties {

    /** File path or http(s) URL of the signed bundle. Empty means local config only. */
    private String source = "";

    /**
     * Trusted signing keys, keyed by the {@code keyid} that appears in the envelope,
     * values base64 X.509 Ed25519 public keys. More than one so keys can be rotated
     * without a flag day.
     */
    private Map<String, String> publicKeys = new LinkedHashMap<>();

    /**
     * Where to keep the last accepted bundle, so a restart while offline does not start
     * with no policy at all. Re-verified on load exactly like a fresh download.
     */
    private String cacheFile = "~/.toolgate/bundle.cache.json";

    /** How often to re-fetch. */
    private Duration refreshInterval = Duration.ofMinutes(5);

    /**
     * How long past {@code expiresAt} a bundle may still be enforced.
     *
     * <p>A laptop on a plane should not have its agent stop working the moment a bundle
     * ages out, but it must not enforce last quarter's policy forever either. Past the
     * grace period the gateway fails closed.
     */
    private Duration staleGrace = Duration.ofHours(24);

    /**
     * Refuse to serve without a valid bundle.
     *
     * <p>On for a managed fleet: falling back to whatever YAML happens to be on the laptop
     * would let anyone who can edit that file opt out of central policy, which is the same
     * as having none. Off for a single developer running this locally.
     */
    private boolean required = false;

    public String getCacheFile() { return cacheFile; }
    public void setCacheFile(String cacheFile) { this.cacheFile = cacheFile; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public Map<String, String> getPublicKeys() { return publicKeys; }
    public void setPublicKeys(Map<String, String> publicKeys) { this.publicKeys = publicKeys; }
    public Duration getRefreshInterval() { return refreshInterval; }
    public void setRefreshInterval(Duration refreshInterval) { this.refreshInterval = refreshInterval; }
    public Duration getStaleGrace() { return staleGrace; }
    public void setStaleGrace(Duration staleGrace) { this.staleGrace = staleGrace; }
    public boolean isRequired() { return required; }
    public void setRequired(boolean required) { this.required = required; }

    public boolean enabled() {
        return source != null && !source.isBlank();
    }
}
