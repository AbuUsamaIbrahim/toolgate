package dev.mahadi.toolgate.integrity;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "toolgate.pins")
@Component
public class PinProperties {

    /**
     * Where pins are stored. Empty disables persistence, which is appropriate only for
     * tests: a gateway that forgets its pins on restart is not enforcing anything.
     */
    private String file = "";

    /**
     * Refuse to start if the pin file is group- or world-writable.
     *
     * <p>On by default. The pin file decides which tool definitions are trusted, so write
     * access to it is equivalent to the ability to pre-approve a poisoned tool. Treating
     * loose permissions as a startup failure rather than a warning is the same reasoning
     * that makes SSH refuse an over-permissive private key.
     */
    private boolean requireSecurePermissions = true;

    /**
     * Re-read a tool's definition from its upstream before each call and compare it to
     * the pin.
     *
     * <p>On by default, and it costs a round-trip per call. Without it the only pin check
     * happens at {@code tools/list}, which protects the model's context but not an agent
     * that listed before the mutation and still holds the tool — and that agent is the one
     * the attack is aimed at. Drift already on record is refused without asking upstream,
     * so the cost falls only on calls where nothing is yet known to be wrong.
     *
     * <p>Turning it off leaves the cheap check in place. That is a defensible trade for a
     * latency-sensitive deployment that lists often, and indefensible for one that does
     * not list at all.
     */
    private boolean verifyOnCall = true;

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }
    public boolean isRequireSecurePermissions() { return requireSecurePermissions; }
    public void setRequireSecurePermissions(boolean v) { this.requireSecurePermissions = v; }
    public boolean isVerifyOnCall() { return verifyOnCall; }
    public void setVerifyOnCall(boolean v) { this.verifyOnCall = v; }
}
