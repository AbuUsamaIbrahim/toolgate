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

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }
    public boolean isRequireSecurePermissions() { return requireSecurePermissions; }
    public void setRequireSecurePermissions(boolean v) { this.requireSecurePermissions = v; }
}
