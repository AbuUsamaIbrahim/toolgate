package dev.mahadi.toolgate.audit;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "toolgate.audit")
@Component
public class AuditProperties {

    /** Where to append the audit trail. Empty means in-memory only. */
    private String file = "";

    /**
     * Refuse requests when the audit trail cannot be written.
     *
     * <p>Off by default, and the choice is a real one. On means an unwritable disk stops
     * the gateway serving — correct where "no record" is legally equivalent to "did not
     * happen", wrong where the gateway is the thing standing between an agent and a
     * poisoned tool, because it disables the protection to protect the paperwork.
     */
    private boolean failClosed = false;

    public String getFile() { return file; }
    public void setFile(String file) { this.file = file; }
    public boolean isFailClosed() { return failClosed; }
    public void setFailClosed(boolean failClosed) { this.failClosed = failClosed; }
}
