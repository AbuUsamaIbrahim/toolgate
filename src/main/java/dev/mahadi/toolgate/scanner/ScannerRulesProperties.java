package dev.mahadi.toolgate.scanner;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "toolgate.scanner")
public class ScannerRulesProperties {

    /**
     * Path to the JSON file where scanner rules are persisted.
     *
     * <p>Leave blank to keep rules in memory only — they will reset to defaults on restart.
     * Set it to a writable path (e.g. {@code /var/lib/toolgate/scanner-rules.json}) to make
     * portal edits survive restarts.
     */
    private String rulesFile = "";

    public String getRulesFile() { return rulesFile; }
    public void setRulesFile(String rulesFile) { this.rulesFile = rulesFile; }
}
