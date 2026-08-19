package dev.mahadi.toolgate.scanner;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * One detection signal the injection scanner evaluates.
 *
 * <p>Built-in rules ship with the gateway and represent the signals that existed before
 * this configuration layer existed. They can be disabled (to suppress a false-positive
 * category) but not deleted — deleting them would make it impossible to restore defaults
 * without a redeploy. Custom rules added through the portal can be deleted freely.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScannerRule(
        String id,
        String category,
        String pattern,
        int weight,
        boolean enabled,
        boolean builtIn,
        String description,
        Instant createdAt) {

    /** Categories match the finding rule names the scanner reports. */
    public static final String IMPERATIVE_INSTRUCTION = "imperative_instruction";
    public static final String CREDENTIAL_TARGET      = "credential_target";
    public static final String EXFILTRATION_SHAPE     = "exfiltration_shape";
    public static final String HIDDEN_UNICODE         = "hidden_unicode";
}
