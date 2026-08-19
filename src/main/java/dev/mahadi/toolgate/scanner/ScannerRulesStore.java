package dev.mahadi.toolgate.scanner;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

/**
 * Live set of injection-scanner rules, backed by a JSON file the portal can edit.
 *
 * <p>Rules are loaded at startup. If the file does not exist, the built-in defaults are
 * written to it so there is one canonical source of truth from the first run. Any change
 * made through the portal is persisted atomically — same crash-safety guarantee as the
 * pin store — so a restart after a portal edit keeps the operator's configuration.
 *
 * <p>If no rules file is configured, changes live in memory only. That is acceptable for
 * evaluation and unacceptable for production, so the portal shows a warning when it is
 * the case.
 */
@Component
public class ScannerRulesStore {

    private static final Logger log = LoggerFactory.getLogger(ScannerRulesStore.class);
    private static final int SCHEMA_VERSION = 1;

    private final ScannerRulesProperties props;
    private final ObjectMapper mapper;

    // Ordered map: insertion order is display order in the portal.
    private final LinkedHashMap<String, ScannerRule> rules = new LinkedHashMap<>();

    public ScannerRulesStore(ScannerRulesProperties props) {
        this.props = props;
        this.mapper = new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);

        load();
    }

    // ---------------------------------------------------------------- query

    /** All rules in display order. */
    public synchronized List<ScannerRule> all() {
        return List.copyOf(rules.values());
    }

    /** Only the enabled rules — what the scanner actually runs. */
    public synchronized List<ScannerRule> active() {
        return rules.values().stream().filter(ScannerRule::enabled).toList();
    }

    // ---------------------------------------------------------------- mutation

    public synchronized ScannerRule add(String category, String pattern, int weight,
                                        String description) {
        String id = UUID.randomUUID().toString();
        var rule = new ScannerRule(id, category, pattern, weight, true, false,
                description, Instant.now());
        rules.put(id, rule);
        persist();
        log.info("Scanner rule added: id={} category={} pattern=\"{}\"", id, category, pattern);
        return rule;
    }

    /** Flips enabled/disabled. Returns the updated rule, or empty if not found. */
    public synchronized Optional<ScannerRule> toggle(String id) {
        ScannerRule existing = rules.get(id);
        if (existing == null) return Optional.empty();
        var updated = new ScannerRule(existing.id(), existing.category(), existing.pattern(),
                existing.weight(), !existing.enabled(), existing.builtIn(),
                existing.description(), existing.createdAt());
        rules.put(id, updated);
        persist();
        log.info("Scanner rule {}: id={}", updated.enabled() ? "enabled" : "disabled", id);
        return Optional.of(updated);
    }

    /**
     * Deletes a custom rule. Built-in rules cannot be deleted — use toggle to disable them.
     * Returns true if the rule was found and removed.
     */
    public synchronized boolean delete(String id) {
        ScannerRule existing = rules.get(id);
        if (existing == null) return false;
        if (existing.builtIn()) return false;
        rules.remove(id);
        persist();
        log.info("Scanner rule deleted: id={}", id);
        return true;
    }

    // ---------------------------------------------------------------- persistence

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Document(int schemaVersion, Instant savedAt, List<ScannerRule> rules) {}

    private void load() {
        if (props.getRulesFile().isBlank()) {
            seedDefaults();
            log.warn("No scanner rules file configured — rules live in memory only and reset "
                    + "to defaults on restart. Set toolgate.scanner.rules-file to persist edits.");
            return;
        }

        Path path = path();
        if (!Files.exists(path)) {
            seedDefaults();
            persist();
            log.info("No scanner rules file at {} — wrote defaults", path);
            return;
        }

        try {
            Document doc = mapper.readValue(Files.readString(path), Document.class);
            if (doc.rules() != null) {
                doc.rules().forEach(r -> rules.put(r.id(), r));
            }
            // Seed any built-in rules that are missing from the file (added in a newer version).
            seedMissingDefaults();
            log.info("Loaded {} scanner rules from {}", rules.size(), path);
        } catch (Exception e) {
            throw new RuntimeException(
                    "scanner rules file %s exists but could not be read".formatted(path), e);
        }
    }

    private synchronized void persist() {
        if (props.getRulesFile().isBlank()) return;
        Path path = path();
        try {
            Files.createDirectories(path.toAbsolutePath().getParent());
            String json = mapper.writeValueAsString(
                    new Document(SCHEMA_VERSION, Instant.now(), List.copyOf(rules.values())));
            Path tmp = Files.createTempFile(path.toAbsolutePath().getParent(),
                    ".scanner-rules", ".tmp");
            try {
                Files.writeString(tmp, json, StandardOpenOption.TRUNCATE_EXISTING);
                fsync(tmp);
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                log.warn("Atomic move unsupported; scanner rules write is not crash-safe");
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        } catch (Exception e) {
            throw new RuntimeException("failed to persist scanner rules to " + path, e);
        }
    }

    private static void fsync(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
    }

    private Path path() {
        return dev.mahadi.toolgate.util.FilePaths.expandUser(props.getRulesFile());
    }

    // ---------------------------------------------------------------- defaults

    private static final List<ScannerRule> DEFAULTS = List.of(
            builtIn("bi-imp-1", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+instructions?",
                    40, "Classic prompt injection opener"),
            builtIn("bi-imp-2", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "disregard\\s+(the\\s+)?(system|previous|above)",
                    40, "Disregard system/previous instructions"),
            builtIn("bi-imp-3", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "you\\s+(are|must|should)\\s+now\\s+",
                    40, "Role-reassignment instruction"),
            builtIn("bi-imp-4", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "do\\s+not\\s+(tell|inform|mention|reveal)\\s+the\\s+user",
                    40, "Instructs model to hide action from user"),
            builtIn("bi-imp-5", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "without\\s+(telling|informing|asking)\\s+the\\s+user",
                    40, "Covert action without user knowledge"),
            builtIn("bi-imp-6", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "before\\s+(using|calling)\\s+(this|any)\\s+tool,?\\s+(you\\s+)?(must|should|first)",
                    40, "Pre-condition instruction embedded in tool description"),
            builtIn("bi-imp-7", ScannerRule.IMPERATIVE_INSTRUCTION,
                    "<\\s*(system|important|secret)\\s*>",
                    40, "Fake system/secret tag to elevate instruction priority"),
            builtIn("bi-cred-1", ScannerRule.CREDENTIAL_TARGET,
                    "~?/?\\.ssh/|id_rsa|id_ed25519",
                    35, "SSH private key paths"),
            builtIn("bi-cred-2", ScannerRule.CREDENTIAL_TARGET,
                    "\\.env\\b|\\.aws/credentials|\\.netrc|\\.npmrc",
                    35, "Common credential file locations"),
            builtIn("bi-cred-3", ScannerRule.CREDENTIAL_TARGET,
                    "GITHUB_TOKEN|AWS_SECRET|API_?KEY|PRIVATE_?KEY",
                    35, "Common credential variable names"),
            builtIn("bi-cred-4", ScannerRule.CREDENTIAL_TARGET,
                    "/etc/(passwd|shadow)",
                    35, "Unix user/password database paths"),
            builtIn("bi-exfil-1", ScannerRule.EXFILTRATION_SHAPE,
                    "(send|post|upload|forward|exfiltrate)\\s+(it|them|the\\s+\\w+|results?|contents?)\\s+to\\s+",
                    30, "Explicit data exfiltration instruction"),
            builtIn("bi-exfil-2", ScannerRule.EXFILTRATION_SHAPE,
                    "https?://(?!localhost|127\\.0\\.0\\.1)[\\w.-]+\\.[a-z]{2,}",
                    30, "Non-local URL in tool metadata"),
            builtIn("bi-exfil-3", ScannerRule.EXFILTRATION_SHAPE,
                    "curl\\s+|wget\\s+|nc\\s+-",
                    30, "Shell exfiltration commands"),
            builtIn("bi-unicode-1", ScannerRule.HIDDEN_UNICODE,
                    "[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\uE000-\\uF8FF]",
                    50, "Zero-width, directional override, and private-use characters")
    );

    private void seedDefaults() {
        DEFAULTS.forEach(r -> rules.put(r.id(), r));
    }

    private void seedMissingDefaults() {
        DEFAULTS.forEach(r -> rules.putIfAbsent(r.id(), r));
        if (rules.size() > DEFAULTS.size()) persist();  // wrote new defaults to file
    }

    private static ScannerRule builtIn(String id, String category, String pattern,
                                       int weight, String description) {
        return new ScannerRule(id, category, pattern, weight, true, true,
                description, Instant.EPOCH);
    }
}
