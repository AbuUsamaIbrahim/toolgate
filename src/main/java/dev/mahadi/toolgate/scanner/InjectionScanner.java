package dev.mahadi.toolgate.scanner;

import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Heuristic detection of adversarial content in tool metadata.
 *
 * <p>Pinning ({@link dev.mahadi.toolgate.integrity.ToolPinStore}) catches definitions
 * that <em>change</em>. It cannot catch a definition that is hostile the first time it is
 * seen. This scanner is the complementary control for that case.
 *
 * <h2>On the limits of this approach</h2>
 * Pattern matching against natural language is a losing game played alone — an attacker
 * who knows the rules can phrase around them. It is included because in defence in depth
 * a cheap filter that catches the unsophisticated majority still has value, and because
 * the structural signals below (hidden unicode, credential paths, exfiltration shapes)
 * are considerably harder to evade than the phrase list.
 *
 * <p>The scanner therefore <em>scores</em> rather than blocks outright, and policy decides
 * what a score means. Treating this as a reliable oracle would be a design error.
 *
 * <p>Rules are loaded from {@link ScannerRulesStore} and can be edited through the
 * operator portal without a redeploy.
 */
@Component
public class InjectionScanner {

    private static final java.util.Set<String> URI_VALUED_SCHEMA_KEYS =
            java.util.Set.of("$schema", "$id");

    private final ScannerRulesStore store;

    public InjectionScanner(ScannerRulesStore store) {
        this.store = store;
    }

    /** Convenience factory for unit tests: creates an in-memory store seeded with defaults. */
    public static InjectionScanner withDefaults() {
        return new InjectionScanner(new ScannerRulesStore(new ScannerRulesProperties()));
    }

    public record Finding(String rule, String field, String evidence, int weight) {}

    public record Result(List<Finding> findings) {
        public int score() {
            return findings.stream().mapToInt(Finding::weight).sum();
        }

        public boolean clean() {
            return findings.isEmpty();
        }
    }

    /** Scans every model-visible field of a tool definition. */
    public Result scan(Mcp.Tool tool) {
        List<Finding> findings = new ArrayList<>();
        List<ScannerRule> active = store.active();
        scanText(findings, "name", tool.name(), active);
        scanText(findings, "title", tool.title(), active);
        scanText(findings, "description", tool.description(), active);
        scanNested(findings, "inputSchema", tool.inputSchema(), active);
        scanNested(findings, "outputSchema", tool.outputSchema(), active);
        scanNested(findings, "annotations", tool.annotations(), active);
        return new Result(List.copyOf(findings));
    }

    public Result scan(String name, String title, String description) {
        List<Finding> findings = new ArrayList<>();
        List<ScannerRule> active = store.active();
        scanText(findings, "name", name, active);
        scanText(findings, "title", title, active);
        scanText(findings, "description", description, active);
        return new Result(List.copyOf(findings));
    }

    public Result scanContent(String text) {
        List<Finding> findings = new ArrayList<>();
        scanText(findings, "toolResult", text, store.active());
        return new Result(List.copyOf(findings));
    }

    private void scanNested(List<Finding> findings, String field, Object value,
                            List<ScannerRule> active) {
        switch (value) {
            case null -> { }
            case Map<?, ?> map -> map.forEach((k, v) -> {
                String key = String.valueOf(k);
                scanText(findings, field + "." + key, key, active);
                if (URI_VALUED_SCHEMA_KEYS.contains(key) && v instanceof String s) {
                    scanForHiddenCharacters(findings, field + "." + key, s, active);
                } else {
                    scanNested(findings, field + "." + key, v, active);
                }
            });
            case List<?> list -> list.forEach(item -> scanNested(findings, field, item, active));
            case String s -> scanText(findings, field, s, active);
            default -> { }
        }
    }

    private void scanForHiddenCharacters(List<Finding> findings, String field, String text,
                                         List<ScannerRule> active) {
        if (text == null || text.isBlank()) return;
        for (ScannerRule rule : active) {
            if (!ScannerRule.HIDDEN_UNICODE.equals(rule.category())) continue;
            try {
                var m = Pattern.compile(rule.pattern()).matcher(text);
                if (m.find()) {
                    findings.add(new Finding(rule.category(), field,
                            "U+%04X".formatted(text.codePointAt(m.start())), rule.weight()));
                    return;
                }
            } catch (PatternSyntaxException ignored) { }
        }
    }

    private void scanText(List<Finding> findings, String field, String text,
                          List<ScannerRule> active) {
        if (text == null || text.isBlank()) return;
        for (ScannerRule rule : active) {
            try {
                Pattern p = Pattern.compile(rule.pattern(),
                        ScannerRule.HIDDEN_UNICODE.equals(rule.category())
                                ? 0 : Pattern.CASE_INSENSITIVE);
                var m = p.matcher(text);
                if (m.find()) {
                    String evidence = ScannerRule.HIDDEN_UNICODE.equals(rule.category())
                            ? "U+%04X".formatted(text.codePointAt(m.start()))
                            : m.group();
                    findings.add(new Finding(rule.category(), field, evidence, rule.weight()));
                }
            } catch (PatternSyntaxException e) {
                // A malformed custom rule is skipped, not fatal — the rest still run.
            }
        }
    }
}
