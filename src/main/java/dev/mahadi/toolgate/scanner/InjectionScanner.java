package dev.mahadi.toolgate.scanner;

import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

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
 * the structural signals below ({@code SUSPICIOUS_UNICODE}, credential paths, exfiltration
 * shapes) are considerably harder to evade than the phrase list.
 *
 * <p>The scanner therefore <em>scores</em> rather than blocks outright, and policy decides
 * what a score means. Treating this as a reliable oracle would be a design error.
 */
@Component
public class InjectionScanner {

    /**
     * Instruction-shaped phrases. A tool <em>description</em> describes what a tool does;
     * it has no legitimate reason to issue commands to the model reading it.
     */
    private static final List<Pattern> IMPERATIVES = List.of(
            Pattern.compile("ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+instructions?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("disregard\\s+(the\\s+)?(system|previous|above)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("you\\s+(are|must|should)\\s+now\\s+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("do\\s+not\\s+(tell|inform|mention|reveal)\\s+the\\s+user", Pattern.CASE_INSENSITIVE),
            Pattern.compile("without\\s+(telling|informing|asking)\\s+the\\s+user", Pattern.CASE_INSENSITIVE),
            Pattern.compile("before\\s+(using|calling)\\s+(this|any)\\s+tool,?\\s+(you\\s+)?(must|should|first)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\s*(system|important|secret)\\s*>", Pattern.CASE_INSENSITIVE)
    );

    /** Paths and identifiers that appear in credential-theft payloads. */
    private static final List<Pattern> CREDENTIAL_TARGETS = List.of(
            Pattern.compile("~?/?\\.ssh/|id_rsa|id_ed25519", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\.env\\b|\\.aws/credentials|\\.netrc|\\.npmrc", Pattern.CASE_INSENSITIVE),
            Pattern.compile("GITHUB_TOKEN|AWS_SECRET|API_?KEY|PRIVATE_?KEY", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/etc/(passwd|shadow)", Pattern.CASE_INSENSITIVE)
    );

    /** Shapes associated with moving data somewhere the user did not ask for. */
    private static final List<Pattern> EXFILTRATION = List.of(
            Pattern.compile("(send|post|upload|forward|exfiltrate)\\s+(it|them|the\\s+\\w+|results?|contents?)\\s+to\\s+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("https?://(?!localhost|127\\.0\\.0\\.1)[\\w.-]+\\.[a-z]{2,}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("curl\\s+|wget\\s+|nc\\s+-", Pattern.CASE_INSENSITIVE)
    );

    /**
     * Characters used to hide text from human reviewers while leaving it visible to a
     * model: zero-width spaces, bidirectional overrides, private-use area, and the
     * Unicode "tag" block used for invisible ASCII smuggling.
     */
    private static final Pattern SUSPICIOUS_UNICODE =
            Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\uE000-\\uF8FF]|[\\x{E0000}-\\x{E007F}]");

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
        scanText(findings, "name", tool.name());
        scanText(findings, "title", tool.title());
        scanText(findings, "description", tool.description());
        scanNested(findings, "inputSchema", tool.inputSchema());
        scanNested(findings, "outputSchema", tool.outputSchema());
        scanNested(findings, "annotations", tool.annotations());
        return new Result(List.copyOf(findings));
    }

    /** Scans tool output, which reaches the model just as directly as a description. */
    public Result scanContent(String text) {
        List<Finding> findings = new ArrayList<>();
        scanText(findings, "toolResult", text);
        return new Result(List.copyOf(findings));
    }

    private void scanNested(List<Finding> findings, String field, Object value) {
        switch (value) {
            case null -> { }
            case Map<?, ?> map -> map.forEach((k, v) -> {
                scanText(findings, field + "." + k, String.valueOf(k));
                scanNested(findings, field + "." + k, v);
            });
            case List<?> list -> list.forEach(item -> scanNested(findings, field, item));
            case String s -> scanText(findings, field, s);
            default -> { }
        }
    }

    private void scanText(List<Finding> findings, String field, String text) {
        if (text == null || text.isBlank()) return;

        for (Pattern p : IMPERATIVES) {
            var m = p.matcher(text);
            if (m.find()) findings.add(new Finding("imperative_instruction", field, m.group(), 40));
        }
        for (Pattern p : CREDENTIAL_TARGETS) {
            var m = p.matcher(text);
            if (m.find()) findings.add(new Finding("credential_target", field, m.group(), 35));
        }
        for (Pattern p : EXFILTRATION) {
            var m = p.matcher(text);
            if (m.find()) findings.add(new Finding("exfiltration_shape", field, m.group(), 30));
        }
        var u = SUSPICIOUS_UNICODE.matcher(text);
        if (u.find()) {
            // Report the codepoint, not the character — it is invisible by construction.
            findings.add(new Finding("hidden_unicode", field,
                    "U+%04X".formatted(text.codePointAt(u.start())), 50));
        }
    }
}
