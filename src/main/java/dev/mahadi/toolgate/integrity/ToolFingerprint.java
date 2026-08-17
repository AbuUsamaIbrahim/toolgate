package dev.mahadi.toolgate.integrity;

import dev.mahadi.toolgate.protocol.Mcp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Computes a stable fingerprint over everything in a tool definition that can influence
 * a model's behaviour.
 *
 * <p>The threat this addresses: an upstream MCP server advertises a benign tool, the
 * operator approves it, and the server later mutates the tool's {@code description},
 * {@code annotations} or {@code inputSchema} to carry adversarial instructions. Because
 * the model reads those fields as trusted operational context, the change is invisible
 * to the user and requires no code execution to exploit.
 *
 * <p>Fingerprinting the definition turns that silent mutation into a detectable event.
 *
 * <h2>What is covered</h2>
 * {@code name}, {@code title}, {@code description}, {@code inputSchema},
 * {@code outputSchema} and {@code annotations}. Everything a model sees.
 *
 * <p>{@code icons} are deliberately excluded: they are display metadata that never
 * reaches the model, and including them would produce drift alerts for cosmetic changes,
 * which is how a security control trains its operators to ignore it.
 *
 * <h2>Canonicalisation</h2>
 * JSON object key order is not semantically meaningful, so a naive hash of the serialised
 * form would produce false positives whenever an upstream reordered its output. Maps are
 * therefore sorted recursively before hashing; list order <em>is</em> preserved, because
 * in JSON Schema (notably {@code required} and {@code enum}) order can matter and, more
 * importantly, reordering is a cheap way to smuggle a change past a lazy comparator.
 */
public final class ToolFingerprint {

    private ToolFingerprint() {}

    /** SHA-256 over the canonical form, hex-encoded. */
    public static String of(Mcp.Tool tool) {
        StringBuilder sb = new StringBuilder();
        appendField(sb, "name", tool.name());
        appendField(sb, "title", tool.title());
        appendField(sb, "description", tool.description());
        appendField(sb, "inputSchema", tool.inputSchema());
        appendField(sb, "outputSchema", tool.outputSchema());
        appendField(sb, "annotations", tool.annotations());
        return sha256(sb.toString());
    }

    /** Unit separator: cannot appear unescaped in JSON, so it is a safe delimiter. */
    private static final char FIELD_SEP = '\u001e';

    /** Record separator, terminating each field. */
    private static final char RECORD_SEP = '\u001d';

    private static void appendField(StringBuilder sb, String key, Object value) {
        sb.append(key).append(FIELD_SEP);
        canonical(sb, value);
        sb.append(RECORD_SEP);
    }

    /**
     * Writes a deterministic textual encoding of an arbitrary JSON value.
     *
     * <p>Type tags are included so that {@code "1"} and {@code 1}, or {@code null} and
     * the string {@code "null"}, cannot collide — a distinction an attacker would
     * otherwise be free to exploit.
     */
    private static void canonical(StringBuilder sb, Object value) {
        switch (value) {
            case null -> sb.append("~null");
            case Map<?, ?> map -> {
                sb.append("{");
                // TreeMap gives us deterministic ordering regardless of upstream key order.
                Map<String, Object> sorted = new TreeMap<>();
                map.forEach((k, v) -> sorted.put(String.valueOf(k), v));
                sorted.forEach((k, v) -> {
                    sb.append(k).append(':');
                    canonical(sb, v);
                    sb.append(',');
                });
                sb.append("}");
            }
            case List<?> list -> {
                sb.append("[");
                for (Object item : list) {
                    canonical(sb, item);
                    sb.append(',');
                }
                sb.append("]");
            }
            case String s -> sb.append("s\"").append(s).append('"');
            case Boolean b -> sb.append("b").append(b);
            case Number n -> sb.append("n").append(n);
            default -> sb.append("o\"").append(value).append('"');
        }
    }

    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS; if it is missing the JVM is broken.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
