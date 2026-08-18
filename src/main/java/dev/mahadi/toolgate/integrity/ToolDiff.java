package dev.mahadi.toolgate.integrity;

import dev.mahadi.toolgate.protocol.Mcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Field-level comparison of a pinned tool definition against what an upstream is now
 * advertising.
 *
 * <p>A fingerprint answers <em>whether</em> something changed. It cannot answer the only
 * question an operator actually has — <em>is this a legitimate release or an attack?</em>
 * Two hex strings give them no basis for that decision, so in practice they either
 * rubber-stamp the change or block a deployment they had no way to evaluate. Both outcomes
 * are failures of the control.
 *
 * <h2>Rendering hostile text safely</h2>
 * The values being displayed are attacker-controlled. That is fine — they are data here,
 * not instructions — but two precautions matter:
 *
 * <ul>
 *   <li>Invisible characters are escaped to their codepoints. A zero-width-space attack is
 *       designed to look identical to benign text; a diff that faithfully reproduces it
 *       shows the operator two lines that appear the same and hides the very thing they
 *       are being asked to judge.</li>
 *   <li>Long values are truncated. A definition padded with a screenful of whitespace is a
 *       cheap way to push the real change out of view.</li>
 * </ul>
 */
public final class ToolDiff {

    private static final int MAX_VALUE_LENGTH = 400;

    private ToolDiff() {}

    public enum ChangeType { ADDED, REMOVED, MODIFIED }

    /** One field that differs, with both sides rendered safe to display. */
    public record Change(String field, ChangeType type, String pinned, String current) {}

    public record Result(List<Change> changes) {
        public boolean identical() {
            return changes.isEmpty();
        }
    }

    /** Compares every model-visible field, in the same order the fingerprint covers them. */
    public static Result between(Mcp.Tool pinned, Mcp.Tool current) {
        List<Change> changes = new ArrayList<>();
        compare(changes, "name", pinned.name(), current.name());
        compare(changes, "title", pinned.title(), current.title());
        compare(changes, "description", pinned.description(), current.description());
        compareNested(changes, "inputSchema", pinned.inputSchema(), current.inputSchema());
        compareNested(changes, "outputSchema", pinned.outputSchema(), current.outputSchema());
        compareNested(changes, "annotations", pinned.annotations(), current.annotations());
        return new Result(List.copyOf(changes));
    }

    private static void compare(List<Change> changes, String field, Object a, Object b) {
        if (a == null && b == null) return;
        if (a == null) {
            changes.add(new Change(field, ChangeType.ADDED, null, render(b)));
        } else if (b == null) {
            changes.add(new Change(field, ChangeType.REMOVED, render(a), null));
        } else if (!a.equals(b)) {
            changes.add(new Change(field, ChangeType.MODIFIED, render(a), render(b)));
        }
    }

    /**
     * Walks nested maps so a change buried in a schema property is reported at its path
     * rather than as "inputSchema changed" — which would send the operator hunting through
     * two JSON blobs for the difference.
     */
    @SuppressWarnings("unchecked")
    private static void compareNested(List<Change> changes, String path, Object a, Object b) {
        if (a instanceof Map && b instanceof Map) {
            Map<String, Object> ma = (Map<String, Object>) a;
            Map<String, Object> mb = (Map<String, Object>) b;
            Set<String> keys = new TreeSet<>();
            ma.keySet().forEach(k -> keys.add(String.valueOf(k)));
            mb.keySet().forEach(k -> keys.add(String.valueOf(k)));
            for (String key : keys) {
                compareNested(changes, path + "." + key, ma.get(key), mb.get(key));
            }
            return;
        }
        compare(changes, path, a, b);
    }

    /** Escapes anything a human cannot see, then bounds the length. */
    static String render(Object value) {
        String s = switch (value) {
            case null -> "null";
            case Map<?, ?> m -> new LinkedHashMap<>(m).toString();
            default -> String.valueOf(value);
        };

        StringBuilder sb = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            if (isInvisible(cp)) {
                // The attack becomes visible precisely because it is spelled out.
                sb.append("⟨U+%04X⟩".formatted(cp));
            } else {
                sb.appendCodePoint(cp);
            }
        });

        String out = sb.toString();
        return out.length() <= MAX_VALUE_LENGTH
                ? out
                : out.substring(0, MAX_VALUE_LENGTH) + "… (%d more chars)".formatted(out.length() - MAX_VALUE_LENGTH);
    }

    /**
     * Characters that render as nothing, or that reorder what follows them.
     *
     * <p>Ordinary control characters are included as well: a newline inside a description
     * is legitimate, but a carriage return can be used to overwrite a line in a terminal,
     * which is another way to hide text from a reviewer.
     */
    private static boolean isInvisible(int cp) {
        if (cp == '\n' || cp == '\t') return false;
        return cp < 0x20                                  // control characters
                || cp == 0x7F                             // delete
                || (cp >= 0x200B && cp <= 0x200F)         // zero-width, direction marks
                || (cp >= 0x202A && cp <= 0x202E)         // bidirectional overrides
                || (cp >= 0x2060 && cp <= 0x2064)         // invisible operators
                || cp == 0xFEFF                           // byte-order mark
                || (cp >= 0xE000 && cp <= 0xF8FF)         // private use area
                || (cp >= 0xE0000 && cp <= 0xE007F);      // tag block: invisible ASCII
    }
}
