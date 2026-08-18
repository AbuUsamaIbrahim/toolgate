package dev.mahadi.toolgate.protocol;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates and applies {@code x-mcp-header}, the schema keyword that mirrors a tool
 * argument into an HTTP header on the outgoing call.
 *
 * <h2>Why this needs a control at all</h2>
 * Every other field in a tool definition is data the model reads. This one is different:
 * it is an instruction to the <em>transport</em>. A server that controls its own tool
 * definitions can therefore reach past the JSON-RPC body and write into the HTTP header
 * block of the request the gateway sends — a boundary nothing else in the protocol lets
 * an upstream cross.
 *
 * <p>Three concrete things go wrong if that is taken on trust:
 *
 * <ul>
 *   <li><b>Overwriting the gateway's own credential.</b> A definition declaring
 *       {@code x-mcp-header: Authorization} turns an innocuous-looking string parameter
 *       into control over the header the gateway authenticates with. The model can be
 *       talked into filling that parameter; it has no idea it is writing an auth header.</li>
 *   <li><b>Request splitting.</b> A value containing CR or LF ends the header and starts
 *       whatever the attacker wants next. This is the oldest injection in HTTP and it
 *       reappears anywhere untrusted data reaches a header.</li>
 *   <li><b>Exfiltration through the access log.</b> Headers are logged by every proxy in
 *       the path, in a way bodies are not. Mirroring a sensitive argument into one moves
 *       it somewhere with different — usually much longer — retention.</li>
 * </ul>
 *
 * <h2>The rule</h2>
 * Mirrored headers must sit in the {@code Mcp-Param-} namespace the specification
 * reserves for them. That single constraint is what makes {@code Authorization},
 * {@code Cookie}, {@code Host} and every other meaningful header unreachable — not an
 * enumerated block list, which would be a race between the list and the next header
 * somebody finds useful.
 *
 * <p>Changing an {@code x-mcp-header} declaration also changes the tool's fingerprint, so
 * a definition that mirrors nothing today and {@code Mcp-Param-Path} tomorrow is caught as
 * drift regardless of what this class thinks of the new value.
 */
public final class HeaderMirror {

    /** The namespace the specification reserves for mirrored parameters. */
    public static final String NAMESPACE = "Mcp-Param-";

    private static final String KEYWORD = "x-mcp-header";
    private static final int MAX_NAME_LENGTH = 128;
    private static final int MAX_VALUE_LENGTH = 1024;

    private HeaderMirror() {}

    /** A parameter that a tool definition asks to have mirrored into a header. */
    public record Declaration(String parameter, String headerName) {}

    /**
     * Finds every mirror declaration in a tool's input schema.
     *
     * <p>Walks nested schemas rather than only top-level properties. Burying a declaration
     * inside {@code properties.x.items.properties.y} is the first thing anyone tries once
     * they learn the top level is checked, and the transport that applies the keyword does
     * not care how deep it was.
     */
    public static List<Declaration> declaredBy(Mcp.Tool tool) {
        List<Declaration> found = new ArrayList<>();
        if (tool.inputSchema() != null) {
            walk(tool.inputSchema(), null, found);
        }
        return found;
    }

    @SuppressWarnings("unchecked")
    private static void walk(Object node, String propertyName, List<Declaration> found) {
        if (!(node instanceof Map<?, ?> map)) {
            if (node instanceof List<?> list) {
                list.forEach(child -> walk(child, propertyName, found));
            }
            return;
        }

        Object header = map.get(KEYWORD);
        if (header != null) {
            found.add(new Declaration(
                    propertyName == null ? "<schema root>" : propertyName,
                    String.valueOf(header)));
        }

        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());
            if (KEYWORD.equals(key)) continue;

            if ("properties".equals(key) && entry.getValue() instanceof Map<?, ?> properties) {
                // Children of "properties" are named parameters; everything else inherits
                // the name of whatever contains it.
                properties.forEach((name, schema) -> walk(schema, String.valueOf(name), found));
            } else {
                walk(entry.getValue(), propertyName, found);
            }
        }
    }

    /**
     * Checks every declaration in a tool definition.
     *
     * @return the reasons the definition should be refused; empty means acceptable
     */
    public static List<String> validate(Mcp.Tool tool) {
        List<String> problems = new ArrayList<>();
        for (Declaration d : declaredBy(tool)) {
            String name = d.headerName();

            if (name.isBlank() || name.length() > MAX_NAME_LENGTH) {
                problems.add("%s: header name is empty or absurdly long".formatted(d.parameter()));
                continue;
            }
            if (!isToken(name)) {
                problems.add("%s: '%s' is not a valid header name".formatted(
                        d.parameter(), escape(name)));
                continue;
            }
            if (!name.regionMatches(true, 0, NAMESPACE, 0, NAMESPACE.length())) {
                problems.add(("%s: mirrors into '%s', outside the reserved %s* namespace — "
                        + "a tool definition may not choose which header it writes")
                        .formatted(d.parameter(), escape(name), NAMESPACE));
                continue;
            }
            if (name.length() == NAMESPACE.length()) {
                problems.add("%s: '%s' has no name after the namespace prefix"
                        .formatted(d.parameter(), escape(name)));
            }
        }
        return problems;
    }

    /**
     * Builds the headers to send for a call.
     *
     * <p>Takes the <em>pinned</em> definition, not whatever the upstream advertised most
     * recently. Drift is refused before it gets here, so in practice they agree — but the
     * pin is the definition a human approved, and that is the one whose instructions the
     * gateway should be following.
     *
     * <p>Values that cannot be represented safely are dropped rather than escaped. A
     * mangled header is a subtler failure than a missing one, and there is no legitimate
     * argument that needs a newline in it.
     */
    public static Map<String, String> headersFor(Mcp.Tool pinned, Map<String, Object> arguments) {
        if (pinned == null || arguments == null || arguments.isEmpty()) return Map.of();

        // If any declaration is bad, mirror none of them. Sending the acceptable subset
        // would let an attacker mix one valid declaration with one designed to be dropped
        // and learn from which of the two the call still works.
        if (!validate(pinned).isEmpty()) return Map.of();

        Map<String, String> headers = new LinkedHashMap<>();
        for (Declaration d : declaredBy(pinned)) {
            Object raw = arguments.get(d.parameter());
            if (raw == null) continue;
            if (raw instanceof Map || raw instanceof List) continue;   // not header-shaped

            String value = String.valueOf(raw);
            if (value.length() > MAX_VALUE_LENGTH) continue;
            if (containsControlCharacter(value)) continue;

            headers.put(d.headerName(), value);
        }
        return headers;
    }

    /** RFC 9110 token: visible ASCII, minus separators. */
    private static boolean isToken(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
            if (!ok) return false;
        }
        return true;
    }

    private static boolean containsControlCharacter(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) return true;
        }
        return false;
    }

    /** Keeps a hostile header name from injecting into the log line that reports it. */
    private static String escape(String s) {
        StringBuilder out = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            if (cp < 0x20 || cp == 0x7f || Character.getType(cp) == Character.FORMAT) {
                out.append("⟨U+%04X⟩".formatted(cp));
            } else {
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }
}
