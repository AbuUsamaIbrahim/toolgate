package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.protocol.Mcp;

import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The Streamable HTTP rules that exist for security rather than for framing.
 *
 * <h2>Origin validation, against DNS rebinding</h2>
 * The specification requires it, and the reason is specific: a page on the open web can
 * point a name it controls at {@code 127.0.0.1} and then have the browser make requests to
 * a gateway running on the user's own machine. The browser will happily send them; the
 * gateway has no idea the request came from a hostile page rather than the agent. The
 * {@code Origin} header is the only thing that distinguishes them, so an invalid one gets
 * 403 rather than a JSON-RPC error — the request never becomes MCP at all.
 *
 * <h2>Header and body must agree</h2>
 * This revision mirrors {@code method}, and the tool or resource name, into
 * {@code Mcp-Method} and {@code Mcp-Name} so that intermediaries can route without parsing
 * the body. The spec then requires servers to check that the two agree, and says exactly
 * why: <em>"different components in the network rely on different sources of truth (e.g., a
 * load balancer routing on the header value while the MCP server executes based on the body
 * value)"</em>.
 *
 * <p>That warning is about something standing between the client and the server, which is
 * what this gateway is. A request with {@code Mcp-Name: read_file} and a body calling
 * {@code delete_everything} is a request designed to be judged by one component and
 * executed by another. Toolgate decides on the body, because the body is what the upstream
 * will act on — and refuses the mismatch outright, so nothing downstream of it can be
 * fooled either.
 */
public final class HttpTransportRules {

    /** Error code the specification allocates for a header that disagrees with the body. */
    public static final int HEADER_MISMATCH = -32020;

    private static final String SENTINEL_PREFIX = "=?base64?";
    private static final String SENTINEL_SUFFIX = "?=";

    private HttpTransportRules() {}

    public record Rejection(int httpStatus, int jsonRpcCode, String message) {}

    /**
     * Checks the {@code Origin} header.
     *
     * <p>Absent is fine: a non-browser client has no reason to send one, and requiring it
     * would break every command-line agent. Present and unrecognised is not — a browser
     * sent it, and it is not one this gateway serves.
     */
    public static Optional<Rejection> checkOrigin(String origin, Set<String> allowedOrigins) {
        if (origin == null || origin.isBlank()) return Optional.empty();

        String normalised = normaliseOrigin(origin);
        if (allowedOrigins.stream().map(HttpTransportRules::normaliseOrigin)
                .anyMatch(normalised::equals)) {
            return Optional.empty();
        }
        return Optional.of(new Rejection(403, Mcp.Codes.POLICY_DENIED,
                "origin not permitted: " + origin));
    }

    private static String normaliseOrigin(String origin) {
        try {
            URI uri = URI.create(origin.trim());
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            return port < 0 ? scheme + "://" + host : scheme + "://" + host + ":" + port;
        } catch (IllegalArgumentException e) {
            return origin.trim().toLowerCase(Locale.ROOT);
        }
    }

    /**
     * Checks that the mirrored headers agree with the body.
     *
     * <p>Only checked when present. This revision requires clients to send them, but a
     * gateway that refuses every request from a client one revision behind is a gateway
     * nobody can adopt — and a header that is absent cannot be used to desync anything.
     * A header that is present and <em>wrong</em> is the attack, and that is refused.
     */
    public static Optional<Rejection> checkMirroredHeaders(Mcp.Request request,
                                                           String mcpMethod, String mcpName) {
        if (mcpMethod != null && !mcpMethod.equals(request.method())) {
            return Optional.of(new Rejection(400, HEADER_MISMATCH,
                    "Header mismatch: Mcp-Method header value '%s' does not match body value '%s'"
                            .formatted(mcpMethod, request.method())));
        }

        if (mcpName != null) {
            String decoded = decodeSentinel(mcpName);
            String body = nameFromBody(request);
            if (body != null && !decoded.equals(body)) {
                return Optional.of(new Rejection(400, HEADER_MISMATCH,
                        "Header mismatch: Mcp-Name header value '%s' does not match body value '%s'"
                                .formatted(decoded, body)));
            }
        }
        return Optional.empty();
    }

    /** {@code params.name} for tools and prompts, {@code params.uri} for resources. */
    private static String nameFromBody(Mcp.Request request) {
        Map<String, Object> params = request.params();
        if (params == null) return null;
        Object name = params.get("name");
        if (name != null) return String.valueOf(name);
        Object uri = params.get("uri");
        return uri == null ? null : String.valueOf(uri);
    }

    /**
     * Decodes the {@code =?base64?…?=} form the spec defines for values that cannot travel
     * as plain ASCII. Comparing without decoding would let any non-ASCII name bypass the
     * check simply by being encoded.
     */
    public static String decodeSentinel(String value) {
        String trimmed = value.trim();
        if (!trimmed.startsWith(SENTINEL_PREFIX) || !trimmed.endsWith(SENTINEL_SUFFIX)) {
            return trimmed;
        }
        String encoded = trimmed.substring(SENTINEL_PREFIX.length(),
                trimmed.length() - SENTINEL_SUFFIX.length());
        try {
            return new String(Base64.getDecoder().decode(encoded),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Undecodable, so it cannot equal anything in the body, and the mismatch
            // check will refuse it. Returning the raw value keeps the error readable.
            return trimmed;
        }
    }

    /** Methods this revision no longer defines on the MCP endpoint. */
    public static final List<String> REMOVED_METHODS = List.of("GET", "DELETE");
}
