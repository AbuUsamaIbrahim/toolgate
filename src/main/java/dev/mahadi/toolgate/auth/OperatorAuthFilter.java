package dev.mahadi.toolgate.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Guards the operator API.
 *
 * <p>Implemented as a filter rather than checks inside each handler. A handler-by-handler
 * approach means the next endpoint someone adds is unprotected until they remember to
 * guard it, and "remember to" is not an access control model. Here the default for
 * anything under {@code /toolgate/} is closed.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class OperatorAuthFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(OperatorAuthFilter.class);
    /**
     * The operator area. Both forms, and that is not pedantry: a filter guarding only
     * {@code /toolgate/} leaves {@code /toolgate} itself wide open, which is exactly how
     * the dashboard shipped unauthenticated for its first ten minutes of existence. This
     * class already argued that "remember to guard the next endpoint" is not an access
     * control model; a prefix that misses its own root is the same mistake one level down.
     */
    private static final String PREFIX = "/toolgate/";
    private static final String ROOT = "/toolgate";

    private final OperatorProperties props;

    public OperatorAuthFilter(OperatorProperties props) {
        this.props = props;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        boolean operatorArea = path.equals(ROOT) || path.startsWith(PREFIX);
        if (!operatorArea || !props.isEnabled()) {
            return chain.filter(exchange);
        }

        if (props.isLoopbackOnly() && !isLoopback(exchange)) {
            log.warn("Rejected operator request to {} from {}", path, remote(exchange));
            return deny(exchange, HttpStatus.FORBIDDEN);
        }

        String presented = bearer(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        String expected = props.getTokenSha256();

        if (expected == null || expected.isBlank()) {
            // Enabled but unconfigured. Failing closed is the only safe reading: the
            // alternative is a gateway that silently leaves its most powerful API open
            // because someone forgot a line of configuration.
            log.error("Operator API is enabled but no token is configured — refusing all "
                    + "operator requests. Set toolgate.operator.token-sha256 or disable it explicitly.");
            return deny(exchange, HttpStatus.UNAUTHORIZED);
        }
        if (presented == null || !constantTimeEquals(sha256(presented), expected.toLowerCase())) {
            return deny(exchange, HttpStatus.UNAUTHORIZED);
        }
        return chain.filter(exchange);
    }

    private static boolean isLoopback(ServerWebExchange exchange) {
        InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
        return remote != null && remote.getAddress() != null && remote.getAddress().isLoopbackAddress();
    }

    private static String remote(ServerWebExchange exchange) {
        InetSocketAddress a = exchange.getRequest().getRemoteAddress();
        return a == null ? "unknown" : String.valueOf(a.getAddress());
    }

    private Mono<Void> deny(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        if (status == HttpStatus.UNAUTHORIZED) {
            exchange.getResponse().getHeaders().add(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"toolgate-operator\"");
        }
        return exchange.getResponse().setComplete();
    }

    private static String bearer(String header) {
        if (header == null) return null;
        if (header.length() < 7 || !header.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        return header.substring(7).trim();
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
