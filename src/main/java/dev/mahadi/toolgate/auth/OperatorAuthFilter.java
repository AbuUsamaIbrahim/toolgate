package dev.mahadi.toolgate.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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

    /**
     * Paths a browser may reach without a session, because they are how one is obtained.
     * Deliberately exact matches rather than a prefix: a prefix is what let the dashboard
     * escape this filter in the first place.
     */
    private static final java.util.Set<String> UNAUTHENTICATED =
            java.util.Set.of("/toolgate/login");

    private final OperatorProperties props;
    private final dev.mahadi.toolgate.api.OperatorSessions sessions;

    public OperatorAuthFilter(OperatorProperties props, dev.mahadi.toolgate.api.OperatorSessions sessions) {
        this.sessions = sessions;
        this.props = props;
    }

    /**
     * Says out loud what was configured.
     *
     * <p>Serving the console to strangers is a deliberate choice for one kind of deployment
     * and a serious mistake on any other, and the difference between them is a single line
     * of YAML. A line in the log at every start is what makes it visible to whoever inherits
     * the deployment rather than only to whoever wrote the config.
     */
    @jakarta.annotation.PostConstruct
    void announce() {
        if (!props.isEnabled()) {
            log.warn("Operator API authentication is disabled — anything that can reach this "
                    + "port can approve a blocked call and re-pin a changed definition");
        } else if (props.isPublicReadOnly()) {
            log.warn("Operator console is PUBLIC and READ-ONLY: anyone who can reach it may "
                    + "read the audit trail, the pins and every drift diff, and no credential "
                    + "on this deployment can accept, approve or sign in. Intended for a "
                    + "demonstration; do not run a real gateway this way.");
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        boolean operatorArea = path.equals(ROOT) || path.startsWith(PREFIX);
        if (!operatorArea || !props.isEnabled()) {
            return chain.filter(exchange);
        }

        // A public demonstration: the console is the point, and nothing here is worth
        // deciding. Reads are open; every write is refused before authentication is even
        // considered, so there is no credential anywhere that can accept a drifted
        // definition on this deployment — not the operator's, and not the one whoever
        // deployed it still holds.
        //
        // Checked ahead of the unauthenticated paths below, which is the whole reason this
        // block sits here rather than after them: signing in is itself a POST, and a login
        // that still worked would hand out a session whose every button leads to a 403.
        // No session can be created here, so the console renders in the one state that is
        // true — read-only — instead of offering actions it will refuse.
        if (props.isPublicReadOnly()) {
            if (isReadOnlyMethod(exchange)) {
                return chain.filter(exchange);
            }
            log.warn("Refused {} {} — this deployment is read-only",
                    exchange.getRequest().getMethod(), path);
            return deny(exchange, HttpStatus.FORBIDDEN);
        }

        if (UNAUTHENTICATED.contains(path)) {
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
        // A browser session counts, and is checked before the bearer token because that is
        // how the dashboard arrives. It is still this filter making the decision: the
        // dashboard has no authentication logic of its own to get wrong.
        String sessionId = exchange.getRequest().getCookies()
                .getFirst(dev.mahadi.toolgate.api.OperatorSessions.COOKIE) == null ? null
                : exchange.getRequest().getCookies()
                        .getFirst(dev.mahadi.toolgate.api.OperatorSessions.COOKIE).getValue();
        if (sessions.lookup(sessionId).isPresent()) {
            return chain.filter(exchange);
        }

        if (presented == null || !constantTimeEquals(sha256(presented), expected.toLowerCase())) {
            // A browser has no Authorization header and cannot act on a 401. Redirect it to
            // the login page so it can obtain a session. An API client carrying a bearer
            // token that failed gets the 401 it can handle.
            boolean isBrowser = presented == null
                    && acceptsHtml(exchange.getRequest().getHeaders().getFirst(HttpHeaders.ACCEPT));
            if (isBrowser) {
                exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                exchange.getResponse().getHeaders().setLocation(
                        java.net.URI.create("/toolgate/login"));
                return exchange.getResponse().setComplete();
            }
            return deny(exchange, HttpStatus.UNAUTHORIZED);
        }
        return chain.filter(exchange);
    }

    private static boolean acceptsHtml(String accept) {
        return accept != null && accept.contains("text/html");
    }

    /**
     * An allowlist of methods, not a block list of the ones that change things.
     *
     * <p>A block list is wrong the first time a method is added to HTTP or to this service.
     * Anything not named here is treated as a write and refused, which is the direction the
     * mistake should fall in.
     */
    private static boolean isReadOnlyMethod(ServerWebExchange exchange) {
        HttpMethod method = exchange.getRequest().getMethod();
        return HttpMethod.GET.equals(method) || HttpMethod.HEAD.equals(method);
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
