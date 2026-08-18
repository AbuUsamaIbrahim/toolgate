package dev.mahadi.toolgate.api;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Browser sessions for the operator dashboard, and the CSRF tokens that go with them.
 *
 * <h2>Why a session exists at all</h2>
 * The operator API authenticates with a bearer header. A browser form cannot send one, so
 * making the dashboard's buttons work means the browser has to carry something — and the
 * moment a credential travels automatically with every request, cross-site request forgery
 * becomes possible. A page on another site cannot read this gateway's responses, but it can
 * absolutely cause the browser to <em>send</em> a request, and the cookie would ride along.
 *
 * <p>On the API that can approve a blocked tool call, that would mean a random web page
 * approving a poisoned definition on the operator's behalf. So the session is deliberately
 * narrow and defended twice over:
 *
 * <ul>
 *   <li><b>{@code SameSite=Strict}</b> — the browser refuses to send the cookie on any
 *       cross-site request at all. This is the control that actually stops it.</li>
 *   <li><b>A CSRF token in the form body</b> — belt to that braces. An attacker who can
 *       make the browser send a request still cannot read the token to put in it, because
 *       reading it requires same-origin access to the page.</li>
 *   <li><b>{@code HttpOnly}</b> — script cannot read the session, so an XSS bug on the
 *       dashboard does not immediately become session theft.</li>
 *   <li><b>{@code Path=/toolgate}</b> — the cookie is never sent to {@code /mcp}, where an
 *       agent's requests arrive. An agent must not be able to borrow the operator's
 *       session simply by being on the same origin.</li>
 * </ul>
 *
 * <p>Sessions live in memory and are lost on restart, which is correct: they are a browser
 * convenience, not durable authorisation, and the bearer token is always still there.
 */
@Component
public class OperatorSessions {

    public static final String COOKIE = "toolgate_session";
    public static final String CSRF_FIELD = "_csrf";

    /** Short. This is the console that can approve anything; an unattended tab is a risk. */
    private static final Duration LIFETIME = Duration.ofHours(8);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public record Session(String id, String csrfToken, String operator, Instant createdAt) {
        boolean expired() {
            return Instant.now().isAfter(createdAt.plus(LIFETIME));
        }
    }

    public Session create(String operator) {
        Session session = new Session(randomToken(), randomToken(), operator, Instant.now());
        sessions.put(session.id(), session);
        return session;
    }

    public Optional<Session> lookup(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) return Optional.empty();
        Session session = sessions.get(sessionId);
        if (session == null) return Optional.empty();
        if (session.expired()) {
            sessions.remove(sessionId);
            return Optional.empty();
        }
        return Optional.of(session);
    }

    /**
     * Checks a submitted CSRF token against the session's.
     *
     * <p>Constant-time, for the same reason every other comparison in this project is: an
     * early return on the first differing byte leaks, through timing, how much of a guess
     * was right.
     */
    public boolean csrfValid(Session session, String submitted) {
        if (submitted == null) return false;
        return MessageDigest.isEqual(
                session.csrfToken().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                submitted.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public void invalidate(String sessionId) {
        if (sessionId != null) sessions.remove(sessionId);
    }

    public int size() {
        return sessions.size();
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
