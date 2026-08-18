package dev.mahadi.toolgate;

import dev.mahadi.toolgate.api.OperatorSessions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The dashboard's buttons act on the API that can approve a blocked tool call, so a forged
 * request is not an inconvenience — it is a poisoned definition accepted in the operator's
 * name, recorded in the audit trail as their deliberate decision.
 */
class DashboardCsrfTest {

    private OperatorSessions sessions;

    @BeforeEach
    void setUp() {
        sessions = new OperatorSessions();
    }

    @Test
    @DisplayName("each session gets its own unguessable CSRF token")
    void tokensAreDistinct() {
        var a = sessions.create("operator");
        var b = sessions.create("operator");

        assertThat(a.csrfToken()).isNotEqualTo(b.csrfToken());
        assertThat(a.id()).isNotEqualTo(b.id());
        // 32 random bytes, base64url — long enough that guessing is not a strategy.
        assertThat(a.csrfToken().length()).isGreaterThanOrEqualTo(40);
    }

    @Test
    @DisplayName("the session's own token is accepted")
    void ownTokenAccepted() {
        var session = sessions.create("operator");

        assertThat(sessions.csrfValid(session, session.csrfToken())).isTrue();
    }

    @Test
    @DisplayName("another session's token is refused")
    void otherSessionsTokenRefused() {
        var mine = sessions.create("operator");
        var theirs = sessions.create("operator");

        // Holding a valid token is not enough; it has to be bound to this session.
        assertThat(sessions.csrfValid(mine, theirs.csrfToken())).isFalse();
    }

    @Test
    @DisplayName("a missing or empty token is refused")
    void missingTokenRefused() {
        var session = sessions.create("operator");

        // What a forged cross-site form actually submits: it can cause the request, but it
        // cannot read the token to include, because that needs same-origin access.
        assertThat(sessions.csrfValid(session, null)).isFalse();
        assertThat(sessions.csrfValid(session, "")).isFalse();
        assertThat(sessions.csrfValid(session, "guessed")).isFalse();
    }

    @Test
    @DisplayName("a token that is a prefix of the real one is refused")
    void prefixRefused() {
        var session = sessions.create("operator");
        String truncated = session.csrfToken().substring(0, 20);

        assertThat(sessions.csrfValid(session, truncated)).isFalse();
    }

    @Test
    @DisplayName("an unknown session id resolves to nothing")
    void unknownSession() {
        assertThat(sessions.lookup("not-a-session")).isEmpty();
        assertThat(sessions.lookup(null)).isEmpty();
        assertThat(sessions.lookup("")).isEmpty();
    }

    @Test
    @DisplayName("signing out ends the session immediately")
    void invalidateWorks() {
        var session = sessions.create("operator");
        assertThat(sessions.lookup(session.id())).isPresent();

        sessions.invalidate(session.id());

        assertThat(sessions.lookup(session.id())).isEmpty();
    }

}
