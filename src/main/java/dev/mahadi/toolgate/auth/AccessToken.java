package dev.mahadi.toolgate.auth;

import java.time.Instant;
import java.util.Set;

/**
 * A validated caller identity.
 *
 * <p>This is what the gateway knows about whoever is on the other end of a request, and
 * it is derived from a token the caller had to present — not from a header they asserted.
 * Everything downstream keys off {@link #subject()}, so an agent can no longer choose who
 * the audit log thinks it is.
 *
 * <p>{@link #teams()} comes from the identity provider's group claim, never from anything
 * the caller supplies. It exists so policy can differ by team without the gateway keeping
 * its own copy of the org chart — the IdP already knows who is in which team, and a second
 * source of that truth is a second thing to get out of date.
 */
public record AccessToken(String subject, Set<String> scopes, Set<String> teams,
                          String audience, Instant expiresAt) {

    /** Convenience for callers with no team membership, and for tests. */
    public AccessToken(String subject, Set<String> scopes, String audience, Instant expiresAt) {
        this(subject, scopes, Set.of(), audience, expiresAt);
    }

    public boolean expired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean hasScope(String required) {
        return scopes.contains(required);
    }
}
