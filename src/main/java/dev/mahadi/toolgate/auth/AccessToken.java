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
 */
public record AccessToken(String subject, Set<String> scopes, String audience, Instant expiresAt) {

    public boolean expired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean hasScope(String required) {
        return scopes.contains(required);
    }
}
