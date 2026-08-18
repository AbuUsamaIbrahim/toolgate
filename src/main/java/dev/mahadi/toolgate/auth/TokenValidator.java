package dev.mahadi.toolgate.auth;

import java.util.Optional;

/**
 * Turns a bearer token into a caller identity, or rejects it.
 *
 * <p>Deliberately an interface. The bundled implementation validates against configured
 * tokens, which is the right amount of machinery for a self-hosted gateway and for tests.
 * A deployment fronted by a real OAuth 2.1 authorization server swaps in a JWT or
 * introspection validator without anything else in the gateway changing.
 */
public interface TokenValidator {

    /** Reasons a token can be refused, mapped to the status codes the spec requires. */
    enum Failure { MISSING, MALFORMED, UNKNOWN, EXPIRED, WRONG_AUDIENCE }

    sealed interface Result {
        record Valid(AccessToken token) implements Result {}
        record Invalid(Failure failure, String detail) implements Result {}
    }

    Result validate(String bearerToken);

    /** The canonical URI identifying this resource server, per RFC 8707. */
    String resourceUri();

    default Optional<AccessToken> validated(String bearerToken) {
        return validate(bearerToken) instanceof Result.Valid v ? Optional.of(v.token()) : Optional.empty();
    }
}
