package dev.mahadi.toolgate.auth;

import java.util.List;

/**
 * Tries each configured validator and takes the first identity that holds up.
 *
 * <p>Both kinds of caller exist in a real deployment and they are not the same kind of
 * thing. People get OIDC tokens: short-lived, revocable, and attributable to a name. Build
 * agents and cron jobs have no browser and no human to authenticate, so they keep a static
 * token — which should be understood as a shared secret in a config file, because that is
 * what it is, and reserved for callers that are not people.
 *
 * <p>Order matters only for reporting. A token either verifies against a trusted signing
 * key or matches a configured hash; nothing here can turn a failure into a success, and
 * adding a validator can only ever accept tokens the deployment explicitly configured it
 * to accept.
 */
public class CompositeTokenValidator implements TokenValidator {

    private final List<TokenValidator> delegates;
    private final String resourceUri;

    public CompositeTokenValidator(List<TokenValidator> delegates, String resourceUri) {
        this.delegates = List.copyOf(delegates);
        this.resourceUri = resourceUri;
    }

    @Override
    public Result validate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return new Result.Invalid(Failure.MISSING, "no bearer token presented");
        }
        if (delegates.isEmpty()) {
            // Authentication is on and nothing can perform it. Refusing everything is the
            // only honest response; the alternative is a gateway that appears to require
            // credentials and accepts none, or worse, all.
            return new Result.Invalid(Failure.UNKNOWN, "no token validator is configured");
        }

        Result.Invalid best = null;
        for (TokenValidator delegate : delegates) {
            Result result = delegate.validate(bearerToken);
            if (result instanceof Result.Valid valid) return valid;

            Result.Invalid invalid = (Result.Invalid) result;
            if (best == null || rank(invalid.failure()) > rank(best.failure())) best = invalid;
        }
        return best;
    }

    /**
     * Which rejection to report when several validators refuse the same token.
     *
     * <p>"Expired" and "wrong audience" are worth telling the caller: the first means
     * refresh and retry, the second means they are pointing at the wrong service. Both are
     * things a legitimate client needs to act on, and neither helps an attacker who already
     * knows they do not hold a valid token. Everything else collapses to one answer.
     */
    private static int rank(Failure failure) {
        return switch (failure) {
            case EXPIRED -> 3;
            case WRONG_AUDIENCE -> 2;
            case MALFORMED -> 1;
            default -> 0;
        };
    }

    @Override
    public String resourceUri() {
        return resourceUri;
    }
}
