package dev.mahadi.toolgate.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Validates bearer tokens against hashes held in configuration.
 *
 * <p>Adequate for a self-hosted gateway and correct for callers that are not people —
 * build agents and scheduled jobs have no browser to authenticate through. It should not
 * be how humans are identified once an identity provider exists: a hash in a file cannot
 * be revoked without editing every machine, never expires, and produces audit lines that
 * name a config entry rather than a person.
 *
 * <p>Assembled by {@link AuthConfiguration} rather than component-scanned, so that "which
 * credentials does this gateway accept" has one readable answer in one place.
 */
public class StaticTokenValidator implements TokenValidator {

    private final AuthProperties props;

    public StaticTokenValidator(AuthProperties props) {
        this.props = props;
    }

    @Override
    public Result validate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return new Result.Invalid(Failure.MISSING, "no bearer token presented");
        }

        String presented = sha256(bearerToken);

        // Every configured caller is compared, and the comparison is constant-time.
        // Returning early on the first match would leak, through timing, roughly where
        // in the map a token sits — a small leak, but free to avoid.
        String matchedSubject = null;
        Set<String> matchedScopes = Set.of();
        for (Map.Entry<String, AuthProperties.Caller> e : props.getCallers().entrySet()) {
            String expected = e.getValue().getTokenSha256();
            if (expected == null) continue;
            if (constantTimeEquals(presented, expected.toLowerCase())) {
                matchedSubject = e.getKey();
                matchedScopes = e.getValue().getScopes();
            }
        }

        if (matchedSubject == null) {
            return new Result.Invalid(Failure.UNKNOWN, "token not recognised");
        }
        return new Result.Valid(new AccessToken(
                matchedSubject, Set.copyOf(matchedScopes), props.getResourceUri(), null));
    }

    @Override
    public String resourceUri() {
        return props.getResourceUri();
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
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
