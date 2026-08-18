package dev.mahadi.toolgate.auth;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/**
 * Validates bearer tokens against hashes held in configuration.
 *
 * <p>Adequate for a self-hosted gateway; swap in a JWT or introspection validator when
 * there is a real authorization server to talk to. The interface is the seam.
 */
@Component
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
