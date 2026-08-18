package dev.mahadi.toolgate.auth;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates OIDC access tokens issued by the company identity provider.
 *
 * <h2>Why this replaces static token hashes</h2>
 * A hash in a configuration file identifies a <em>deployment</em>, not a person. It cannot
 * be revoked without editing every machine, never expires, and produces audit lines naming
 * {@code example-agent} — which answers "which config entry was used" when the question
 * after an incident is "who did this". At fleet scale that is the difference between an
 * audit trail and a log file.
 *
 * <h2>The four ways JWT validation is usually broken</h2>
 * Each is closed here deliberately, because each has shipped in production somewhere:
 *
 * <ol>
 *   <li><b>Trusting the token's own {@code alg}.</b> Accepting {@code none} is the famous
 *       one; the subtler one is accepting HS256 when expecting RS256, so the attacker signs
 *       with the <em>public</em> key as the HMAC secret and the signature verifies. The key
 *       selector below is pinned to specific asymmetric algorithms, and the algorithm is
 *       matched against the selected key rather than against the header's request.</li>
 *   <li><b>Selecting the key from the token.</b> A {@code jku} header pointing at an
 *       attacker's key set is a complete bypass. Keys come only from the configured JWKS
 *       endpoint; {@code kid} selects <em>among</em> trusted keys and never introduces
 *       one.</li>
 *   <li><b>Skipping the audience.</b> This is the confused-deputy check. Without it any
 *       token from the same identity provider — one minted for the wiki, or for a service
 *       an attacker already controls — opens this gateway.</li>
 *   <li><b>Generous clock skew.</b> Expiry is the only revocation a stateless token has.
 *       Widening the window to paper over a clock problem extends the life of every stolen
 *       token by the same amount.</li>
 * </ol>
 *
 * <p>Nimbus refreshes and caches the key set, and rate-limits refetching so that a stream
 * of tokens bearing unknown key ids cannot be turned into a request amplifier aimed at the
 * identity provider.
 */
public class JwtTokenValidator implements TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenValidator.class);

    /**
     * Asymmetric only. An HMAC algorithm here would mean the verification key and the
     * signing key are the same value, and the gateway does not hold a signing key.
     */
    private static final Set<JWSAlgorithm> PERMITTED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
            JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);

    private final OidcProperties props;
    private final String resourceUri;
    private final DefaultJWTProcessor<SecurityContext> processor;

    public JwtTokenValidator(OidcProperties props, String resourceUri, JWKSource<SecurityContext> keys) {
        this.props = props;
        this.resourceUri = resourceUri;

        Set<String> audiences = new LinkedHashSet<>(props.getAudiences());
        if (audiences.isEmpty()) audiences.add(resourceUri);

        this.processor = new DefaultJWTProcessor<>();

        // Reject a token whose "typ" claims to be something else. Cheap defence against a
        // signed artifact of another kind being replayed as an access token.
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                JOSEObjectType.JWT, new JOSEObjectType("at+jwt"), null));

        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(PERMITTED_ALGORITHMS, keys));

        // iss and aud are required and exact. sub and exp must be present: a token with no
        // expiry is a permanent credential, and one with no subject is anonymous.
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                audiences,
                new JWTClaimsSet.Builder().issuer(props.getIssuer()).build(),
                Set.of("sub", "exp"),
                null));

        DefaultJWTClaimsVerifier<SecurityContext> verifier =
                (DefaultJWTClaimsVerifier<SecurityContext>) processor.getJWTClaimsSetVerifier();
        verifier.setMaxClockSkew((int) props.getClockSkew().toSeconds());

        log.info("JWT validation active: issuer={} audiences={} skew={}s",
                props.getIssuer(), audiences, props.getClockSkew().toSeconds());
    }

    /** Builds a validator, discovering the key set from the issuer when not configured. */
    public static JwtTokenValidator create(OidcProperties props, String resourceUri) {
        try {
            String jwksUri = props.getJwksUri();
            if (jwksUri == null || jwksUri.isBlank()) {
                jwksUri = discoverJwksUri(props.getIssuer());
            }
            JWKSource<SecurityContext> source = JWKSourceBuilder
                    .create(URI.create(jwksUri).toURL())
                    .cache(props.getJwksCacheTtl().toMillis(), 30_000)
                    .retrying(true)
                    .rateLimited(300_000)   // caps refetches triggered by unknown key ids
                    .build();
            return new JwtTokenValidator(props, resourceUri, source);
        } catch (Exception e) {
            // Startup fails rather than silently running without JWT validation. An
            // operator who configured an issuer and got static-token-only authentication
            // has a gateway that is weaker than they believe it to be.
            throw new IllegalStateException(
                    "could not initialise JWT validation for issuer " + props.getIssuer()
                            + ": " + e.getMessage(), e);
        }
    }

    private static String discoverJwksUri(String issuer) throws Exception {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        URI discovery = URI.create(base + "/.well-known/openid-configuration");

        HttpResponse<String> response = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10)).build()
                .send(HttpRequest.newBuilder(discovery).timeout(Duration.ofSeconds(15)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("discovery returned HTTP " + response.statusCode());
        }

        var doc = new com.fasterxml.jackson.databind.ObjectMapper().readTree(response.body());

        // The discovery document is fetched from the issuer, but it still has to agree
        // with it. A document that names a different issuer is either misconfiguration or
        // someone redirecting discovery somewhere useful to them.
        String declared = doc.path("issuer").asText("");
        if (!issuer.equals(declared) && !base.equals(declared)) {
            throw new IllegalStateException(
                    "discovery document declares issuer '" + declared + "', expected '" + issuer + "'");
        }
        String jwks = doc.path("jwks_uri").asText("");
        if (jwks.isBlank()) throw new IllegalStateException("discovery document has no jwks_uri");

        URL url = URI.create(jwks).toURL();
        if (!"https".equalsIgnoreCase(url.getProtocol()) && !isLoopback(url.getHost())) {
            throw new IllegalStateException("refusing a non-HTTPS jwks_uri: " + jwks);
        }
        return jwks;
    }

    private static boolean isLoopback(String host) {
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }

    @Override
    public Result validate(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            return new Result.Invalid(Failure.MISSING, "no bearer token");
        }
        JWTClaimsSet claims;
        try {
            claims = processor.process(bearerToken, null);
        } catch (java.text.ParseException e) {
            return new Result.Invalid(Failure.MALFORMED, "not a well-formed JWT");
        } catch (com.nimbusds.jwt.proc.BadJWTException e) {
            // Distinguish only what the caller is entitled to know. "Expired" is safe and
            // useful — the client should refresh. Everything else collapses to one answer,
            // because telling an attacker which check failed is free help.
            String message = String.valueOf(e.getMessage());
            if (message.contains("Expired")) {
                return new Result.Invalid(Failure.EXPIRED, "token has expired");
            }
            if (message.contains("audience")) {
                return new Result.Invalid(Failure.WRONG_AUDIENCE,
                        "token was not issued for this resource");
            }
            return new Result.Invalid(Failure.UNKNOWN, "token rejected");
        } catch (Exception e) {
            log.debug("JWT rejected: {}", e.toString());
            return new Result.Invalid(Failure.UNKNOWN, "token rejected");
        }

        String subject = stringClaim(claims, props.getSubjectClaim());
        if (subject == null || subject.isBlank()) subject = claims.getSubject();

        return new Result.Valid(new AccessToken(
                subject,
                scopesOf(claims),
                teamsOf(claims),
                audienceOf(claims),
                claims.getExpirationTime() == null ? null : claims.getExpirationTime().toInstant()));
    }

    /**
     * Scopes arrive as a space-delimited {@code scope} string (RFC 8693) or an array in
     * {@code scp}, depending on the identity provider. Both are read; neither is required.
     */
    private static Set<String> scopesOf(JWTClaimsSet claims) {
        Set<String> scopes = new HashSet<>();
        Object scope = claims.getClaim("scope");
        if (scope instanceof String s) {
            for (String part : s.split("\\s+")) if (!part.isBlank()) scopes.add(part);
        }
        Object scp = claims.getClaim("scp");
        if (scp instanceof List<?> list) list.forEach(v -> scopes.add(String.valueOf(v)));
        else if (scp instanceof String s) {
            for (String part : s.split("\\s+")) if (!part.isBlank()) scopes.add(part);
        }
        return Set.copyOf(scopes);
    }

    private Set<String> teamsOf(JWTClaimsSet claims) {
        Object groups = claims.getClaim(props.getGroupsClaim());
        if (groups instanceof List<?> list) {
            Set<String> teams = new LinkedHashSet<>();
            list.forEach(v -> teams.add(String.valueOf(v)));
            return Set.copyOf(teams);
        }
        if (groups instanceof String s && !s.isBlank()) return Set.of(s);
        return Set.of();
    }

    private static String audienceOf(JWTClaimsSet claims) {
        List<String> audience = claims.getAudience();
        return audience == null || audience.isEmpty() ? null : audience.get(0);
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        Object value = claims.getClaim(name);
        return value instanceof String s ? s : null;
    }

    @Override
    public String resourceUri() {
        return resourceUri;
    }
}
