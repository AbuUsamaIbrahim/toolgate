package dev.mahadi.toolgate.auth;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JWT validation, exercised against the ways it is actually broken in the wild rather than
 * against the happy path.
 */
class JwtValidationTest {

    private static final String ISSUER = "https://idp.example.com";
    private static final String RESOURCE = "https://toolgate.example.com/mcp";

    private RSAKey signingKey;
    private JwtTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();

        var props = new OidcProperties();
        props.setIssuer(ISSUER);
        props.setAudiences(List.of(RESOURCE));
        props.setClockSkew(Duration.ofSeconds(30));
        props.setSubjectClaim("preferred_username");
        props.setGroupsClaim("groups");

        validator = new JwtTokenValidator(props, RESOURCE,
                new ImmutableJWKSet<SecurityContext>(new JWKSet(signingKey.toPublicJWK())));
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(RESOURCE)
                .subject("u-1042")
                .claim("preferred_username", "mahadi@example.com")
                .claim("scope", "tools:read tools:call")
                .claim("groups", List.of("platform", "billing"))
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plus(10, ChronoUnit.MINUTES)));
    }

    private String sign(JWTClaimsSet c) throws Exception {
        return sign(c, signingKey);
    }

    private String sign(JWTClaimsSet c, RSAKey key) throws Exception {
        var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(key.getKeyID()).type(JOSEObjectType.JWT).build(),
                c);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Nested
    @DisplayName("Accepted")
    class Accepted {

        @Test
        @DisplayName("a properly issued token yields a named person, their scopes and their teams")
        void validTokenGivesIdentity() throws Exception {
            var result = validator.validate(sign(claims().build()));

            assertThat(result).isInstanceOf(TokenValidator.Result.Valid.class);
            var token = ((TokenValidator.Result.Valid) result).token();

            // The audit trail names a person, which is the entire point of this increment.
            assertThat(token.subject()).isEqualTo("mahadi@example.com");
            assertThat(token.scopes()).containsExactlyInAnyOrder("tools:read", "tools:call");
            assertThat(token.teams()).containsExactlyInAnyOrder("platform", "billing");
        }

        @Test
        @DisplayName("scopes are read from scp as well as scope")
        void scpArraySupported() throws Exception {
            var c = claims().claim("scope", null).claim("scp", List.of("tools:read")).build();

            var token = ((TokenValidator.Result.Valid) validator.validate(sign(c))).token();
            assertThat(token.scopes()).containsExactly("tools:read");
        }

        @Test
        @DisplayName("the raw sub is used when the display claim is absent")
        void fallsBackToSub() throws Exception {
            var c = claims().claim("preferred_username", null).build();

            var token = ((TokenValidator.Result.Valid) validator.validate(sign(c))).token();
            assertThat(token.subject()).isEqualTo("u-1042");
        }
    }

    @Nested
    @DisplayName("Algorithm confusion")
    class AlgorithmConfusion {

        @Test
        @DisplayName("an unsigned token is refused")
        void noneAlgorithmRefused() throws Exception {
            // alg:none — the oldest JWT bypass there is.
            String header = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
            String body = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(claims().build().toString().getBytes());

            var result = validator.validate(header + "." + body + ".");

            assertThat(result).isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("HMAC signed with the public key as the secret is refused")
        void hmacWithPublicKeyRefused() throws Exception {
            // The subtle one: the attacker knows the RSA public key, because it is public.
            // A validator that honours the token's own "alg" will treat that key material
            // as an HMAC secret and verify the signature happily.
            byte[] secret = signingKey.toPublicJWK().toJSONString()
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] padded = java.util.Arrays.copyOf(secret, Math.max(32, secret.length));

            var jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("k1").build(),
                    claims().build());
            jwt.sign(new MACSigner(padded));

            var result = validator.validate(jwt.serialize());

            assertThat(result).isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("a token signed by a key the gateway does not trust is refused")
        void unknownSigningKeyRefused() throws Exception {
            RSAKey attacker = new RSAKeyGenerator(2048).keyID("k1").generate();

            // Same key id, different key. Key selection must come from the trusted set.
            var result = validator.validate(sign(claims().build(), attacker));

            assertThat(result).isInstanceOf(TokenValidator.Result.Invalid.class);
        }
    }

    @Nested
    @DisplayName("Claim checks")
    class Claims {

        @Test
        @DisplayName("a token for another service does not open this one")
        void wrongAudienceRefused() throws Exception {
            var c = claims().audience("https://wiki.example.com").build();

            var result = validator.validate(sign(c));

            assertThat(result).isInstanceOf(TokenValidator.Result.Invalid.class);
            assertThat(((TokenValidator.Result.Invalid) result).failure())
                    .isEqualTo(TokenValidator.Failure.WRONG_AUDIENCE);
        }

        @Test
        @DisplayName("a token from another issuer is refused")
        void wrongIssuerRefused() throws Exception {
            var c = claims().issuer("https://evil.example.com").build();

            assertThat(validator.validate(sign(c)))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("an expired token is refused, and says so")
        void expiredRefused() throws Exception {
            var c = claims()
                    .expirationTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                    .build();

            var result = validator.validate(sign(c));

            assertThat(((TokenValidator.Result.Invalid) result).failure())
                    .isEqualTo(TokenValidator.Failure.EXPIRED);
        }

        @Test
        @DisplayName("a token with no expiry is refused — a permanent credential is not a token")
        void missingExpiryRefused() throws Exception {
            var c = claims().expirationTime(null).build();

            assertThat(validator.validate(sign(c)))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("a not-yet-valid token is refused")
        void notYetValidRefused() throws Exception {
            var c = claims()
                    .notBeforeTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                    .build();

            assertThat(validator.validate(sign(c)))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("expiry inside the skew window is tolerated, well outside it is not")
        void clockSkewIsBounded() throws Exception {
            var justExpired = claims()
                    .expirationTime(Date.from(Instant.now().minusSeconds(10))).build();
            assertThat(validator.validate(sign(justExpired)))
                    .isInstanceOf(TokenValidator.Result.Valid.class);

            var wellExpired = claims()
                    .expirationTime(Date.from(Instant.now().minusSeconds(600))).build();
            assertThat(validator.validate(sign(wellExpired)))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
        }

        @Test
        @DisplayName("garbage is refused as malformed rather than throwing")
        void garbageRefused() {
            assertThat(validator.validate("not-a-token"))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
            assertThat(validator.validate(""))
                    .isInstanceOf(TokenValidator.Result.Invalid.class);
        }
    }
}
