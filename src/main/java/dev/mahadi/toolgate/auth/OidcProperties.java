package dev.mahadi.toolgate.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "toolgate.auth.oidc")
@Component
public class OidcProperties {

    /** Expected {@code iss}. Empty disables JWT validation entirely. */
    private String issuer = "";

    /**
     * Where the signing keys live. Left empty, it is derived from the issuer via
     * {@code /.well-known/openid-configuration} at startup.
     */
    private String jwksUri = "";

    /**
     * Accepted {@code aud} values. Defaults to the resource URI.
     *
     * <p>This is the confused-deputy control and it is not optional in spirit: a token
     * minted for some other internal service must not open this one. Skipping the audience
     * check turns every service that shares an identity provider into a credential store
     * for every other service.
     */
    private List<String> audiences = List.of();

    /**
     * Tolerance for clock difference between here and the identity provider.
     *
     * <p>Small on purpose. Generous skew is how an expired token stays usable, and the
     * usual reason people widen it is a broken NTP configuration they should fix instead.
     */
    private Duration clockSkew = Duration.ofSeconds(60);

    /** Claim holding the human-readable identity used in the audit trail. */
    private String subjectClaim = "preferred_username";

    /** Claim holding the caller's teams or groups. */
    private String groupsClaim = "groups";

    /** How long to cache the JWKS before refetching. */
    private Duration jwksCacheTtl = Duration.ofMinutes(15);

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }
    public List<String> getAudiences() { return audiences; }
    public void setAudiences(List<String> audiences) { this.audiences = audiences; }
    public Duration getClockSkew() { return clockSkew; }
    public void setClockSkew(Duration clockSkew) { this.clockSkew = clockSkew; }
    public String getSubjectClaim() { return subjectClaim; }
    public void setSubjectClaim(String subjectClaim) { this.subjectClaim = subjectClaim; }
    public String getGroupsClaim() { return groupsClaim; }
    public void setGroupsClaim(String groupsClaim) { this.groupsClaim = groupsClaim; }
    public Duration getJwksCacheTtl() { return jwksCacheTtl; }
    public void setJwksCacheTtl(Duration jwksCacheTtl) { this.jwksCacheTtl = jwksCacheTtl; }

    public boolean enabled() {
        return issuer != null && !issuer.isBlank();
    }
}
