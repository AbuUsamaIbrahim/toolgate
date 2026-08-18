package dev.mahadi.toolgate.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Caller authentication configuration.
 *
 * <p>Tokens are configured as SHA-256 hashes rather than plaintext. A config file is a
 * thing that gets committed, pasted into tickets and shipped in container images; storing
 * the verifier rather than the secret means a leaked config does not hand over working
 * credentials. Generate one with:
 *
 * <pre>{@code printf '%s' "$TOKEN" | shasum -a 256}</pre>
 */
@Component
@ConfigurationProperties(prefix = "toolgate.auth")
public class AuthProperties {

    /**
     * Whether to require authentication. Defaults to {@code true}: a security gateway
     * that ships open by default has the wrong default.
     */
    private boolean enabled = true;

    /** Canonical URI of this gateway, used as the expected token audience (RFC 8707). */
    private String resourceUri = "http://localhost:8080/mcp";

    /** Where a client should look for authorization server details (RFC 9728). */
    private String authorizationServer = "";

    /** Callers, keyed by subject. */
    private Map<String, Caller> callers = new LinkedHashMap<>();

    public static class Caller {
        /** Lowercase hex SHA-256 of the bearer token. Never the token itself. */
        private String tokenSha256;
        /** Scopes granted to this caller. */
        private Set<String> scopes = Set.of();

        public String getTokenSha256() { return tokenSha256; }
        public void setTokenSha256(String tokenSha256) { this.tokenSha256 = tokenSha256; }
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getResourceUri() { return resourceUri; }
    public void setResourceUri(String resourceUri) { this.resourceUri = resourceUri; }
    public String getAuthorizationServer() { return authorizationServer; }
    public void setAuthorizationServer(String authorizationServer) { this.authorizationServer = authorizationServer; }
    public Map<String, Caller> getCallers() { return callers; }
    public void setCallers(Map<String, Caller> callers) { this.callers = callers; }
}
