package dev.mahadi.toolgate.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Access control for the operator API.
 *
 * <p>The operator API can approve a blocked call and re-pin a changed definition — it can
 * switch off every control the gateway has. Keeping it on a different path from
 * {@code /mcp} stops an agent reaching it <em>through the protocol</em>, but says nothing
 * about an agent that can open a socket. On a developer machine the agent and the gateway
 * share a host, so that is not a hypothetical.
 */
@ConfigurationProperties(prefix = "toolgate.operator")
@Component
public class OperatorProperties {

    /**
     * Require a token on operator routes. On by default: this API grants the authority to
     * disable the gateway's own protections.
     */
    private boolean enabled = true;

    /** Lowercase hex SHA-256 of the operator token. Never the token itself. */
    private String tokenSha256 = "";

    /**
     * Refuse non-loopback requests. On by default, because the default deployment is a
     * gateway sitting beside the agent it protects, where nothing remote has any business
     * approving a tool call.
     */
    private boolean loopbackOnly = true;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getTokenSha256() { return tokenSha256; }
    public void setTokenSha256(String tokenSha256) { this.tokenSha256 = tokenSha256; }
    public boolean isLoopbackOnly() { return loopbackOnly; }
    public void setLoopbackOnly(boolean loopbackOnly) { this.loopbackOnly = loopbackOnly; }
}
