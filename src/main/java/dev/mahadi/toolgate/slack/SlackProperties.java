package dev.mahadi.toolgate.slack;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "toolgate.slack")
@Component
public class SlackProperties {

    /** Bot token (xoxb-…) used to post approval requests. Empty disables posting. */
    private String botToken = "";

    /** Channel to post into. A private channel of the people allowed to approve. */
    private String channel = "";

    /**
     * Slack's signing secret, used to verify that interactions came from Slack.
     *
     * <p>Empty means the interaction endpoint refuses everything. It has to: without this
     * the endpoint is an unauthenticated approve-anything API reachable from the internet.
     */
    private String signingSecret = "";

    /**
     * Slack user id to gateway identity, e.g. {@code U024BE7LH: alice@example.com}.
     *
     * <p>Explicit rather than derived from the Slack profile email. Slack profile fields
     * are editable by the user in many workspaces, so trusting one would let somebody set
     * their own approver identity — including to the identity of the person whose request
     * they want to approve. An unmapped user cannot approve, which also makes the list of
     * people who can approve something a reviewer can read.
     */
    private Map<String, String> approvers = new LinkedHashMap<>();

    public String getBotToken() { return botToken; }
    public void setBotToken(String botToken) { this.botToken = botToken; }
    public String getChannel() { return channel; }
    public void setChannel(String channel) { this.channel = channel; }
    public String getSigningSecret() { return signingSecret; }
    public void setSigningSecret(String signingSecret) { this.signingSecret = signingSecret; }
    public Map<String, String> getApprovers() { return approvers; }
    public void setApprovers(Map<String, String> approvers) { this.approvers = approvers; }

    public boolean postingEnabled() {
        return !botToken.isBlank() && !channel.isBlank();
    }

    public boolean interactionsEnabled() {
        return !signingSecret.isBlank();
    }
}
