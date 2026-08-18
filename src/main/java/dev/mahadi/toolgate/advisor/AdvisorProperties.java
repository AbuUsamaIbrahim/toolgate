package dev.mahadi.toolgate.advisor;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@ConfigurationProperties(prefix = "toolgate.advisor")
@Component
public class AdvisorProperties {

    /**
     * Off unless switched on deliberately.
     *
     * <p>Enabling this is the first time the gateway talks to anything other than its
     * configured upstreams. Tool descriptions, resource URIs and the reasons behind
     * refusals leave the machine — which is a change in what this software does with your
     * data, not a feature flag, and it should be a decision somebody made rather than a
     * default they inherited.
     */
    private boolean enabled = false;

    /** Messages-API-compatible endpoint. */
    private String endpoint = "https://api.anthropic.com/v1/messages";

    private String model = "claude-sonnet-5";

    /**
     * Environment variable holding the API key. Never the key itself: this file is read by
     * everything that reads configuration, and gets committed, pasted into tickets and
     * baked into images.
     */
    private String apiKeyEnv = "ANTHROPIC_API_KEY";

    /** Short. An advisory note that arrives late is worse than none, because it blocks. */
    private Duration timeout = Duration.ofSeconds(20);

    /**
     * Which HTTP dialect the endpoint speaks.
     *
     * <p>Two shapes cover nearly everything worth pointing this at. {@code ANTHROPIC} is
     * the Messages API. {@code OPENAI} is the chat-completions shape that DeepSeek,
     * OpenAI, Groq, Together and most self-hosted servers implement — a different auth
     * header, the system prompt as the first message rather than its own field, and the
     * reply under {@code choices[0].message.content}.
     *
     * <p>The advisor is advisory and reads hostile text either way, so the choice changes
     * nothing about the trust model: whatever comes back is escaped and cannot act.
     */
    public enum Dialect { ANTHROPIC, OPENAI }

    private Dialect api = Dialect.ANTHROPIC;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }
    public String getModel() { return model; }
    public void setModel(String model) { this.model = model; }
    public String getApiKeyEnv() { return apiKeyEnv; }
    public void setApiKeyEnv(String apiKeyEnv) { this.apiKeyEnv = apiKeyEnv; }
    public Duration getTimeout() { return timeout; }
    public void setTimeout(Duration timeout) { this.timeout = timeout; }
    public Dialect getApi() { return api; }
    public void setApi(Dialect api) { this.api = api; }

    public String apiKey() {
        String key = System.getenv(apiKeyEnv);
        return key == null ? "" : key.trim();
    }

    public boolean usable() {
        return enabled && !apiKey().isEmpty();
    }
}
