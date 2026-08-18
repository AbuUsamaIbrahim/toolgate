package dev.mahadi.toolgate.notify;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "toolgate.notify")
@Component
public class NotifyProperties {

    /**
     * Webhook to POST notifications to. Slack and most chat tools accept a JSON body with
     * a {@code text} field, which is what this sends. Empty disables webhooks; events are
     * still logged.
     */
    private String webhookUrl = "";

    public String getWebhookUrl() { return webhookUrl; }
    public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
}
