package dev.mahadi.toolgate.slack;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Posts an approval request into Slack with Approve and Deny buttons.
 *
 * <p>Separate from the generic webhook notifier because this one is interactive: the
 * message carries the approval id in the button value, so a click comes back to
 * {@link SlackInteractionController} knowing what it refers to.
 *
 * <p>That id travels through Slack and returns as untrusted input. It is not a capability
 * — knowing an id grants nothing. Approval requires a Slack-signed request from a
 * configured approver who is not the requester, all checked on the way back in.
 */
@Component
public class SlackNotifier {

    private static final Logger log = LoggerFactory.getLogger(SlackNotifier.class);
    private static final URI POST_MESSAGE = URI.create("https://slack.com/api/chat.postMessage");

    private final SlackProperties props;
    private final ObjectMapper mapper;
    private final HttpClient http;

    public SlackNotifier(SlackProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public void requestApproval(ApprovalStore.Pending pending, String reason) {
        if (!props.postingEnabled()) return;

        Map<String, Object> message = Map.of(
                "channel", props.getChannel(),
                "text", "Approval needed: %s wants to call %s/%s"
                        .formatted(pending.caller(), pending.serverId(), pending.tool()),
                "blocks", blocks(pending, reason));

        // Fire and forget. A Slack outage must not fail a tool call — the request is
        // already recorded in the approval queue and reachable through the operator API,
        // so the worst case is that somebody has to go looking rather than being told.
        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(POST_MESSAGE)
                            .timeout(Duration.ofSeconds(10))
                            .header("Content-Type", "application/json; charset=utf-8")
                            .header("Authorization", "Bearer " + props.getBotToken())
                            .POST(HttpRequest.BodyPublishers.ofByteArray(
                                    mapper.writeValueAsBytes(message)))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            // Slack answers 200 with {"ok": false} on failure, so the status code alone
            // tells you nothing. A silently unposted approval is the failure that makes
            // people stop trusting the gate.
            if (!mapper.readTree(response.body()).path("ok").asBoolean(false)) {
                log.warn("Slack rejected the approval message: {}", response.body());
            }
        } catch (Exception e) {
            log.warn("Could not post the approval request to Slack: {}", e.toString());
        }
    }

    private static List<Map<String, Object>> blocks(ApprovalStore.Pending p, String reason) {
        return List.of(
                Map.of("type", "section", "text", Map.of("type", "mrkdwn",
                        "text", "*Tool call needs approval*")),
                Map.of("type", "section", "fields", List.of(
                        Map.of("type", "mrkdwn", "text", "*Who:*\n" + p.caller()),
                        Map.of("type", "mrkdwn", "text", "*Tool:*\n`%s/%s`".formatted(
                                p.serverId(), p.tool())),
                        Map.of("type", "mrkdwn", "text", "*Why blocked:*\n" + reason),
                        Map.of("type", "mrkdwn", "text", "*Expires:*\nin 10 minutes"))),
                Map.of("type", "context", "elements", List.of(
                        Map.of("type", "mrkdwn",
                                "text", "The requester cannot approve this. "
                                        + "One use only; the grant is not reusable."))),
                Map.of("type", "actions", "elements", List.of(
                        Map.of("type", "button", "action_id", "toolgate_approve",
                                "style", "primary", "value", p.id(),
                                "text", Map.of("type", "plain_text", "text", "Approve")),
                        Map.of("type", "button", "action_id", "toolgate_deny",
                                "style", "danger", "value", p.id(),
                                "text", Map.of("type", "plain_text", "text", "Deny")))));
    }
}
