package dev.mahadi.toolgate.slack;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Receives Approve/Deny button clicks from Slack.
 *
 * <p>Everything arriving here is untrusted until the signature checks out — including the
 * approval id, the user id, and the action. The order below is therefore load-bearing:
 * verify the raw bytes, then parse them, then map the Slack user to a known approver, then
 * act. Parsing before verifying would hand attacker-controlled JSON to a deserialiser; and
 * a Slack user id is not an identity until this gateway's configuration says which person
 * it belongs to.
 *
 * <p>The endpoint always answers 200 with a message for Slack, even when it refuses. Slack
 * renders non-200 as a generic failure the user cannot act on, so a refusal that says
 * <em>why</em> — you cannot approve your own request, you are not on the approver list —
 * is more useful and gives away nothing an attacker could not already determine.
 */
@RestController
public class SlackInteractionController {

    private static final Logger log = LoggerFactory.getLogger(SlackInteractionController.class);

    private final SlackProperties props;
    private final ApprovalStore approvals;
    private final AuditLog audit;
    private final ObjectMapper mapper;

    public SlackInteractionController(SlackProperties props, ApprovalStore approvals,
                                      AuditLog audit, ObjectMapper mapper) {
        this.props = props;
        this.approvals = approvals;
        this.audit = audit;
        this.mapper = mapper;
    }

    @PostMapping(value = "/slack/interactions",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> interaction(
            @RequestHeader(value = "X-Slack-Request-Timestamp", required = false) String timestamp,
            @RequestHeader(value = "X-Slack-Signature", required = false) String signature,
            @RequestBody byte[] rawBody) {

        if (!props.interactionsEnabled()) {
            // No signing secret means no way to tell Slack from anyone else. Refusing is
            // the only option: this endpoint approves tool calls.
            log.warn("Slack interaction refused: no signing secret configured");
            return ResponseEntity.status(503).body(ephemeral("Slack approvals are not configured."));
        }

        if (!SlackSignature.verify(props.getSigningSecret(), timestamp, signature,
                rawBody, Instant.now())) {
            // Deliberately terse, and deliberately audited. Someone probing this endpoint
            // is worth knowing about.
            audit.record("slack", "-", "-", "slack/interaction", AuditLog.Outcome.DENIED,
                    "rejected an unverified Slack interaction", List.of());
            return ResponseEntity.status(401).build();
        }

        JsonNode payload;
        try {
            payload = mapper.readTree(formField(rawBody, "payload"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }

        String slackUser = payload.path("user").path("id").asText("");
        JsonNode action = payload.path("actions").path(0);
        String actionId = action.path("action_id").asText("");
        String approvalId = action.path("value").asText("");

        String approver = props.getApprovers().get(slackUser);
        if (approver == null) {
            // A verified Slack request from somebody this gateway has never been told
            // about. The signature proves where it came from, not who may approve.
            audit.record("slack:" + slackUser, "-", "-", "slack/interaction",
                    AuditLog.Outcome.DENIED, "Slack user is not a configured approver",
                    List.of("slackUser=" + slackUser));
            return ResponseEntity.ok(ephemeral(
                    "You are not on the approver list for this gateway."));
        }

        return switch (actionId) {
            case "toolgate_approve" -> approve(approvalId, approver, slackUser);
            case "toolgate_deny" -> deny(approvalId, approver);
            default -> ResponseEntity.ok(ephemeral("Unrecognised action."));
        };
    }

    private ResponseEntity<?> approve(String id, String approver, String slackUser) {
        return switch (approvals.approve(id, approver)) {
            case ApprovalStore.Outcome.Granted g -> {
                audit.record(g.request().caller(), g.request().serverId(), g.request().tool(),
                        "approval", AuditLog.Outcome.APPROVED,
                        "granted by " + approver + " via Slack",
                        List.of("id=" + id, "approver=" + approver,
                                "approverSource=slack", "slackUser=" + slackUser));
                yield ResponseEntity.ok(replacement(
                        ":white_check_mark: *Approved* by <@%s> — %s may call `%s/%s` once."
                                .formatted(slackUser, g.request().caller(),
                                        g.request().serverId(), g.request().tool())));
            }
            case ApprovalStore.Outcome.SelfApproval self -> {
                audit.record(self.request().caller(), self.request().serverId(),
                        self.request().tool(), "approval", AuditLog.Outcome.DENIED,
                        "refused: requester cannot approve their own call",
                        List.of("id=" + id, "approver=" + approver, "approverSource=slack"));
                yield ResponseEntity.ok(ephemeral(
                        "You raised this request, so you cannot approve it. "
                                + "Someone else on the approver list needs to."));
            }
            case ApprovalStore.Outcome.Unknown ignored -> ResponseEntity.ok(ephemeral(
                    "That request has already been decided, or it expired."));
        };
    }

    private ResponseEntity<?> deny(String id, String approver) {
        return approvals.deny(id, approver)
                .<ResponseEntity<?>>map(p -> {
                    audit.record(p.caller(), p.serverId(), p.tool(), "approval",
                            AuditLog.Outcome.DENIED, "denied by " + approver + " via Slack",
                            List.of("id=" + id, "approver=" + approver, "approverSource=slack"));
                    return ResponseEntity.ok(replacement(
                            ":no_entry: *Denied* by %s — `%s/%s` was not run."
                                    .formatted(approver, p.serverId(), p.tool())));
                })
                .orElseGet(() -> ResponseEntity.ok(ephemeral(
                        "That request has already been decided, or it expired.")));
    }

    /**
     * Pulls one field out of an {@code application/x-www-form-urlencoded} body.
     *
     * <p>Done by hand against the same bytes the signature covered. Letting the framework
     * bind the form would mean verifying one representation and reading another, which is
     * the gap every signature-bypass writeup is about.
     */
    private static String formField(byte[] rawBody, String name) {
        String body = new String(rawBody, StandardCharsets.UTF_8);
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(name)) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    /** Visible only to the person who clicked. */
    private static Map<String, Object> ephemeral(String text) {
        return Map.of("response_type", "ephemeral", "text", text);
    }

    /**
     * Replaces the original message for everyone in the channel.
     *
     * <p>So the buttons disappear once a decision is made. Leaving them live invites a
     * second person to click and be told it is already decided, which trains people to
     * ignore the message.
     */
    private static Map<String, Object> replacement(String text) {
        return Map.of("replace_original", true, "text", text);
    }
}
