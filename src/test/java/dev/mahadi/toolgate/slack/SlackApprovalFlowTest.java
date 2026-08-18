package dev.mahadi.toolgate.slack;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import dev.mahadi.toolgate.gateway.ApprovalProperties;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The approval workflow end to end, minus Slack itself: a correctly signed interaction is
 * indistinguishable to this code from a real one, which is the point of signing it.
 */
class SlackApprovalFlowTest {

    private static final String SECRET = "test-signing-secret";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ApprovalStore approvals;
    private SlackInteractionController controller;
    private List<AuditLog.Entry> recorded;

    @BeforeEach
    void setUp() {
        var props = new SlackProperties();
        props.setSigningSecret(SECRET);
        props.setApprovers(Map.of(
                "U_ALICE", "alice@example.com",
                "U_BOB", "bob@example.com"));

        approvals = new ApprovalStore(new ApprovalProperties(), MAPPER);
        recorded = new ArrayList<>();
        var audit = new AuditLog(List.of((AuditSink) recorded::add));

        controller = new SlackInteractionController(props, approvals, audit, MAPPER);
    }

    /** Builds the form body Slack posts, and signs it the way Slack would. */
    private ResponseEntity<?> click(String slackUser, String actionId, String approvalId,
                                    String secret, long timestamp) {
        String payload = """
                {"user":{"id":"%s"},"actions":[{"action_id":"%s","value":"%s"}]}"""
                .formatted(slackUser, actionId, approvalId);
        byte[] body = ("payload=" + URLEncoder.encode(payload, StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8);

        return controller.interaction(String.valueOf(timestamp),
                SlackSignature.sign(secret, timestamp, body), body);
    }

    private ResponseEntity<?> click(String slackUser, String actionId, String approvalId) {
        return click(slackUser, actionId, approvalId, SECRET, Instant.now().getEpochSecond());
    }

    private ApprovalStore.Pending request(String caller) {
        return approvals.request(caller, "files", "write_file", "tool requires human approval");
    }

    @Test
    @DisplayName("a colleague clicking Approve grants the call")
    void colleagueApproves() {
        var pending = request("bob@example.com");

        var response = click("U_ALICE", "toolgate_approve", pending.id());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isTrue();
        assertThat(recorded).anyMatch(e ->
                e.outcome() == AuditLog.Outcome.APPROVED
                        && e.reason().contains("alice@example.com")
                        && e.evidence().contains("approverSource=slack"));
    }

    @Test
    @DisplayName("the requester cannot approve their own call")
    void selfApprovalRefused() {
        // Bob raised it, Bob clicks Approve. A gate the requester can open measures
        // persistence, not agreement.
        var pending = request("bob@example.com");

        var response = click("U_BOB", "toolgate_approve", pending.id());

        assertThat(response.getStatusCode().value()).isEqualTo(200);   // Slack needs 200
        assertThat(String.valueOf(response.getBody())).contains("cannot approve");
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isFalse();
        assertThat(recorded).anyMatch(e ->
                e.outcome() == AuditLog.Outcome.DENIED && e.reason().contains("own call"));
    }

    @Test
    @DisplayName("a refused self-approval leaves the request open for someone else")
    void selfApprovalDoesNotConsumeTheRequest() {
        var pending = request("bob@example.com");
        click("U_BOB", "toolgate_approve", pending.id());

        // Otherwise a requester could cancel their own pending request by trying to
        // approve it, which is a denial-of-service against the queue.
        assertThat(click("U_ALICE", "toolgate_approve", pending.id())
                .getStatusCode().value()).isEqualTo(200);
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isTrue();
    }

    @Test
    @DisplayName("a Slack user nobody configured cannot approve")
    void unmappedSlackUserRefused() {
        var pending = request("bob@example.com");

        // Correctly signed — genuinely from Slack — but this workspace member was never
        // made an approver. The signature proves origin, not authority.
        var response = click("U_STRANGER", "toolgate_approve", pending.id());

        assertThat(String.valueOf(response.getBody())).contains("not on the approver list");
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isFalse();
    }

    @Test
    @DisplayName("an unsigned request is refused with 401 and audited")
    void unsignedRequestRefused() {
        var pending = request("bob@example.com");
        byte[] body = "payload=%7B%7D".getBytes(StandardCharsets.UTF_8);

        var response = controller.interaction(
                String.valueOf(Instant.now().getEpochSecond()), "v0=forged", body);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(approvals.outstanding()).containsKey(pending.id());
        assertThat(recorded).anyMatch(e -> e.reason().contains("unverified Slack interaction"));
    }

    @Test
    @DisplayName("a request signed with the wrong secret is refused")
    void wrongSecretRefused() {
        var pending = request("bob@example.com");

        var response = click("U_ALICE", "toolgate_approve", pending.id(),
                "attacker-secret", Instant.now().getEpochSecond());

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isFalse();
    }

    @Test
    @DisplayName("Deny closes the request without granting anything")
    void denyWorks() {
        var pending = request("bob@example.com");

        var response = click("U_ALICE", "toolgate_deny", pending.id());

        assertThat(String.valueOf(response.getBody())).contains("Denied");
        assertThat(approvals.outstanding()).doesNotContainKey(pending.id());
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isFalse();
    }

    @Test
    @DisplayName("clicking twice does not grant twice")
    void grantIsSingleUse() {
        var pending = request("bob@example.com");
        click("U_ALICE", "toolgate_approve", pending.id());

        var second = click("U_ALICE", "toolgate_approve", pending.id());
        assertThat(String.valueOf(second.getBody())).contains("already been decided");

        // And the grant itself is consumed by the first call, not the second click.
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isTrue();
        assertThat(approvals.consumeGrant("bob@example.com", "files", "write_file")).isFalse();
    }

    @Test
    @DisplayName("with no signing secret configured the endpoint refuses everything")
    void unconfiguredRefuses() {
        var props = new SlackProperties();          // no signing secret
        var audit = new AuditLog(List.of((AuditSink) recorded::add));
        var unconfigured = new SlackInteractionController(props, approvals, audit, MAPPER);

        var response = unconfigured.interaction("1", "v0=whatever", "payload=%7B%7D".getBytes());

        assertThat(response.getStatusCode().value()).isEqualTo(503);
    }
}
