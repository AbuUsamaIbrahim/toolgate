package dev.mahadi.toolgate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The operator API can approve blocked calls and re-pin changed definitions — it can turn
 * off every control the gateway has. Separating it from {@code /mcp} stops an agent
 * reaching it through the protocol; it does not stop an agent that can open a socket, and
 * on a developer machine the agent shares a host with the gateway.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OperatorApiAuthTest {

    private static final String OPERATOR_TOKEN = "operator-secret";

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add("toolgate.auth.enabled", () -> "false");
        registry.add("toolgate.operator.enabled", () -> "true");
        registry.add("toolgate.operator.token-sha256", () -> sha256(OPERATOR_TOKEN));
        // Tests connect over loopback, so this stays on and is exercised implicitly.
        registry.add("toolgate.operator.loopback-only", () -> "true");
    }

    private static String sha256(String s) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of()
                    .formatHex(md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    @Test
    @DisplayName("operator routes reject an unauthenticated request")
    void unauthenticatedRejected() {
        client().get().uri("/toolgate/audit").exchange().expectStatus().isUnauthorized();
        client().get().uri("/toolgate/pins").exchange().expectStatus().isUnauthorized();
        client().get().uri("/toolgate/drift").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("approving a call without the operator token is refused")
    void approvalNeedsToken() {
        client().post().uri("/toolgate/approvals/any-id/approve")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("re-pinning a drifted definition without the token is refused")
    void repinNeedsToken() {
        client().post().uri("/toolgate/drift/files/read_file/accept")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("the dashboard at the operator root is guarded, not just the paths under it")
    void dashboardRootRequiresToken() {
        // A prefix of "/toolgate/" does not match "/toolgate", so the dashboard shipped
        // reachable without a credential — on the one API that can approve anything.
        client().get().uri("/toolgate").exchange().expectStatus().isUnauthorized();
        client().get().uri("/toolgate/").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("the live event stream is guarded like every other operator route")
    void eventStreamRequiresToken() {
        // The stream carries refusal reasons, caller identities and drift diffs. It was
        // added after this filter and inherits it only because it sits under the prefix —
        // which is the argument for a filter, and worth an assertion rather than a comment.
        client().get().uri("/toolgate/events").exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("a wrong token is refused")
    void wrongTokenRejected() {
        client().get().uri("/toolgate/audit")
                .header("Authorization", "Bearer not-the-operator-token")
                .exchange().expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("the correct token is accepted")
    void correctTokenAccepted() {
        client().get().uri("/toolgate/audit")
                .header("Authorization", "Bearer " + OPERATOR_TOKEN)
                .exchange().expectStatus().isOk();
    }

    @Test
    @DisplayName("the agent endpoint is unaffected by operator auth")
    void agentPathUnaffected() {
        client().post().uri("/mcp")
                .header("MCP-Protocol-Version", "2026-07-28")
                .bodyValue(java.util.Map.of("jsonrpc", "2.0", "id", 1,
                        "method", "server/discover", "params", java.util.Map.of()))
                .exchange().expectStatus().isOk();
    }
}
