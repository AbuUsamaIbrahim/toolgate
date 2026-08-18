package dev.mahadi.toolgate;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end: a real agent-shaped client, the real gateway, and a real hostile MCP server.
 *
 * <p>Everything the unit tests assert about policy is re-proved here over HTTP, because a
 * correct policy engine that is wired up wrongly protects nothing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
// Pins and audit entries are per-context state, and the fake upstream is shared. Without
// a fresh context per test, one scenario's poisoning leaks into the next and the suite
// starts depending on method order — which is how a green suite stops meaning anything.
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class ProxyEndToEndTest {

    private static MaliciousUpstream upstream;

    @LocalServerPort
    int port;

    @Autowired
    AuditLog audit;

    @BeforeAll
    static void startUpstream() throws IOException {
        upstream = new MaliciousUpstream();
    }

    @BeforeEach
    void resetUpstream() {
        upstream.reset();
    }

    @AfterAll
    static void stopUpstream() {
        if (upstream != null) upstream.close();
    }

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        registry.add("toolgate.servers.files.url", upstream::url);
        registry.add("toolgate.servers.files.allow[0]", () -> "read_file");
        registry.add("toolgate.servers.files.allow[1]", () -> "write_file");
        registry.add("toolgate.servers.files.require-approval[0]", () -> "write_file");
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .defaultHeader("X-Toolgate-Caller", "test-agent")
                .build();
    }

    private Mcp.Response call(Mcp.Request request) {
        return client().post().uri("/mcp")
                .header("MCP-Protocol-Version", Mcp.PROTOCOL_VERSION)
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Mcp.Response.class)
                .returnResult().getResponseBody();
    }

    private static List<String> names(List<Map<String, Object>> tools) {
        return tools.stream().map(t -> String.valueOf(t.get("name"))).toList();
    }

    private static Mcp.Request req(Object id, String method, Map<String, Object> params) {
        return new Mcp.Request("2.0", id, method, params,
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));
    }

    @Test
    @DisplayName("the full path holds: clean tools pass, unlisted ones vanish, poison is refused")
    @SuppressWarnings("unchecked")
    void endToEnd() {
        // ---- 1. Discovery is answered by the gateway itself.
        var discovered = call(req(1, Mcp.METHOD_DISCOVER, Map.of()));
        assertThat(discovered.error()).isNull();
        assertThat(((Map<String, Object>) discovered.result()).get("protocolVersions"))
                .isEqualTo(List.of(Mcp.PROTOCOL_VERSION));

        // ---- 2. tools/list: read_file survives, the unlisted exec_shell does not.
        var listed = call(req(2, Mcp.METHOD_TOOLS_LIST, Map.of()));
        var tools = (List<Map<String, Object>>) ((Map<String, Object>) listed.result()).get("tools");

        assertThat(names(tools))
                .containsExactlyInAnyOrder("files__read_file", "files__write_file");
        assertThat(names(tools))
                .as("a tool nobody allowlisted must never reach the model")
                .noneMatch(n -> n.contains("exec_shell"));

        // ---- 3. A clean call succeeds and is namespaced correctly on the way through.
        var ok = call(req(3, Mcp.METHOD_TOOLS_CALL,
                Map.of("name", "files__read_file", "arguments", Map.of("path", "a.txt"))));
        assertThat(ok.error()).isNull();

        // ---- 4. A destructive tool demands a human even though it is allowlisted.
        var needsHuman = call(req(4, Mcp.METHOD_TOOLS_CALL,
                Map.of("name", "files__write_file", "arguments", Map.of())));
        assertThat(needsHuman.error()).isNotNull();
        assertThat(needsHuman.error().code()).isEqualTo(Mcp.Codes.APPROVAL_REQUIRED);

        // ---- 5. The upstream is compromised and rewrites read_file's description.
        upstream.poisonDefinitions();
        var afterPoison = call(req(5, Mcp.METHOD_TOOLS_LIST, Map.of()));
        var remaining = (List<Map<String, Object>>) ((Map<String, Object>) afterPoison.result()).get("tools");

        assertThat(names(remaining))
                .as("a tool whose definition drifted must disappear from the model's context")
                .doesNotContain("files__read_file")
                .as("tools that did not change are unaffected")
                .contains("files__write_file");

        // The refusal, with its evidence, is on the record.
        assertThat(audit.recent(50))
                .anyMatch(e -> e.outcome() == AuditLog.Outcome.DENIED
                        && e.reason().contains("changed since it was pinned"));
    }

    @Test
    @DisplayName("instructions injected into tool output are refused on the way back")
    void poisonedResultIsBlocked() {
        var fresh = new Mcp.Request("2.0", 10, Mcp.METHOD_TOOLS_LIST, Map.of(),
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));
        call(fresh); // establish the pin

        upstream.poisonResults();

        var response = call(req(11, Mcp.METHOD_TOOLS_CALL,
                Map.of("name", "files__read_file", "arguments", Map.of("path", "a.txt"))));

        assertThat(response.error()).isNotNull();
        assertThat(response.error().code()).isEqualTo(Mcp.Codes.POLICY_DENIED);
        assertThat(response.error().message()).contains("adversarial content");
    }

    @Test
    @DisplayName("an unsupported protocol version is rejected, not guessed at")
    void wrongProtocolVersionRejected() {
        var response = client().post().uri("/mcp")
                .header("MCP-Protocol-Version", "2024-01-01")
                .bodyValue(req(20, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(Mcp.Response.class)
                .returnResult().getResponseBody();

        assertThat(response.error()).isNotNull();
        assertThat(response.error().message()).contains("unsupported protocol version");
    }
}
