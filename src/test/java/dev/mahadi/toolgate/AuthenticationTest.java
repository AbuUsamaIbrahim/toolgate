package dev.mahadi.toolgate;

import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.util.Map;

/**
 * Caller authentication.
 *
 * <p>Before this existed, callers asserted an identity in a header and the gateway
 * believed them — which meant the audit trail recorded whatever an agent chose to claim,
 * and per-caller policy was unenforceable. These tests pin the replacement behaviour.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthenticationTest {

    /** Plaintext only ever exists in this test; config holds the SHA-256. */
    private static final String READER_TOKEN = "reader-token-abc123";
    private static final String FULL_TOKEN = "full-token-xyz789";

    private static MaliciousUpstream upstream;

    @LocalServerPort
    int port;

    @BeforeAll
    static void startUpstream() throws IOException {
        upstream = new MaliciousUpstream();
    }

    @AfterAll
    static void stopUpstream() {
        if (upstream != null) upstream.close();
    }

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add("toolgate.auth.enabled", () -> "true");
        registry.add("toolgate.auth.resource-uri", () -> "http://localhost:8080/mcp");
        registry.add("toolgate.auth.authorization-server", () -> "https://auth.example.com");

        // A caller who may read the catalogue but not invoke anything.
        registry.add("toolgate.auth.callers.reader.token-sha256", () -> sha256(READER_TOKEN));
        registry.add("toolgate.auth.callers.reader.scopes[0]", () -> "tools:read");

        // A caller with both scopes.
        registry.add("toolgate.auth.callers.agent-one.token-sha256", () -> sha256(FULL_TOKEN));
        registry.add("toolgate.auth.callers.agent-one.scopes[0]", () -> "tools:read");
        registry.add("toolgate.auth.callers.agent-one.scopes[1]", () -> "tools:call");

        registry.add("toolgate.servers.files.url", upstream::url);
        registry.add("toolgate.servers.files.allow[0]", () -> "read_file");
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

    private static Mcp.Request req(Object id, String method, Map<String, Object> params) {
        return new Mcp.Request("2.0", id, method, params,
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));
    }

    @Test
    @DisplayName("no token is 401 with a WWW-Authenticate pointing at the metadata document")
    void missingTokenChallenged() {
        client().post().uri("/mcp")
                .bodyValue(req(1, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches("WWW-Authenticate",
                        ".*Bearer .*resource_metadata=.*oauth-protected-resource.*");
    }

    @Test
    @DisplayName("an unrecognised token is 401, not 403 — we do not confirm it exists")
    void unknownTokenRejected() {
        client().post().uri("/mcp")
                .header("Authorization", "Bearer not-a-real-token")
                .bodyValue(req(2, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("a valid token with the wrong scope is 403 and says which scope is needed")
    void insufficientScopeChallenged() {
        client().post().uri("/mcp")
                .header("Authorization", "Bearer " + READER_TOKEN)
                .bodyValue(req(3, Mcp.METHOD_TOOLS_CALL,
                        Map.of("name", "files__read_file", "arguments", Map.of())))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueMatches("WWW-Authenticate",
                        ".*error=\"insufficient_scope\".*scope=\"tools:call\".*");
    }

    @Test
    @DisplayName("the read scope is enough to list tools")
    void readScopeCanList() {
        client().post().uri("/mcp")
                .header("Authorization", "Bearer " + READER_TOKEN)
                .bodyValue(req(4, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.error").doesNotExist();
    }

    @Test
    @DisplayName("the bearer scheme is matched case-insensitively, per RFC 7235")
    void schemeIsCaseInsensitive() {
        client().post().uri("/mcp")
                .header("Authorization", "bearer " + FULL_TOKEN)
                .bodyValue(req(5, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    @DisplayName("identity comes from the token, so a spoofed caller header is ignored")
    void callerHeaderCannotSpoofIdentity() {
        client().post().uri("/mcp")
                .header("Authorization", "Bearer " + FULL_TOKEN)
                .header("X-Toolgate-Caller", "someone-else")
                .bodyValue(req(6, Mcp.METHOD_TOOLS_LIST, Map.of()))
                .exchange()
                .expectStatus().isOk();

        // The audit trail must show the token subject, never the asserted header.
        client().get().uri("/toolgate/audit?limit=50")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$[?(@.caller == 'someone-else')]").doesNotExist()
                .jsonPath("$[?(@.caller == 'agent-one')]").exists();
    }

    @Test
    @DisplayName("discovery stays reachable so a client can learn the protocol version")
    void discoveryNeedsNoScope() {
        client().post().uri("/mcp")
                .header("Authorization", "Bearer " + READER_TOKEN)
                .bodyValue(req(7, Mcp.METHOD_DISCOVER, Map.of()))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    @DisplayName("protected resource metadata is served, per RFC 9728")
    void metadataDocumentServed() {
        client().get().uri("/.well-known/oauth-protected-resource")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.resource").isEqualTo("http://localhost:8080/mcp")
                .jsonPath("$.authorization_servers[0]").isEqualTo("https://auth.example.com")
                .jsonPath("$.scopes_supported").isArray();
    }
}
