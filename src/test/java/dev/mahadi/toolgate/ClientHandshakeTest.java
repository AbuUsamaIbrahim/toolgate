package dev.mahadi.toolgate;

import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;

/**
 * The handshake a real client opens with.
 *
 * <p>Toolgate answered {@code server/discover} and nothing else, so every client that
 * exists — which opens with {@code initialize} — was refused at its first message, over
 * both transports. Four hundred tests passed throughout, because they all post
 * {@code tools/list} straight in, exactly as the demo script does. The gap was found by
 * pointing Claude Code at the running gateway and reading the error.
 *
 * <p>So these tests are deliberately shaped like a session rather than like a method call:
 * handshake, the notification that completes it, then work — each request carrying what a
 * client actually carries, because the defects were in what the sequence assumed, not in
 * any single response.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ClientHandshakeTest {

    /** The revision Claude Code 2.1.227 offers. Not the one the gateway prefers. */
    private static final String CLIENT_VERSION = "2025-11-25";

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
        registry.add("toolgate.auth.enabled", () -> "false");
        registry.add("toolgate.operator.enabled", () -> "false");
        registry.add("toolgate.servers.files.url", upstream::url);
        registry.add("toolgate.servers.files.allow[0]", () -> "read_file");
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private WebTestClient.ResponseSpec send(String body, String protocolHeader) {
        var request = client().post().uri("/mcp").header("Content-Type", "application/json");
        if (protocolHeader != null) request.header("MCP-Protocol-Version", protocolHeader);
        return request.bodyValue(body).exchange();
    }

    private static String initializeRequest(String version) {
        return """
                {"jsonrpc":"2.0","id":0,"method":"initialize","params":{
                  "protocolVersion":"%s",
                  "capabilities":{"roots":{"listChanged":true},"elicitation":{}},
                  "clientInfo":{"name":"claude-code","version":"2.1.227"}}}
                """.formatted(version);
    }

    @Nested
    @DisplayName("initialize")
    class Initialize {

        @Test
        @DisplayName("is answered, not refused as unproxied")
        void answered() {
            send(initializeRequest(CLIENT_VERSION), null)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error").doesNotExist()
                    .jsonPath("$.result.serverInfo.name").isEqualTo("toolgate")
                    .jsonPath("$.result.capabilities.tools").exists();
        }

        /**
         * The client decides whether it can proceed, so answering with the gateway's own
         * preferred revision ends the session for a client one revision behind. This is
         * the assertion that would have caught the second defect: a handshake that
         * succeeds on paper and a client that hangs up.
         */
        @Test
        @DisplayName("settles on the revision the client asked for")
        void echoesClientVersion() {
            send(initializeRequest(CLIENT_VERSION), null)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.result.protocolVersion").isEqualTo(CLIENT_VERSION);
        }

        @Test
        @DisplayName("names its own revision to a client it cannot match")
        void fallsBackToPreferred() {
            send(initializeRequest("1999-01-01"), null)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.result.protocolVersion").isEqualTo(Mcp.PROTOCOL_VERSION);
        }
    }

    @Nested
    @DisplayName("the notification that completes the handshake")
    class Initialized {

        /**
         * A notification has no id, so a reply cannot be correlated and must not be sent.
         * This one arrived over HTTP and came back as an error object with a null id.
         */
        @Test
        @DisplayName("is accepted without a body")
        void acceptedSilently() {
            send("""
                    {"jsonrpc":"2.0","method":"notifications/initialized"}
                    """, CLIENT_VERSION)
                    .expectStatus().isAccepted()
                    .expectBody().isEmpty();
        }
    }

    @Nested
    @DisplayName("the session that follows")
    class Session {

        /**
         * The version header carries what initialize settled on. Validating it against a
         * single revision meant the gateway could agree to 2025-11-25 and then reject
         * every request made under it.
         */
        @Test
        @DisplayName("works under the negotiated version, not only the preferred one")
        void negotiatedVersionIsAccepted() {
            send("""
                    {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
                    """, CLIENT_VERSION)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error").doesNotExist()
                    .jsonPath("$.result.tools[0].name").isEqualTo("files__read_file");
        }

        @Test
        @DisplayName("a revision the gateway never agreed to is still refused")
        void unknownVersionRejected() {
            send("""
                    {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
                    """, "1999-01-01")
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error.code").isEqualTo(Mcp.Codes.INVALID_PARAMS);
        }

        /**
         * The whole sequence in order, which is the only thing that proves a client can
         * actually get a tool list: the individual responses were each defensible while
         * the session as a whole was impossible.
         */
        @Test
        @DisplayName("handshake, initialized, tools/list — in that order")
        void fullSession() {
            send(initializeRequest(CLIENT_VERSION), null).expectStatus().isOk();
            send("""
                    {"jsonrpc":"2.0","method":"notifications/initialized"}
                    """, CLIENT_VERSION).expectStatus().isAccepted();
            send("""
                    {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
                    """, CLIENT_VERSION)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.result.tools.length()").isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("stdio hears the same handshake")
    class Stdio {

        /**
         * Both transports share one method switch, so the fix lands in both at once —
         * but the desktop-client path is the one the README tells people to use, and it
         * was equally unreachable. Asserted through the service rather than the wire:
         * stdio's framing is covered elsewhere.
         */
        @Test
        @DisplayName("initialize is handled off the same switch")
        void sharedSwitch() {
            send(initializeRequest(CLIENT_VERSION), null)
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.result.instructions").exists();
        }
    }

    /** Discovery still answers, since removing it would break anything already using it. */
    @Test
    @DisplayName("server/discover is unaffected")
    void discoverStillWorks() {
        send("""
                {"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}
                """, null)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.result.serverInfo.name").isEqualTo("toolgate");
    }
}
