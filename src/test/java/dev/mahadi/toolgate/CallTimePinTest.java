package dev.mahadi.toolgate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
 * Calling a tool whose definition changed after it was pinned.
 *
 * <p>The gap these cover: {@code tools/list} withheld a mutated tool, and {@code tools/call}
 * forwarded to it anyway, because the call path checked that a pin <em>existed</em> rather
 * than that it still <em>matched</em>. Every poisoning test in the suite listed and asserted
 * the tool was absent; none of them then called it. The demo script had the same shape, so
 * the attack the product exists to stop succeeded against any agent that had already listed.
 *
 * <p>An agent that lists, keeps the definition in context and calls later is the ordinary
 * case, not an exotic one — which is why these tests call without listing in between.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CallTimePinTest {

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

    @BeforeEach
    void healthy() {
        upstream.reset();
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private WebTestClient.ResponseSpec list() {
        return client().post().uri("/mcp").header("Content-Type", "application/json")
                .bodyValue("""
                        {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
                        """)
                .exchange();
    }

    private WebTestClient.ResponseSpec call() {
        return client().post().uri("/mcp").header("Content-Type", "application/json")
                .bodyValue("""
                        {"jsonrpc":"2.0","id":2,"method":"tools/call",
                         "params":{"name":"files__read_file","arguments":{"path":"README.md"}}}
                        """)
                .exchange();
    }

    /** Establishes the pin, the way an agent's first list would. */
    private void listOnce() {
        list().expectStatus().isOk().expectBody()
                .jsonPath("$.result.tools[0].name").isEqualTo("files__read_file");
    }

    @Nested
    @DisplayName("after the definition is mutated")
    class Mutated {

        /**
         * The regression. Before the fix this returned a successful tool result: the agent
         * held a definition from before the mutation, and the gateway had no objection to
         * calling whatever the tool had since become.
         */
        @Test
        @DisplayName("the call is refused, with no list in between")
        void refusedWithoutAnyList() {
            listOnce();
            upstream.poisonDefinitions();

            call().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.result").doesNotExist()
                    .jsonPath("$.error.message").value(
                            (String m) -> org.assertj.core.api.Assertions.assertThat(m)
                                    .contains("changed since it was pinned"));
        }

        /**
         * The upstream is asked once and the answer is remembered, so a second call costs
         * nothing — the drift is on record by then and refusable without a round-trip.
         */
        @Test
        @DisplayName("the refusal survives without asking upstream again")
        void secondCallUsesRecordedDrift() {
            listOnce();
            upstream.poisonDefinitions();
            call().expectStatus().isOk();

            int before = upstream.listRequests();
            call().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error.message").value(
                            (String m) -> org.assertj.core.api.Assertions.assertThat(m)
                                    .contains("changed since it was pinned"));

            org.assertj.core.api.Assertions.assertThat(upstream.listRequests())
                    .as("second refusal should need no upstream round-trip")
                    .isEqualTo(before);
        }

        /**
         * Reverting is still enough to restore service, with no operator action: the
         * gateway blocks a state, not a server. Asserted because the recorded-drift fast
         * path is the obvious way to break it — a refusal cached forever would turn a
         * transient upstream mistake into a permanent outage.
         */
        @Test
        @DisplayName("the tool works again once the upstream reverts")
        void revertRestoresIt() {
            listOnce();
            upstream.poisonDefinitions();
            call().expectStatus().isOk().expectBody().jsonPath("$.error").exists();

            upstream.reset();
            list();  // the revert is observed the same way the mutation was

            call().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error").doesNotExist()
                    .jsonPath("$.result").exists();
        }
    }

    @Nested
    @DisplayName("when the definition is intact")
    class Intact {

        @Test
        @DisplayName("the call goes through")
        void allowed() {
            listOnce();
            call().expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.error").doesNotExist()
                    .jsonPath("$.result").exists();
        }
    }

    @Nested
    @DisplayName("when the upstream cannot be reached")
    class Unreachable {

        /**
         * Fails closed. Verification that is skipped whenever a server misbehaves is
         * verification that is absent exactly when it is needed.
         */
        @Test
        @DisplayName("the call is refused rather than forwarded unverified")
        void failsClosed() {
            listOnce();
            upstream.stopAnswering();
            try {
                call().expectStatus().isOk()
                        .expectBody()
                        .jsonPath("$.result").doesNotExist()
                        .jsonPath("$.error.message").value(
                                (String m) -> org.assertj.core.api.Assertions.assertThat(m)
                                        .containsAnyOf("could not verify",
                                                "no longer advertises"));
            } finally {
                upstream.resumeAnswering();
            }
        }
    }
}
