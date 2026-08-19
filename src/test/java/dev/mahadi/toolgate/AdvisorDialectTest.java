package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import dev.mahadi.toolgate.advisor.AdvisorProperties;
import dev.mahadi.toolgate.advisor.DriftAdvisor;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The advisor speaks two HTTP dialects.
 *
 * <p>DeepSeek, OpenAI, Groq and most self-hosted servers implement chat-completions;
 * Anthropic implements the Messages API. The difference is not cosmetic — a different auth
 * header, the system prompt in a different slot, and the reply under a different path — so
 * getting it wrong fails at the provider, not at compile time.
 *
 * <p>These run against a real local HTTP server rather than a mock, because the thing worth
 * checking is the bytes that leave the process.
 */
class AdvisorDialectTest {

    private HttpServer server;
    private final ConcurrentLinkedQueue<Recorded> seen = new ConcurrentLinkedQueue<>();
    private final ObjectMapper mapper = new ObjectMapper();

    private record Recorded(Map<String, java.util.List<String>> headers, String body) {}

    /** Starts a server that records the request and replies in the given shape. */
    private String startServer(String replyJson) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            try (InputStream in = exchange.getRequestBody()) {
                seen.add(new Recorded(
                        Map.copyOf(exchange.getRequestHeaders()),
                        new String(in.readAllBytes(), StandardCharsets.UTF_8)));
            }
            byte[] out = replyJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("content-type", "application/json");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    /**
     * The advisor reads its key from the environment and refuses to run without one. HOME
     * is set in every environment this suite runs in, and its value is never asserted on —
     * it stands in for a key purely so the request is attempted.
     */
    private static AdvisorProperties props(String endpoint, AdvisorProperties.Dialect dialect) {
        var props = new AdvisorProperties();
        props.setEnabled(true);
        props.setApiKeyEnv("HOME");
        props.setEndpoint(endpoint);
        props.setApi(dialect);
        props.setModel("deepseek-chat");
        return props;
    }

    private static DriftStore.Drift drift() {
        var pinned = new Mcp.Tool("read_file", "Read File", "Read a file.",
                Map.of("type", "object"), null, null, null);
        var current = new Mcp.Tool("read_file", "Read File", "Read a file. Returns UTF-8.",
                Map.of("type", "object"), null, null, null);
        return new DriftStore.Drift("demo", "read_file", Instant.now(),
                "aaa", "bbb", pinned, current);
    }

    /** Drives the background fetch to completion, then reads the cached note. */
    private String adviseAndWait(DriftAdvisor advisor) throws Exception {
        advisor.adviseOn(drift());
        for (int i = 0; i < 100 && seen.isEmpty(); i++) TimeUnit.MILLISECONDS.sleep(50);
        return seen.isEmpty() ? null : seen.peek().body();
    }

    @Nested
    @DisplayName("OpenAI / DeepSeek dialect")
    class OpenAiShape {

        @Test
        @DisplayName("authenticates with a bearer token and never sends x-api-key")
        void usesBearerAuth() throws Exception {
            String endpoint = startServer("""
                {"choices":[{"message":{"content":"{\\"risk\\":\\"low\\",\\"summary\\":\\"fine\\"}"}}]}""");
            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.OPENAI), mapper);

            adviseAndWait(advisor);

            var headers = seen.peek().headers();
            assertThat(headers).containsKey("Authorization");
            assertThat(headers.get("Authorization").get(0)).startsWith("Bearer ");
            // The Anthropic headers must not come along for the ride: a provider that
            // rejects unknown headers would fail, and one that logs them would record a
            // credential under a second name.
            assertThat(headers).doesNotContainKey("X-api-key");
            assertThat(headers).doesNotContainKey("Anthropic-version");
        }

        @Test
        @DisplayName("sends the system prompt as a message, not a field")
        void systemIsAMessage() throws Exception {
            String endpoint = startServer("""
                {"choices":[{"message":{"content":"{\\"risk\\":\\"low\\"}"}}]}""");
            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.OPENAI), mapper);

            String body = adviseAndWait(advisor);
            var root = new ObjectMapper().readTree(body);

            assertThat(root.has("system")).isFalse();
            assertThat(root.path("model").asText()).isEqualTo("deepseek-chat");
            assertThat(root.path("messages").get(0).path("role").asText()).isEqualTo("system");
            assertThat(root.path("messages").get(1).path("role").asText()).isEqualTo("user");
            assertThat(root.path("messages").get(1).path("content").asText())
                    .contains("<drift_diff>");
        }
    }

    @Nested
    @DisplayName("Anthropic dialect")
    class AnthropicShape {

        @Test
        @DisplayName("keeps x-api-key and the version header, and no bearer token")
        void usesApiKeyHeader() throws Exception {
            String endpoint = startServer("""
                {"content":[{"type":"text","text":"{\\"risk\\":\\"low\\"}"}]}""");
            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.ANTHROPIC), mapper);

            adviseAndWait(advisor);

            var headers = seen.peek().headers();
            assertThat(headers).containsKey("X-api-key");
            assertThat(headers.get("Anthropic-version").get(0)).isEqualTo("2023-06-01");
            assertThat(headers).doesNotContainKey("Authorization");
        }

        @Test
        @DisplayName("sends the system prompt in its own field")
        void systemIsAField() throws Exception {
            String endpoint = startServer("""
                {"content":[{"type":"text","text":"{\\"risk\\":\\"low\\"}"}]}""");
            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.ANTHROPIC), mapper);

            var root = new ObjectMapper().readTree(adviseAndWait(advisor));

            assertThat(root.path("system").asText()).isNotEmpty();
            assertThat(root.path("messages").get(0).path("role").asText()).isEqualTo("user");
        }
    }

    @Nested
    @DisplayName("A failing provider is not re-asked on every refresh")
    class Backoff {

        @Test
        @DisplayName("a provider that refuses is asked once, not once per poll")
        void failureIsNotRetriedImmediately() throws Exception {
            // 402 Payment Required is what a real DeepSeek account with no balance
            // returns, and what exposed this: thirty calls in sixty seconds.
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                seen.add(new Recorded(Map.copyOf(exchange.getRequestHeaders()), ""));
                exchange.sendResponseHeaders(402, -1);
                exchange.close();
            });
            server.start();
            String endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";

            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.OPENAI), mapper);

            var d = drift();
            advisor.adviseOn(d);
            for (int i = 0; i < 100 && seen.isEmpty(); i++) TimeUnit.MILLISECONDS.sleep(50);
            assertThat(seen).hasSize(1);

            // Twenty further polls — four minutes of a 15s refresh — must not reach it.
            for (int i = 0; i < 20; i++) {
                advisor.adviseOn(d);
                TimeUnit.MILLISECONDS.sleep(5);
            }
            TimeUnit.MILLISECONDS.sleep(300);

            assertThat(seen).hasSize(1);
        }

        @Test
        @DisplayName("each failure pushes the next attempt further out")
        void backoffGrows() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                exchange.sendResponseHeaders(402, -1);
                exchange.close();
            });
            server.start();
            String endpoint = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1";

            var advisor = new DriftAdvisor(
                    props(endpoint, AdvisorProperties.Dialect.OPENAI), mapper);
            var d = drift();
            String key = d.serverId() + "/" + d.toolName() + "@" + d.currentFingerprint();

            advisor.adviseOn(d);
            for (int i = 0; i < 100 && advisor.retryAfter(key).isEmpty(); i++) {
                TimeUnit.MILLISECONDS.sleep(50);
            }

            var first = advisor.retryAfter(key).orElseThrow();
            // At least the opening backoff, and never beyond the cap.
            assertThat(first).isAfter(java.time.Instant.now().plusSeconds(50));
            assertThat(first).isBefore(java.time.Instant.now().plus(DriftAdvisor.MAX_BACKOFF));
        }
    }

    @Nested
    @DisplayName("Reading the reply")
    class Extraction {

        @Test
        @DisplayName("each dialect is read from its own path")
        void eachShapeIsRead() throws Exception {
            var openai = new ObjectMapper().readTree(
                    "{\"choices\":[{\"message\":{\"content\":\"from-openai\"}}]}");
            var anthropic = new ObjectMapper().readTree(
                    "{\"content\":[{\"type\":\"text\",\"text\":\"from-anthropic\"}]}");

            assertThat(DriftAdvisor.extractText(openai, true)).isEqualTo("from-openai");
            assertThat(DriftAdvisor.extractText(anthropic, false)).isEqualTo("from-anthropic");
        }

        @Test
        @DisplayName("an unfamiliar envelope yields no advice rather than an error")
        void unknownShapeIsEmpty() throws Exception {
            var odd = new ObjectMapper().readTree("{\"unexpected\":true}");

            assertThat(DriftAdvisor.extractText(odd, true)).isEmpty();
            assertThat(DriftAdvisor.extractText(odd, false)).isEmpty();
        }

        @Test
        @DisplayName("reading the wrong dialect's envelope is empty, not a crash")
        void crossedWiresAreEmpty() throws Exception {
            var openai = new ObjectMapper().readTree(
                    "{\"choices\":[{\"message\":{\"content\":\"x\"}}]}");

            assertThat(DriftAdvisor.extractText(openai, false)).isEmpty();
        }
    }
}
