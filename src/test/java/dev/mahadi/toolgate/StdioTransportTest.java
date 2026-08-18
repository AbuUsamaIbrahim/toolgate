package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.upstream.StdioUpstream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The stdio binding, exercised against a real subprocess.
 *
 * <p>These are the tests that would catch the mistakes the framing rules invite: a log
 * line on stdout, a pretty-printed message spanning several lines, or a stderr pipe left
 * unread until the child blocks on it.
 */
class StdioTransportTest {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Writes a small MCP server as a shell script. Deliberately a separate process
     * speaking over real pipes — an in-process fake would skip the framing, which is the
     * only part of this worth testing.
     */
    private Path writeServer(String body) throws Exception {
        Path script = Files.createTempFile("mcp-server", ".sh");
        Files.writeString(script, "#!/bin/sh\n" + body);
        script.toFile().setExecutable(true);
        return script;
    }

    private static Mcp.Request req(Object id, String method) {
        return new Mcp.Request("2.0", id, method, Map.of(),
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));
    }

    @Test
    @DisplayName("a request is framed as one line and the response is correlated by id")
    void roundTrip() throws Exception {
        Path server = writeServer("""
                while IFS= read -r line; do
                  printf '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}\\n'
                done
                """);

        try (var upstream = new StdioUpstream("t", List.of(server.toString()), Map.of(), mapper)) {
            Mcp.Response response = upstream.send(req(1, Mcp.METHOD_TOOLS_LIST)).block();

            assertThat(response).isNotNull();
            assertThat(response.error()).isNull();
            assertThat(response.id()).isEqualTo(1);
        }
    }

    @Test
    @DisplayName("responses arriving out of order still reach the right caller")
    void outOfOrderResponsesCorrelate() throws Exception {
        // Answers every request with id 7, regardless of what was asked. A transport that
        // assumed replies arrive in request order would hand this to the wrong caller.
        Path server = writeServer("""
                while IFS= read -r line; do
                  printf '{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete"}}\\n'
                done
                """);

        try (var upstream = new StdioUpstream("t", List.of(server.toString()), Map.of(), mapper)) {
            var seven = upstream.send(req(7, Mcp.METHOD_TOOLS_LIST));
            assertThat(seven.block()).isNotNull();

            // id 8 is never answered, so it must time out rather than steal id 7's reply.
            var eight = upstream.send(req(8, Mcp.METHOD_TOOLS_LIST))
                    .timeout(java.time.Duration.ofMillis(600))
                    .onErrorReturn(Mcp.Response.error(8, -1, "timed out", null))
                    .block();

            assertThat(eight).isNotNull();
            assertThat(eight.error()).isNotNull();
            assertThat(eight.error().message()).isEqualTo("timed out");
        }
    }

    @Test
    @DisplayName("a chatty stderr does not block the upstream")
    void noisyStderrDoesNotDeadlock() throws Exception {
        // Far more stderr than a pipe buffer holds. If stderr were not drained, the child
        // would block on write and this test would hang rather than fail.
        Path server = writeServer("""
                i=0
                while [ $i -lt 2000 ]; do
                  echo "verbose diagnostic line $i padding padding padding padding" >&2
                  i=$((i+1))
                done
                while IFS= read -r line; do
                  printf '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}\\n'
                done
                """);

        try (var upstream = new StdioUpstream("t", List.of(server.toString()), Map.of(), mapper)) {
            Mcp.Response response = upstream.send(req(1, Mcp.METHOD_TOOLS_LIST)).block();
            assertThat(response).isNotNull();
            assertThat(response.error()).isNull();
        }
    }

    @Test
    @DisplayName("a request is written as exactly one newline-terminated line")
    void requestIsSingleLine() throws Exception {
        Path captured = Files.createTempFile("captured", ".txt");
        Path server = writeServer("""
                while IFS= read -r line; do
                  printf '%%s\\n' "$line" >> %s
                  printf '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}\\n'
                done
                """.formatted(captured));

        try (var upstream = new StdioUpstream("t", List.of(server.toString()), Map.of(), mapper)) {
            upstream.send(req(1, Mcp.METHOD_TOOLS_LIST)).block();
        }

        List<String> lines = Files.readAllLines(captured);
        assertThat(lines).hasSize(1);
        assertThat(lines.get(0)).startsWith("{").endsWith("}");
        // Embedded newlines would have split this into several unparseable fragments.
        assertThat(mapper.readTree(lines.get(0)).get("method").asText())
                .isEqualTo(Mcp.METHOD_TOOLS_LIST);
    }

    @Test
    @DisplayName("when the upstream dies, waiting callers fail instead of hanging")
    void deathReleasesWaiters() throws Exception {
        Path server = writeServer("read -r line\nexit 0\n");

        try (var upstream = new StdioUpstream("t", List.of(server.toString()), Map.of(), mapper)) {
            Mcp.Response response = upstream.send(req(1, Mcp.METHOD_TOOLS_LIST))
                    .onErrorReturn(Mcp.Response.error(1, -1, "upstream gone", null))
                    .block();

            assertThat(response).isNotNull();
            assertThat(response.error()).isNotNull();
        }
    }
}
