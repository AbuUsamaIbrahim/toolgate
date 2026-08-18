package dev.mahadi.toolgate;

import dev.mahadi.toolgate.api.HttpTransportRules;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two Streamable HTTP rules that exist for security rather than framing.
 */
class HttpTransportRulesTest {

    private static Mcp.Request request(String method, Map<String, Object> params) {
        return new Mcp.Request("2.0", 1, method, params, Map.of());
    }

    @Nested
    @DisplayName("Origin, against DNS rebinding")
    class Origin {

        @Test
        @DisplayName("no Origin is fine — a command-line agent has no reason to send one")
        void absentOriginAllowed() {
            assertThat(HttpTransportRules.checkOrigin(null, Set.of())).isEmpty();
            assertThat(HttpTransportRules.checkOrigin("", Set.of())).isEmpty();
        }

        @Test
        @DisplayName("an Origin nobody allowlisted is refused with 403")
        void unknownOriginRefused() {
            // A page on the open web pointing a name it controls at 127.0.0.1. The browser
            // sends the request happily; Origin is the only thing that gives it away.
            var rejection = HttpTransportRules.checkOrigin("https://evil.example.com", Set.of());

            assertThat(rejection).isPresent();
            assertThat(rejection.get().httpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("an allowlisted Origin passes")
        void allowedOrigin() {
            assertThat(HttpTransportRules.checkOrigin("http://localhost:3000",
                    Set.of("http://localhost:3000"))).isEmpty();
        }

        @Test
        @DisplayName("comparison ignores case and a trailing slash")
        void normalised() {
            assertThat(HttpTransportRules.checkOrigin("HTTP://LocalHost:3000/",
                    Set.of("http://localhost:3000"))).isEmpty();
        }

        @Test
        @DisplayName("a different port is a different origin")
        void portMatters() {
            assertThat(HttpTransportRules.checkOrigin("http://localhost:3001",
                    Set.of("http://localhost:3000"))).isPresent();
        }
    }

    @Nested
    @DisplayName("Headers must agree with the body")
    class HeaderBody {

        @Test
        @DisplayName("matching headers pass")
        void matching() {
            var request = request("tools/call", Map.of("name", "read_file"));

            assertThat(HttpTransportRules.checkMirroredHeaders(request, "tools/call", "read_file"))
                    .isEmpty();
        }

        @Test
        @DisplayName("a header naming a different tool than the body is refused")
        void nameMismatchRefused() {
            // Built to be judged by one component and executed by another. This gateway is
            // exactly the intermediary the spec has in mind.
            var request = request("tools/call", Map.of("name", "delete_everything"));

            var rejection = HttpTransportRules.checkMirroredHeaders(request, "tools/call", "read_file");

            assertThat(rejection).isPresent();
            assertThat(rejection.get().jsonRpcCode()).isEqualTo(HttpTransportRules.HEADER_MISMATCH);
            assertThat(rejection.get().httpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("a header naming a different method than the body is refused")
        void methodMismatchRefused() {
            var request = request("tools/call", Map.of("name", "x"));

            assertThat(HttpTransportRules.checkMirroredHeaders(request, "tools/list", "x"))
                    .isPresent();
        }

        @Test
        @DisplayName("a resource URI is compared against params.uri")
        void resourceUriCompared() {
            var request = request("resources/read", Map.of("uri", "file:///etc/shadow"));

            assertThat(HttpTransportRules.checkMirroredHeaders(
                    request, "resources/read", "file:///project/readme.md")).isPresent();
            assertThat(HttpTransportRules.checkMirroredHeaders(
                    request, "resources/read", "file:///etc/shadow")).isEmpty();
        }

        @Test
        @DisplayName("a base64 sentinel value is decoded before comparison")
        void sentinelDecoded() {
            // Comparing without decoding would let any non-ASCII name bypass the check
            // simply by being encoded.
            String encoded = "=?base64?" + Base64.getEncoder()
                    .encodeToString("Hello, 世界".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                    + "?=";
            var request = request("tools/call", Map.of("name", "Hello, 世界"));

            assertThat(HttpTransportRules.checkMirroredHeaders(request, "tools/call", encoded))
                    .isEmpty();
        }

        @Test
        @DisplayName("an encoded value that decodes to something else is still refused")
        void sentinelMismatchRefused() {
            String encoded = "=?base64?" + Base64.getEncoder()
                    .encodeToString("delete_everything".getBytes()) + "?=";
            var request = request("tools/call", Map.of("name", "read_file"));

            assertThat(HttpTransportRules.checkMirroredHeaders(request, "tools/call", encoded))
                    .isPresent();
        }

        @Test
        @DisplayName("absent headers are not an error — a client one revision behind still works")
        void absentHeadersAllowed() {
            var request = request("tools/call", Map.of("name", "read_file"));

            // A header that is absent cannot desync anything; one that is present and
            // wrong is the attack.
            assertThat(HttpTransportRules.checkMirroredHeaders(request, null, null)).isEmpty();
        }
    }
}
