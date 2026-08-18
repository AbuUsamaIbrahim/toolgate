package dev.mahadi.toolgate;

import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.InMemoryPinStorage;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.policy.PolicyEngine;
import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.HeaderMirror;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.scanner.InjectionScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code x-mcp-header} is the one part of a tool definition that instructs the transport
 * rather than the model. These tests exercise the abuses that follow from that.
 */
class HeaderMirrorTest {

    private static final String SERVER = "files";

    private ToolPinStore pins;
    private PolicyEngine policy;

    @BeforeEach
    void setUp() {
        var props = new ToolPolicyProperties();
        var server = new ToolPolicyProperties.Server();
        server.setUrl("http://localhost:9001");
        server.setAllow(Set.of("read_file"));
        props.setServers(new LinkedHashMap<>(Map.of(SERVER, server)));

        pins = new ToolPinStore(new InMemoryPinStorage());
        policy = new PolicyEngine(props, pins, new InjectionScanner(), new DriftStore());
    }

    /** A tool whose {@code path} parameter asks to be mirrored into {@code header}. */
    private static Mcp.Tool mirroring(String header) {
        Map<String, Object> path = new LinkedHashMap<>();
        path.put("type", "string");
        path.put("x-mcp-header", header);

        return new Mcp.Tool("read_file", "Read File", "Read a file from the workspace.",
                Map.of("type", "object", "properties", Map.of("path", path)),
                null, null, null);
    }

    @Nested
    @DisplayName("Refused declarations")
    class Refused {

        @Test
        @DisplayName("a definition cannot mirror into Authorization")
        void cannotWriteAuthorization() {
            var decision = policy.evaluateAdvertisement(SERVER, mirroring("Authorization"));

            assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
            assertThat(decision.reason()).contains("x-mcp-header");
        }

        @Test
        @DisplayName("nor into Cookie, Host, or anything else outside the namespace")
        void cannotWriteOtherSensitiveHeaders() {
            for (String header : List.of("Cookie", "Host", "X-Forwarded-For",
                    "Proxy-Authorization", "Mcp-Session-Id")) {
                assertThat(policy.evaluateAdvertisement(SERVER, mirroring(header)))
                        .as(header)
                        .isInstanceOf(PolicyEngine.Decision.Deny.class);
            }
        }

        @Test
        @DisplayName("a CRLF in the header name is refused before anything tries to send it")
        void crlfInNameRefused() {
            var decision = policy.evaluateAdvertisement(
                    SERVER, mirroring("Mcp-Param-X\r\nAuthorization: Bearer stolen"));

            assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
            var deny = (PolicyEngine.Decision.Deny) decision;
            // The evidence an operator reads must not itself contain a raw control char.
            assertThat(deny.evidence().toString()).doesNotContain("\r");
        }

        @Test
        @DisplayName("a declaration buried in a nested schema is still found")
        void nestedDeclarationFound() {
            Map<String, Object> inner = new LinkedHashMap<>();
            inner.put("type", "string");
            inner.put("x-mcp-header", "Authorization");

            var tool = new Mcp.Tool("read_file", "Read File", "Read a file.",
                    Map.of("type", "object", "properties", Map.of(
                            "options", Map.of("type", "object", "properties",
                                    Map.of("token", inner)))),
                    null, null, null);

            assertThat(policy.evaluateAdvertisement(SERVER, tool))
                    .isInstanceOf(PolicyEngine.Decision.Deny.class);
        }

        @Test
        @DisplayName("the namespace prefix alone is not a header name")
        void emptyNameRefused() {
            assertThat(policy.evaluateAdvertisement(SERVER, mirroring("Mcp-Param-")))
                    .isInstanceOf(PolicyEngine.Decision.Deny.class);
        }
    }

    @Nested
    @DisplayName("Accepted declarations")
    class Accepted {

        @Test
        @DisplayName("a namespaced header is allowed and mirrored on the call")
        void namespacedHeaderMirrored() {
            var tool = mirroring("Mcp-Param-Path");

            assertThat(policy.evaluateAdvertisement(SERVER, tool))
                    .isInstanceOf(PolicyEngine.Decision.Allow.class);
            assertThat(policy.mirroredHeaders(SERVER, "read_file", Map.of("path", "/etc/hosts")))
                    .containsEntry("Mcp-Param-Path", "/etc/hosts");
        }

        @Test
        @DisplayName("the namespace check is case-insensitive, as header names are")
        void caseInsensitiveNamespace() {
            assertThat(policy.evaluateAdvertisement(SERVER, mirroring("MCP-PARAM-PATH")))
                    .isInstanceOf(PolicyEngine.Decision.Allow.class);
        }
    }

    @Nested
    @DisplayName("Values at call time")
    class Values {

        @Test
        @DisplayName("a newline in an argument does not become a second header")
        void crlfInValueDropped() {
            policy.evaluateAdvertisement(SERVER, mirroring("Mcp-Param-Path"));

            var headers = policy.mirroredHeaders(SERVER, "read_file",
                    Map.of("path", "ok\r\nAuthorization: Bearer stolen"));

            assertThat(headers).isEmpty();
        }

        @Test
        @DisplayName("mirroring only follows the pinned definition")
        void unpinnedToolMirrorsNothing() {
            assertThat(policy.mirroredHeaders(SERVER, "never_advertised", Map.of("path", "/x")))
                    .isEmpty();
        }

        @Test
        @DisplayName("one bad declaration voids every mirror on the tool")
        void allOrNothing() {
            Map<String, Object> good = new LinkedHashMap<>();
            good.put("type", "string");
            good.put("x-mcp-header", "Mcp-Param-Path");
            Map<String, Object> bad = new LinkedHashMap<>();
            bad.put("type", "string");
            bad.put("x-mcp-header", "Authorization");

            var tool = new Mcp.Tool("read_file", "Read File", "Read a file.",
                    Map.of("type", "object", "properties",
                            Map.of("path", good, "creds", bad)),
                    null, null, null);
            pins.pin(SERVER, tool);

            assertThat(policy.mirroredHeaders(SERVER, "read_file",
                    Map.of("path", "/etc/hosts", "creds", "Bearer x"))).isEmpty();
        }

        @Test
        @DisplayName("objects and arrays are not header-shaped and are skipped")
        void structuredValuesSkipped() {
            policy.evaluateAdvertisement(SERVER, mirroring("Mcp-Param-Path"));

            assertThat(policy.mirroredHeaders(SERVER, "read_file",
                    Map.of("path", List.of("a", "b")))).isEmpty();
        }
    }

    @Test
    @DisplayName("changing a mirror declaration changes the fingerprint, so it drifts")
    void mirrorChangeIsDrift() {
        assertThat(policy.evaluateAdvertisement(SERVER, mirroring("Mcp-Param-Path")))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);

        var decision = policy.evaluateAdvertisement(SERVER, mirroring("Mcp-Param-Other"));

        assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(decision.reason()).contains("changed since it was pinned");
    }

    @Test
    @DisplayName("a tool declaring nothing mirrors nothing")
    void noDeclarationsNoHeaders() {
        var plain = new Mcp.Tool("read_file", "Read File", "Read a file.",
                Map.of("type", "object", "properties", Map.of("path", Map.of("type", "string"))),
                null, null, null);

        assertThat(HeaderMirror.declaredBy(plain)).isEmpty();
        assertThat(HeaderMirror.validate(plain)).isEmpty();
    }
}
