package dev.mahadi.toolgate;

import dev.mahadi.toolgate.policy.ResourceGuard;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Resources can do two things tools cannot: choose who fetches the content, and tell the
 * client how much of the model's context the content deserves. Both are decided by the
 * least trusted party in the system.
 */
class ResourceGuardTest {

    private static final Set<String> DEFAULT_SCHEMES = Set.of("file", "git");

    private static Mcp.Resource resource(String uri, Map<String, Object> annotations) {
        return new Mcp.Resource(uri, "thing", "Thing", "a thing",
                "text/plain", null, annotations, null);
    }

    @Nested
    @DisplayName("URI schemes")
    class Uris {

        @Test
        @DisplayName("an https resource is refused, because the client would fetch it directly")
        void httpsRefused() {
            var verdict = ResourceGuard.checkUri("https://evil.example.com/payload", DEFAULT_SCHEMES);

            assertThat(verdict.allowed()).isFalse();
            // The reason has to explain itself: refusing a perfectly valid URL looks like a
            // bug unless the operator is told the content would bypass the gateway.
            assertThat(verdict.reason()).contains("never passes through this gateway");
        }

        @Test
        @DisplayName("plain http is refused for the same reason")
        void httpRefused() {
            assertThat(ResourceGuard.checkUri("http://internal.local/admin", DEFAULT_SCHEMES)
                    .allowed()).isFalse();
        }

        @Test
        @DisplayName("permitted schemes pass")
        void allowedSchemesPass() {
            assertThat(ResourceGuard.checkUri("file:///project/src/main.rs", DEFAULT_SCHEMES)
                    .allowed()).isTrue();
            assertThat(ResourceGuard.checkUri("git://repo/HEAD", DEFAULT_SCHEMES)
                    .allowed()).isTrue();
        }

        @Test
        @DisplayName("scheme matching is case-insensitive, as URIs are")
        void schemeCaseInsensitive() {
            assertThat(ResourceGuard.checkUri("FILE:///x", DEFAULT_SCHEMES).allowed()).isTrue();
            assertThat(ResourceGuard.checkUri("HTTPS://x/y", DEFAULT_SCHEMES).allowed()).isFalse();
        }

        @Test
        @DisplayName("a file URI that climbs out of its tree is refused")
        void traversalRefused() {
            // The spec puts this obligation on servers, which is precisely why a
            // client-side gateway does not rely on it.
            assertThat(ResourceGuard.checkUri("file:///project/../../etc/shadow", DEFAULT_SCHEMES)
                    .allowed()).isFalse();
            assertThat(ResourceGuard.checkUri("file:///project/%2e%2e/%2e%2e/etc/shadow",
                    DEFAULT_SCHEMES).allowed()).isFalse();
        }

        @Test
        @DisplayName("a URI with no scheme, or none at all, is refused")
        void malformedRefused() {
            assertThat(ResourceGuard.checkUri("just-a-string", DEFAULT_SCHEMES).allowed()).isFalse();
            assertThat(ResourceGuard.checkUri("", DEFAULT_SCHEMES).allowed()).isFalse();
            assertThat(ResourceGuard.checkUri(null, DEFAULT_SCHEMES).allowed()).isFalse();
        }

        @Test
        @DisplayName("an operator can opt into https deliberately")
        void httpsAllowedWhenConfigured() {
            assertThat(ResourceGuard.checkUri("https://docs.internal/handbook",
                    Set.of("file", "https")).allowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("Annotation clamping")
    class Annotations {

        @Test
        @DisplayName("an unreviewed resource cannot declare itself required")
        void priorityClamped() {
            // priority 1.0 is defined by the spec as "effectively required" — a hostile
            // server demanding the model's attention for its payload.
            var hostile = resource("file:///notes.md",
                    Map.of("audience", List.of("assistant"), "priority", 1.0));

            var clamped = ResourceGuard.clampAnnotations(hostile, false);

            assertThat(clamped.annotations().get("priority"))
                    .isEqualTo(ResourceGuard.UNREVIEWED_PRIORITY_CEILING);
            // The hint survives; only the ability to demand is removed.
            assertThat(clamped.annotations().get("audience")).isEqualTo(List.of("assistant"));
        }

        @Test
        @DisplayName("a modest priority is left alone")
        void modestPriorityUntouched() {
            var ordinary = resource("file:///notes.md", Map.of("priority", 0.3));

            // Same instance back: nothing needed changing, so nothing was copied.
            assertThat(ResourceGuard.clampAnnotations(ordinary, false)).isSameAs(ordinary);
        }

        @Test
        @DisplayName("a reviewed resource keeps the priority a human approved")
        void reviewedNotClamped() {
            var reviewed = resource("file:///runbook.md", Map.of("priority", 1.0));

            assertThat(ResourceGuard.clampAnnotations(reviewed, true).annotations()
                    .get("priority")).isEqualTo(1.0);
        }

        @Test
        @DisplayName("resources without annotations pass through untouched")
        void noAnnotations() {
            var plain = resource("file:///x", null);
            assertThat(ResourceGuard.clampAnnotations(plain, false)).isSameAs(plain);
        }

        @Test
        @DisplayName("a non-numeric priority is not coerced, only ignored")
        void nonNumericPriority() {
            Map<String, Object> odd = new LinkedHashMap<>();
            odd.put("priority", "critical");
            var r = resource("file:///x", odd);

            // Clamping a string to a number would invent data. The scanner and the
            // fingerprint still see it; this control simply has no opinion.
            assertThat(ResourceGuard.clampAnnotations(r, false)).isSameAs(r);
        }

        @Test
        @DisplayName("the clamp is reported, so the audit says what was changed")
        void clampIsAudited() {
            var hostile = resource("file:///x", Map.of("priority", 1.0));
            var clamped = ResourceGuard.clampAnnotations(hostile, false);

            assertThat(ResourceGuard.clampEvidence(hostile, clamped))
                    .anyMatch(e -> e.contains("1.0") && e.contains("0.5"));
        }
    }
}
