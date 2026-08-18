package dev.mahadi.toolgate;

import dev.mahadi.toolgate.gateway.SurfaceRouter;
import dev.mahadi.toolgate.policy.ResourceGuard;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * URI templates are expanded by the client, so the gateway never sees the expansion happen.
 * The allowlist therefore has to be enforced against every URI a template <em>could</em>
 * produce, at the moment it is advertised — afterwards there is nothing left to decide.
 */
class TemplateContainmentTest {

    private static final Set<String> RULES = Set.of("file:///project/*");
    private static final Set<String> SCHEMES = Set.of("file", "git");

    @Nested
    @DisplayName("Containment")
    class Containment {

        @Test
        @DisplayName("a template whose fixed part is inside the allowlist is permitted")
        void containedTemplate() {
            assertThat(ResourceGuard.checkTemplate("file:///project/{name}", RULES, SCHEMES)
                    .allowed()).isTrue();
        }

        @Test
        @DisplayName("a template whose variable starts too early is refused")
        void escapingTemplate() {
            // file:///{path} expands to anything at all. The allowlist would be decorative.
            var verdict = ResourceGuard.checkTemplate("file:///{path}", RULES, SCHEMES);

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("chosen by the client");
        }

        @Test
        @DisplayName("a template rooted in a different subtree is refused")
        void wrongSubtree() {
            assertThat(ResourceGuard.checkTemplate("file:///etc/{name}", RULES, SCHEMES)
                    .allowed()).isFalse();
        }

        @Test
        @DisplayName("a template with no variables is judged as an ordinary resource")
        void noVariables() {
            assertThat(ResourceGuard.checkTemplate("file:///project/readme.md", RULES, SCHEMES)
                    .allowed()).isTrue();
            assertThat(ResourceGuard.checkTemplate("file:///etc/shadow", RULES, SCHEMES)
                    .allowed()).isFalse();
        }

        @Test
        @DisplayName("the scheme rule applies to templates too")
        void schemeStillApplies() {
            // An https template would have the client fetching expansions from the web,
            // which is the bypass the scheme rule exists for — now parameterised.
            assertThat(ResourceGuard.checkTemplate("https://evil.example.com/{path}",
                    Set.of("https://*"), SCHEMES).allowed()).isFalse();
        }

        @Test
        @DisplayName("a malformed template is refused rather than guessed at")
        void malformed() {
            assertThat(ResourceGuard.checkTemplate("", RULES, SCHEMES).allowed()).isFalse();
            assertThat(ResourceGuard.checkTemplate(null, RULES, SCHEMES).allowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("Containment is only half of it")
    class TraversalStillMatters {

        @Test
        @DisplayName("a contained template can still expand into a traversal, caught at read")
        void traversalCaughtAtRead() {
            // The template passes containment: its fixed part is inside the subtree.
            assertThat(ResourceGuard.checkTemplate("file:///project/{name}", RULES, SCHEMES)
                    .allowed()).isTrue();

            // But the client chooses `name`, and this is what it chose. Prefix containment
            // cannot see this coming; the read-time check is what catches it.
            assertThat(ResourceGuard.checkUri("file:///project/../../etc/shadow", SCHEMES)
                    .allowed()).isFalse();
        }
    }

    @Nested
    @DisplayName("Routing an expansion")
    class Routing {

        @Test
        @DisplayName("an expansion routes to the server that offered the template")
        void expansionRoutes() {
            var router = new SurfaceRouter();
            router.templateAdvertised("docs", "file:///project/{name}");

            assertThat(router.ownerOf("file:///project/readme.md")).contains("docs");
            assertThat(router.viaTemplate("file:///project/readme.md")).isTrue();
        }

        @Test
        @DisplayName("a URI outside every template and advertisement has no owner")
        void unroutable() {
            var router = new SurfaceRouter();
            router.templateAdvertised("docs", "file:///project/{name}");

            assertThat(router.ownerOf("file:///etc/shadow")).isEmpty();
        }

        @Test
        @DisplayName("an exact advertisement beats a template")
        void exactWins() {
            var router = new SurfaceRouter();
            router.templateAdvertised("templated", "file:///project/{name}");
            router.advertised("exact", "file:///project/readme.md");

            assertThat(router.ownerOf("file:///project/readme.md")).contains("exact");
            assertThat(router.viaTemplate("file:///project/readme.md")).isFalse();
        }

        @Test
        @DisplayName("the most specific template wins when two could serve a URI")
        void longestPrefixWins() {
            var router = new SurfaceRouter();
            router.templateAdvertised("general", "file:///project/{name}");
            router.templateAdvertised("specific", "file:///project/docs/{name}");

            assertThat(router.ownerOf("file:///project/docs/readme.md")).contains("specific");
            assertThat(router.ownerOf("file:///project/other.md")).contains("general");
        }

        @Test
        @DisplayName("a withdrawn template stops routing its expansions")
        void withdrawnTemplate() {
            var router = new SurfaceRouter();
            router.templateAdvertised("docs", "file:///project/{name}");

            router.retainOnlyTemplates("docs", Set.of());

            assertThat(router.ownerOf("file:///project/readme.md")).isEmpty();
        }
    }
}
