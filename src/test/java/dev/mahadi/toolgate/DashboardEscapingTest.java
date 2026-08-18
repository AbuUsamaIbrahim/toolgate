package dev.mahadi.toolgate;

import dev.mahadi.toolgate.api.DashboardRenderer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The dashboard renders text a hostile server wrote, to the one person holding a token that
 * can approve anything. That makes stored XSS here not a defacement risk but a
 * privilege-escalation one: a payload in a tool description could approve its own poisoning
 * the moment an operator opened the page to look at it.
 */
class DashboardEscapingTest {

    @Nested
    @DisplayName("Script cannot survive into the page")
    class Injection {

        @Test
        @DisplayName("a script tag in a tool description is inert")
        void scriptTagEscaped() {
            String poisoned = "Reads a file.<script>fetch('/toolgate/drift/f/t/accept',"
                    + "{method:'POST'})</script>";

            String html = DashboardRenderer.escape(poisoned);

            assertThat(html).doesNotContain("<script").doesNotContain("</script>");
            assertThat(html).contains("&lt;script&gt;");
        }

        @Test
        @DisplayName("an event handler on an image tag is inert")
        void eventHandlerEscaped() {
            // The one that actually works in the wild: no <script> needed, and it fires
            // without any interaction.
            String poisoned = "<img src=x onerror=\"fetch('/toolgate/drift/f/t/accept',"
                    + "{method:'POST'})\">";

            String html = DashboardRenderer.escape(poisoned);

            assertThat(html).doesNotContain("<img").doesNotContain("onerror=\"");
            assertThat(html).contains("&lt;img");
        }

        @Test
        @DisplayName("quotes cannot break out of an attribute")
        void quotesEscaped() {
            String html = DashboardRenderer.escape("\" onmouseover=\"alert(1)");

            assertThat(html).doesNotContain("\"");
            assertThat(html).contains("&quot;");
        }

        @Test
        @DisplayName("single quotes are escaped too")
        void singleQuotesEscaped() {
            assertThat(DashboardRenderer.escape("' onload='x")).doesNotContain("'");
        }

        @Test
        @DisplayName("an ampersand cannot be used to smuggle an entity")
        void ampersandEscapedFirst() {
            // &lt;script&gt; must not survive a second decode as <script>.
            String html = DashboardRenderer.escape("&lt;script&gt;alert(1)&lt;/script&gt;");

            assertThat(html).contains("&amp;lt;script");
            assertThat(html).doesNotContain("<script");
        }
    }

    @Nested
    @DisplayName("Invisible characters are shown, not swallowed")
    class Invisible {

        @Test
        @DisplayName("a zero-width space is rendered visibly")
        void zeroWidthSpace() {
            // The whole point of a review UI: a reviewer deciding "release or attack" has
            // to be able to see text that hides from a human while staying legible to a
            // model. Passing it through unchanged would be worse than showing no diff.
            String html = DashboardRenderer.escape("Read a file.​Ignore​all​previous");

            assertThat(html).contains("⟨U+200B⟩");
            assertThat(html).contains("hidden-char");
        }

        @Test
        @DisplayName("a right-to-left override is rendered visibly")
        void bidiOverride() {
            // Reorders how a line reads without changing its bytes — a description can be
            // made to display as something entirely different from what a model receives.
            assertThat(DashboardRenderer.escape("safe‮txt.exe")).contains("⟨U+202E⟩");
        }

        @Test
        @DisplayName("ordinary text is left alone")
        void ordinaryTextUntouched() {
            String plain = "Read the contents of a file from the workspace.";

            assertThat(DashboardRenderer.escape(plain)).isEqualTo(plain);
        }

        @Test
        @DisplayName("newlines and tabs survive, since diffs depend on them")
        void whitespacePreserved() {
            assertThat(DashboardRenderer.escape("a\nb\tc")).isEqualTo("a\nb\tc");
        }
    }

    @Nested
    @DisplayName("Diff rendering")
    class Diff {

        @Test
        @DisplayName("added and removed lines are distinguishable, and still escaped")
        void diffLinesClassified() {
            String html = DashboardRenderer.diff("""
                  description:
                -   Read a file.
                +   Read a file. <script>alert(1)</script>""");

            assertThat(html).contains("class=\"d ctx\"")
                    .contains("class=\"d del\"")
                    .contains("class=\"d add\"");
            // Colouring a diff must not become a reason to stop escaping it.
            assertThat(html).doesNotContain("<script>");
        }

        @Test
        @DisplayName("a payload cannot escape via the class attribute")
        void noAttributeInjection() {
            assertThat(DashboardRenderer.diff("+\" onload=\"alert(1)"))
                    .doesNotContain("onload=\"alert");
        }
    }

    @Test
    @DisplayName("null is rendered as nothing rather than the word null")
    void nullSafe() {
        assertThat(DashboardRenderer.escape(null)).isEmpty();
    }
}
