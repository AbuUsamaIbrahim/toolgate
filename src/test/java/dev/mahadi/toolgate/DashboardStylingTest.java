package dev.mahadi.toolgate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The console has to still look like a console.
 *
 * <h2>What this is guarding against, exactly</h2>
 * A nonce in {@code style-src} makes a browser ignore {@code 'unsafe-inline'} — that is the
 * content-security-policy specification working as designed, and it is not obvious until
 * you are looking at the consequence. When the live-update script arrived it added a nonce
 * for its own {@code <style>} block and left {@code 'unsafe-inline'} in the header beside
 * it. From that moment the browser refused the page's entire stylesheet, which carried no
 * nonce, and every one of the fifty-six {@code style="…"} attributes, which a nonce cannot
 * cover at all. The dashboard rendered as unstyled markup: Times New Roman on white, no
 * cards, the drift diff's red markers for invisible characters gone.
 *
 * <p>Every test passed and {@code curl} showed correct HTML, because the markup <em>was</em>
 * correct — it was the policy that refused to apply it. Only a browser could see it. These
 * assertions are the cheap stand-in: no inline styles anywhere, a nonce on every stylesheet,
 * and the header naming that same nonce and nothing weaker.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DashboardStylingTest {

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add("toolgate.auth.enabled", () -> "false");
        // Off so the pages are reachable without a session; the policy this asserts on is
        // rendered by the same code either way, and OperatorApiAuthTest owns the guarding.
        registry.add("toolgate.operator.enabled", () -> "false");
    }

    private static final Pattern STYLE_TAG = Pattern.compile("<style([^>]*)>");
    private static final Pattern NONCE_IN_CSP = Pattern.compile("style-src 'nonce-([^']+)'");

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private record Page(String html, String csp) {}

    private Page fetch(String uri) {
        var result = client().get().uri(uri).exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult();
        return new Page(result.getResponseBody(),
                result.getResponseHeaders().getFirst("Content-Security-Policy"));
    }

    @Test
    @DisplayName("the dashboard carries no inline style attribute")
    void dashboardHasNoInlineStyles() {
        // Not a matter of taste: under this policy an inline style attribute is markup the
        // browser will not apply, so one appearing here is a piece of the page silently
        // losing its formatting.
        assertThat(fetch("/toolgate").html()).doesNotContain("style=\"");
    }

    @Test
    @DisplayName("the sign-in page carries no inline style attribute")
    void signInHasNoInlineStyles() {
        assertThat(fetch("/toolgate/login").html()).doesNotContain("style=\"");
    }

    @Test
    @DisplayName("every stylesheet on the dashboard carries the nonce")
    void everyStyleTagIsNonced() {
        Page page = fetch("/toolgate");

        Matcher m = STYLE_TAG.matcher(page.html());
        int found = 0;
        while (m.find()) {
            found++;
            assertThat(m.group(1))
                    .as("a <style> tag without the nonce is a stylesheet the browser drops")
                    .contains("nonce=\"");
        }
        assertThat(found).as("the page should serve its stylesheet").isGreaterThan(0);
    }

    @Test
    @DisplayName("the policy names the nonce the page actually used")
    void headerNonceMatchesThePage() {
        Page page = fetch("/toolgate");

        Matcher m = NONCE_IN_CSP.matcher(page.csp());
        assertThat(m.find()).as("style-src should carry a nonce").isTrue();
        String nonce = m.group(1);

        // A mismatch between header and markup fails exactly the same way as no nonce at
        // all, and is harder to spot by reading either one alone.
        assertThat(page.html()).contains("<style nonce=\"" + nonce + "\">");
        assertThat(page.html()).contains("<script nonce=\"" + nonce + "\">");
        assertThat(page.csp()).contains("script-src 'nonce-" + nonce + "'");
    }

    @Test
    @DisplayName("'unsafe-inline' is gone rather than present and ignored")
    void policyDoesNotClaimUnsafeInline() {
        // Leaving it beside a nonce is not harmless: it reads as though inline styles work,
        // which is exactly the belief that produced an unstyled dashboard.
        assertThat(fetch("/toolgate").csp()).doesNotContain("'unsafe-inline'");
        assertThat(fetch("/toolgate/login").csp()).doesNotContain("'unsafe-inline'");
    }

    @Test
    @DisplayName("each response gets its own nonce")
    void nonceIsPerResponse() {
        String first = fetch("/toolgate").csp();
        String second = fetch("/toolgate").csp();

        // A fixed nonce is a nonce an attacker can copy into injected markup, at which point
        // the whole mechanism is decoration.
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("the page still ships the stylesheet it depends on")
    void stylesheetIsServed() {
        String html = fetch("/toolgate").html();

        // Guards the other direction: a page with a perfect policy and no CSS is just as
        // unstyled as one whose CSS is refused.
        assertThat(html).contains(".card").contains(".topbar").contains(".hidden-char");
    }
}
