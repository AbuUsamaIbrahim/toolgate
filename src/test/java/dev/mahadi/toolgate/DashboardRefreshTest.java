package dev.mahadi.toolgate;

import dev.mahadi.toolgate.api.DashboardRenderer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Auto-refresh is opt-in.
 *
 * <p>The sign-in page once inherited the dashboard's fifteen-second meta refresh, so the
 * browser discarded a half-typed operator token before it could be submitted. Fetching the
 * page and reading its markup — which is what every other test does — cannot see that;
 * only a browser sitting on the page long enough to be reloaded can. These assertions are
 * the cheap stand-in for that.
 */
class DashboardRefreshTest {

    @Test
    @DisplayName("a page does not refresh unless it asks to")
    void refreshIsOptIn() {
        assertThat(DashboardRenderer.page("Sign in", "<p>form</p>"))
                .doesNotContain("http-equiv=\"refresh\"");
    }

    @Test
    @DisplayName("a page that opts in carries the interval it asked for")
    void optingInEmitsTheInterval() {
        assertThat(DashboardRenderer.page("Dashboard", "<p>body</p>", 15))
                .contains("<meta http-equiv=\"refresh\" content=\"15\">");
    }

    @Test
    @DisplayName("a form page never reloads under the operator's fingers")
    void aFormPageDoesNotRefresh() {
        String signIn = DashboardRenderer.page("Sign in",
                "<form method=\"post\" action=\"/toolgate/login\">"
                        + "<input type=\"password\" name=\"token\"></form>");

        assertThat(signIn).contains("name=\"token\"");
        assertThat(signIn).doesNotContain("refresh");
    }
}
