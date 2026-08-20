package dev.mahadi.toolgate;

import dev.mahadi.toolgate.auth.OperatorProperties;
import dev.mahadi.toolgate.demo.DemoProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mode the public demonstration runs in.
 *
 * <h2>Read-only has to mean the endpoint, not the page</h2>
 * The console already renders without buttons when there is no session, and it would have
 * been easy to call that read-only and stop. It is not: hiding a form is a statement about
 * one page, and the accept and approve routes take a POST from anything that can reach
 * them. What makes this safe to expose is that unsafe methods are refused in the filter,
 * before authentication is considered — so the answer to "what could someone do with the
 * operator token if it leaked from this deployment" is nothing.
 *
 * <p>These assertions matter more than most in this project, because they are the ones
 * standing between a demonstration and a gateway that anyone on the internet can tell to
 * trust a poisoned tool definition.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicReadOnlyConsoleTest {

    private static final String OPERATOR_TOKEN = "operator-secret";

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add("toolgate.auth.enabled", () -> "false");
        registry.add("toolgate.operator.enabled", () -> "true");
        registry.add("toolgate.operator.public-read-only", () -> "true");
        // Configured, and deliberately so: the point is that even a correct credential
        // cannot write here.
        registry.add("toolgate.operator.token-sha256", () -> sha256(OPERATOR_TOKEN));
        registry.add("toolgate.operator.loopback-only", () -> "true");
    }

    private static String sha256(String s) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of()
                    .formatHex(md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private WebTestClient client() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    @Test
    @DisplayName("the console is readable without any credential")
    void consoleIsPublic() {
        client().get().uri("/toolgate").exchange().expectStatus().isOk();
        client().get().uri("/toolgate/audit").exchange().expectStatus().isOk();
        client().get().uri("/toolgate/drift").exchange().expectStatus().isOk();
        client().get().uri("/toolgate/pins").exchange().expectStatus().isOk();
    }

    @Test
    @DisplayName("accepting a drifted definition is refused without a credential")
    void acceptRefused() {
        client().post().uri("/toolgate/drift/demo/read_file/accept")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    @DisplayName("accepting is refused with the correct operator token too")
    void acceptRefusedEvenWithTheToken() {
        // The claim this whole mode rests on. If the token still worked, publishing the
        // console would mean the deployment is one leaked credential away from an attacker
        // re-pinning a poisoned definition — and the credential is in the deployer's shell
        // history, their CI, and wherever they pasted it.
        client().post().uri("/toolgate/drift/demo/read_file/accept")
                .header("Authorization", "Bearer " + OPERATOR_TOKEN)
                .exchange().expectStatus().isForbidden();

        client().post().uri("/toolgate/approvals/any-id/approve")
                .header("Authorization", "Bearer " + OPERATOR_TOKEN)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    @DisplayName("no session can be created, so no page can offer a button")
    void signInIsRefused() {
        // Signing in is itself a POST. A login that still worked would issue a session
        // whose every button leads to a 403 — a console that lies about what it can do.
        client().post().uri("/toolgate/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("token=" + OPERATOR_TOKEN)
                .exchange().expectStatus().isForbidden();
    }

    @Test
    @DisplayName("the dashboard's own form routes are refused")
    void uiRoutesRefused() {
        client().post().uri("/toolgate/ui/drift/accept")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("server=demo&tool=read_file")
                .exchange().expectStatus().isForbidden();

        client().post().uri("/toolgate/ui/scanner/toggle")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("id=anything")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    @DisplayName("a method nobody thought about is refused rather than allowed")
    void unknownMethodsRefused() {
        // The allowlist is the point: a route added tomorrow, or a method this service does
        // not handle today, lands on the closed side without anyone remembering to add it.
        client().delete().uri("/toolgate/pins/demo/read_file")
                .exchange().expectStatus().isForbidden();
        client().put().uri("/toolgate/anything").exchange().expectStatus().isForbidden();
    }

    @Test
    @DisplayName("the page says what it is, and offers nothing it would refuse")
    void pageDeclaresItself() {
        String html = client().get().uri("/toolgate").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).returnResult().getResponseBody();

        assertThat(html).contains("public demonstration");
        // No form pointing at a route that would 403. A visitor should not learn what this
        // console can do by pressing something and being refused.
        assertThat(html).doesNotContain("action=\"/toolgate/ui/");
        assertThat(html).doesNotContain("/toolgate/logout");
    }

    @Test
    @DisplayName("both demonstration switches are off unless set")
    void defaultsAreOff() {
        // Read from the objects rather than the file, so a default changed in code is
        // caught as well as one changed in YAML.
        assertThat(new OperatorProperties().isPublicReadOnly()).isFalse();
        assertThat(new DemoProperties().isEnabled()).isFalse();
    }
}
