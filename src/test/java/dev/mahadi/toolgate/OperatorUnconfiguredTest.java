package dev.mahadi.toolgate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Enabled but unconfigured must fail closed.
 *
 * <p>The tempting behaviour is to let requests through when no token is set, on the
 * grounds that the operator "hasn't set it up yet". That leaves the most powerful API in
 * the system open because someone forgot a line of configuration — which is exactly the
 * kind of default that turns up in an incident report.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OperatorUnconfiguredTest {

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry registry) {
        registry.add("toolgate.auth.enabled", () -> "false");
        registry.add("toolgate.operator.enabled", () -> "true");
        registry.add("toolgate.operator.token-sha256", () -> "");   // deliberately unset
    }

    @Test
    @DisplayName("no configured operator token means no operator access, not open access")
    void failsClosed() {
        WebTestClient.bindToServer().baseUrl("http://localhost:" + port)
                .build()
                .get().uri("/toolgate/audit")
                .exchange()
                .expectStatus().isUnauthorized();
    }
}
