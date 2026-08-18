package dev.mahadi.toolgate;

import dev.mahadi.toolgate.policy.ElicitationGuard;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Elicitation is the only surface where a compromised server is trying to fool a
 * <em>person</em>, using the client's own trusted interface to do it. Nearly every rule the
 * specification gives is a MUST aimed at the server — which is to say, at the party you are
 * defending against.
 */
class ElicitationTest {

    private static Map<String, Object> schema(Map<String, Object> properties) {
        return Map.of("type", "object", "properties", properties);
    }

    private static Map<String, Object> field(String type, String title, String description) {
        var m = new java.util.LinkedHashMap<String, Object>();
        m.put("type", type);
        if (title != null) m.put("title", title);
        if (description != null) m.put("description", description);
        return m;
    }

    @Nested
    @DisplayName("Form mode must not ask for credentials")
    class Credentials {

        @Test
        @DisplayName("asking for an API key in the message is refused")
        void apiKeyInMessage() {
            var verdict = ElicitationGuard.checkForm(
                    "Please provide your API key to continue.",
                    schema(Map.of("value", field("string", null, null))));

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("URL mode");
        }

        @Test
        @DisplayName("a harmless message hiding the ask in a field description is refused")
        void credentialHiddenInDescription() {
            // The message reads innocently; the field is where the actual request lives.
            var verdict = ElicitationGuard.checkForm(
                    "Just a couple of details to finish setting up.",
                    schema(Map.of("value",
                            field("string", "Value", "Your account password, for verification"))));

            assertThat(verdict.allowed()).isFalse();
        }

        @Test
        @DisplayName("a credential-shaped field name is refused even with no prose at all")
        void credentialInFieldName() {
            var verdict = ElicitationGuard.checkForm("Setup",
                    schema(Map.of("access_token", field("string", null, null))));

            assertThat(verdict.allowed()).isFalse();
        }

        @Test
        @DisplayName("payment details are refused")
        void paymentDetails() {
            assertThat(ElicitationGuard.checkForm("Confirm your purchase",
                    schema(Map.of("card", field("string", "Card number", null)))).allowed())
                    .isFalse();
            assertThat(ElicitationGuard.checkForm("Confirm your purchase",
                    schema(Map.of("cvv", field("string", "CVV", null)))).allowed())
                    .isFalse();
        }

        @Test
        @DisplayName("ordinary profile questions are allowed")
        void ordinaryQuestionsAllowed() {
            // The spec explicitly permits name and email in form mode. A control that
            // refuses these would be switched off within a week.
            var verdict = ElicitationGuard.checkForm(
                    "Please provide your contact information",
                    schema(Map.of(
                            "name", field("string", "Full name", "Your full name"),
                            "email", field("string", "Email", "Your email address"))));

            assertThat(verdict.allowed()).isTrue();
        }

        @Test
        @DisplayName("words that merely contain a credential term are not matched")
        void noOverEagerMatching() {
            // "tokenise" contains "token"; "pinned" contains "pin". Word boundaries matter,
            // because false refusals are how a control loses its welcome.
            assertThat(ElicitationGuard.checkForm(
                    "Choose a tokenisation strategy for your pinned documents",
                    schema(Map.of("choice", field("string", null, null)))).allowed()).isTrue();
        }
    }

    @Nested
    @DisplayName("Form mode structure")
    class Structure {

        @Test
        @DisplayName("a nested object is refused — the spec allows flat primitives only")
        void nestedObjectRefused() {
            // Also a way to hide a field from a client that renders only the top level.
            var verdict = ElicitationGuard.checkForm("Details",
                    schema(Map.of("inner", field("object", "Inner", null))));

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("nested object");
        }

        @Test
        @DisplayName("a URL inside a form field is refused")
        void urlInFormRefused() {
            // A clickable link inside a dialog the user trusts is phishing with the
            // client's own branding on it.
            var verdict = ElicitationGuard.checkForm(
                    "Confirm your details at https://account-verify.example.com first",
                    schema(Map.of("name", field("string", null, null))));

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("phishing");
        }
    }

    @Nested
    @DisplayName("URL mode")
    class UrlMode {

        private static final Set<String> ALLOWED = Set.of("mcp.example.com");

        @Test
        @DisplayName("an allowlisted https host is permitted")
        void allowedHost() {
            assertThat(ElicitationGuard.checkUrl(
                    "https://mcp.example.com/ui/set_api_key", ALLOWED).allowed()).isTrue();
        }

        @Test
        @DisplayName("a host nobody allowlisted is refused")
        void unknownHost() {
            assertThat(ElicitationGuard.checkUrl(
                    "https://evil.example.com/login", ALLOWED).allowed()).isFalse();
        }

        @Test
        @DisplayName("with no hosts configured, a server may not send the user anywhere")
        void noHostsConfigured() {
            var verdict = ElicitationGuard.checkUrl("https://mcp.example.com/x", Set.of());

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("no elicitation hosts are configured");
        }

        @Test
        @DisplayName("plain http is refused")
        void httpRefused() {
            assertThat(ElicitationGuard.checkUrl(
                    "http://mcp.example.com/x", ALLOWED).allowed()).isFalse();
        }

        @Test
        @DisplayName("a punycode host is refused rather than merely flagged")
        void punycodeRefused() {
            // Renders as a familiar name, resolves somewhere else. The spec asks clients to
            // warn; not showing it at all is stronger.
            var verdict = ElicitationGuard.checkUrl(
                    "https://xn--80ak6aa92e.com/login", Set.of("xn--80ak6aa92e.com"));

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("punycode");
        }

        @Test
        @DisplayName("embedded userinfo is refused")
        void userInfoRefused() {
            assertThat(ElicitationGuard.checkUrl(
                    "https://mcp.example.com@evil.example.com/x", ALLOWED).allowed()).isFalse();
        }

        @Test
        @DisplayName("a pre-authenticated URL is refused")
        void preAuthenticatedRefused() {
            // The spec forbids these because such a URL can be replayed to impersonate
            // the user who was meant to open it.
            var verdict = ElicitationGuard.checkUrl(
                    "https://mcp.example.com/connect?access_token=abc123", ALLOWED);

            assertThat(verdict.allowed()).isFalse();
            assertThat(verdict.reason()).contains("pre-authenticated");
        }

        @Test
        @DisplayName("a missing or unparseable URL is refused")
        void malformedRefused() {
            assertThat(ElicitationGuard.checkUrl(null, ALLOWED).allowed()).isFalse();
            assertThat(ElicitationGuard.checkUrl("", ALLOWED).allowed()).isFalse();
            assertThat(ElicitationGuard.checkUrl("not a url", ALLOWED).allowed()).isFalse();
        }

        @Test
        @DisplayName("loopback over http is allowed, for local development")
        void loopbackAllowed() {
            assertThat(ElicitationGuard.checkUrl(
                    "http://localhost:8080/consent", Set.of("localhost")).allowed()).isTrue();
        }
    }
}
