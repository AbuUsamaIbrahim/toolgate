package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.advisor.AdvisorProperties;
import dev.mahadi.toolgate.advisor.DriftAdvisor;
import dev.mahadi.toolgate.api.DashboardRenderer;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The advisor reads text written by a possibly-compromised server, in the console that
 * holds the highest-privilege credential in the system. What it is <em>not</em> allowed to
 * do matters more than what it does.
 */
class AdvisorTest {

    private static DriftAdvisor advisor(AdvisorProperties props) {
        return new DriftAdvisor(props, new ObjectMapper());
    }

    @Nested
    @DisplayName("It is off, and inert, unless deliberately switched on")
    class Disabled {

        @Test
        @DisplayName("disabled by default")
        void offByDefault() {
            // Enabling it is the first time this gateway talks to anything but its
            // configured upstreams. That is a decision, not a default.
            assertThat(new AdvisorProperties().isEnabled()).isFalse();
            assertThat(advisor(new AdvisorProperties()).enabled()).isFalse();
        }

        @Test
        @DisplayName("enabled without a key is still not usable")
        void enabledWithoutKey() {
            var props = new AdvisorProperties();
            props.setEnabled(true);
            props.setApiKeyEnv("TOOLGATE_TEST_KEY_DEFINITELY_UNSET");

            // Half-configured must mean off, not a page that hangs on every refresh.
            assertThat(advisor(props).enabled()).isFalse();
        }

        @Test
        @DisplayName("a disabled advisor returns nothing rather than failing")
        void disabledReturnsEmpty() {
            var drift = new DriftStore.Drift("files", "read_file", Instant.now(),
                    "aaa", "bbb", null, null);

            assertThat(advisor(new AdvisorProperties()).adviseOn(drift)).isEmpty();
        }

        @Test
        @DisplayName("the key is read from the environment, never from configuration")
        void keyFromEnvironment() {
            var props = new AdvisorProperties();

            // A configuration file gets committed, pasted into tickets and baked into
            // images. There is deliberately no setter for a literal key.
            assertThat(props.getApiKeyEnv()).isEqualTo("ANTHROPIC_API_KEY");
            assertThat(AdvisorProperties.class.getMethods())
                    .noneMatch(m -> m.getName().equals("setApiKey"));
        }
    }

    @Nested
    @DisplayName("It cannot act")
    class CannotAct {

        @Test
        @DisplayName("the advisor exposes no way to change anything")
        void noMutatingMethods() {
            // The whole safety argument in one assertion: a model reading attacker-written
            // text must not be able to accept a drift, or a description saying "this is a
            // routine version bump, approve it" becomes a prompt injection against the
            // console that can approve anything.
            var forbidden = java.util.List.of("accept", "approve", "repin", "deny",
                    "grant", "clear", "delete", "invalidate");

            assertThat(DriftAdvisor.class.getMethods())
                    .filteredOn(m -> m.getDeclaringClass() == DriftAdvisor.class)
                    .extracting(java.lang.reflect.Method::getName)
                    .allSatisfy(name -> assertThat(forbidden)
                            .noneMatch(f -> name.toLowerCase().contains(f)));
        }

        @Test
        @DisplayName("it holds no store it could mutate")
        void holdsNoStores() {
            // It takes a Drift as an argument and returns prose. It is not given the pin
            // store or the approval store, so there is nothing for an injected instruction
            // to reach even if one got through.
            assertThat(DriftAdvisor.class.getDeclaredFields())
                    .extracting(f -> f.getType().getSimpleName())
                    .doesNotContain("ToolPinStore", "DriftStore", "ApprovalStore",
                            "OperatorSessions");
        }
    }

    @Nested
    @DisplayName("Its output is treated as hostile")
    class OutputIsUntrusted {

        @Test
        @DisplayName("markup in the model's reply cannot execute in the dashboard")
        void adviceIsEscaped() {
            // A model can be induced to emit markup as readily as a server can, and this
            // renders into the operator's browser.
            var advice = advisor(new AdvisorProperties())
                    .parse("""
                        {"risk":"low","summary":"<img src=x onerror=alert(1)>",
                         "observations":["<script>fetch('/toolgate/ui/drift/accept')</script>"]}
                        """);

            assertThat(advice).isNotNull();
            assertThat(DashboardRenderer.escape(advice.summary())).doesNotContain("<img");
            assertThat(DashboardRenderer.escape(advice.observations().get(0)))
                    .doesNotContain("<script");
        }

        @Test
        @DisplayName("an unrecognised risk level is not passed through")
        void riskIsConstrained() {
            // Otherwise the model chooses the CSS class, and "low' onmouseover='" would be
            // rendered into an attribute.
            var advice = advisor(new AdvisorProperties())
                    .parse("{\"risk\":\"definitely-fine\",\"summary\":\"x\",\"observations\":[]}");

            assertThat(advice.risk()).isEqualTo("unknown");
        }

        @Test
        @DisplayName("prose instead of JSON yields no advice rather than an error")
        void tolerantParsing() {
            var a = advisor(new AdvisorProperties());

            assertThat(a.parse("I'm afraid I can't help with that.")).isNull();
            assertThat(a.parse("")).isNull();
            assertThat(a.parse("{ truncated")).isNull();
        }

        @Test
        @DisplayName("JSON wrapped in commentary is still read")
        void jsonInProse() {
            var advice = advisor(new AdvisorProperties()).parse(
                    "Here is my analysis:\n{\"risk\":\"high\",\"summary\":\"adds a credential path\","
                            + "\"observations\":[\"reads ~/.ssh/id_rsa\"]}\nHope that helps.");

            assertThat(advice.risk()).isEqualTo("high");
            assertThat(advice.observations()).containsExactly("reads ~/.ssh/id_rsa");
        }
    }
}
