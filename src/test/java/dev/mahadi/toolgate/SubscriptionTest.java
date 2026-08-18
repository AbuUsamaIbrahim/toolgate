package dev.mahadi.toolgate;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import dev.mahadi.toolgate.gateway.NotificationGate;
import dev.mahadi.toolgate.gateway.SubscriptionRegistry;
import dev.mahadi.toolgate.gateway.SurfaceRouter;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * One client subscription fans out to several upstream subscriptions, and the several
 * streams that come back have to look like the one the client asked for. The interesting
 * part is what happens when a server lies about which stream it is on.
 */
class SubscriptionTest {

    private SurfaceRouter router;
    private SubscriptionRegistry registry;
    private NotificationGate gate;
    private List<AuditLog.Entry> recorded;

    @BeforeEach
    void setUp() {
        router = new SurfaceRouter();
        registry = new SubscriptionRegistry();
        recorded = new ArrayList<>();
        gate = new NotificationGate(router, registry,
                new AuditLog(List.of((AuditSink) recorded::add)));
    }

    private static Mcp.Request onStream(String method, Object subscriptionId, String uri) {
        Map<String, Object> params = new java.util.LinkedHashMap<>();
        params.put("_meta", Map.of(NotificationGate.SUBSCRIPTION_ID, subscriptionId));
        if (uri != null) params.put("uri", uri);
        return new Mcp.Request("2.0", null, method, params, Map.of());
    }

    private SubscriptionRegistry.Filter filter(Set<String> uris, boolean tools) {
        return new SubscriptionRegistry.Filter(tools, false, false, uris);
    }

    @Nested
    @DisplayName("Cross-stream injection")
    class CrossStream {

        @Test
        @DisplayName("a server cannot deliver into a subscription it was never given")
        void cannotClaimAnotherSubscription() {
            // The client holds two subscriptions. Server A serves only the first.
            registry.open("1", filter(Set.of("file:///a.md"), false), Map.of("A", "tg-sub-1-A"));
            registry.open("2", filter(Set.of("file:///b.md"), false), Map.of("B", "tg-sub-2-B"));
            router.advertised("A", "file:///a.md");
            router.advertised("B", "file:///b.md");

            // A stamps its notification with B's upstream id, hoping to land in stream 2.
            var verdict = gate.evaluate("A", onStream(
                    "notifications/resources/updated", "tg-sub-2-B", "file:///b.md"));

            // Resolution is keyed on the sender as well as the id, so this resolves to
            // nothing at all rather than to somebody else's stream.
            assertThat(verdict).isInstanceOf(NotificationGate.Verdict.Drop.class);
            assertThat(recorded).anyMatch(e ->
                    e.reason().contains("never given"));
        }

        @Test
        @DisplayName("the id the client sees is its own, not the upstream's")
        void subscriptionIdIsRewritten() {
            registry.open("client-7", filter(Set.of("file:///a.md"), false),
                    Map.of("A", "tg-sub-7-A"));
            router.advertised("A", "file:///a.md");

            var verdict = gate.evaluate("A", onStream(
                    "notifications/resources/updated", "tg-sub-7-A", "file:///a.md"));

            // The upstream's id is meaningless to a client that never issued it.
            assertThat(verdict).isInstanceOf(NotificationGate.Verdict.Forward.class);
            assertThat(((NotificationGate.Verdict.Forward) verdict).clientSubscriptionId())
                    .isEqualTo("client-7");
        }
    }

    @Nested
    @DisplayName("The filter the spec says servers must respect")
    class FilterEnforcement {

        @Test
        @DisplayName("a type the client did not ask for is dropped")
        void unrequestedTypeDropped() {
            // Subscribed to resource updates only. The spec says the server MUST NOT send
            // other types — and a gateway that can check a MUST beats a spec that states one.
            registry.open("1", filter(Set.of("file:///a.md"), false), Map.of("A", "up-1"));

            var verdict = gate.evaluate("A",
                    onStream("notifications/tools/list_changed", "up-1", null));

            assertThat(verdict).isInstanceOf(NotificationGate.Verdict.Drop.class);
            assertThat(recorded).anyMatch(e -> e.reason().contains("did not subscribe"));
        }

        @Test
        @DisplayName("a URI the client did not subscribe to is dropped")
        void unsubscribedUriDropped() {
            registry.open("1", filter(Set.of("file:///watched.md"), false), Map.of("A", "up-1"));
            router.advertised("A", "file:///other.md");

            // Advertised, readable, and still not something this client asked to hear about.
            var verdict = gate.evaluate("A", onStream(
                    "notifications/resources/updated", "up-1", "file:///other.md"));

            assertThat(verdict).isInstanceOf(NotificationGate.Verdict.Drop.class);
        }

        @Test
        @DisplayName("a type the client did ask for is forwarded")
        void requestedTypeForwarded() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1"));

            assertThat(gate.evaluate("A", onStream("notifications/tools/list_changed", "up-1", null)))
                    .isInstanceOf(NotificationGate.Verdict.Forward.class);
        }
    }

    @Nested
    @DisplayName("Lifecycle")
    class Lifecycle {

        @Test
        @DisplayName("cancelling returns the upstream subscriptions that need tearing down")
        void cancelReturnsUpstreams() {
            registry.open("1", filter(Set.of("file:///a.md"), false),
                    Map.of("A", "up-1-A", "B", "up-1-B"));

            var toTearDown = registry.cancel("1");

            // Leaking these would keep every upstream streaming for the life of the process.
            assertThat(toTearDown).containsEntry("A", "up-1-A").containsEntry("B", "up-1-B");
            assertThat(registry.byClientId("1")).isEmpty();
        }

        @Test
        @DisplayName("notifications stop being deliverable once cancelled")
        void cancelledStreamRejects() {
            registry.open("1", filter(Set.of("file:///a.md"), false), Map.of("A", "up-1"));
            router.advertised("A", "file:///a.md");
            registry.cancel("1");

            assertThat(gate.evaluate("A", onStream(
                    "notifications/resources/updated", "up-1", "file:///a.md")))
                    .isInstanceOf(NotificationGate.Verdict.Drop.class);
        }

        @Test
        @DisplayName("one upstream closing cleanly does not end the client's subscription")
        void oneUpstreamClosing() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1-A", "B", "up-1-B"));

            // A subscription spanning five servers should not end because one of them
            // shut down tidily.
            assertThat(registry.upstreamClosed("1", "A")).isFalse();
            assertThat(registry.byClientId("1")).isPresent();

            // B is still serving it.
            assertThat(gate.evaluate("B", onStream("notifications/tools/list_changed", "up-1-B", null)))
                    .isInstanceOf(NotificationGate.Verdict.Forward.class);
            // A is not.
            assertThat(gate.evaluate("A", onStream("notifications/tools/list_changed", "up-1-A", null)))
                    .isInstanceOf(NotificationGate.Verdict.Drop.class);
        }

        @Test
        @DisplayName("the last upstream closing ends the client's subscription")
        void lastUpstreamClosing() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1-A", "B", "up-1-B"));

            assertThat(registry.upstreamClosed("1", "A")).isFalse();
            // Only now is there nobody left to serve it, so the client gets the empty
            // response that distinguishes a clean end from a dropped transport.
            assertThat(registry.upstreamClosed("1", "B")).isTrue();
            assertThat(registry.byClientId("1")).isEmpty();
        }

        @Test
        @DisplayName("closing an upstream twice does not end the subscription early")
        void closingTwiceIsSafe() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1-A", "B", "up-1-B"));

            // The subscribe callback fires on both completion and error, so a duplicate is
            // entirely possible and must not be mistaken for the last upstream leaving.
            assertThat(registry.upstreamClosed("1", "A")).isFalse();
            assertThat(registry.upstreamClosed("1", "A")).isFalse();
            assertThat(registry.byClientId("1")).isPresent();
        }

        @Test
        @DisplayName("closing an upstream on a subscription that never existed is harmless")
        void closingUnknownSubscription() {
            assertThat(registry.upstreamClosed("nope", "A")).isFalse();
        }

        @Test
        @DisplayName("one upstream dying does not silence the others")
        void upstreamDeathIsContained() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1-A", "B", "up-1-B"));

            registry.upstreamGone("A");

            // Tearing the client's subscription down because one server exited would let a
            // single crashy upstream silence every other.
            assertThat(registry.byClientId("1")).isPresent();
            assertThat(gate.evaluate("B", onStream("notifications/tools/list_changed", "up-1-B", null)))
                    .isInstanceOf(NotificationGate.Verdict.Forward.class);
            assertThat(gate.evaluate("A", onStream("notifications/tools/list_changed", "up-1-A", null)))
                    .isInstanceOf(NotificationGate.Verdict.Drop.class);
        }

        @Test
        @DisplayName("a notification outside any subscription falls back to the unsolicited rules")
        void unsolicitedStillGoverned() {
            router.advertised("A", "file:///a.md");

            // No _meta, so no subscription. list_changed is allowed unsolicited; an update
            // for a resource nobody advertised is not.
            var plain = new Mcp.Request("2.0", null, "notifications/tools/list_changed",
                    Map.of(), Map.of());
            assertThat(gate.evaluate("A", plain))
                    .isInstanceOf(NotificationGate.Verdict.Forward.class);

            var bogus = new Mcp.Request("2.0", null, "notifications/resources/updated",
                    Map.of("uri", "file:///etc/shadow"), Map.of());
            assertThat(gate.evaluate("A", bogus))
                    .isInstanceOf(NotificationGate.Verdict.Drop.class);
        }
    }

    @Nested
    @DisplayName("Ordinary protocol traffic")
    class Housekeeping {

        @Test
        @DisplayName("an upstream acknowledgement is consumed, not shown to the client")
        void ackConsumedSilently() {
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1"));

            var verdict = gate.evaluate("A",
                    onStream("notifications/subscriptions/acknowledged", "up-1", null));

            // The client holds one subscription, not one per server, and already has the
            // gateway's own acknowledgement describing the whole thing.
            assertThat(verdict).isInstanceOf(NotificationGate.Verdict.Drop.class);
        }

        @Test
        @DisplayName("consuming an acknowledgement is not audited as an anomaly")
        void ackNotAuditedAsAttack() {
            // A live run produced one alarming audit line per upstream per subscription,
            // for entirely routine traffic. Auditing that is how an operator learns to
            // scroll past the entries that matter.
            registry.open("1", filter(Set.of(), true), Map.of("A", "up-1"));
            gate.evaluate("A", onStream("notifications/subscriptions/acknowledged", "up-1", null));

            assertThat(recorded).noneMatch(e -> e.outcome() == AuditLog.Outcome.DENIED);
        }

        @Test
        @DisplayName("an acknowledgement from an upstream with no subscription is still quiet")
        void unknownAckAlsoQuiet() {
            gate.evaluate("A", onStream("notifications/subscriptions/acknowledged", "up-1", null));

            assertThat(recorded).noneMatch(e -> e.outcome() == AuditLog.Outcome.DENIED);
        }
    }

    @Nested
    @DisplayName("Filter shape")
    class FilterShape {

        @Test
        @DisplayName("an empty filter subscribes to nothing")
        void emptyFilter() {
            assertThat(new SubscriptionRegistry.Filter(false, false, false, Set.of())
                    .wantsNothing()).isTrue();
        }

        @Test
        @DisplayName("admits() answers exactly the four defined types and nothing else")
        void admitsKnownTypesOnly() {
            var f = new SubscriptionRegistry.Filter(true, false, false, Set.of("file:///a"));

            assertThat(f.admits("notifications/tools/list_changed", null)).isTrue();
            assertThat(f.admits("notifications/prompts/list_changed", null)).isFalse();
            assertThat(f.admits("notifications/resources/updated", "file:///a")).isTrue();
            assertThat(f.admits("notifications/resources/updated", "file:///b")).isFalse();
            assertThat(f.admits("notifications/something/invented", null)).isFalse();
        }
    }
}
