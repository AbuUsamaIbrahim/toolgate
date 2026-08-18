package dev.mahadi.toolgate;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import dev.mahadi.toolgate.gateway.NotificationGate;
import dev.mahadi.toolgate.gateway.SurfaceRouter;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A notification is the only message where the upstream chooses both the timing and the
 * frequency. These are the two things that makes possible.
 */
class NotificationGateTest {

    private SurfaceRouter router;
    private dev.mahadi.toolgate.gateway.SubscriptionRegistry subscriptions;
    private NotificationGate gate;
    private List<AuditLog.Entry> recorded;

    @BeforeEach
    void setUp() {
        router = new SurfaceRouter();
        subscriptions = new dev.mahadi.toolgate.gateway.SubscriptionRegistry();
        recorded = new ArrayList<>();
        gate = new NotificationGate(router, subscriptions,
                new AuditLog(List.of((AuditSink) recorded::add)));
    }

    private static Mcp.Request notification(String method, Map<String, Object> params) {
        return new Mcp.Request("2.0", null, method, params, Map.of());
    }

    private static Mcp.Request updated(String uri) {
        return notification("notifications/resources/updated", Map.of("uri", uri));
    }

    @Test
    @DisplayName("an update for an advertised resource is passed on")
    void advertisedUpdatePasses() {
        router.advertised("docs", "file:///project/readme.md");

        assertThat(gate.permit("docs", updated("file:///project/readme.md"))).isTrue();
    }

    @Test
    @DisplayName("an update for a resource nobody advertised is dropped")
    void unadvertisedUpdateDropped() {
        // Defined to arrive on a subscription stream. One for a URI never offered is
        // either confused or probing, and following it invites a read of something that
        // was never on any list.
        assertThat(gate.permit("docs", updated("file:///etc/shadow"))).isFalse();
        assertThat(recorded).anyMatch(e -> e.reason().contains("never advertised"));
    }

    @Test
    @DisplayName("one upstream cannot announce that another's resource changed")
    void crossServerUpdateDropped() {
        router.advertised("docs", "file:///project/readme.md");

        // There is no legitimate reason for this, and honouring it would let a hostile
        // server steer the client's reads towards a peer it does not control.
        assertThat(gate.permit("other", updated("file:///project/readme.md"))).isFalse();
        assertThat(recorded).anyMatch(e -> e.reason().contains("different upstream"));
    }

    @Test
    @DisplayName("an update for a template expansion is permitted")
    void templateExpansionPasses() {
        router.templateAdvertised("docs", "file:///project/{name}");

        assertThat(gate.permit("docs", updated("file:///project/anything.md"))).isTrue();
    }

    @Test
    @DisplayName("list_changed is passed on — it only prompts a re-list, which re-runs policy")
    void listChangedPasses() {
        assertThat(gate.permit("docs", notification("notifications/tools/list_changed", Map.of())))
                .isTrue();
        assertThat(gate.permit("docs",
                notification("notifications/resources/list_changed", Map.of()))).isTrue();
    }

    @Test
    @DisplayName("a notification this gateway does not understand is dropped")
    void unknownNotificationDropped() {
        // Same rule as unknown requests. A proxy that forwards what it cannot evaluate is
        // not a proxy, it is a pipe.
        assertThat(gate.permit("docs", notification("notifications/something/new", Map.of())))
                .isFalse();
        assertThat(gate.permit("docs", notification(null, Map.of()))).isFalse();
    }

    @Test
    @DisplayName("a flood is cut off, and audited once rather than a thousand times")
    void floodIsRateLimited() {
        int permitted = 0;
        for (int i = 0; i < 200; i++) {
            if (gate.permit("noisy", notification("notifications/tools/list_changed", Map.of()))) {
                permitted++;
            }
        }

        // A well-behaved server never reaches this; one that does is making the agent
        // re-list in a loop, which costs context and tokens.
        assertThat(permitted).isEqualTo(20);

        var complaints = recorded.stream()
                .filter(e -> e.reason().contains("rate exceeded")).toList();
        // Auditing every dropped message would be the same denial with an extra step.
        assertThat(complaints).hasSize(1);

        // The message has to name the offending notification, and it has to actually
        // substitute it — an unrendered %s reached a live audit trail before this assert
        // existed, because `"a %s" + "b".formatted(x)` formats only the second literal.
        assertThat(complaints.get(0).reason())
                .contains("notifications/tools/list_changed")
                .doesNotContain("%s");
    }

    @Test
    @DisplayName("rate limits are per server and per kind, so one chatty stream does not mask another")
    void limitsAreScoped() {
        for (int i = 0; i < 200; i++) {
            gate.permit("noisy", notification("notifications/tools/list_changed", Map.of()));
        }

        // A different kind from the same server, and the same kind from a different
        // server, both still get through.
        assertThat(gate.permit("noisy",
                notification("notifications/prompts/list_changed", Map.of()))).isTrue();
        assertThat(gate.permit("quiet",
                notification("notifications/tools/list_changed", Map.of()))).isTrue();
    }
}
