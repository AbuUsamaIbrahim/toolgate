package dev.mahadi.toolgate.gateway;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.protocol.Mcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Decides which server-initiated notifications reach the client.
 *
 * <h2>Why notifications need a gate of their own</h2>
 * Everything else in this gateway is a response to something the agent asked for. A
 * notification is the upstream speaking unprompted, and it is the only message in the
 * protocol where the server chooses both the timing and the frequency. That makes two
 * things possible that requests do not:
 *
 * <ul>
 *   <li><b>Notifying about a resource nobody is watching.</b> {@code resources/updated} is
 *       defined to arrive on a subscription stream. One that arrives for a URI this gateway
 *       never advertised is either confused or probing, and forwarding it invites the
 *       client to read something that was never offered.</li>
 *   <li><b>Flooding.</b> A {@code list_changed} makes a well-behaved client re-list, and a
 *       {@code resources/updated} makes it re-read. A server that emits either in a tight
 *       loop turns the agent into a machine for burning context and tokens on its
 *       behalf — a denial of wallet with no exploit in it, just enthusiasm.</li>
 * </ul>
 *
 * <p>Rate limiting is per server and per notification kind, so a chatty resource cannot
 * drown out a genuine {@code tools/list_changed} from the same upstream.
 */
@Component
public class NotificationGate {

    private static final Logger log = LoggerFactory.getLogger(NotificationGate.class);

    /**
     * Notifications this gateway understands well enough to reason about.
     *
     * <p>Anything else is dropped, matching how unknown <em>requests</em> are handled. A
     * proxy that forwards messages it cannot evaluate is not a proxy, it is a pipe.
     */
    private static final java.util.Set<String> LIST_CHANGED = java.util.Set.of(
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed");

    private static final String RESOURCE_UPDATED = "notifications/resources/updated";

    /** Per kind, per server. Generous enough that no honest server notices. */
    private static final int MAX_PER_WINDOW = 20;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final SurfaceRouter router;
    private final SubscriptionRegistry subscriptions;
    private final AuditLog audit;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public NotificationGate(SurfaceRouter router, SubscriptionRegistry subscriptions,
                            AuditLog audit) {
        this.router = router;
        this.subscriptions = subscriptions;
        this.audit = audit;
    }

    /** What the gateway decided about one inbound notification. */
    public sealed interface Verdict {
        /** Forward it, after replacing the subscription id with the client's own. */
        record Forward(String clientSubscriptionId) implements Verdict {}
        record Drop(String reason) implements Verdict {}
    }

    public static final String SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId";

    /**
     * Decides an inbound notification when subscriptions are in play.
     *
     * <p>Three things are checked that {@link #permit} does not, and each corresponds to a
     * requirement the specification places on servers — which is the case for checking
     * them here, since a gateway exists precisely because a server's compliance cannot be
     * assumed:
     *
     * <ul>
     *   <li><b>It belongs to a subscription this upstream actually opened.</b> Resolution
     *       is keyed on the sender as well as the id, so a server stamping another's
     *       subscription id resolves to nothing. Without that, a client running two
     *       subscriptions is one hostile server away from having notifications delivered
     *       into the wrong stream.</li>
     *   <li><b>The client asked for this type.</b> The spec says a server MUST NOT send
     *       types the client did not request. Servers that do are either buggy or
     *       probing.</li>
     *   <li><b>The URI is one the client actually subscribed to</b>, not merely one the
     *       server would like it to re-read.</li>
     * </ul>
     */
    public Verdict evaluate(String serverId, Mcp.Request notification) {
        String method = notification.method();
        if (method == null) return new Verdict.Drop("no method");

        Object claimed = subscriptionIdOf(notification);
        if (claimed == null) {
            // Outside any subscription. Falls back to the unsolicited rules, which are
            // stricter about resources/updated and looser about list_changed.
            return permit(serverId, notification)
                    ? new Verdict.Forward(null)
                    : new Verdict.Drop("refused as an unsolicited notification");
        }

        var subscription = subscriptions.resolve(serverId, String.valueOf(claimed));
        if (subscription.isEmpty()) {
            audit.record("-", serverId, method, "notification", AuditLog.Outcome.DENIED,
                    "notification carries a subscription id this upstream was never given",
                    List.of("claimed=" + claimed));
            return new Verdict.Drop("unknown subscription");
        }

        String uri = uriOf(notification);
        if (!subscription.get().granted().admits(method, uri)) {
            audit.record("-", serverId, uri == null ? method : uri, "notification",
                    AuditLog.Outcome.DENIED,
                    "server sent a notification type the client did not subscribe to",
                    List.of("method=" + method));
            return new Verdict.Drop("outside the agreed filter");
        }

        if (!withinRate(serverId, method)) return new Verdict.Drop("rate exceeded");

        return new Verdict.Forward(subscription.get().clientId());
    }

    private static Object subscriptionIdOf(Mcp.Request notification) {
        Object params = notification.params() == null ? null : notification.params().get("_meta");
        if (params instanceof Map<?, ?> meta) return meta.get(SUBSCRIPTION_ID);
        return null;
    }

    private static String uriOf(Mcp.Request notification) {
        Object uri = notification.params() == null ? null : notification.params().get("uri");
        return uri == null ? null : String.valueOf(uri);
    }

    private static final class Window {
        Instant startedAt = Instant.now();
        final AtomicInteger count = new AtomicInteger();
        boolean reported;
    }

    /** @return true when the notification may be passed on to the client */
    public boolean permit(String serverId, Mcp.Request notification) {
        String method = notification.method();
        if (method == null) return false;

        if (!LIST_CHANGED.contains(method) && !RESOURCE_UPDATED.equals(method)) {
            log.debug("dropping unrecognised notification {} from {}", method, serverId);
            return false;
        }

        if (RESOURCE_UPDATED.equals(method)) {
            Object uriParam = notification.params() == null ? null : notification.params().get("uri");
            String uri = uriParam == null ? null : String.valueOf(uriParam);

            if (router.ownerOf(uri).isEmpty()) {
                // Nothing this gateway advertised, and no approved template covers it.
                audit.record("-", serverId, String.valueOf(uri), "notification",
                        AuditLog.Outcome.DENIED,
                        "update for a resource that was never advertised", List.of());
                return false;
            }
            if (!serverId.equals(router.ownerOf(uri).orElse(null))) {
                // One upstream claiming another's resource changed. There is no legitimate
                // reason for that, and following it would let a hostile server steer the
                // client's reads towards a peer it does not control.
                audit.record("-", serverId, uri, "notification", AuditLog.Outcome.DENIED,
                        "update for a resource belonging to a different upstream",
                        List.of("owner=" + router.ownerOf(uri).orElse("?")));
                return false;
            }
        }

        return withinRate(serverId, method);
    }

    private boolean withinRate(String serverId, String method) {
        Window window = windows.computeIfAbsent(serverId + "|" + method, k -> new Window());

        synchronized (window) {
            if (Duration.between(window.startedAt, Instant.now()).compareTo(WINDOW) > 0) {
                window.startedAt = Instant.now();
                window.count.set(0);
                window.reported = false;
            }
            if (window.count.incrementAndGet() > MAX_PER_WINDOW) {
                // Audited once per window. A flood that also floods the audit trail would
                // be the same attack with an extra step.
                if (!window.reported) {
                    window.reported = true;
                    // Parenthesised: `"a %s" + "b".formatted(x)` applies the format to
                    // the second literal only, and the placeholder in the first survives
                    // into the message an operator has to read.
                    audit.record("-", serverId, method, "notification", AuditLog.Outcome.DENIED,
                            ("notification rate exceeded — further %s from this server are "
                                    + "being dropped this minute").formatted(method),
                            List.of("limit=" + MAX_PER_WINDOW + "/" + WINDOW));
                }
                return false;
            }
        }
        return true;
    }
}
