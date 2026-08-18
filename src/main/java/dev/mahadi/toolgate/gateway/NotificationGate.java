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
    private final AuditLog audit;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public NotificationGate(SurfaceRouter router, AuditLog audit) {
        this.router = router;
        this.audit = audit;
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
