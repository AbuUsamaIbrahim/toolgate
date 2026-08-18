package dev.mahadi.toolgate.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks client subscriptions and the upstream subscriptions opened to serve them.
 *
 * <h2>One client subscription becomes several</h2>
 * A client sends one {@code subscriptions/listen} to the gateway. The gateway opens one to
 * each upstream that can serve part of the filter, so notifications arrive from several
 * places and have to look to the client as though they came from the single stream it
 * asked for.
 *
 * <h2>The subscription id must be rewritten, not passed through</h2>
 * The specification makes the id of the {@code subscriptions/listen} request the
 * subscription id, and requires every notification to carry it so a client can demultiplex
 * several concurrent streams. That id is chosen by whoever opened the subscription — which
 * upstream is a different party from the client.
 *
 * <p>Pass an upstream's id straight through and a client demultiplexes against an id it
 * never issued. Worse, a client with two subscriptions open is one hostile server away from
 * having notifications delivered into the wrong one: server A, serving subscription 1,
 * simply stamps its notifications with 2. The client attributes them to a subscription
 * about entirely different resources, and nothing in the protocol contradicts it.
 *
 * <p>So the mapping is kept here and the id is rewritten on the way out, based on which
 * upstream subscription the message actually arrived on rather than what it claims to be.
 */
@Component
public class SubscriptionRegistry {

    private static final Logger log = LoggerFactory.getLogger(SubscriptionRegistry.class);

    /**
     * What a client asked to hear about.
     *
     * <p>Kept because the spec says a server <em>MUST NOT</em> send notification types the
     * client did not request — and a gateway that can check a MUST is more useful than a
     * specification that states one.
     */
    public record Filter(boolean toolsListChanged, boolean promptsListChanged,
                         boolean resourcesListChanged, Set<String> resourceSubscriptions) {

        public Filter {
            resourceSubscriptions = resourceSubscriptions == null
                    ? Set.of() : Set.copyOf(resourceSubscriptions);
        }

        public boolean wantsNothing() {
            return !toolsListChanged && !promptsListChanged && !resourcesListChanged
                    && resourceSubscriptions.isEmpty();
        }

        /** Whether this filter admits a given notification. */
        public boolean admits(String method, String uri) {
            return switch (method) {
                case "notifications/tools/list_changed" -> toolsListChanged;
                case "notifications/prompts/list_changed" -> promptsListChanged;
                case "notifications/resources/list_changed" -> resourcesListChanged;
                case "notifications/resources/updated" -> resourceSubscriptions.contains(uri);
                default -> false;
            };
        }
    }

    public record Subscription(String clientId, Filter granted, Map<String, String> upstreamIds) {}

    /** Client subscription id -> subscription. */
    private final Map<String, Subscription> byClientId = new ConcurrentHashMap<>();

    /** "serverId|upstreamSubscriptionId" -> client subscription id. */
    private final Map<String, String> upstreamToClient = new ConcurrentHashMap<>();

    public Subscription open(String clientId, Filter granted, Map<String, String> upstreamIds) {
        Subscription subscription = new Subscription(clientId, granted, Map.copyOf(upstreamIds));
        byClientId.put(clientId, subscription);
        upstreamIds.forEach((serverId, upstreamId) ->
                upstreamToClient.put(link(serverId, upstreamId), clientId));
        log.info("subscription {} open across {} upstream(s)", clientId, upstreamIds.size());
        return subscription;
    }

    /**
     * Resolves an inbound notification to the client subscription it belongs to.
     *
     * <p>Keyed on the upstream that sent it as well as the id it carries, so a server can
     * only ever resolve to a subscription that was opened with it. Claiming another
     * server's id resolves to nothing and the notification is dropped.
     */
    public Optional<Subscription> resolve(String serverId, String upstreamSubscriptionId) {
        String clientId = upstreamToClient.get(link(serverId, upstreamSubscriptionId));
        return Optional.ofNullable(clientId).map(byClientId::get);
    }

    public Optional<Subscription> byClientId(String clientId) {
        return Optional.ofNullable(byClientId.get(clientId));
    }

    /** @return the upstream subscriptions that need tearing down */
    public Map<String, String> cancel(String clientId) {
        Subscription subscription = byClientId.remove(clientId);
        if (subscription == null) return Map.of();

        subscription.upstreamIds().forEach((serverId, upstreamId) ->
                upstreamToClient.remove(link(serverId, upstreamId)));
        log.info("subscription {} cancelled", clientId);
        return subscription.upstreamIds();
    }

    /**
     * Records that one upstream ended its half of a subscription.
     *
     * @return true when that was the last one, so the client's subscription is now over
     */
    public boolean upstreamClosed(String clientId, String serverId) {
        // compute() rather than get-then-put. Upstreams shut down together — a deploy, a
        // laptop sleeping — and with a read followed by a write each caller sees the state
        // before any of them acted, every one of them concludes it was not the last, and
        // the client is never told its subscription ended. A concurrent map makes each
        // operation atomic; it does nothing for a read followed by a write.
        java.util.concurrent.atomic.AtomicBoolean wasLast =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        byClientId.compute(clientId, (key, existing) -> {
            if (existing == null) return null;

            Map<String, String> remaining = new java.util.LinkedHashMap<>(existing.upstreamIds());
            String closed = remaining.remove(serverId);
            if (closed != null) upstreamToClient.remove(link(serverId, closed));

            if (remaining.isEmpty()) {
                wasLast.set(true);
                log.info("subscription {} closed: every upstream has ended", clientId);
                return null;      // removes the entry
            }
            // Still served by the others. A subscription spanning five servers should not
            // end because one of them shut down cleanly.
            return new Subscription(clientId, existing.granted(), remaining);
        });

        return wasLast.get();
    }

    /**
     * Forgets everything for one upstream, for when it dies.
     *
     * <p>The client's subscription survives: the other upstreams are still serving it, and
     * tearing the whole thing down because one server exited would make a single crashy
     * upstream able to silence notifications from every other.
     */
    public void upstreamGone(String serverId) {
        upstreamToClient.keySet().removeIf(k -> k.startsWith(serverId + "|"));
    }

    public Set<String> activeClientIds() {
        return new LinkedHashSet<>(byClientId.keySet());
    }

    public int size() {
        return byClientId.size();
    }

    private static String link(String serverId, String upstreamSubscriptionId) {
        return serverId + "|" + upstreamSubscriptionId;
    }
}
