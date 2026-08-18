package dev.mahadi.toolgate.gateway;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers which upstream advertised which resource URI.
 *
 * <h2>Why resources need this and tools do not</h2>
 * Tool names are namespaced on the way out — {@code files__read_file} — so a call carries
 * its own routing information and the gateway can split it back apart. A resource is
 * identified by a URI, and rewriting one would be both ugly and wrong: the URI is
 * meaningful to the server and sometimes to the client, and a mangled {@code file://} path
 * is a different path.
 *
 * <p>So the mapping is recorded when a resource is advertised and consulted when one is
 * read. That has a second effect worth more than the routing: <b>a read of a URI this
 * gateway never advertised is refused.</b> It is the same control as "tool was never
 * advertised through this gateway", and it matters more here, because a resource URI is
 * something a model can be persuaded to construct — a poisoned tool description that says
 * "then read file:///etc/shadow" produces a URI that was never on any list.
 *
 * <p>In-memory and per-process, which is correct for a sidecar: the routing table describes
 * what <em>this</em> gateway advertised to <em>this</em> agent, and a restart genuinely
 * should forget it, because the agent will list again before it reads.
 */
@Component
public class SurfaceRouter {

    private final Map<String, String> resourceOwner = new ConcurrentHashMap<>();

    /** Fixed prefix of an approved template -> the server that offered it. */
    private final Map<String, String> templatePrefixOwner = new ConcurrentHashMap<>();

    /** Records that {@code serverId} offered this URI, replacing any earlier claim. */
    public void advertised(String serverId, String uri) {
        if (uri != null && !uri.isBlank()) resourceOwner.put(uri, serverId);
    }

    /**
     * Records an approved template by its fixed prefix.
     *
     * <p>Only the part before the first variable is kept, because that is the only part
     * the server controls. Everything after it is chosen by the client at expansion time,
     * and {@link dev.mahadi.toolgate.policy.ResourceGuard#checkTemplate} has already
     * established that the fixed part sits inside the allowlist.
     */
    public void templateAdvertised(String serverId, String uriTemplate) {
        if (uriTemplate == null || uriTemplate.isBlank()) return;
        int firstVar = uriTemplate.indexOf('{');
        templatePrefixOwner.put(firstVar < 0 ? uriTemplate : uriTemplate.substring(0, firstVar),
                serverId);
    }

    /**
     * Which server may be asked for this URI.
     *
     * <p>An exact advertisement wins. Failing that, a URI produced by expanding an approved
     * template is routed to whichever server offered that template — which is the whole
     * reason templates need this: the expansion was never advertised and never could be.
     *
     * <p>The longest matching prefix wins, so a specific template beats a general one when
     * both could serve the URI.
     */
    public Optional<String> ownerOf(String uri) {
        if (uri == null) return Optional.empty();

        String exact = resourceOwner.get(uri);
        if (exact != null) return Optional.of(exact);

        String bestPrefix = null;
        for (String prefix : templatePrefixOwner.keySet()) {
            if (uri.startsWith(prefix) && (bestPrefix == null || prefix.length() > bestPrefix.length())) {
                bestPrefix = prefix;
            }
        }
        return Optional.ofNullable(bestPrefix).map(templatePrefixOwner::get);
    }

    /** True when this URI is only reachable because a template covers it. */
    public boolean viaTemplate(String uri) {
        return uri != null && !resourceOwner.containsKey(uri) && ownerOf(uri).isPresent();
    }

    /** Forgets URIs a server no longer advertises, so a withdrawn resource stops resolving. */
    public void retainOnly(String serverId, java.util.Set<String> stillAdvertised) {
        resourceOwner.entrySet().removeIf(e ->
                e.getValue().equals(serverId) && !stillAdvertised.contains(e.getKey()));
    }

    /** The same, for templates: one a server stops offering stops routing expansions. */
    public void retainOnlyTemplates(String serverId, java.util.Set<String> stillAdvertised) {
        templatePrefixOwner.entrySet().removeIf(e ->
                e.getValue().equals(serverId) && !stillAdvertised.contains(e.getKey()));
    }

    public int size() {
        return resourceOwner.size();
    }
}
