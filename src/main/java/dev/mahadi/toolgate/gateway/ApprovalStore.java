package dev.mahadi.toolgate.gateway;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pending human approvals.
 *
 * <p>The spec says there SHOULD "always be a human in the loop with the ability to deny
 * tool invocations". A gateway can only honour that by refusing and handing back
 * something a person can act on, so a blocked call becomes a ticket rather than a
 * silent failure.
 *
 * <p>Grants are single-use and expire. A standing approval is just an allowlist entry
 * with extra steps, and a reusable one would let a compromised agent replay a human's
 * single "yes" indefinitely.
 */
@Component
public class ApprovalStore {

    private static final Duration TTL = Duration.ofMinutes(10);

    public record Pending(String id, String caller, String serverId, String tool,
                          String reason, Instant createdAt) {
        boolean expired() {
            return Instant.now().isAfter(createdAt.plus(TTL));
        }
    }

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Instant> granted = new ConcurrentHashMap<>();

    public Pending request(String caller, String serverId, String tool, String reason) {
        Pending p = new Pending(UUID.randomUUID().toString(), caller, serverId, tool,
                reason, Instant.now());
        pending.put(p.id(), p);
        return p;
    }

    /** Approves a pending request, returning it so the caller can audit what was granted. */
    public Optional<Pending> approve(String id) {
        Pending p = pending.remove(id);
        if (p == null || p.expired()) return Optional.empty();
        granted.put(grantKey(p.caller(), p.serverId(), p.tool()), Instant.now());
        return Optional.of(p);
    }

    public Optional<Pending> deny(String id) {
        return Optional.ofNullable(pending.remove(id));
    }

    /** Consumes a grant if one exists. Single-use by construction. */
    public boolean consumeGrant(String caller, String serverId, String tool) {
        String key = grantKey(caller, serverId, tool);
        Instant at = granted.remove(key);
        if (at == null) return false;
        if (Instant.now().isAfter(at.plus(TTL))) return false;
        return true;
    }

    public Map<String, Pending> outstanding() {
        pending.values().removeIf(Pending::expired);
        return Map.copyOf(pending);
    }

    private static String grantKey(String caller, String serverId, String tool) {
        return caller + "|" + serverId + "|" + tool;
    }
}
