package dev.mahadi.toolgate.gateway;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.util.FilePaths;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
 *
 * <p>Approvals name the person who granted them, and a requester cannot approve their own
 * call — see {@link #approve(String, String)}.
 *
 * <h2>What survives a restart, and what deliberately does not</h2>
 * Pending <em>requests</em> are written to disk. They represent a decision a human still
 * owes, and losing the queue during a deploy means an operator reviewing a suspicious call
 * watches it vanish mid-review.
 *
 * <p>Granted approvals are never written. A grant is permission for one call, in one
 * moment, in a context a person had in their head at the time — and it is already
 * consumed within seconds. Persisting it would turn a momentary "yes" into a standing
 * permission that outlives the situation that justified it, which is the failure mode the
 * single-use rule exists to prevent. Restarting the gateway revokes every outstanding
 * grant, and that is the correct behaviour rather than a gap.
 *
 * <p>Expired requests are dropped on load for the same reason: a queue that survived a
 * three-day outage is a list of decisions nobody should still be making.
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

    private static final Logger log = LoggerFactory.getLogger(ApprovalStore.class);

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Instant> granted = new ConcurrentHashMap<>();

    private final ApprovalProperties props;
    private final ObjectMapper mapper;

    public ApprovalStore(ApprovalProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
    }

    public Pending request(String caller, String serverId, String tool, String reason) {
        Pending p = new Pending(UUID.randomUUID().toString(), caller, serverId, tool,
                reason, Instant.now());
        pending.put(p.id(), p);
        persist();
        return p;
    }

    /** What happened when someone tried to approve. */
    public sealed interface Outcome {
        record Granted(Pending request, String approver) implements Outcome {}

        /** The requester tried to approve their own call. */
        record SelfApproval(Pending request) implements Outcome {}

        /** No such request, or it aged out while nobody was looking. */
        record Unknown() implements Outcome {}
    }

    /**
     * Approves a pending request on behalf of a named person.
     *
     * <p>The approver is required, not optional, and the signature is the reason: an
     * approval whose grantor is unknown answers "was this allowed" but not "who allowed
     * it", and after an incident only the second question matters. An earlier version of
     * this recorded "granted by operator", which named a shared token.
     *
     * <p>Self-approval is refused. A human gate exists to put a second judgement in front
     * of a destructive call; if the agent's own operator can wave it through, the gate
     * measures persistence rather than agreement. This is enforced here rather than in any
     * user interface, because the interface is not the thing an attacker uses.
     */
    public Outcome approve(String id, String approver) {
        Pending p = pending.get(id);
        if (p == null || p.expired()) {
            pending.remove(id);
            return new Outcome.Unknown();
        }
        if (approver != null && approver.equals(p.caller())) {
            // Deliberately left in the queue. Someone else can still approve it, and
            // removing it would let a requester cancel their own request by trying.
            log.warn("Refused self-approval of {} by {}", id, approver);
            return new Outcome.SelfApproval(p);
        }

        pending.remove(id);
        granted.put(grantKey(p.caller(), p.serverId(), p.tool()), Instant.now());
        persist();
        log.info("Approval {} for {}/{} granted to {} by {}",
                id, p.serverId(), p.tool(), p.caller(), approver);
        return new Outcome.Granted(p, approver);
    }

    /**
     * Denies a request.
     *
     * <p>No approver check here: anyone may refuse, including the requester. Withdrawing
     * your own request is a reasonable thing to want, and the failure mode of an overly
     * permissive deny is that a call does not happen.
     */
    public Optional<Pending> deny(String id, String deniedBy) {
        Optional<Pending> p = Optional.ofNullable(pending.remove(id));
        p.ifPresent(x -> {
            persist();
            log.info("Approval {} for {}/{} denied by {}", id, x.serverId(), x.tool(), deniedBy);
        });
        return p;
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

    private boolean persistent() {
        return props != null && props.getFile() != null && !props.getFile().isBlank();
    }

    @PostConstruct
    public void restore() {
        if (!persistent()) return;
        Path path = FilePaths.expandUser(props.getFile());
        if (!Files.exists(path)) return;
        try {
            List<Pending> loaded = mapper.readValue(Files.readAllBytes(path),
                    new TypeReference<List<Pending>>() {});
            loaded.stream().filter(p -> !p.expired()).forEach(p -> pending.put(p.id(), p));
            log.info("Restored {} outstanding approval request(s)", pending.size());
        } catch (IOException e) {
            // Unlike the pin file, an unreadable queue is not a security failure: the
            // worst case is that an operator re-approves a call the agent retries. Losing
            // it must not stop the gateway enforcing everything else.
            log.warn("Could not read approval queue {} — starting with an empty queue: {}",
                    path, e.toString());
        }
    }

    private synchronized void persist() {
        if (!persistent()) return;
        Path path = FilePaths.expandUser(props.getFile());
        try {
            Files.createDirectories(path.getParent());
            Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
            Files.write(tmp, mapper.writeValueAsBytes(List.copyOf(pending.values())));
            FilePaths.restrictToOwner(tmp);
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            log.error("Could not persist approval queue: {}", e.toString());
        }
    }
}
