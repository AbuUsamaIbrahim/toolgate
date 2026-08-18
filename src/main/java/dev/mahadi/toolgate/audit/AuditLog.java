package dev.mahadi.toolgate.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Append-only record of every decision the gateway made.
 *
 * <p>The MCP specification tells clients to "log tool usage for audit purposes" without
 * saying what that log should contain. The answer that matters after an incident is not
 * "which tools ran" but "what did the gateway decide, and on what evidence" — a denial
 * with its reasoning is worth more than a hundred success lines.
 *
 * <p>In-memory with a bounded ring buffer. That is the right shape for a reference
 * implementation and the wrong shape for production, where these events belong on a
 * durable append-only sink the gateway itself cannot rewrite.
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger("toolgate.audit");
    private static final int CAPACITY = 1000;

    private final Deque<Entry> entries = new ArrayDeque<>(CAPACITY);

    public enum Outcome { ALLOWED, DENIED, APPROVAL_REQUIRED, APPROVED, FAILED }

    public record Entry(
            Instant at,
            String caller,
            String serverId,
            String tool,
            String action,
            Outcome outcome,
            String reason,
            List<String> evidence) {}

    public synchronized void record(Entry entry) {
        if (entries.size() >= CAPACITY) entries.removeFirst();
        entries.addLast(entry);

        // Structured so a log pipeline can alert on outcome without parsing prose.
        log.info("outcome={} action={} caller={} tool={}/{} reason=\"{}\" evidence={}",
                entry.outcome(), entry.action(), entry.caller(),
                entry.serverId(), entry.tool(), entry.reason(), entry.evidence());
    }

    public void record(String caller, String serverId, String tool, String action,
                       Outcome outcome, String reason, List<String> evidence) {
        record(new Entry(Instant.now(), caller, serverId, tool, action, outcome, reason,
                evidence == null ? List.of() : List.copyOf(evidence)));
    }

    /** Most recent first. */
    public synchronized List<Entry> recent(int limit) {
        return entries.stream()
                .collect(java.util.stream.Collectors.collectingAndThen(
                        java.util.stream.Collectors.toList(),
                        l -> { java.util.Collections.reverse(l); return l; }))
                .stream()
                .limit(limit)
                .toList();
    }

    public synchronized int size() {
        return entries.size();
    }
}
