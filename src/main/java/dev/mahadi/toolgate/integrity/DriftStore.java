package dev.mahadi.toolgate.integrity;

import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Outstanding drift, held so an operator can review what actually changed.
 *
 * <p>Deliberately in memory. Drift is re-detected the next time the tool is advertised, so
 * this is a live alert queue rather than a record — the durable account of what happened
 * is the audit log. Persisting it would mean an operator could be shown a stale diff for a
 * definition the upstream has since corrected.
 */
@Component
public class DriftStore {

    public record Drift(String serverId, String toolName, Instant detectedAt,
                        String pinnedFingerprint, String currentFingerprint,
                        Mcp.Tool pinnedDefinition, Mcp.Tool currentDefinition) {

        /** Null when the pin predates definition storage — drift is known, detail is not. */
        public ToolDiff.Result diff() {
            if (pinnedDefinition == null || currentDefinition == null) return null;
            return ToolDiff.between(pinnedDefinition, currentDefinition);
        }
    }

    private final Map<String, Drift> drifts = new ConcurrentHashMap<>();

    public void record(ToolPinStore.Pin pin, Mcp.Tool current, String currentFingerprint) {
        drifts.put(pin.serverId() + "/" + pin.toolName(), new Drift(
                pin.serverId(), pin.toolName(), Instant.now(),
                pin.fingerprint(), currentFingerprint,
                pin.definition(), current));
    }

    /** Cleared when the upstream reverts, so the queue reflects only live problems. */
    public void clear(String serverId, String toolName) {
        drifts.remove(serverId + "/" + toolName);
    }

    public Optional<Drift> get(String serverId, String toolName) {
        return Optional.ofNullable(drifts.get(serverId + "/" + toolName));
    }

    public Map<String, Drift> all() {
        return new LinkedHashMap<>(drifts);
    }

    /**
     * Renders a drift as unified-diff-style text.
     *
     * <p>Terminals and chat clients are where operators will actually read this, and both
     * handle plain text better than a JSON blob.
     */
    public static String renderText(Drift drift) {
        StringBuilder sb = new StringBuilder();
        sb.append("tool: ").append(drift.serverId()).append('/').append(drift.toolName()).append('\n');
        sb.append("pinned:  ").append(abbreviate(drift.pinnedFingerprint())).append('\n');
        sb.append("current: ").append(abbreviate(drift.currentFingerprint())).append('\n');

        ToolDiff.Result result = drift.diff();
        if (result == null) {
            sb.append("\n(no stored definition for the pin — re-pin this tool to enable diffs)\n");
            return sb.toString();
        }
        sb.append('\n');
        for (ToolDiff.Change c : result.changes()) {
            sb.append("  ").append(c.field()).append(":\n");
            if (c.pinned() != null) sb.append("-   ").append(c.pinned()).append('\n');
            if (c.current() != null) sb.append("+   ").append(c.current()).append('\n');
        }
        return sb.toString();
    }

    private static String abbreviate(String hash) {
        return hash == null ? "unknown" : hash.length() <= 12 ? hash : hash.substring(0, 12);
    }

    public List<Drift> list() {
        return List.copyOf(drifts.values());
    }
}
