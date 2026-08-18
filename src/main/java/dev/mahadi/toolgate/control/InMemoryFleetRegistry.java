package dev.mahadi.toolgate.control;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Who is running a gateway, on what policy, and when they were last heard from.
 *
 * <h2>This is the coverage question, and it is the one the rest of the system cannot answer</h2>
 * Signed bundles make policy authoritative <em>on the machines that run the gateway</em>.
 * They say nothing about the machines that do not. A developer who deletes one line from
 * their MCP client configuration reaches every upstream directly, and every control in this
 * project becomes decoration for that person — silently, with no error anywhere.
 *
 * <p>Check-ins turn that from invisible to merely unknown. The registry can say "these
 * forty people are enforcing policy, and these three stopped reporting on Tuesday". It
 * cannot say who never installed it at all: that requires comparing this list against a
 * roster of who <em>should</em> be — from an identity provider or an MDM inventory — and
 * that comparison happens outside this service, because this service has no business
 * holding a copy of the org chart.
 *
 * <h2>What a check-in does and does not prove</h2>
 * Identity comes from the caller's OIDC token, so a report is attributed to a person rather
 * than to a self-asserted name, and one developer cannot manufacture coverage for another.
 * Someone can still fake their own: run a script that posts plausible check-ins while using
 * MCP servers directly. That is a deliberate act of deception rather than a config file
 * nobody edited, which is a different problem with different remedies — and the honest
 * framing is that this control raises the cost of bypass, it does not close it.
 */
public class InMemoryFleetRegistry implements FleetRegistry {

    private static final Logger log = LoggerFactory.getLogger(InMemoryFleetRegistry.class);

    /** Key is {@code subject/instanceId} — one person may run several machines. */
    private final Map<String, Member> members = new ConcurrentHashMap<>();

    @Override
    public Member checkIn(String subject, String instanceId, String version,
                          long bundleSequence, String bundleHealth) {
        String key = subject + "/" + instanceId;
        Instant now = Instant.now();

        Member updated = members.compute(key, (k, existing) -> new Member(
                subject, instanceId, version, bundleSequence, bundleHealth,
                existing == null ? now : existing.firstSeen(), now));

        if (members.get(key).firstSeen().equals(now)) {
            log.info("New gateway checked in: {} on {} (version {}, bundle {})",
                    subject, instanceId, version, bundleSequence);
        }
        return updated;
    }

    /**
     * The fleet, worst first.
     *
     * <p>Ordering matters more than it sounds. A coverage report sorted alphabetically is a
     * list nobody reads to the bottom; sorted by how wrong each entry is, the first screen
     * is the work.
     */
    @Override
    public List<FleetView> view(long publishedSequence, Duration silentAfter) {
        Instant now = Instant.now();
        return members.values().stream()
                .map(m -> new FleetView(m,
                        FleetRegistry.statusOf(m, publishedSequence, silentAfter, now),
                        Duration.between(m.lastSeen(), now)))
                .sorted(FleetRegistry.worstFirst())
                .toList();
    }

    @Override
    public int size() {
        return members.size();
    }

    /**
     * Drops members not seen for a long time.
     *
     * <p>Not called automatically, and that is deliberate: a machine disappearing from a
     * coverage report because it has been quiet for a month is the report answering a
     * question it was not asked. Silence is the finding.
     */
    @Override
    public int forget(Duration olderThan) {
        Instant cutoff = Instant.now().minus(olderThan);
        int before = members.size();
        members.values().removeIf(m -> m.lastSeen().isBefore(cutoff));
        return before - members.size();
    }
}
