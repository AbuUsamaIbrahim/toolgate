package dev.mahadi.toolgate.control;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
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
@Component
public class FleetRegistry {

    private static final Logger log = LoggerFactory.getLogger(FleetRegistry.class);

    /** Key is {@code subject/instanceId} — one person may run several machines. */
    private final Map<String, Member> members = new ConcurrentHashMap<>();

    /**
     * A gateway that has reported in.
     *
     * @param subject      who, from their token — never self-asserted
     * @param instanceId   which of their machines
     * @param version      gateway build, so a fleet-wide upgrade is observable
     * @param bundleSequence the policy actually in force there, not the one we published
     * @param bundleHealth   FRESH / STALE / FAILED / DISABLED as that gateway sees it
     */
    public record Member(String subject, String instanceId, String version,
                         long bundleSequence, String bundleHealth,
                         Instant firstSeen, Instant lastSeen) {}

    /** How a member looks against the expectations of the moment. */
    public enum Status {
        /** Reporting recently, on the current bundle. */
        HEALTHY,
        /** Reporting, but enforcing an older bundle than the one being published. */
        BEHIND,
        /** Reporting, but its own policy is stale or failed. */
        DEGRADED,
        /** Not heard from. Either switched off, or the gateway is no longer running. */
        SILENT
    }

    public record FleetView(Member member, Status status, Duration since) {}

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
    public List<FleetView> view(long publishedSequence, Duration silentAfter) {
        Instant now = Instant.now();
        return members.values().stream()
                .map(m -> {
                    Duration since = Duration.between(m.lastSeen(), now);
                    Status status;
                    if (since.compareTo(silentAfter) > 0) status = Status.SILENT;
                    else if (!"FRESH".equals(m.bundleHealth()) && !"DISABLED".equals(m.bundleHealth()))
                        status = Status.DEGRADED;
                    else if (publishedSequence > 0 && m.bundleSequence() < publishedSequence)
                        status = Status.BEHIND;
                    else status = Status.HEALTHY;
                    return new FleetView(m, status, since);
                })
                .sorted(Comparator
                        .comparingInt((FleetView v) -> switch (v.status()) {
                            case SILENT -> 0;
                            case DEGRADED -> 1;
                            case BEHIND -> 2;
                            case HEALTHY -> 3;
                        })
                        .thenComparing(v -> v.member().subject()))
                .toList();
    }

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
    public int forget(Duration olderThan) {
        Instant cutoff = Instant.now().minus(olderThan);
        int before = members.size();
        members.values().removeIf(m -> m.lastSeen().isBefore(cutoff));
        return before - members.size();
    }
}
