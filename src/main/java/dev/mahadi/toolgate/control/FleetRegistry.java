package dev.mahadi.toolgate.control;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Who is running a gateway, on what policy, and when they were last heard from.
 *
 * <h2>The coverage question, which nothing else in the system can answer</h2>
 * Signed bundles make policy authoritative <em>on the machines that run the gateway</em>.
 * They say nothing about the machines that do not. A developer who deletes one line from
 * their MCP client configuration reaches every upstream directly, and every control in this
 * project becomes decoration for that person — silently, with no error anywhere.
 *
 * <p>Check-ins turn that from invisible to merely unknown. The registry can say "these
 * forty people are enforcing policy, and these three stopped reporting on Tuesday". It
 * cannot say who never installed it at all: that needs comparing this list against a roster
 * of who <em>should</em> be, from an identity provider or an MDM inventory, and that
 * comparison happens elsewhere — this service has no business holding a copy of the org
 * chart.
 *
 * <h2>Why this is an interface</h2>
 * Because where the state lives determines how many replicas the control plane can have,
 * and that turned out to be the most consequential design decision in the component. The
 * in-memory implementation is correct and fast and forces {@code replicas: 1}: with two
 * pods behind one Service, each holds a fraction of the check-ins and the coverage report
 * contradicts itself depending on which pod answers. A report that says two machines are
 * unmonitored when they are not is worse than no report.
 */
public interface FleetRegistry {

    /**
     * A gateway that has reported in.
     *
     * @param subject        who, from their token — never self-asserted
     * @param instanceId     which of their machines
     * @param version        gateway build, so a fleet-wide upgrade is observable
     * @param bundleSequence the policy actually in force there, not the one we published
     * @param bundleHealth   FRESH / STALE / FAILED / DISABLED as that gateway sees it
     */
    record Member(String subject, String instanceId, String version,
                  long bundleSequence, String bundleHealth,
                  Instant firstSeen, Instant lastSeen) {}

    /** How a member looks against the expectations of the moment. */
    enum Status {
        /** Reporting recently, on the current bundle. */
        HEALTHY,
        /** Reporting, but enforcing an older bundle than the one being published. */
        BEHIND,
        /** Reporting, but its own policy is stale or failed. */
        DEGRADED,
        /** Not heard from. Either switched off, or the gateway is no longer running. */
        SILENT
    }

    record FleetView(Member member, Status status, Duration since) {}

    Member checkIn(String subject, String instanceId, String version,
                   long bundleSequence, String bundleHealth);

    /**
     * The fleet, worst first.
     *
     * <p>Ordering matters more than it sounds. A coverage report sorted alphabetically is a
     * list nobody reads to the bottom; sorted by how wrong each entry is, the first screen
     * is the work.
     */
    List<FleetView> view(long publishedSequence, Duration silentAfter);

    int size();

    /**
     * Drops members not seen for a long time.
     *
     * <p>Never called automatically, and that is deliberate: a machine disappearing from a
     * coverage report because it has been quiet for a month is the report answering a
     * question it was not asked. Silence is the finding.
     */
    int forget(Duration olderThan);

    /** Shared by every implementation, so the report reads the same wherever state lives. */
    static Status statusOf(Member m, long publishedSequence, Duration silentAfter, Instant now) {
        Duration since = Duration.between(m.lastSeen(), now);
        if (since.compareTo(silentAfter) > 0) return Status.SILENT;
        if (!"FRESH".equals(m.bundleHealth()) && !"DISABLED".equals(m.bundleHealth())) {
            return Status.DEGRADED;
        }
        if (publishedSequence > 0 && m.bundleSequence() < publishedSequence) return Status.BEHIND;
        return Status.HEALTHY;
    }

    /** Worst first: SILENT, DEGRADED, BEHIND, HEALTHY, then by person. */
    static java.util.Comparator<FleetView> worstFirst() {
        return java.util.Comparator
                .comparingInt((FleetView v) -> switch (v.status()) {
                    case SILENT -> 0;
                    case DEGRADED -> 1;
                    case BEHIND -> 2;
                    case HEALTHY -> 3;
                })
                .thenComparing(v -> v.member().subject());
    }
}
