package dev.mahadi.toolgate.bundle;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A signed, versioned statement of what the fleet is allowed to do.
 *
 * <h2>What is in here, and what deliberately is not</h2>
 * The bundle carries <b>policy</b>: which tools may be advertised, which need a human, the
 * scanner threshold, and the fingerprints a reviewer has actually looked at. It does not
 * carry <b>connectivity</b> — the URL of a server, the command that launches it, its
 * environment, or its credential.
 *
 * <p>That split is the whole design. A stdio upstream's command line is specific to one
 * machine, and its token is a secret that has no business in an artifact distributed to
 * every laptop in the company. Connectivity stays in local configuration; the bundle
 * decides what is permitted once connected. A server the operator can reach but the bundle
 * does not mention is allowed nothing at all, which is how central policy stays
 * authoritative without needing to know anything about the machine it lands on.
 *
 * <h2>Why reviewed fingerprints matter more than the allowlist</h2>
 * Trust on first use has one real weakness: it assumes the first sighting is clean, and at
 * fleet scale it means every laptop independently trusts whatever it happened to see
 * first. {@link Reviewed} replaces that with a fingerprint a named person approved on a
 * named date. It turns "nobody has looked at this" into "somebody has", which is the
 * difference between detecting change and knowing the baseline was ever good.
 */
public record PolicyBundle(

        /** Format version of this document, so a future gateway can refuse what it cannot read. */
        int schemaVersion,

        /**
         * Monotonically increasing. A bundle with a sequence at or below the active one is
         * refused — otherwise an attacker who captures an old, validly signed bundle can
         * replay it to restore a tool that was deliberately removed. Signatures prove
         * authenticity, not freshness.
         */
        long sequence,

        /** Who produced this, for the audit trail. Not used in any trust decision. */
        String issuer,

        Instant issuedAt,

        /**
         * After this, the bundle is stale. Expiry is what makes a fleet converge: a laptop
         * that stops being able to reach the distribution point degrades on a known
         * schedule instead of enforcing last year's policy indefinitely.
         */
        Instant expiresAt,

        /** Scanner score at or above which a tool is denied rather than escalated. */
        int blockThreshold,

        /** Require human approval the first time an unreviewed definition is seen. */
        boolean approveFirstSighting,

        /**
         * Refuse any tool with no reviewed fingerprint, rather than falling back to local
         * trust on first use. The strict setting: nothing reaches a model until a person
         * has read its definition.
         */
        boolean requireReviewed,

        /** Per-server policy, keyed by the same server id used in local configuration. */
        Map<String, ServerPolicy> servers,

        List<Reviewed> reviewedTools) {

    public static final int SCHEMA_VERSION = 1;

    public record ServerPolicy(Set<String> allow, Set<String> requireApproval) {
        public ServerPolicy {
            allow = allow == null ? Set.of() : Set.copyOf(allow);
            requireApproval = requireApproval == null ? Set.of() : Set.copyOf(requireApproval);
        }
    }

    /** A tool definition a human has read and accepted, identified by its fingerprint. */
    public record Reviewed(String serverId, String toolName, String fingerprint,
                           String reviewedBy, Instant reviewedAt, String note) {}

    public boolean expired(Instant now) {
        return expiresAt != null && now.isAfter(expiresAt);
    }

    /** Reviewed fingerprint for a tool, if one exists. */
    public java.util.Optional<Reviewed> reviewed(String serverId, String toolName) {
        if (reviewedTools == null) return java.util.Optional.empty();
        return reviewedTools.stream()
                .filter(r -> r.serverId().equals(serverId) && r.toolName().equals(toolName))
                .findFirst();
    }

    public boolean allows(String serverId, String toolName) {
        ServerPolicy s = servers == null ? null : servers.get(serverId);
        return s != null && s.allow().contains(toolName);
    }

    public boolean requiresApproval(String serverId, String toolName) {
        ServerPolicy s = servers == null ? null : servers.get(serverId);
        return s != null && s.requireApproval().contains(toolName);
    }
}
