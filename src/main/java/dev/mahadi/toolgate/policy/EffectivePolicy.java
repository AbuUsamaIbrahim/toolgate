package dev.mahadi.toolgate.policy;

import dev.mahadi.toolgate.bundle.BundleStore;
import dev.mahadi.toolgate.bundle.PolicyBundle;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * The single answer to "what is policy right now", resolving local configuration against
 * a signed bundle.
 *
 * <p>Precedence is not a merge. When a bundle is in force it is <em>authoritative</em> for
 * every policy question, and local YAML contributes nothing but connectivity — how to reach
 * a server, never what may be done with it. Merging would mean a developer could widen
 * their own allowlist by editing a file on their own laptop, which is the same as having no
 * central policy at all while appearing to have one.
 *
 * <p>The corollary is that a server present in local configuration but absent from the
 * bundle is allowed nothing. That is the intended behaviour: central policy has to be able
 * to say "no" about a server it has never heard of, without knowing it exists.
 */
@Component
public class EffectivePolicy {

    private final ToolPolicyProperties local;
    private final BundleStore bundles;

    public EffectivePolicy(ToolPolicyProperties local, BundleStore bundles) {
        this.local = local;
        this.bundles = bundles;
    }

    /** True when the gateway must refuse everything: a required bundle is missing or stale. */
    public boolean failedClosed() {
        return bundles.health() == BundleStore.Health.FAILED;
    }

    public String failureReason() {
        return "no current policy bundle is in force";
    }

    private Optional<PolicyBundle> bundle() {
        return bundles.health() == BundleStore.Health.DISABLED
                ? Optional.empty()
                : bundles.current();
    }

    public boolean isAllowed(String serverId, String toolName) {
        if (failedClosed()) return false;
        return bundle()
                .map(b -> b.allows(serverId, toolName))
                .orElseGet(() -> local.isAllowed(serverId, toolName));
    }

    public boolean requiresApproval(String serverId, String toolName) {
        return bundle()
                .map(b -> b.requiresApproval(serverId, toolName))
                .orElseGet(() -> local.requiresApproval(serverId, toolName));
    }

    public int blockThreshold() {
        return bundle().map(PolicyBundle::blockThreshold).orElseGet(local::getBlockThreshold);
    }

    public boolean approveFirstSighting() {
        return bundle().map(PolicyBundle::approveFirstSighting)
                .orElseGet(local::isApproveFirstSighting);
    }

    /** Only a bundle can require central review; local configuration has nobody to review it. */
    public boolean requireReviewed() {
        return bundle().map(PolicyBundle::requireReviewed).orElse(false);
    }

    /** The fingerprint a human signed off for this tool, if there is one. */
    public Optional<PolicyBundle.Reviewed> reviewed(String serverId, String toolName) {
        return bundle().flatMap(b -> b.reviewed(serverId, toolName));
    }
}
