package dev.mahadi.toolgate.telemetry;

import dev.mahadi.toolgate.bundle.BundleStore;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Reports whether the gateway is actually governing anything.
 *
 * <p>A process can be perfectly healthy by every ordinary measure — accepting connections,
 * answering quickly, no errors in the log — while enforcing a policy that expired last
 * month, or none at all. That is the failure worth alerting on, and it is invisible to a
 * liveness probe.
 *
 * <p>Stale reports {@code DOWN} rather than something softer. There is no orchestration
 * meaning attached to it here (the sidecar is not restarted by a health check), so the
 * value of the signal is entirely in whether someone is told, and "degraded" is the status
 * people learn to scroll past.
 */
@Component
public class PolicyHealthIndicator implements HealthIndicator {

    private final BundleStore bundles;

    public PolicyHealthIndicator(BundleStore bundles) {
        this.bundles = bundles;
    }

    @Override
    public Health health() {
        BundleStore.Health health = bundles.health();

        Health.Builder builder = switch (health) {
            case DISABLED, FRESH -> Health.up();
            case STALE, FAILED -> Health.down();
        };

        builder.withDetail("policy", switch (health) {
            case DISABLED -> "local configuration (no bundle configured)";
            case FRESH -> "signed bundle in force";
            case STALE -> "signed bundle has expired but is inside the grace period";
            case FAILED -> "no current policy bundle — every request is being denied";
        });

        bundles.active().ifPresent(active -> {
            builder.withDetail("sequence", active.bundle().sequence());
            builder.withDetail("issuer", active.bundle().issuer());
            builder.withDetail("expiresAt", String.valueOf(active.bundle().expiresAt()));
            builder.withDetail("signedBy", active.keyId());
        });

        return builder.build();
    }
}
