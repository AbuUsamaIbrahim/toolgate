package dev.mahadi.toolgate.bundle;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.util.FilePaths;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the active policy bundle and keeps it fresh.
 *
 * <h2>Three rules, each protecting against a different failure</h2>
 *
 * <ul>
 *   <li><b>A failed refresh keeps the last good bundle.</b> Losing the network must not
 *       silently unload policy. The alternative — reverting to no bundle — means an outage
 *       at the distribution point becomes a fleet-wide disarm, which is a far better attack
 *       than anything against the gateway itself.</li>
 *   <li><b>Sequence must increase.</b> A signature proves a bundle is authentic, not that
 *       it is current. Without this, capturing yesterday's validly signed bundle and
 *       serving it back restores every tool that was removed today.</li>
 *   <li><b>Staleness has a deadline.</b> A laptop offline for a week should keep enforcing;
 *       a laptop offline for a quarter should not still be enforcing last quarter's rules.
 *       Past the grace period it fails closed rather than pretending to be current.</li>
 * </ul>
 *
 * <p>The cached copy on disk exists so a restart while offline does not start with nothing.
 * It is re-verified on load exactly like a fresh download — the cache is a convenience, not
 * a trust boundary, and a file on the developer's own machine is precisely the thing an
 * attacker on that machine can edit.
 */
@Component
public class BundleStore {

    private static final Logger log = LoggerFactory.getLogger(BundleStore.class);

    private final BundleProperties props;
    private final ObjectMapper mapper;
    private final AtomicReference<Active> active = new AtomicReference<>();

    private BundleVerifier verifier;
    private ScheduledExecutorService scheduler;
    private HttpClient http;

    public BundleStore(BundleProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
    }

    public record Active(PolicyBundle bundle, String keyId, Instant loadedAt) {}

    /** How the gateway should behave right now, given the bundle it has. */
    public enum Health {
        /** No bundle configured; local YAML is authoritative. */
        DISABLED,
        /** A current bundle is in force. */
        FRESH,
        /** Past expiry but inside the grace period. Enforcing, and complaining. */
        STALE,
        /** Past grace, or never loaded while required. Deny everything. */
        FAILED
    }

    @PostConstruct
    void start() {
        if (!props.enabled()) {
            log.info("No policy bundle configured — local configuration is authoritative");
            return;
        }
        this.verifier = new BundleVerifier(mapper, props.getPublicKeys());
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

        // Cache first, then network — and the order is the point. The cache records the
        // highest sequence this gateway has ever accepted, so loading it establishes the
        // anti-rollback floor before anything is fetched. Fetching first would mean a
        // restart forgets that floor, and replaying an old signed bundle at a gateway that
        // has just come up would work every time. Rollback protection that a restart
        // clears is not rollback protection; it is a reason to restart the gateway.
        loadCache();
        boolean loaded = refresh();
        if (!loaded && active.get() != null) {
            loaded = true;      // the cached bundle is in force, which is a valid state
        }
        if (!loaded && props.isRequired()) {
            // Refusing to start is the honest outcome. Starting anyway would leave a
            // gateway that looks healthy and enforces nothing, which is worse than a
            // gateway that is visibly down.
            throw new IllegalStateException(
                    "policy bundle is required but none could be loaded from " + props.getSource());
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "toolgate-bundle-refresh");
            t.setDaemon(true);
            return t;
        });
        long seconds = Math.max(30, props.getRefreshInterval().toSeconds());
        scheduler.scheduleAtFixedRate(this::refreshQuietly, seconds, seconds, TimeUnit.SECONDS);
    }

    @PreDestroy
    void stop() {
        if (scheduler != null) scheduler.shutdownNow();
    }

    public Optional<PolicyBundle> current() {
        Active a = active.get();
        return a == null ? Optional.empty() : Optional.of(a.bundle());
    }

    public Optional<Active> active() {
        return Optional.ofNullable(active.get());
    }

    public Health health() {
        if (!props.enabled()) return Health.DISABLED;
        Active a = active.get();
        if (a == null) return Health.FAILED;

        Instant now = Instant.now();
        if (!a.bundle().expired(now)) return Health.FRESH;
        return now.isAfter(a.bundle().expiresAt().plus(props.getStaleGrace()))
                ? Health.FAILED
                : Health.STALE;
    }

    private void refreshQuietly() {
        try {
            refresh();
        } catch (RuntimeException e) {
            log.warn("Bundle refresh failed: {}", e.toString());
        }
    }

    /** @return true if a new bundle was accepted */
    public boolean refresh() {
        byte[] bytes;
        try {
            bytes = fetch();
        } catch (Exception e) {
            log.warn("Could not fetch policy bundle from {}: {} — keeping the bundle already "
                    + "in force", props.getSource(), e.toString());
            return false;
        }
        return accept(bytes, true);
    }

    private boolean accept(byte[] bytes, boolean cache) {
        BundleVerifier.Verified verified;
        try {
            verified = verifier.verify(bytes);
        } catch (BundleVerifier.UntrustedBundleException e) {
            // Loud, and not fatal to what is already loaded. A bad bundle at the
            // distribution point must not be able to unload a good one.
            log.error("REJECTED policy bundle from {}: {}", props.getSource(), e.getMessage());
            return false;
        }

        Active existing = active.get();
        if (existing != null && verified.bundle().sequence() <= existing.bundle().sequence()) {
            if (verified.bundle().sequence() < existing.bundle().sequence()) {
                log.error("REJECTED policy bundle: sequence {} is older than the active {} — "
                                + "this is what a rollback attack looks like",
                        verified.bundle().sequence(), existing.bundle().sequence());
            }
            return false;
        }

        active.set(new Active(verified.bundle(), verified.keyId(), Instant.now()));
        log.info("Policy bundle {} in force: sequence={} issuer={} expires={} reviewed={} key={}",
                verified.bundle().schemaVersion(), verified.bundle().sequence(),
                verified.bundle().issuer(), verified.bundle().expiresAt(),
                verified.bundle().reviewedTools() == null ? 0 : verified.bundle().reviewedTools().size(),
                verified.keyId());

        if (cache) writeCache(bytes);
        return true;
    }

    private byte[] fetch() throws Exception {
        String source = props.getSource();
        if (source.startsWith("http://") || source.startsWith("https://")) {
            var request = HttpRequest.newBuilder(URI.create(source))
                    .timeout(Duration.ofSeconds(20))
                    .GET();

            // The bundle is signed, so a credential here buys confidentiality rather than
            // integrity — nobody can forge policy by intercepting this. It still matters:
            // the bundle is a precise description of which tools are reachable and which
            // need a human, which is a useful thing for an attacker to read before
            // deciding what to try.
            String token = controlToken();
            if (!token.isEmpty()) request.header("Authorization", "Bearer " + token);

            HttpResponse<byte[]> response = http.send(request.build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("HTTP " + response.statusCode());
            }
            return response.body();
        }
        return Files.readAllBytes(FilePaths.expandUser(source));
    }

    /**
     * From the environment, not configuration: on a developer machine this is whatever the
     * login flow deposited and it is rotated every few hours. A file that has to be
     * rewritten that often would be rewritten wrongly.
     */
    private static String controlToken() {
        String t = System.getenv("TOOLGATE_CONTROL_TOKEN");
        return t == null ? "" : t.trim();
    }

    private Path cachePath() {
        return FilePaths.expandUser(props.getCacheFile());
    }

    private void writeCache(byte[] bytes) {
        if (props.getCacheFile() == null || props.getCacheFile().isBlank()) return;
        try {
            Path path = cachePath();
            Files.createDirectories(path.getParent());
            Files.write(path, bytes);
            FilePaths.restrictToOwner(path);
        } catch (Exception e) {
            log.debug("Could not cache bundle: {}", e.toString());
        }
    }

    private boolean loadCache() {
        if (props.getCacheFile() == null || props.getCacheFile().isBlank()) return false;
        Path path = cachePath();
        if (!Files.exists(path)) return false;
        try {
            log.info("Falling back to the cached bundle at {}", path);
            // Re-verified, not trusted. This file lives on the machine being defended.
            return accept(Files.readAllBytes(path), false);
        } catch (Exception e) {
            log.warn("Cached bundle unusable: {}", e.toString());
            return false;
        }
    }
}
