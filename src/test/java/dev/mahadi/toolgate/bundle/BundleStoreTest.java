package dev.mahadi.toolgate.bundle;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static dev.mahadi.toolgate.bundle.BundleSigningTest.MAPPER;
import static dev.mahadi.toolgate.bundle.BundleSigningTest.bundle;
import static dev.mahadi.toolgate.bundle.BundleSigningTest.signed;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Distribution behaviour: what happens when the bundle is old, replayed, absent, or the
 * network is gone. These matter more than the cryptography, because they are the states a
 * real fleet spends its time in.
 */
class BundleStoreTest {

    private KeyPair signing;

    @BeforeEach
    void setUp() {
        signing = Dsse.generateKeyPair();
    }

    private BundleStore storeFor(Path source, boolean required, Duration grace) {
        var props = new BundleProperties();
        props.setSource(source.toString());
        props.setPublicKeys(Map.of("prod-2026", Dsse.toBase64(signing.getPublic())));
        props.setRequired(required);
        props.setStaleGrace(grace);
        // Never the real ~/.toolgate: a test run must not be able to leave a bundle behind
        // on a machine that also runs the gateway.
        props.setCacheFile(source.resolveSibling("bundle.cache.json").toString());
        return new BundleStore(props, MAPPER);
    }

    private void write(Path path, PolicyBundle b) throws Exception {
        Files.write(path, signed(b, "prod-2026", signing));
    }

    @Test
    @DisplayName("a valid bundle is loaded and becomes authoritative")
    void loadsValidBundle(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        assertThat(store.health()).isEqualTo(BundleStore.Health.FRESH);
        assertThat(store.current()).isPresent();
        assertThat(store.current().get().allows("files", "read_file", java.util.Set.of())).isTrue();
    }

    @Test
    @DisplayName("replaying an older signed bundle is refused")
    void rollbackRefused(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(5, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(5);

        // An attacker serves back a genuinely signed, genuinely older bundle — the one from
        // before a dangerous tool was removed. The signature is perfectly valid.
        write(source, bundle(4, Instant.now().plus(1, ChronoUnit.DAYS)));

        assertThat(store.refresh()).isFalse();
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(5);
    }

    @Test
    @DisplayName("re-serving the same sequence changes nothing")
    void sameSequenceIgnored(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(7, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        assertThat(store.refresh()).isFalse();
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(7);
    }

    @Test
    @DisplayName("a newer sequence is adopted")
    void newerSequenceAdopted(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        write(source, bundle(2, Instant.now().plus(1, ChronoUnit.DAYS)));

        assertThat(store.refresh()).isTrue();
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(2);
    }

    @Test
    @DisplayName("an unreachable source keeps the bundle already in force")
    void failedRefreshKeepsLastGood(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(3, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        // The distribution point goes away. Unloading policy here would turn an outage at
        // the publisher into a fleet-wide disarm.
        Files.delete(source);

        assertThat(store.refresh()).isFalse();
        assertThat(store.health()).isEqualTo(BundleStore.Health.FRESH);
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(3);
    }

    @Test
    @DisplayName("a corrupt bundle at the source cannot unload a good one")
    void badBundleDoesNotUnload(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(3, Instant.now().plus(1, ChronoUnit.DAYS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        Files.writeString(source, "{ not a bundle");

        assertThat(store.refresh()).isFalse();
        assertThat(store.current().orElseThrow().sequence()).isEqualTo(3);
    }

    @Test
    @DisplayName("past expiry but inside grace, the gateway still enforces")
    void staleWithinGraceStillEnforces(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(1, Instant.now().minus(1, ChronoUnit.HOURS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        assertThat(store.health()).isEqualTo(BundleStore.Health.STALE);
        assertThat(store.current()).isPresent();
    }

    @Test
    @DisplayName("past the grace period, the gateway fails closed")
    void pastGraceFailsClosed(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(1, Instant.now().minus(48, ChronoUnit.HOURS)));

        var store = storeFor(source, true, Duration.ofHours(24));
        store.start();

        assertThat(store.health()).isEqualTo(BundleStore.Health.FAILED);
    }

    @Test
    @DisplayName("a required bundle that cannot be loaded aborts startup")
    void requiredButMissingAbortsStartup(@TempDir Path dir) {
        var store = storeFor(dir.resolve("does-not-exist.json"), true, Duration.ofHours(24));

        // Starting anyway would leave a gateway that looks healthy and enforces nothing.
        assertThatThrownBy(store::start)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("required");
    }

    @Test
    @DisplayName("a restart does not forget the anti-rollback floor")
    void rollbackRefusedAcrossRestart(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(9, Instant.now().plus(1, ChronoUnit.DAYS)));

        var first = storeFor(source, true, Duration.ofHours(24));
        first.start();
        assertThat(first.current().orElseThrow().sequence()).isEqualTo(9);

        // The gateway restarts — a deploy, a laptop waking up — and at that moment the
        // source is serving an older, validly signed bundle. In-process rollback
        // protection is worthless here unless the floor survived the restart.
        write(source, bundle(8, Instant.now().plus(1, ChronoUnit.DAYS)));

        var restarted = storeFor(source, true, Duration.ofHours(24));
        restarted.start();

        assertThat(restarted.current().orElseThrow().sequence()).isEqualTo(9);
    }

    @Test
    @DisplayName("a cached bundle carries a restart through an unreachable source")
    void cacheSurvivesOfflineRestart(@TempDir Path dir) throws Exception {
        Path source = dir.resolve("bundle.json");
        write(source, bundle(4, Instant.now().plus(1, ChronoUnit.DAYS)));

        storeFor(source, true, Duration.ofHours(24)).start();
        Files.delete(source);      // laptop is now offline

        var restarted = storeFor(source, true, Duration.ofHours(24));
        restarted.start();         // required=true, so this would throw without the cache

        assertThat(restarted.current().orElseThrow().sequence()).isEqualTo(4);
        assertThat(restarted.health()).isEqualTo(BundleStore.Health.FRESH);
    }

    @Test
    @DisplayName("with no bundle configured the store is inert, not failed")
    void disabledWhenUnconfigured() {
        var store = new BundleStore(new BundleProperties(), MAPPER);
        store.start();

        assertThat(store.health()).isEqualTo(BundleStore.Health.DISABLED);
        assertThat(store.current()).isEmpty();
    }
}
