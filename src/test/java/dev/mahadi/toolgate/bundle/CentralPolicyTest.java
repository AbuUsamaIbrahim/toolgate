package dev.mahadi.toolgate.bundle;

import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.InMemoryPinStorage;
import dev.mahadi.toolgate.integrity.ToolFingerprint;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.policy.EffectivePolicy;
import dev.mahadi.toolgate.policy.PolicyEngine;
import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.scanner.InjectionScanner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.mahadi.toolgate.bundle.BundleSigningTest.MAPPER;
import static dev.mahadi.toolgate.bundle.BundleSigningTest.signed;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * What central policy is actually for: one security team's decision binding every laptop,
 * and no laptop able to widen it locally.
 */
class CentralPolicyTest {

    private static final String SERVER = "files";

    private static Mcp.Tool readFile(String description) {
        return new Mcp.Tool("read_file", "Read File", description,
                Map.of("type", "object", "properties", Map.of("path", Map.of("type", "string"))),
                null, null, null);
    }

    private static final String BENIGN = "Read the contents of a file from the workspace.";

    /** Local config is deliberately permissive, to prove the bundle overrides it. */
    private static ToolPolicyProperties permissiveLocal() {
        var props = new ToolPolicyProperties();
        var server = new ToolPolicyProperties.Server();
        server.setUrl("http://localhost:9001");
        server.setAllow(Set.of("read_file", "exec_shell", "send_email"));
        props.setServers(new LinkedHashMap<>(Map.of(SERVER, server)));
        return props;
    }

    private record Harness(PolicyEngine policy, ToolPinStore pins, EffectivePolicy effective) {}

    private Harness harness(Path dir, PolicyBundle bundle, KeyPair key) throws Exception {
        Path source = dir.resolve("bundle.json");
        Files.write(source, signed(bundle, "prod", key));

        var bp = new BundleProperties();
        bp.setSource(source.toString());
        bp.setPublicKeys(Map.of("prod", Dsse.toBase64(key.getPublic())));
        bp.setRequired(true);
        bp.setStaleGrace(Duration.ofHours(24));
        bp.setCacheFile(dir.resolve("cache.json").toString());

        var store = new BundleStore(bp, MAPPER);
        store.start();

        var effective = new EffectivePolicy(permissiveLocal(), store);
        var pins = new ToolPinStore(new InMemoryPinStorage());
        return new Harness(
                new PolicyEngine(effective, pins, new InjectionScanner(), new DriftStore()),
                pins, effective);
    }

    private static PolicyBundle bundleWith(Set<String> allow, List<PolicyBundle.Reviewed> reviewed,
                                           boolean requireReviewed, Instant expires) {
        return new PolicyBundle(PolicyBundle.SCHEMA_VERSION, 1, "security@example.com",
                Instant.now().minus(1, ChronoUnit.MINUTES), expires,
                50, false, requireReviewed,
                Map.of(SERVER, new PolicyBundle.ServerPolicy(allow, Set.of())),
                reviewed);
    }

    @Test
    @DisplayName("a developer cannot widen their own allowlist once a bundle is in force")
    void localConfigCannotWiden(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        // Local YAML allows exec_shell. The bundle does not. The bundle wins — otherwise
        // central policy is advisory and anyone who can edit a file opts out of it.
        var shell = new Mcp.Tool("exec_shell", "Run Shell", "Execute a shell command.",
                Map.of("type", "object"), null, null, null);

        assertThat(h.policy().evaluateAdvertisement(SERVER, shell))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(h.policy().evaluateAdvertisement(SERVER, readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("a server the bundle has never heard of is allowed nothing")
    void unknownServerAllowedNothing(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        assertThat(h.policy().evaluateAdvertisement("some-other-server", readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
    }

    @Test
    @DisplayName("a centrally reviewed fingerprint is the baseline, not whatever this machine saw first")
    void reviewBeatsLocalPin(@TempDir Path dir) throws Exception {
        var reviewedTool = readFile(BENIGN);
        var review = new PolicyBundle.Reviewed(SERVER, "read_file",
                ToolFingerprint.of(reviewedTool), "security@example.com",
                Instant.now().minus(1, ChronoUnit.DAYS), "read-only, no side effects");

        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(review), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        // This machine saw a *different* definition first and pinned it locally.
        var somethingElse = readFile("Read a file. Also does other things.");
        h.pins().pin(SERVER, somethingElse);

        // The locally pinned version is still refused: review outranks local history.
        assertThat(h.policy().evaluateAdvertisement(SERVER, somethingElse))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(h.policy().evaluateAdvertisement(SERVER, somethingElse).reason())
                .contains("centrally reviewed");

        // And the reviewed one is allowed even though it was never seen here before.
        assertThat(h.policy().evaluateAdvertisement(SERVER, reviewedTool))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("require-reviewed refuses anything nobody has looked at")
    void requireReviewedRefusesUnreviewed(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), true,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        var decision = h.policy().evaluateAdvertisement(SERVER, readFile(BENIGN));

        assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(decision.reason()).contains("no reviewed definition");
    }

    @Test
    @DisplayName("without require-reviewed, an unreviewed tool falls back to local pinning")
    void unreviewedFallsBackToTofu(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        assertThat(h.policy().evaluateAdvertisement(SERVER, readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
        // Still drifts locally, so the fallback is a real control and not a hole.
        assertThat(h.policy().evaluateAdvertisement(SERVER, readFile("Rewritten.")).reason())
                .contains("changed since it was pinned");
    }

    @Test
    @DisplayName("past the grace period everything is denied, including previously allowed tools")
    void expiredBundleDeniesEverything(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().minus(48, ChronoUnit.HOURS)), Dsse.generateKeyPair());

        assertThat(h.effective().failedClosed()).isTrue();

        var decision = h.policy().evaluateAdvertisement(SERVER, readFile(BENIGN));
        assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(decision.reason()).contains("no current policy bundle");

        assertThat(h.policy().evaluateCall(SERVER, "read_file"))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
    }
}
