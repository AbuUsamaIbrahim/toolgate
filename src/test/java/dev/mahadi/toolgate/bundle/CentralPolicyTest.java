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

    /** Pins held in memory only, so a test run never touches the real trust store. */
    static dev.mahadi.toolgate.integrity.SurfacePinStore memoryPins() {
        var pinProps = new dev.mahadi.toolgate.integrity.PinProperties();
        pinProps.setFile("");
        return new dev.mahadi.toolgate.integrity.SurfacePinStore(
                pinProps, new com.fasterxml.jackson.databind.ObjectMapper());
    }

    /** A caller with no team membership: the base policy, and nothing extra. */
    static final dev.mahadi.toolgate.auth.AccessToken ANYONE =
            new dev.mahadi.toolgate.auth.AccessToken(
                    "test-caller", java.util.Set.of("tools:read", "tools:call"),
                    java.util.Set.of(), null, null);

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
                new PolicyEngine(effective, pins, new InjectionScanner(), new DriftStore(), memoryPins()),
                pins, effective);
    }

    private static PolicyBundle bundleWith(Set<String> allow, List<PolicyBundle.Reviewed> reviewed,
                                           boolean requireReviewed, Instant expires) {
        return bundleWith(allow, reviewed, requireReviewed, expires, Map.of());
    }

    private static PolicyBundle bundleWith(Set<String> allow, List<PolicyBundle.Reviewed> reviewed,
                                           boolean requireReviewed, Instant expires,
                                           Map<String, Map<String, PolicyBundle.ServerPolicy>> teamPolicies) {
        return new PolicyBundle(PolicyBundle.SCHEMA_VERSION, 1, "security@example.com",
                Instant.now().minus(1, ChronoUnit.MINUTES), expires,
                50, false, requireReviewed,
                Map.of(SERVER, new PolicyBundle.ServerPolicy(allow, Set.of())),
                reviewed, teamPolicies);
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

        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, shell))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("a server the bundle has never heard of is allowed nothing")
    void unknownServerAllowedNothing(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        assertThat(h.policy().evaluateAdvertisement(ANYONE, "some-other-server", readFile(BENIGN)))
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
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, somethingElse))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, somethingElse).reason())
                .contains("centrally reviewed");

        // And the reviewed one is allowed even though it was never seen here before.
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, reviewedTool))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("require-reviewed refuses anything nobody has looked at")
    void requireReviewedRefusesUnreviewed(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), true,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        var decision = h.policy().evaluateAdvertisement(ANYONE, SERVER, readFile(BENIGN));

        assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(decision.reason()).contains("no reviewed definition");
    }

    @Test
    @DisplayName("without require-reviewed, an unreviewed tool falls back to local pinning")
    void unreviewedFallsBackToTofu(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS)), Dsse.generateKeyPair());

        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
        // Still drifts locally, so the fallback is a real control and not a hole.
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, readFile("Rewritten.")).reason())
                .contains("changed since it was pinned");
    }

    private static dev.mahadi.toolgate.auth.AccessToken memberOf(String... teams) {
        return new dev.mahadi.toolgate.auth.AccessToken(
                "someone@example.com", Set.of("tools:read", "tools:call"),
                Set.of(teams), null, null);
    }

    @Test
    @DisplayName("a team gets access the base policy does not grant")
    void teamGrantsExtraAccess(@TempDir Path dir) throws Exception {
        var teamPolicies = Map.of("platform",
                Map.of(SERVER, new PolicyBundle.ServerPolicy(Set.of("send_email"), Set.of())));

        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS), teamPolicies), Dsse.generateKeyPair());

        var email = new Mcp.Tool("send_email", "Send Email", "Send an email.",
                Map.of("type", "object"), null, null, null);

        assertThat(h.policy().evaluateAdvertisement(memberOf("platform"), SERVER, email))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
        assertThat(h.policy().evaluateAdvertisement(memberOf("billing"), SERVER, email))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(h.policy().evaluateAdvertisement(ANYONE, SERVER, email))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
    }

    @Test
    @DisplayName("everyone keeps the base policy regardless of team")
    void baseAppliesToEveryone(@TempDir Path dir) throws Exception {
        var teamPolicies = Map.of("platform",
                Map.of(SERVER, new PolicyBundle.ServerPolicy(Set.of("send_email"), Set.of())));

        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS), teamPolicies), Dsse.generateKeyPair());

        assertThat(h.policy().evaluateAdvertisement(memberOf("billing"), SERVER, readFile(BENIGN)))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("belonging to two teams grants the union")
    void multipleTeamsUnion(@TempDir Path dir) throws Exception {
        var teamPolicies = Map.of(
                "platform", Map.of(SERVER, new PolicyBundle.ServerPolicy(Set.of("send_email"), Set.of())),
                "billing", Map.of(SERVER, new PolicyBundle.ServerPolicy(Set.of("exec_shell"), Set.of())));

        var h = harness(dir, bundleWith(Set.of(), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS), teamPolicies), Dsse.generateKeyPair());

        var both = memberOf("platform", "billing");
        var email = new Mcp.Tool("send_email", "Send Email", "Send an email.",
                Map.of("type", "object"), null, null, null);
        var shell = new Mcp.Tool("exec_shell", "Run Shell", "Run a command.",
                Map.of("type", "object"), null, null, null);

        assertThat(h.policy().evaluateAdvertisement(both, SERVER, email))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
        assertThat(h.policy().evaluateAdvertisement(both, SERVER, shell))
                .isInstanceOf(PolicyEngine.Decision.Allow.class);
    }

    @Test
    @DisplayName("a team can require approval for the access it grants")
    void teamCanRequireApproval(@TempDir Path dir) throws Exception {
        var teamPolicies = Map.of("platform",
                Map.of(SERVER, new PolicyBundle.ServerPolicy(
                        Set.of("send_email"), Set.of("send_email"))));

        var h = harness(dir, bundleWith(Set.of(), List.of(), false,
                Instant.now().plus(1, ChronoUnit.DAYS), teamPolicies), Dsse.generateKeyPair());

        var email = new Mcp.Tool("send_email", "Send Email", "Send an email.",
                Map.of("type", "object"), null, null, null);
        var caller = memberOf("platform");
        h.policy().evaluateAdvertisement(caller, SERVER, email);

        assertThat(h.policy().evaluateCall(caller, SERVER, "send_email"))
                .isInstanceOf(PolicyEngine.Decision.NeedsApproval.class);
    }

    @Test
    @DisplayName("a team cannot remove an approval requirement the base policy set")
    void teamCannotWeakenApproval(@TempDir Path dir) throws Exception {
        // The team entry grants send_email with no approval requirement. The base policy
        // says it needs one. Team membership must not be a way to switch a control off.
        var teamPolicies = Map.of("platform",
                Map.of(SERVER, new PolicyBundle.ServerPolicy(Set.of("send_email"), Set.of())));

        var base = new PolicyBundle(PolicyBundle.SCHEMA_VERSION, 1, "security@example.com",
                Instant.now().minus(1, ChronoUnit.MINUTES),
                Instant.now().plus(1, ChronoUnit.DAYS), 50, false, false,
                Map.of(SERVER, new PolicyBundle.ServerPolicy(
                        Set.of("send_email"), Set.of("send_email"))),
                List.of(), teamPolicies);

        var h = harness(dir, base, Dsse.generateKeyPair());
        var email = new Mcp.Tool("send_email", "Send Email", "Send an email.",
                Map.of("type", "object"), null, null, null);
        var caller = memberOf("platform");
        h.policy().evaluateAdvertisement(caller, SERVER, email);

        assertThat(h.policy().evaluateCall(caller, SERVER, "send_email"))
                .isInstanceOf(PolicyEngine.Decision.NeedsApproval.class);
    }

    @Test
    @DisplayName("past the grace period everything is denied, including previously allowed tools")
    void expiredBundleDeniesEverything(@TempDir Path dir) throws Exception {
        var h = harness(dir, bundleWith(Set.of("read_file"), List.of(), false,
                Instant.now().minus(48, ChronoUnit.HOURS)), Dsse.generateKeyPair());

        assertThat(h.effective().failedClosed()).isTrue();

        var decision = h.policy().evaluateAdvertisement(ANYONE, SERVER, readFile(BENIGN));
        assertThat(decision).isInstanceOf(PolicyEngine.Decision.Deny.class);
        assertThat(decision.reason()).contains("no current policy bundle");

        assertThat(h.policy().evaluateCall(ANYONE, SERVER, "read_file"))
                .isInstanceOf(PolicyEngine.Decision.Deny.class);
    }
}
