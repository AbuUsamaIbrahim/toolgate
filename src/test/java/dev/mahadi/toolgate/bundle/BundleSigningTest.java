package dev.mahadi.toolgate.bundle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A signature check is only as good as what it refuses. These are the ways signed-artifact
 * verification is usually got wrong.
 */
class BundleSigningTest {

    static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private KeyPair signing;
    private BundleVerifier verifier;

    @BeforeEach
    void setUp() {
        signing = Dsse.generateKeyPair();
        verifier = new BundleVerifier(MAPPER,
                Map.of("prod-2026", Dsse.toBase64(signing.getPublic())));
    }

    static PolicyBundle bundle(long sequence, Instant expires) {
        return new PolicyBundle(
                PolicyBundle.SCHEMA_VERSION, sequence, "security@example.com",
                Instant.now().minus(1, ChronoUnit.MINUTES), expires,
                50, false, false,
                Map.of("files", new PolicyBundle.ServerPolicy(Set.of("read_file"), Set.of())),
                List.of(), Map.of());
    }

    static byte[] signed(PolicyBundle b, String keyId, KeyPair key) throws Exception {
        return MAPPER.writeValueAsBytes(
                BundleVerifier.signBundle(MAPPER, b, keyId, key.getPrivate()));
    }

    @Test
    @DisplayName("a correctly signed bundle verifies")
    void validBundleAccepted() throws Exception {
        var verified = verifier.verify(
                signed(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)), "prod-2026", signing));

        assertThat(verified.keyId()).isEqualTo("prod-2026");
        assertThat(verified.bundle().sequence()).isEqualTo(1);
        assertThat(verified.bundle().allows("files", "read_file", Set.of())).isTrue();
    }

    @Test
    @DisplayName("a payload edited after signing is refused")
    void tamperedPayloadRejected() throws Exception {
        byte[] envelopeBytes = signed(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)),
                "prod-2026", signing);
        var envelope = MAPPER.readValue(envelopeBytes, BundleEnvelope.class);

        // Widen the allowlist the way an attacker would, keeping the original signature.
        var original = bundle(1, Instant.now().plus(1, ChronoUnit.DAYS));
        var widened = new PolicyBundle(
                original.schemaVersion(), original.sequence(), original.issuer(),
                original.issuedAt(), original.expiresAt(), original.blockThreshold(),
                original.approveFirstSighting(), original.requireReviewed(),
                Map.of("files", new PolicyBundle.ServerPolicy(
                        Set.of("read_file", "exec_shell"), Set.of())),
                List.of(), Map.of());

        var forged = new BundleEnvelope(envelope.payloadType(),
                Base64.getEncoder().encodeToString(MAPPER.writeValueAsBytes(widened)),
                envelope.signatures());

        assertThatThrownBy(() -> verifier.verify(MAPPER.writeValueAsBytes(forged)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class)
                .hasMessageContaining("no signature from a trusted key");
    }

    @Test
    @DisplayName("a bundle signed by an untrusted key is refused")
    void wrongKeyRejected() {
        KeyPair attacker = Dsse.generateKeyPair();

        assertThatThrownBy(() -> verifier.verify(
                signed(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)), "prod-2026", attacker)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class);
    }

    @Test
    @DisplayName("claiming an unknown key id does not bypass verification")
    void unknownKeyIdRejected() {
        assertThatThrownBy(() -> verifier.verify(
                signed(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)), "not-a-key", signing)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class);
    }

    @Test
    @DisplayName("an envelope with no signatures is refused")
    void unsignedRejected() throws Exception {
        var payload = Base64.getEncoder().encodeToString(
                MAPPER.writeValueAsBytes(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS))));
        var envelope = new BundleEnvelope(Dsse.PAYLOAD_TYPE, payload, List.of());

        assertThatThrownBy(() -> verifier.verify(MAPPER.writeValueAsBytes(envelope)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class)
                .hasMessageContaining("no signatures");
    }

    @Test
    @DisplayName("a signature over a different payload type does not transfer")
    void payloadTypeIsSigned() throws Exception {
        byte[] payload = MAPPER.writeValueAsBytes(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)));
        byte[] sig = Dsse.sign(signing.getPrivate(), payload);

        // Same bytes, same signature, different declared type.
        var envelope = new BundleEnvelope("application/json",
                Base64.getEncoder().encodeToString(payload),
                List.of(new BundleEnvelope.Signature("prod-2026",
                        Base64.getEncoder().encodeToString(sig))));

        assertThatThrownBy(() -> verifier.verify(MAPPER.writeValueAsBytes(envelope)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class)
                .hasMessageContaining("payload type");
    }

    @Test
    @DisplayName("verification with no configured keys refuses everything")
    void noKeysMeansNoTrust() {
        var empty = new BundleVerifier(MAPPER, Map.of());

        assertThatThrownBy(() -> empty.verify(
                signed(bundle(1, Instant.now().plus(1, ChronoUnit.DAYS)), "prod-2026", signing)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class)
                .hasMessageContaining("no signing keys configured");
    }

    @Test
    @DisplayName("either key verifies during a rotation")
    void rotationAcceptsBothKeys() throws Exception {
        KeyPair incoming = Dsse.generateKeyPair();
        var rotating = new BundleVerifier(MAPPER, Map.of(
                "prod-2026", Dsse.toBase64(signing.getPublic()),
                "prod-2027", Dsse.toBase64(incoming.getPublic())));

        var b = bundle(2, Instant.now().plus(1, ChronoUnit.DAYS));

        assertThat(rotating.verify(signed(b, "prod-2026", signing)).keyId()).isEqualTo("prod-2026");
        assertThat(rotating.verify(signed(b, "prod-2027", incoming)).keyId()).isEqualTo("prod-2027");
    }

    @Test
    @DisplayName("a future schema version is refused rather than half-understood")
    void unknownSchemaRejected() {
        var future = new PolicyBundle(99, 1, "x", Instant.now(),
                Instant.now().plus(1, ChronoUnit.DAYS), 50, false, false,
                Map.of(), List.of(), Map.of());

        assertThatThrownBy(() -> verifier.verify(signed(future, "prod-2026", signing)))
                .isInstanceOf(BundleVerifier.UntrustedBundleException.class)
                .hasMessageContaining("schema version");
    }
}
