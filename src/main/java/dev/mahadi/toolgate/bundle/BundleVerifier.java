package dev.mahadi.toolgate.bundle;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Turns bytes off the network into a bundle you are allowed to believe.
 *
 * <p>The order of operations is the security property: verify the signature over the raw
 * bytes, and only then parse them. Parsing first — even just to read the key id — hands
 * attacker-controlled data to a deserialiser before anything has been authenticated.
 * The envelope is the one exception, and it is deliberately tiny: three fields, no nesting.
 */
public class BundleVerifier {

    private final ObjectMapper mapper;
    private final Map<String, PublicKey> trustedKeys;

    public BundleVerifier(ObjectMapper mapper, Map<String, String> base64Keys) {
        this.mapper = mapper;
        Map<String, PublicKey> keys = new HashMap<>();
        base64Keys.forEach((id, b64) -> keys.put(id, Dsse.publicKeyFromBase64(b64)));
        this.trustedKeys = Map.copyOf(keys);
    }

    public static class UntrustedBundleException extends RuntimeException {
        public UntrustedBundleException(String message) { super(message); }
        public UntrustedBundleException(String message, Throwable cause) { super(message, cause); }
    }

    /** The verified bundle together with the key that vouched for it. */
    public record Verified(PolicyBundle bundle, String keyId) {}

    public Verified verify(byte[] envelopeBytes) {
        if (trustedKeys.isEmpty()) {
            throw new UntrustedBundleException(
                    "no signing keys configured — a bundle cannot be trusted without one");
        }

        BundleEnvelope envelope;
        try {
            envelope = mapper.readValue(envelopeBytes, BundleEnvelope.class);
        } catch (Exception e) {
            throw new UntrustedBundleException("bundle envelope is not readable", e);
        }

        if (!Dsse.PAYLOAD_TYPE.equals(envelope.payloadType())) {
            throw new UntrustedBundleException(
                    "unexpected payload type: " + envelope.payloadType());
        }
        if (envelope.signatures() == null || envelope.signatures().isEmpty()) {
            throw new UntrustedBundleException("bundle carries no signatures");
        }

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(envelope.payload());
        } catch (IllegalArgumentException e) {
            throw new UntrustedBundleException("bundle payload is not valid base64", e);
        }

        // One good signature is enough. Requiring every signature to verify would mean a
        // single lost or retired key takes the whole fleet down, which turns key rotation
        // into an outage and therefore into something nobody does.
        String acceptedKey = null;
        for (BundleEnvelope.Signature s : envelope.signatures()) {
            PublicKey key = trustedKeys.get(s.keyid());
            if (key == null) continue;      // signed by a key we do not trust: ignore it
            byte[] sig;
            try {
                sig = Base64.getDecoder().decode(s.sig());
            } catch (IllegalArgumentException e) {
                continue;
            }
            if (Dsse.verify(key, payload, sig)) {
                acceptedKey = s.keyid();
                break;
            }
        }
        if (acceptedKey == null) {
            throw new UntrustedBundleException(
                    "no signature from a trusted key verified against the payload");
        }

        PolicyBundle bundle;
        try {
            bundle = mapper.readValue(payload, PolicyBundle.class);
        } catch (Exception e) {
            throw new UntrustedBundleException("bundle payload is not readable", e);
        }
        if (!PolicyBundle.READABLE_SCHEMA_VERSIONS.contains(bundle.schemaVersion())) {
            throw new UntrustedBundleException(
                    "bundle schema version %d is not supported by this gateway (reads %s)"
                            .formatted(bundle.schemaVersion(), PolicyBundle.READABLE_SCHEMA_VERSIONS));
        }
        return new Verified(bundle, acceptedKey);
    }

    /** Signs a bundle. Used by the CLI, and by tests that need a real signature. */
    public static BundleEnvelope signBundle(ObjectMapper mapper, PolicyBundle bundle,
                                            String keyId, java.security.PrivateKey key) {
        try {
            byte[] payload = mapper.writeValueAsBytes(bundle);
            byte[] sig = Dsse.sign(key, payload);
            return new BundleEnvelope(
                    Dsse.PAYLOAD_TYPE,
                    Base64.getEncoder().encodeToString(payload),
                    java.util.List.of(new BundleEnvelope.Signature(
                            keyId, Base64.getEncoder().encodeToString(sig))));
        } catch (Exception e) {
            throw new IllegalStateException("could not sign bundle", e);
        }
    }
}
