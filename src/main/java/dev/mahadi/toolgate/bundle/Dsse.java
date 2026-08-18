package dev.mahadi.toolgate.bundle;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 signing over a DSSE-style pre-authentication encoding.
 *
 * <p>The obvious way to sign a JSON document is to serialise it and sign the string. That
 * breaks the first time anything reserialises the object, because key order, whitespace and
 * number formatting are all free to change and the signature is over bytes, not meaning.
 * Every system that tries this eventually grows a canonicalisation spec, and
 * canonicalisation bugs are a rich source of signature-bypass vulnerabilities.
 *
 * <p>So the signature covers the <em>exact bytes</em> that were signed, carried verbatim in
 * the envelope as base64. Verification never reserialises anything; it checks the bytes and
 * only then parses them. Parsing is a consequence of trust, not a step towards it.
 *
 * <p>The payload type is signed alongside the payload — the PAE construction below, from
 * in-toto's DSSE. Without it, a signature over one kind of document could be replayed as a
 * signature over a different kind that happens to parse.
 */
public final class Dsse {

    public static final String PAYLOAD_TYPE = "application/vnd.toolgate.bundle+json";

    private static final String ALGORITHM = "Ed25519";

    private Dsse() {}

    /**
     * Pre-authentication encoding: {@code DSSEv1 SP len(type) SP type SP len(body) SP body}.
     *
     * <p>Length-prefixing is what stops a crafted payload from impersonating a different
     * (type, payload) pair by moving the boundary between them.
     */
    static byte[] pae(String payloadType, byte[] payload) {
        byte[] typeBytes = payloadType.getBytes(StandardCharsets.UTF_8);
        String prefix = "DSSEv1 " + typeBytes.length + " " + payloadType + " "
                + payload.length + " ";
        byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);

        byte[] out = new byte[prefixBytes.length + payload.length];
        System.arraycopy(prefixBytes, 0, out, 0, prefixBytes.length);
        System.arraycopy(payload, 0, out, prefixBytes.length, payload.length);
        return out;
    }

    public static byte[] sign(PrivateKey key, byte[] payload) {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initSign(key);
            sig.update(pae(PAYLOAD_TYPE, payload));
            return sig.sign();
        } catch (Exception e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    public static boolean verify(PublicKey key, byte[] payload, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(ALGORITHM);
            sig.initVerify(key);
            sig.update(pae(PAYLOAD_TYPE, payload));
            return sig.verify(signature);
        } catch (Exception e) {
            // A malformed signature is a failed verification, not an error to propagate.
            // Callers must not be able to tell "invalid" from "broken" — both mean no.
            return false;
        }
    }

    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("key generation failed", e);
        }
    }

    public static PublicKey publicKeyFromBase64(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64.trim());
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("not a valid Ed25519 public key: " + e.getMessage(), e);
        }
    }

    public static PrivateKey privateKeyFromBase64(String base64) {
        try {
            byte[] der = Base64.getDecoder().decode(base64.trim());
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("not a valid Ed25519 private key: " + e.getMessage(), e);
        }
    }

    public static String toBase64(java.security.Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}
