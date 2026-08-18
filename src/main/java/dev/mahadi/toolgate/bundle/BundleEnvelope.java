package dev.mahadi.toolgate.bundle;

import java.util.List;

/**
 * The signed wrapper around a {@link PolicyBundle}.
 *
 * <p>{@code payload} is the base64 of the exact bundle bytes that were signed — see
 * {@link Dsse} for why it is carried verbatim rather than reserialised.
 *
 * <p>Multiple signatures are permitted so a key can be rotated without a flag day: publish
 * bundles signed by both the outgoing and incoming key, roll the gateways' trusted key set,
 * then drop the old one. A single accepted signature is sufficient — requiring all of them
 * would mean losing one key takes the fleet down.
 */
public record BundleEnvelope(String payloadType, String payload, List<Signature> signatures) {

    public record Signature(String keyid, String sig) {}
}
