package dev.mahadi.toolgate.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.mahadi.toolgate.bundle.BundleEnvelope;
import dev.mahadi.toolgate.bundle.BundleVerifier;
import dev.mahadi.toolgate.bundle.Dsse;
import dev.mahadi.toolgate.bundle.PolicyBundle;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

/**
 * Creates, signs and inspects policy bundles.
 *
 * <p>Kept as a plain {@code main} rather than a Spring command so it can run without
 * booting the gateway — the person signing a bundle is on a release machine or in CI, and
 * has no reason to start a server to produce a file.
 *
 * <pre>
 *   java -cp toolgate.jar dev.mahadi.toolgate.cli.BundleTool keygen
 *   java -cp toolgate.jar dev.mahadi.toolgate.cli.BundleTool sign policy.json key.pem prod-2026 out.json
 *   java -cp toolgate.jar dev.mahadi.toolgate.cli.BundleTool verify out.json prod-2026 &lt;pubkey&gt;
 *   java -cp toolgate.jar dev.mahadi.toolgate.cli.BundleTool inspect out.json
 * </pre>
 */
public final class BundleTool {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    private static final ObjectMapper PRETTY = MAPPER.copy()
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        switch (args[0]) {
            case "keygen" -> keygen();
            case "sign" -> sign(args);
            case "verify" -> verify(args);
            case "inspect" -> inspect(args);
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private static void usage() {
        System.err.println("""
                toolgate bundle tool

                  keygen
                      Print a new Ed25519 key pair. The private key signs bundles and
                      belongs in your secret store; the public key goes in every
                      gateway's configuration.

                  sign <bundle.json> <private-key-file> <key-id> <out.json>
                      Sign a bundle document into a distributable envelope.

                  verify <envelope.json> <key-id> <public-key-base64>
                      Check an envelope the way a gateway would. Exit 0 if it would be
                      accepted.

                  inspect <envelope.json>
                      Print the payload WITHOUT verifying it. For debugging only — never
                      make a trust decision on this output.
                """);
    }

    private static void keygen() {
        var pair = Dsse.generateKeyPair();
        System.out.println("# private key (PKCS#8) — keep secret, this signs policy for the fleet");
        System.out.println(Dsse.toBase64(pair.getPrivate()));
        System.out.println();
        System.out.println("# public key (X.509) — put this in toolgate.bundle.public-keys");
        System.out.println(Dsse.toBase64(pair.getPublic()));
    }

    private static void sign(String[] args) throws Exception {
        if (args.length != 5) {
            usage();
            System.exit(2);
        }
        PolicyBundle bundle = MAPPER.readValue(Files.readAllBytes(Path.of(args[1])), PolicyBundle.class);

        if (bundle.schemaVersion() != PolicyBundle.SCHEMA_VERSION) {
            System.err.println("refusing to sign: schemaVersion must be " + PolicyBundle.SCHEMA_VERSION);
            System.exit(1);
        }
        if (bundle.expiresAt() == null || bundle.expiresAt().isBefore(Instant.now())) {
            // Signing something already stale produces an artifact that fails on arrival
            // and looks like a gateway bug rather than an operator mistake.
            System.err.println("refusing to sign: expiresAt is missing or already past");
            System.exit(1);
        }

        var key = Dsse.privateKeyFromBase64(Files.readString(Path.of(args[2])));
        BundleEnvelope envelope = BundleVerifier.signBundle(MAPPER, bundle, args[3], key);
        Files.write(Path.of(args[4]), PRETTY.writeValueAsBytes(envelope));

        System.out.printf("signed sequence=%d expires=%s -> %s%n",
                bundle.sequence(), bundle.expiresAt(), args[4]);
    }

    private static void verify(String[] args) throws Exception {
        if (args.length != 4) {
            usage();
            System.exit(2);
        }
        var verifier = new BundleVerifier(MAPPER, Map.of(args[2], args[3]));
        try {
            var verified = verifier.verify(Files.readAllBytes(Path.of(args[1])));
            System.out.printf("OK  sequence=%d issuer=%s expires=%s reviewed=%d signedBy=%s%n",
                    verified.bundle().sequence(), verified.bundle().issuer(),
                    verified.bundle().expiresAt(),
                    verified.bundle().reviewedTools() == null
                            ? 0 : verified.bundle().reviewedTools().size(),
                    verified.keyId());
            if (verified.bundle().expired(Instant.now())) {
                System.out.println("WARNING: this bundle has expired");
            }
        } catch (BundleVerifier.UntrustedBundleException e) {
            System.err.println("REJECTED: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void inspect(String[] args) throws Exception {
        if (args.length != 2) {
            usage();
            System.exit(2);
        }
        var envelope = MAPPER.readValue(Files.readAllBytes(Path.of(args[1])), BundleEnvelope.class);
        byte[] payload = java.util.Base64.getDecoder().decode(envelope.payload());

        System.err.println("!! UNVERIFIED — this output has not been checked against any key");
        System.out.println(PRETTY.writeValueAsString(MAPPER.readValue(payload, PolicyBundle.class)));
        envelope.signatures().forEach(s ->
                System.out.println("# signature by key: " + s.keyid()));
    }

    private BundleTool() {}
}
