package dev.mahadi.toolgate.slack;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Verifies that an interaction really came from Slack.
 *
 * <p>This endpoint has to be reachable from the internet for buttons to work, and what it
 * does is approve blocked tool calls. Without this check it is an unauthenticated
 * "approve anything" API — the attacker does not need Slack, or an account, or a token;
 * they need the URL and an approval id.
 *
 * <p>Slack signs {@code v0:<timestamp>:<raw body>} with HMAC-SHA256 under a shared signing
 * secret. Three details matter and each is a real vulnerability if skipped:
 *
 * <ul>
 *   <li><b>The raw body, byte for byte.</b> Not a reparsed or reserialised form. Any
 *       normalisation between verifying and using means the bytes you checked are not the
 *       bytes you acted on.</li>
 *   <li><b>The timestamp is inside the signed material and must be checked.</b> A valid
 *       signature is valid forever otherwise, so anyone who captures one approval request
 *       can replay it whenever they like. Slack recommends a five-minute window.</li>
 *   <li><b>Constant-time comparison.</b> A byte-by-byte early return leaks, through
 *       timing, how much of a guess was correct — which turns forging a signature from
 *       impossible into a few thousand requests.</li>
 * </ul>
 */
public final class SlackSignature {

    private static final String VERSION = "v0";
    private static final String ALGORITHM = "HmacSHA256";

    /** Slack's recommendation. Wide enough for clock drift, narrow enough to bound replay. */
    static final Duration MAX_AGE = Duration.ofMinutes(5);

    private SlackSignature() {}

    public static boolean verify(String signingSecret, String timestampHeader,
                                 String signatureHeader, byte[] rawBody, Instant now) {
        if (signingSecret == null || signingSecret.isBlank()) return false;
        if (timestampHeader == null || signatureHeader == null || rawBody == null) return false;

        long timestamp;
        try {
            timestamp = Long.parseLong(timestampHeader.trim());
        } catch (NumberFormatException e) {
            return false;
        }

        // Both directions. A far-future timestamp is as suspicious as an old one, and
        // only checking the past leaves a signature that becomes valid later.
        Duration skew = Duration.between(Instant.ofEpochSecond(timestamp), now).abs();
        if (skew.compareTo(MAX_AGE) > 0) return false;

        String expected;
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(signingSecret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            mac.update((VERSION + ":" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
            mac.update(rawBody);
            expected = VERSION + "=" + HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            return false;
        }

        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                signatureHeader.getBytes(StandardCharsets.UTF_8));
    }

    /** Produces a signature the way Slack would. Used by tests, and by nothing else. */
    public static String sign(String signingSecret, long timestamp, byte[] rawBody) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(signingSecret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            mac.update((VERSION + ":" + timestamp + ":").getBytes(StandardCharsets.UTF_8));
            mac.update(rawBody);
            return VERSION + "=" + HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
