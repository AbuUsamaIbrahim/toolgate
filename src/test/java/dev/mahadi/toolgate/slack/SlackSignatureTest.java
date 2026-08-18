package dev.mahadi.toolgate.slack;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This endpoint approves tool calls and must be reachable from the internet. Without a
 * correct signature check it is an unauthenticated approve-anything API, so these are the
 * tests that matter most in the Slack integration.
 */
class SlackSignatureTest {

    private static final String SECRET = "8f742231b10e8888abcd99yyyzzz85a5";
    private static final byte[] BODY =
            "payload=%7B%22user%22%3A%7B%22id%22%3A%22U1%22%7D%7D".getBytes(StandardCharsets.UTF_8);

    private static final Instant NOW = Instant.parse("2026-08-18T12:00:00Z");

    @Test
    @DisplayName("a genuine Slack signature verifies")
    void validSignature() {
        long ts = NOW.getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, BODY, NOW)).isTrue();
    }

    @Test
    @DisplayName("a body edited after signing is refused")
    void tamperedBodyRejected() {
        long ts = NOW.getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        byte[] swapped = "payload=%7B%22user%22%3A%7B%22id%22%3A%22U2%22%7D%7D"
                .getBytes(StandardCharsets.UTF_8);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, swapped, NOW)).isFalse();
    }

    @Test
    @DisplayName("a captured request cannot be replayed later")
    void oldTimestampRejected() {
        // The classic mistake: verifying the HMAC but never looking at the timestamp,
        // which makes every captured approval valid forever.
        long ts = NOW.minus(30, ChronoUnit.MINUTES).getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, BODY, NOW)).isFalse();
    }

    @Test
    @DisplayName("a future timestamp is refused too")
    void futureTimestampRejected() {
        long ts = NOW.plus(30, ChronoUnit.MINUTES).getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, BODY, NOW)).isFalse();
    }

    @Test
    @DisplayName("moving the timestamp invalidates the signature, because it is signed too")
    void timestampIsCoveredBySignature() {
        long ts = NOW.minus(30, ChronoUnit.MINUTES).getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        // An attacker with an old captured request cannot simply update the timestamp
        // header to make it current: the timestamp is inside the signed material.
        assertThat(SlackSignature.verify(SECRET, String.valueOf(NOW.getEpochSecond()), sig, BODY, NOW))
                .isFalse();
    }

    @Test
    @DisplayName("the wrong signing secret is refused")
    void wrongSecretRejected() {
        long ts = NOW.getEpochSecond();
        String sig = SlackSignature.sign("someone-elses-secret", ts, BODY);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, BODY, NOW)).isFalse();
    }

    @Test
    @DisplayName("no configured secret means nothing verifies")
    void noSecretVerifiesNothing() {
        long ts = NOW.getEpochSecond();

        // Even presented with a signature that is valid under some other secret, an
        // unconfigured gateway must refuse. It has no way to tell Slack from anyone else.
        String sigUnderRealSecret = SlackSignature.sign(SECRET, ts, BODY);

        assertThat(SlackSignature.verify("", String.valueOf(ts), sigUnderRealSecret, BODY, NOW))
                .isFalse();
        assertThat(SlackSignature.verify(null, String.valueOf(ts), sigUnderRealSecret, BODY, NOW))
                .isFalse();
    }

    @Test
    @DisplayName("malformed input is refused rather than throwing")
    void malformedInputRejected() {
        long ts = NOW.getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        assertThat(SlackSignature.verify(SECRET, "not-a-number", sig, BODY, NOW)).isFalse();
        assertThat(SlackSignature.verify(SECRET, null, sig, BODY, NOW)).isFalse();
        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), null, BODY, NOW)).isFalse();
        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), "v0=zzzz", BODY, NOW)).isFalse();
        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, null, NOW)).isFalse();
    }

    @Test
    @DisplayName("the signature covers the exact bytes, not a normalised form")
    void exactBytesMatter() {
        long ts = NOW.getEpochSecond();
        String sig = SlackSignature.sign(SECRET, ts, BODY);

        // One extra byte of whitespace — the kind of thing a reserialisation introduces.
        byte[] reserialised = (new String(BODY, StandardCharsets.UTF_8) + " ")
                .getBytes(StandardCharsets.UTF_8);

        assertThat(SlackSignature.verify(SECRET, String.valueOf(ts), sig, reserialised, NOW))
                .isFalse();
    }
}
