package dev.mahadi.toolgate;

import dev.mahadi.toolgate.upstream.HttpUpstream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The gateway validates {@code Mcp-Name} on the way in, so it has to emit it correctly on
 * the way out — including for names that cannot travel as a plain header value.
 */
class HttpHeaderEncodingTest {

    @Test
    @DisplayName("a plain ASCII name is sent as-is")
    void plainAscii() {
        assertThat(HttpUpstream.encodeHeaderValue("read_file")).isEqualTo("read_file");
        assertThat(HttpUpstream.encodeHeaderValue("file:///project/readme.md"))
                .isEqualTo("file:///project/readme.md");
    }

    @Test
    @DisplayName("a non-ASCII name is base64-wrapped in the sentinel the spec defines")
    void nonAsciiEncoded() {
        String encoded = HttpUpstream.encodeHeaderValue("Hello, 世界");

        assertThat(encoded).startsWith("=?base64?").endsWith("?=");
        // Round-trips through the decoder the inbound side uses, so header and body agree.
        assertThat(dev.mahadi.toolgate.api.HttpTransportRules.decodeSentinel(encoded))
                .isEqualTo("Hello, 世界");
    }

    @Test
    @DisplayName("values with leading or trailing space are encoded")
    void paddedEncoded() {
        assertThat(HttpUpstream.encodeHeaderValue(" padded ")).startsWith("=?base64?");
    }

    @Test
    @DisplayName("a value that looks like the sentinel is itself encoded")
    void sentinelLookalikeEncoded() {
        // Otherwise a name of "=?base64?literal?=" would be decoded by the receiver into
        // something else entirely, and header and body would disagree.
        String tricky = "=?base64?literal?=";

        String encoded = HttpUpstream.encodeHeaderValue(tricky);

        assertThat(encoded).isNotEqualTo(tricky);
        assertThat(dev.mahadi.toolgate.api.HttpTransportRules.decodeSentinel(encoded))
                .isEqualTo(tricky);
    }

    @Test
    @DisplayName("a value containing a newline is encoded rather than splitting the header")
    void newlineEncoded() {
        assertThat(HttpUpstream.encodeHeaderValue("line1\nline2")).startsWith("=?base64?");
    }
}
