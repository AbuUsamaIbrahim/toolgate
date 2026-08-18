package dev.mahadi.toolgate.upstream;

import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Streamable HTTP binding: each message is a POST to a single MCP endpoint.
 *
 * <p>Reactive because a proxy is almost pure I/O wait, and a thread-per-request model
 * spends its memory on parked threads at exactly the moment an upstream starts
 * misbehaving.
 */
public class HttpUpstream implements UpstreamTransport {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final WebClient client;
    private final String token;

    public HttpUpstream(WebClient.Builder builder, String baseUrl, String token) {
        this.client = builder.clone().baseUrl(baseUrl).build();
        this.token = token;
    }

    @Override
    public Mono<Mcp.Response> send(Mcp.Request request, java.util.Map<String, String> extraHeaders) {
        var spec = client.post()
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("MCP-Protocol-Version", Mcp.PROTOCOL_VERSION);

        // The gateway's own credential for this upstream — never the caller's.
        if (token != null && !token.isBlank()) {
            spec = spec.header("Authorization", "Bearer " + token);
        }

        // Mirrored parameters go on last, but they cannot overwrite anything set above:
        // the policy engine confines them to the Mcp-Param-* namespace, so a definition
        // cannot name Authorization however it is written.
        for (var e : extraHeaders.entrySet()) {
            spec = spec.header(e.getKey(), e.getValue());
        }

        return spec.bodyValue(request)
                .retrieve()
                .bodyToMono(Mcp.Response.class)
                .timeout(TIMEOUT);
    }

    @Override
    public void close() {
        // Nothing to release; WebClient holds no per-upstream resources worth closing here.
    }
}
