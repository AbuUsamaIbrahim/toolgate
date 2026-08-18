package dev.mahadi.toolgate.upstream;

import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Talks Streamable HTTP to the upstream MCP servers.
 *
 * <p>Reactive for the same reason his verification gateway was: a proxy is almost pure
 * I/O wait, and a thread-per-request model spends its memory on parked threads at exactly
 * the moment an upstream starts misbehaving. The component protecting everything must not
 * be the component that falls over when something behind it is slow.
 */
@Component
public class UpstreamClient {

    /** An upstream that has not answered by now is treated as failed, not waited on. */
    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private final ToolPolicyProperties props;
    private final WebClient.Builder builder;
    private final Map<String, WebClient> clients = new ConcurrentHashMap<>();

    public UpstreamClient(ToolPolicyProperties props, WebClient.Builder builder) {
        this.props = props;
        this.builder = builder;
    }

    /** Forwards a JSON-RPC request to one upstream server. */
    public Mono<Mcp.Response> send(String serverId, Mcp.Request request) {
        ToolPolicyProperties.Server server = props.server(serverId);
        if (server == null) {
            return Mono.error(new IllegalArgumentException("unknown upstream: " + serverId));
        }
        return client(serverId, server.getUrl())
                .post()
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                // Carried in the header as well as _meta, per the Streamable HTTP transport.
                .header("MCP-Protocol-Version", Mcp.PROTOCOL_VERSION)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(Mcp.Response.class)
                .timeout(TIMEOUT);
    }

    private WebClient client(String serverId, String baseUrl) {
        return clients.computeIfAbsent(serverId, id -> builder.clone().baseUrl(baseUrl).build());
    }
}
