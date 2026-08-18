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
 * <p>Reactive because a proxy is almost pure I/O wait, and a thread-per-request model
 * spends its memory on parked threads at exactly the moment an upstream starts
 * misbehaving. The component protecting everything must not be the component that falls
 * over when something behind it is slow.
 *
 * <h2>The caller's token never leaves the gateway</h2>
 * The specification is unambiguous: a server <em>MUST NOT</em> accept or transit tokens
 * other than those issued for itself. Forwarding the agent's bearer token to an upstream
 * is the confused-deputy bug in its textbook form — the upstream would receive a
 * credential scoped to the gateway, and any upstream could then replay it against the
 * gateway wearing the caller's identity.
 *
 * <p>Each upstream therefore gets its own credential from configuration, or none. There
 * is deliberately no code path that copies an inbound {@code Authorization} header.
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

    /**
     * Forwards a JSON-RPC request to one upstream server.
     *
     * <p>Note the absence of any parameter carrying the caller's credentials. That is the
     * point: the signature makes token passthrough impossible rather than merely
     * discouraged.
     */
    public Mono<Mcp.Response> send(String serverId, Mcp.Request request) {
        ToolPolicyProperties.Server server = props.server(serverId);
        if (server == null) {
            return Mono.error(new IllegalArgumentException("unknown upstream: " + serverId));
        }

        var spec = client(serverId, server.getUrl())
                .post()
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                // Carried in the header as well as _meta, per the Streamable HTTP transport.
                .header("MCP-Protocol-Version", Mcp.PROTOCOL_VERSION);

        // The gateway's own credential for this upstream — never the caller's.
        if (server.getToken() != null && !server.getToken().isBlank()) {
            spec = spec.header("Authorization", "Bearer " + server.getToken());
        }

        return spec.bodyValue(request)
                .retrieve()
                .bodyToMono(Mcp.Response.class)
                .timeout(TIMEOUT);
    }

    private WebClient client(String serverId, String baseUrl) {
        return clients.computeIfAbsent(serverId, id -> builder.clone().baseUrl(baseUrl).build());
    }
}
