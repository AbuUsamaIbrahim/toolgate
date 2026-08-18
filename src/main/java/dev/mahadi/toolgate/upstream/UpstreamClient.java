package dev.mahadi.toolgate.upstream;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.Mcp;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Routes requests to the right upstream over whichever binding that upstream uses.
 *
 * <h2>The caller's token never leaves the gateway</h2>
 * The specification is unambiguous: a server <em>MUST NOT</em> accept or transit tokens
 * other than those issued for itself. Forwarding the agent's bearer token upstream is the
 * confused-deputy bug in textbook form — the upstream would receive a credential scoped
 * to the gateway and could replay it wearing the caller's identity.
 *
 * <p>Each upstream gets its own credential from configuration, or none. Note that
 * {@link #send} takes no parameter that could carry a caller credential: passthrough is
 * unrepresentable rather than merely discouraged.
 */
@Component
public class UpstreamClient {

    private final ToolPolicyProperties props;
    private final WebClient.Builder builder;
    private final ObjectMapper mapper;
    private final Map<String, UpstreamTransport> transports = new ConcurrentHashMap<>();

    /**
     * Notified when an upstream speaks unprompted.
     *
     * <p>Only stdio upstreams can do this today. Streamable HTTP carries server-initiated
     * messages over SSE, which this gateway does not implement — stated in the README
     * rather than left to be discovered, because "notifications silently never arrive" is
     * a bad thing to find out during an incident.
     */
    private volatile java.util.function.BiConsumer<String, Mcp.Request> notificationListener;

    public void onNotification(java.util.function.BiConsumer<String, Mcp.Request> listener) {
        this.notificationListener = listener;
        transports.forEach((id, t) -> {
            if (t instanceof StdioUpstream stdio) stdio.onNotification(listener);
        });
    }

    public UpstreamClient(ToolPolicyProperties props, WebClient.Builder builder, ObjectMapper mapper) {
        this.props = props;
        this.builder = builder;
        this.mapper = mapper;
    }

    public Mono<Mcp.Response> send(String serverId, Mcp.Request request) {
        return send(serverId, request, Map.of());
    }

    public Mono<Mcp.Response> send(String serverId, Mcp.Request request,
                                   Map<String, String> mirroredHeaders) {
        ToolPolicyProperties.Server server = props.server(serverId);
        if (server == null) {
            return Mono.error(new IllegalArgumentException("unknown upstream: " + serverId));
        }
        try {
            return transport(serverId, server).send(request, mirroredHeaders);
        } catch (Exception e) {
            return Mono.error(e);
        }
    }

    /**
     * Resolves the binding from configuration. A {@code command} means a subprocess; a
     * {@code url} means HTTP. Configuring both is rejected rather than silently preferred,
     * because guessing which the operator meant is how a gateway ends up talking to
     * something nobody intended.
     */
    private UpstreamTransport transport(String serverId, ToolPolicyProperties.Server server) {
        return transports.computeIfAbsent(serverId, id -> {
            boolean hasCommand = server.getCommand() != null && !server.getCommand().isEmpty();
            boolean hasUrl = server.getUrl() != null && !server.getUrl().isBlank();

            if (hasCommand && hasUrl) {
                throw new IllegalStateException(
                        "upstream '" + id + "' sets both command and url; pick one");
            }
            if (hasCommand) {
                try {
                    StdioUpstream stdio = new StdioUpstream(id, server.getCommand(),
                            server.getEnv(), mapper);
                    // Upstreams are created lazily, so a listener registered before this
                    // one existed still has to reach it.
                    if (notificationListener != null) stdio.onNotification(notificationListener);
                    return stdio;
                } catch (IOException e) {
                    throw new IllegalStateException("failed to launch upstream '" + id + "'", e);
                }
            }
            if (hasUrl) {
                return new HttpUpstream(builder, server.getUrl(), server.getToken());
            }
            throw new IllegalStateException("upstream '" + id + "' has neither command nor url");
        });
    }

    /** Subprocess upstreams are children of this process and must not outlive it. */
    @PreDestroy
    public void shutdown() {
        transports.values().forEach(UpstreamTransport::close);
        transports.clear();
    }
}
