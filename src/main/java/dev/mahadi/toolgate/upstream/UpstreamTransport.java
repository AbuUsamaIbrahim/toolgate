package dev.mahadi.toolgate.upstream;

import dev.mahadi.toolgate.protocol.Mcp;
import reactor.core.publisher.Mono;

/**
 * One way of reaching an upstream MCP server.
 *
 * <p>The protocol is identical on every transport — a binding only decides how messages
 * are framed and delivered. Keeping that behind an interface means the policy engine
 * never learns whether a tool came from a subprocess or an HTTP endpoint, which is
 * exactly as much as it should know.
 */
public interface UpstreamTransport extends AutoCloseable {

    /**
     * Sends a message, mirroring {@code extraHeaders} where the binding has headers.
     *
     * <p>The map is validated by {@link dev.mahadi.toolgate.protocol.HeaderMirror} before
     * it arrives — a transport applies it, it does not vet it.
     */
    Mono<Mcp.Response> send(Mcp.Request request, java.util.Map<String, String> extraHeaders);

    default Mono<Mcp.Response> send(Mcp.Request request) {
        return send(request, java.util.Map.of());
    }

    @Override
    void close();
}
