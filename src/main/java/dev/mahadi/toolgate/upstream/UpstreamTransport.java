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

    Mono<Mcp.Response> send(Mcp.Request request);

    @Override
    void close();
}
