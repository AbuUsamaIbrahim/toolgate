package dev.mahadi.toolgate.upstream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.protocol.Mcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.function.BiConsumer;

/**
 * Streamable HTTP binding: each message is a POST to a single MCP endpoint.
 *
 * <p>Reactive because a proxy is almost pure I/O wait, and a thread-per-request model
 * spends its memory on parked threads at exactly the moment an upstream starts
 * misbehaving.
 *
 * <h2>A reply is either a JSON object or a stream</h2>
 * The server decides per request. A {@code tools/call} usually answers with one JSON
 * object; a {@code subscriptions/listen} answers with an SSE stream that stays open and
 * carries notifications until somebody closes it. Both arrive as the response to the same
 * POST, so this cannot be decided in advance — the content type is inspected and the
 * response handled accordingly.
 *
 * <p>The timeout follows from that. Twenty seconds is right for a request that should
 * answer promptly and wrong for a subscription, where silence is the expected state: a
 * stream carrying nothing for an hour is a server with nothing to report, not a hung one.
 */
public class HttpUpstream implements UpstreamTransport {

    private static final Logger log = LoggerFactory.getLogger(HttpUpstream.class);

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private static final ParameterizedTypeReference<ServerSentEvent<String>> SSE_TYPE =
            new ParameterizedTypeReference<>() {};

    private final WebClient client;
    private final String token;
    private final String serverId;
    private final ObjectMapper mapper;

    private volatile BiConsumer<String, Mcp.Request> notificationListener;

    public HttpUpstream(WebClient.Builder builder, String serverId, String baseUrl,
                        String token, ObjectMapper mapper) {
        this.client = builder.clone().baseUrl(baseUrl).build();
        this.serverId = serverId;
        this.token = token;
        this.mapper = mapper;
    }

    public void onNotification(BiConsumer<String, Mcp.Request> listener) {
        this.notificationListener = listener;
    }

    @Override
    public Mono<Mcp.Response> send(Mcp.Request request, Map<String, String> extraHeaders) {
        var spec = client.post()
                .contentType(MediaType.APPLICATION_JSON)
                // Both, as the specification requires of clients: the server chooses which
                // it sends, and a client that accepts only one cannot be given a stream.
                .accept(MediaType.APPLICATION_JSON, MediaType.TEXT_EVENT_STREAM)
                .header("MCP-Protocol-Version", Mcp.PROTOCOL_VERSION);

        // The mirrored headers this gateway validates on the way in, emitted on the way
        // out. Anything sitting between here and the upstream is entitled to route on
        // them, and is entitled to have them agree with the body.
        spec = spec.header("Mcp-Method", request.method());
        String name = nameOf(request);
        if (name != null) spec = spec.header("Mcp-Name", encodeHeaderValue(name));

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

        boolean longLived = Mcp.METHOD_SUBSCRIPTIONS_LISTEN.equals(request.method());

        Mono<Mcp.Response> exchange = spec.bodyValue(request.forWire()).exchangeToMono(response -> {
            MediaType contentType = response.headers().contentType().orElse(MediaType.APPLICATION_JSON);
            if (MediaType.TEXT_EVENT_STREAM.isCompatibleWith(contentType)) {
                return consumeStream(response.bodyToFlux(SSE_TYPE));
            }
            return response.bodyToMono(Mcp.Response.class);
        });

        return longLived ? exchange : exchange.timeout(TIMEOUT);
    }

    /**
     * Reads an SSE reply.
     *
     * <p>Notifications on the stream go to the listener; the first response completes the
     * Mono and, per the spec, should be the last thing on the stream. A stream that ends
     * without one completes empty — which is exactly what graceful closure of a
     * subscription looks like, and the caller treats it as the end of that subscription.
     *
     * <p>Comment lines carry no data and are skipped. They are the keep-alives that stop an
     * idle subscription being closed by an intermediary, so receiving them is a sign of
     * health rather than something to react to.
     */
    private Mono<Mcp.Response> consumeStream(Flux<ServerSentEvent<String>> events) {
        return events
                .mapNotNull(ServerSentEvent::data)
                .concatMap(data -> {
                    JsonNode node;
                    try {
                        node = mapper.readTree(data);
                    } catch (Exception e) {
                        log.warn("upstream {} sent an unreadable SSE event: {}", serverId, e.toString());
                        return Mono.empty();
                    }

                    // No id means a notification: the upstream speaking, not answering.
                    if (node.get("id") == null || node.get("id").isNull()) {
                        deliverNotification(node);
                        return Mono.<Mcp.Response>empty();
                    }
                    try {
                        return Mono.just(mapper.treeToValue(node, Mcp.Response.class));
                    } catch (Exception e) {
                        return Mono.<Mcp.Response>empty();
                    }
                })
                .next();
    }

    private void deliverNotification(JsonNode node) {
        var listener = notificationListener;
        if (listener == null) return;
        try {
            listener.accept(serverId, mapper.treeToValue(node, Mcp.Request.class));
        } catch (Exception e) {
            log.warn("upstream {} sent an unreadable notification: {}", serverId, e.toString());
        }
    }

    /** {@code params.name} for tools and prompts, {@code params.uri} for resources. */
    private static String nameOf(Mcp.Request request) {
        Map<String, Object> params = request.params();
        if (params == null) return null;
        Object name = params.get("name");
        if (name != null) return String.valueOf(name);
        Object uri = params.get("uri");
        return uri == null ? null : String.valueOf(uri);
    }

    /**
     * Encodes a value that cannot travel as a plain header.
     *
     * <p>Header values are visible ASCII. A tool name or resource URI that is not — or that
     * happens to look like the sentinel itself — is carried base64-wrapped, which the spec
     * defines precisely so that a server can decode and compare it against the body rather
     * than having to guess.
     */
    public static String encodeHeaderValue(String value) {
        boolean plain = value.chars().allMatch(c -> c >= 0x20 && c <= 0x7e)
                && !value.startsWith(" ") && !value.endsWith(" ")
                && !(value.startsWith("=?base64?") && value.endsWith("?="));
        if (plain) return value;
        return "=?base64?" + Base64.getEncoder()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    @Override
    public void close() {
        // Nothing to release; WebClient holds no per-upstream resources worth closing here.
    }
}
