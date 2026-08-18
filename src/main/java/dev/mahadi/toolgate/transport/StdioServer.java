package dev.mahadi.toolgate.transport;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.gateway.GatewayService;
import dev.mahadi.toolgate.protocol.Mcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Serves MCP over stdio, so a desktop client can launch the gateway as its MCP server.
 *
 * <p>This is the binding that makes toolgate usable with the clients people actually run.
 * Configure it once and every tool the agent sees has been through policy:
 *
 * <pre>{@code
 * {
 *   "mcpServers": {
 *     "toolgate": { "command": "java", "args": ["-jar", "toolgate.jar", "--stdio"] }
 *   }
 * }
 * }</pre>
 *
 * <h2>stdout belongs to the protocol</h2>
 * The spec is absolute: the server <em>MUST NOT</em> write anything to stdout that is not
 * a valid MCP message. That is a genuine hazard for a Spring application, where the
 * banner, the startup log and any stray {@code System.out.println} all default to stdout
 * and would corrupt the stream with output the client cannot parse.
 *
 * <p>Two things guard against it. Logging is redirected to stderr by configuration, and
 * {@link System#out} is swapped for a stream pointed at stderr immediately on entry — so
 * a careless {@code println} in any library on the classpath becomes a harmless stderr
 * line rather than a protocol violation. The real stdout is captured first and used only
 * for writing frames.
 */
@Component
@Profile("stdio")
public class StdioServer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(StdioServer.class);

    private final GatewayService gateway;
    private final ObjectMapper mapper;
    private final ConfigurableApplicationContext context;
    private final dev.mahadi.toolgate.upstream.UpstreamClient upstream;
    private final dev.mahadi.toolgate.gateway.NotificationGate gate;

    public StdioServer(GatewayService gateway, ObjectMapper mapper,
                       ConfigurableApplicationContext context,
                       dev.mahadi.toolgate.upstream.UpstreamClient upstream,
                       dev.mahadi.toolgate.gateway.NotificationGate gate) {
        this.gateway = gateway;
        this.mapper = mapper;
        this.context = context;
        this.upstream = upstream;
        this.gate = gate;
    }

    /**
     * Forwards approved server-initiated notifications to the client.
     *
     * <p>Only stdio can do this. The HTTP endpoint is request/response, so a notification
     * arriving while an agent is connected over HTTP has nowhere to go — see the README.
     * Writes are synchronised with the response path, because a notification arriving
     * mid-response would otherwise interleave two JSON documents on one line and break
     * framing for everything after it.
     */
    private void forwardNotification(BufferedWriter out, String serverId, Mcp.Request notification) {
        var verdict = gate.evaluate(serverId, notification);
        if (!(verdict instanceof dev.mahadi.toolgate.gateway.NotificationGate.Verdict.Forward f)) {
            return;
        }

        Mcp.Request outbound = f.clientSubscriptionId() == null
                ? notification
                : withSubscriptionId(notification, f.clientSubscriptionId());

        try {
            synchronized (out) {
                out.write(mapper.writeValueAsString(outbound));
                out.write('\n');
                out.flush();
            }
        } catch (Exception e) {
            log.warn("failed forwarding {} from {}: {}",
                    notification.method(), serverId, e.toString());
        }
    }

    /**
     * Replaces the subscription id with the one the client issued.
     *
     * <p>The upstream's id is meaningless to the client and dangerous to relay: a client
     * running two subscriptions would otherwise be one hostile server away from having
     * notifications delivered into the wrong stream.
     */
    private static Mcp.Request withSubscriptionId(Mcp.Request notification, String clientId) {
        java.util.Map<String, Object> params =
                new java.util.LinkedHashMap<>(notification.params() == null
                        ? java.util.Map.of() : notification.params());

        java.util.Map<String, Object> meta =
                params.get("_meta") instanceof java.util.Map<?, ?> existing
                        ? new java.util.LinkedHashMap<>(
                                (java.util.Map<String, Object>) existing)
                        : new java.util.LinkedHashMap<>();

        meta.put(dev.mahadi.toolgate.gateway.NotificationGate.SUBSCRIPTION_ID, clientId);
        params.put("_meta", meta);

        return new Mcp.Request(notification.jsonrpc(), null, notification.method(),
                params, notification._meta());
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // Claim the real stdout before anything else can write to it, then make the
        // global System.out harmless.
        PrintStream protocolOut = System.out;
        System.setOut(new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err),
                true, StandardCharsets.UTF_8));

        try (BufferedReader in = new BufferedReader(
                     new InputStreamReader(System.in, StandardCharsets.UTF_8));
             BufferedWriter out = new BufferedWriter(
                     new OutputStreamWriter(protocolOut, StandardCharsets.UTF_8))) {

            // Only now is there somewhere to write, so this is where the listener goes.
            upstream.onNotification((serverId, notification) ->
                    forwardNotification(out, serverId, notification));

            // Graceful closure of a subscription arrives as a response to a request the
            // client is still waiting on, so it needs the same channel.
            gateway.onOutOfBandResponse(response -> write(out, response));

            log.info("toolgate listening on stdio");

            String line;
            while ((line = in.readLine()) != null) {
                if (line.isBlank()) continue;
                handleLine(line, out);
            }
            // EOF on stdin is the graceful shutdown signal, and the only portable one.
            log.info("stdin closed; shutting down");
        } finally {
            int code = org.springframework.boot.SpringApplication.exit(context, () -> 0);
            System.exit(code);
        }
    }

    private void handleLine(String line, BufferedWriter out) {
        Mcp.Request request;
        try {
            request = mapper.readValue(line, Mcp.Request.class);
        } catch (Exception e) {
            log.warn("unparseable input: {}", e.toString());
            // No id means no correlation, so there is nothing meaningful to reply to.
            return;
        }

        // Notifications get no response. Replying to one is a protocol violation.
        if (request.isNotification()) {
            // Except that one of them means something to the gateway: a cancellation has
            // to tear down the upstream subscriptions opened on the client's behalf, or
            // they leak for the life of the process.
            if (Mcp.NOTIFICATION_CANCELLED.equals(request.method()) && request.params() != null) {
                Object id = request.params().get("requestId");
                if (id != null) gateway.cancelSubscription(String.valueOf(id));
            }
            log.debug("notification: {}", request.method());
            return;
        }

        try {
            // stdio is a single ordered channel; handling requests sequentially keeps
            // framing trivially correct. Concurrency here would buy little — the work is
            // dominated by the upstream call — and would need a write lock anyway.
            Mcp.Response response = gateway.handle(callerIdentity(), request).block();
            if (response != null) write(out, response);
        } catch (Exception e) {
            log.error("failed handling {}: {}", request.method(), e.toString());
            write(out, Mcp.Response.error(request.id(), Mcp.Codes.INTERNAL_ERROR,
                    "gateway error", null));
        }
    }

    /**
     * Identity over stdio.
     *
     * <p>There is no bearer token here and there should not be: the client launched this
     * process, so the trust boundary is the operating system's, not the protocol's.
     * Whoever can spawn the subprocess already has the privileges the subprocess runs
     * with. Naming the caller {@code local-stdio} keeps the audit trail honest about
     * where that authority came from.
     */
    private static dev.mahadi.toolgate.auth.AccessToken callerIdentity() {
        // No teams, so a stdio caller gets the base policy only and never a team's extra
        // access. Team membership comes from an identity provider's group claim, and there
        // is no token here to carry one — inferring it from the logged-in user would be
        // the gateway inventing an identity it cannot verify.
        return new dev.mahadi.toolgate.auth.AccessToken(
                "local-stdio", java.util.Set.of("tools:read", "tools:call"),
                java.util.Set.of(), null, null);
    }

    private void write(BufferedWriter out, Mcp.Response response) {
        try {
            // One compact line. An embedded newline anywhere here would split one message
            // into two unparseable halves.
            //
            // Synchronised on the same writer the notification path uses: a notification
            // arriving mid-response would otherwise interleave two JSON documents on one
            // line and break framing for every message after it.
            synchronized (out) {
                out.write(mapper.writeValueAsString(response));
                out.write('\n');
                out.flush();
            }
        } catch (Exception e) {
            log.error("failed writing response: {}", e.toString());
        }
    }
}
