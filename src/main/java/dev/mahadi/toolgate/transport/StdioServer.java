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

    public StdioServer(GatewayService gateway, ObjectMapper mapper,
                       ConfigurableApplicationContext context) {
        this.gateway = gateway;
        this.mapper = mapper;
        this.context = context;
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
    private static String callerIdentity() {
        return "local-stdio";
    }

    private void write(BufferedWriter out, Mcp.Response response) {
        try {
            // One compact line. An embedded newline anywhere here would split one message
            // into two unparseable halves.
            out.write(mapper.writeValueAsString(response));
            out.write('\n');
            out.flush();
        } catch (Exception e) {
            log.error("failed writing response: {}", e.toString());
        }
    }
}
