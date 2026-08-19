package dev.mahadi.toolgate.upstream;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.protocol.Mcp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * stdio binding: the upstream MCP server runs as a subprocess we launch.
 *
 * <p>This is how most MCP servers actually ship — a command the client spawns, speaking
 * newline-delimited JSON-RPC over pipes. Supporting it is what lets the gateway sit in
 * front of the filesystem, github and database servers people already run, rather than
 * only the HTTP ones they mostly do not.
 *
 * <h2>The parts that are easy to get wrong</h2>
 * <ul>
 *   <li><b>One line per message.</b> Messages must not contain embedded newlines, so the
 *       JSON is written compact. A pretty-printer anywhere in this path corrupts the
 *       stream.</li>
 *   <li><b>stdout is protocol, stderr is prose.</b> The upstream's stderr is drained on a
 *       separate thread and logged. The spec is explicit that stderr output does not
 *       indicate an error, so it is logged at debug.</li>
 *   <li><b>Draining stderr is not optional.</b> A subprocess whose stderr pipe fills up
 *       blocks forever. Leaving it unread is a deadlock waiting for a chatty upstream.</li>
 *   <li><b>Shutdown means closing stdin first.</b> That is the portable graceful signal;
 *       killing the process is the fallback, not the opening move.</li>
 * </ul>
 */
public class StdioUpstream implements UpstreamTransport {

    private static final Logger log = LoggerFactory.getLogger(StdioUpstream.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private final String serverId;
    private final ObjectMapper mapper;
    private final Process process;
    private final BufferedWriter stdin;
    private final Map<String, Sinks.One<Mcp.Response>> pending = new ConcurrentHashMap<>();

    /**
     * Where unsolicited messages go. Set by {@link UpstreamClient}; null means nobody is
     * listening, in which case they are dropped exactly as before.
     */
    private volatile java.util.function.BiConsumer<String, Mcp.Request> notificationListener;

    public StdioUpstream(String serverId, List<String> command, Map<String, String> env,
                         ObjectMapper mapper) throws IOException {
        this.serverId = serverId;
        this.mapper = mapper;

        ProcessBuilder pb = new ProcessBuilder(command);
        if (env != null) pb.environment().putAll(env);
        // Kept separate: merging stderr into stdout would inject log lines into the
        // protocol stream, which is precisely what the spec forbids.
        pb.redirectErrorStream(false);

        this.process = pb.start();
        this.stdin = new BufferedWriter(
                new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));

        startReader();
        startErrorDrain();
        log.info("Started stdio upstream {} pid={} command={}", serverId, process.pid(), command);
    }

    /** Reads responses off stdout and completes whichever request was waiting for them. */
    private void startReader() {
        Thread.ofVirtual().name("toolgate-stdio-out-" + serverId).start(() -> {
            try (BufferedReader out = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = out.readLine()) != null) {
                    if (line.isBlank()) continue;
                    dispatch(line);
                }
            } catch (IOException e) {
                log.warn("stdio upstream {} stdout closed: {}", serverId, e.toString());
            } finally {
                // Nothing further will arrive; fail anything still waiting rather than
                // leaving callers hanging until their timeout.
                pending.values().forEach(sink -> sink.tryEmitError(
                        new IllegalStateException("upstream " + serverId + " terminated")));
                pending.clear();
            }
        });
    }

    public void onNotification(java.util.function.BiConsumer<String, Mcp.Request> listener) {
        this.notificationListener = listener;
    }

    private void notifyListener(String line) {
        var listener = notificationListener;
        if (listener == null) {
            log.debug("stdio upstream {} notification with nobody listening: {}", serverId, line);
            return;
        }
        try {
            listener.accept(serverId, mapper.readValue(line, Mcp.Request.class));
        } catch (Exception e) {
            log.warn("stdio upstream {} sent an unreadable notification: {}", serverId, e.toString());
        }
    }

    private void dispatch(String line) {
        try {
            Mcp.Response response = mapper.readValue(line, Mcp.Response.class);
            if (response.id() == null) {
                // No id, so it correlates to nothing: the upstream is speaking unprompted.
                // Handed to the listener rather than dropped, which is what makes
                // server-initiated messages governable at all.
                notifyListener(line);
                return;
            }
            Sinks.One<Mcp.Response> sink = pending.remove(String.valueOf(response.id()));
            if (sink == null) {
                log.debug("stdio upstream {} response for unknown id {}", serverId, response.id());
                return;
            }
            sink.tryEmitValue(response);
        } catch (Exception e) {
            log.warn("stdio upstream {} sent unparseable line: {}", serverId, e.toString());
        }
    }

    /**
     * Drains the upstream's stderr.
     *
     * <p>Not for observability — for liveness. An unread pipe fills its buffer and the
     * subprocess blocks on its next write, which looks exactly like a hung upstream.
     */
    private void startErrorDrain() {
        Thread.ofVirtual().name("toolgate-stdio-err-" + serverId).start(() -> {
            try (BufferedReader err = new BufferedReader(
                    new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = err.readLine()) != null) {
                    // The spec says stderr does not imply an error condition.
                    log.debug("[{} stderr] {}", serverId, line);
                }
            } catch (IOException ignored) {
                // Process exited; the reader thread reports that.
            }
        });
    }

    @Override
    public Mono<Mcp.Response> send(Mcp.Request request, java.util.Map<String, String> extraHeaders) {
        // A subprocess pipe has no header block. Dropping mirrored parameters is the only
        // option, but it is logged rather than silent: a tool that depends on one will
        // misbehave in a way nothing else explains.
        if (!extraHeaders.isEmpty()) {
            log.warn("Dropping {} mirrored header(s) for stdio upstream {} — the transport "
                    + "cannot carry them", extraHeaders.size(), serverId);
        }
        if (!process.isAlive()) {
            return Mono.error(new IllegalStateException("upstream " + serverId + " is not running"));
        }
        String id = String.valueOf(request.id());
        Sinks.One<Mcp.Response> sink = Sinks.one();
        pending.put(id, sink);

        try {
            // Compact, single line. writeValueAsString never emits newlines for these types,
            // but the newline we append is the frame delimiter and must be the only one.
            String json = mapper.writeValueAsString(request.forWire());
            synchronized (stdin) {
                stdin.write(json);
                stdin.write('\n');
                stdin.flush();
            }
        } catch (IOException e) {
            pending.remove(id);
            return Mono.error(e);
        }

        return sink.asMono()
                .timeout(TIMEOUT)
                .doFinally(signal -> pending.remove(id));
    }

    @Override
    public void close() {
        log.info("Stopping stdio upstream {}", serverId);
        try {
            // Closing stdin is the portable graceful shutdown signal; servers are told to
            // exit promptly on EOF. Killing first would skip any cleanup they do.
            synchronized (stdin) {
                stdin.close();
            }
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroy();
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            }
        } catch (IOException | InterruptedException e) {
            process.destroyForcibly();
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }
}
