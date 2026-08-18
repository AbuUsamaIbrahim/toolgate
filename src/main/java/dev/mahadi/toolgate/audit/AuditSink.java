package dev.mahadi.toolgate.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.util.FilePaths;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;

/**
 * Appends the audit trail to a file as JSON Lines.
 *
 * <p>Four properties, each chosen against an alternative:
 *
 * <ul>
 *   <li><b>JSON Lines, not a database.</b> The reader of an audit trail is usually someone
 *       under time pressure with {@code grep} and {@code jq}, or a log shipper. Neither
 *       wants a schema migration first.</li>
 *   <li><b>Flushed on every record.</b> Buffering loses precisely the entries worth having
 *       — the ones written in the seconds before a process died during an incident. The
 *       throughput cost is irrelevant next to a human approving a tool call.</li>
 *   <li><b>Append only, never rewritten.</b> There is no compaction and no in-process
 *       rotation. A writer that can rewrite its own history is not an audit log; rotation
 *       belongs to logrotate, which can be pointed at a file this process only ever
 *       appends to.</li>
 *   <li><b>Owner-readable.</b> The trail records tool names, arguments-adjacent reasons
 *       and caller identities. It is created 0600 for the same reason the pin file is.</li>
 * </ul>
 */
@Component
public class AuditSink {

    private static final Logger log = LoggerFactory.getLogger(AuditSink.class);

    private final AuditProperties props;
    private final ObjectMapper mapper;

    private volatile OutputStream out;
    private volatile boolean degraded;

    public AuditSink(AuditProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
    }

    public boolean enabled() {
        return props.getFile() != null && !props.getFile().isBlank();
    }

    @PostConstruct
    public void open() {
        if (!enabled()) return;
        try {
            Path path = FilePaths.expandUser(props.getFile());
            Files.createDirectories(path.getParent());
            out = Files.newOutputStream(path,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            FilePaths.restrictToOwner(path);
            log.info("Audit trail appending to {}", path);
        } catch (IOException e) {
            // Startup fails: an operator who configured an audit file and got a gateway
            // that silently isn't writing one has the worst of both.
            throw new IllegalStateException(
                    "cannot open audit file " + props.getFile() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Writes one entry.
     *
     * @throws AuditWriteException if the write fails and the deployment is configured to
     *         fail closed
     */
    public void append(AuditLog.Entry entry) {
        if (out == null) return;
        try {
            byte[] line = (mapper.writeValueAsString(entry) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                out.write(line);
                out.flush();
            }
            degraded = false;
        } catch (IOException e) {
            if (props.isFailClosed()) {
                throw new AuditWriteException("audit write failed", e);
            }
            // Log once per outage rather than once per request: a full disk would
            // otherwise fill the remaining space with complaints about the full disk.
            if (!degraded) {
                degraded = true;
                log.error("Audit trail is not being written — decisions continue but are "
                        + "no longer recorded to disk: {}", e.toString());
            }
        }
    }

    @PreDestroy
    void close() {
        try {
            if (out != null) out.close();
        } catch (IOException e) {
            log.warn("Failed to close audit file: {}", e.toString());
        }
    }

    public static class AuditWriteException extends RuntimeException {
        public AuditWriteException(String message, Throwable cause) { super(message, cause); }
    }
}
