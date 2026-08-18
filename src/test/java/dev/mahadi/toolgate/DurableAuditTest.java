package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditProperties;
import dev.mahadi.toolgate.audit.AuditSink;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The ring buffer behind the operator API forgets the start of an incident at exactly the
 * moment someone begins investigating it, and a restart forgets all of it. These tests
 * cover the file that is the actual record.
 */
class DurableAuditTest {

    private static ObjectMapper mapper() {
        return new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.SerializationFeature
                        .WRITE_DATES_AS_TIMESTAMPS);
    }

    private static AuditSink sink(Path file, boolean failClosed) {
        var props = new AuditProperties();
        props.setFile(file.toString());
        props.setFailClosed(failClosed);
        var s = new AuditSink(props, mapper());
        s.open();
        return s;
    }

    @Test
    @DisplayName("every decision is appended as one JSON line")
    void appendsJsonLines(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        var log = new AuditLog(sink(file, false));

        log.record("agent", "files", "read_file", "tools/call",
                AuditLog.Outcome.ALLOWED, "allowlisted and pinned", List.of());
        log.record("agent", "files", "exec_shell", "advertise",
                AuditLog.Outcome.DENIED, "tool not in allowlist", List.of("files/exec_shell"));

        List<String> lines = Files.readAllLines(file);
        assertThat(lines).hasSize(2);

        var second = mapper().readTree(lines.get(1));
        assertThat(second.get("outcome").asText()).isEqualTo("DENIED");
        assertThat(second.get("reason").asText()).contains("allowlist");
        assertThat(second.get("evidence").get(0).asText()).isEqualTo("files/exec_shell");
        assertThat(second.get("at").asText()).isNotBlank();
    }

    @Test
    @DisplayName("the trail is flushed per entry, not on close")
    void flushedImmediately(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        var log = new AuditLog(sink(file, false));

        log.record("agent", "files", "read_file", "tools/call",
                AuditLog.Outcome.ALLOWED, "ok", List.of());

        // No close, no shutdown hook — a process killed here must still have the record.
        assertThat(Files.readAllLines(file)).hasSize(1);
    }

    @Test
    @DisplayName("existing entries are appended to, never truncated")
    void appendsAcrossRestart(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");

        new AuditLog(sink(file, false)).record("agent", "files", "a", "tools/call",
                AuditLog.Outcome.ALLOWED, "first run", List.of());
        new AuditLog(sink(file, false)).record("agent", "files", "b", "tools/call",
                AuditLog.Outcome.ALLOWED, "second run", List.of());

        assertThat(Files.readAllLines(file)).hasSize(2);
    }

    @Test
    @DisplayName("the trail is created owner-only")
    void ownerOnlyPermissions(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("audit.jsonl");
        sink(file, false);

        assertThat(Files.getPosixFilePermissions(file))
                .containsExactlyInAnyOrder(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
    }

    @Test
    @DisplayName("an unwritable trail configured at startup aborts, rather than running silently")
    void unopenableFileFailsStartup(@TempDir Path dir) throws Exception {
        Path blocked = dir.resolve("not-a-dir");
        Files.writeString(blocked, "");            // a file where a directory is needed

        var props = new AuditProperties();
        props.setFile(blocked.resolve("audit.jsonl").toString());

        assertThatThrownBy(() -> new AuditSink(props, mapper()).open())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot open audit file");
    }

    @Test
    @DisplayName("with no file configured the sink is inert, not broken")
    void inMemoryOnlyStillWorks() {
        var props = new AuditProperties();
        var s = new AuditSink(props, mapper());
        s.open();

        var log = new AuditLog(s);
        log.record("agent", "files", "read_file", "tools/call",
                AuditLog.Outcome.ALLOWED, "ok", List.of());

        assertThat(log.size()).isEqualTo(1);
    }
}
