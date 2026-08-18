package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.gateway.ApprovalProperties;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A restart in the middle of an operator's review should not empty their queue — and
 * should absolutely revoke anything they already said yes to.
 */
class DurableApprovalTest {

    private static ObjectMapper mapper() {
        return new ObjectMapper()
                .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
                .disable(com.fasterxml.jackson.databind.SerializationFeature
                        .WRITE_DATES_AS_TIMESTAMPS);
    }

    private static ApprovalStore store(Path file) {
        var props = new ApprovalProperties();
        props.setFile(file.toString());
        var s = new ApprovalStore(props, mapper());
        s.restore();
        return s;
    }

    @Test
    @DisplayName("an outstanding request survives a restart")
    void pendingSurvives(@TempDir Path dir) {
        Path file = dir.resolve("approvals.json");

        var first = store(file);
        var pending = first.request("agent", "files", "write_file", "requires human approval");

        var afterRestart = store(file);

        assertThat(afterRestart.outstanding()).containsKey(pending.id());
        assertThat(afterRestart.outstanding().get(pending.id()).reason())
                .isEqualTo("requires human approval");
    }

    @Test
    @DisplayName("a grant does not survive a restart")
    void grantDoesNotSurvive(@TempDir Path dir) {
        Path file = dir.resolve("approvals.json");

        var first = store(file);
        var pending = first.request("agent", "files", "write_file", "needs a human");
        assertThat(first.approve(pending.id(), "approver@example.com"))
                .isInstanceOf(ApprovalStore.Outcome.Granted.class);

        // Still redeemable in the process where it was granted...
        var second = store(file);
        // ...but a new process must not honour it. A momentary "yes" is not a standing
        // permission, and nothing on disk should be able to turn it into one.
        assertThat(second.consumeGrant("agent", "files", "write_file")).isFalse();
    }

    @Test
    @DisplayName("an approved request leaves the persisted queue")
    void approvalClearsTheQueue(@TempDir Path dir) {
        Path file = dir.resolve("approvals.json");

        var first = store(file);
        var pending = first.request("agent", "files", "write_file", "needs a human");
        first.approve(pending.id(), "approver@example.com");

        assertThat(store(file).outstanding()).isEmpty();
    }

    @Test
    @DisplayName("a denied request leaves the persisted queue")
    void denialClearsTheQueue(@TempDir Path dir) {
        Path file = dir.resolve("approvals.json");

        var first = store(file);
        var pending = first.request("agent", "files", "write_file", "needs a human");
        first.deny(pending.id(), "approver@example.com");

        assertThat(store(file).outstanding()).isEmpty();
    }

    @Test
    @DisplayName("a corrupt queue file does not stop the gateway starting")
    void corruptFileIsSurvivable(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("approvals.json");
        Files.writeString(file, "{ this is not json");

        // Unlike the pin file, losing this is not a security failure — the worst outcome
        // is an operator re-approving a call the agent retries anyway. Refusing to start
        // would trade a harmless loss for an outage.
        assertThat(store(file).outstanding()).isEmpty();
    }

    @Test
    @DisplayName("the queue file is owner-only")
    void ownerOnlyPermissions(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("approvals.json");
        store(file).request("agent", "files", "write_file", "needs a human");

        assertThat(Files.getPosixFilePermissions(file))
                .containsExactlyInAnyOrder(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
    }

    @Test
    @DisplayName("with no file configured nothing is written")
    void memoryOnlyWritesNothing(@TempDir Path dir) {
        var s = new ApprovalStore(new ApprovalProperties(), mapper());
        s.restore();
        var p = s.request("agent", "files", "write_file", "needs a human");

        assertThat(s.outstanding()).containsKey(p.id());
        assertThat(dir.toFile().list()).isEmpty();
    }
}
