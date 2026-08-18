package dev.mahadi.toolgate.integrity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Pins persisted as a JSON document on disk.
 *
 * <h2>Why a file rather than a database</h2>
 * The dataset is one small record per tool, written rarely and read on every
 * {@code tools/list}. What actually matters is that an operator can <em>read</em> it:
 * reviewing which definitions are trusted, diffing that set in review, and committing an
 * approved baseline to version control are all workflows a JSON file supports and an
 * opaque database file obstructs. Embedding SQLite would also add a per-platform native
 * library to something desktop clients launch as a subprocess, where a load failure is
 * both likely and painful to debug.
 *
 * <h2>Durability</h2>
 * Writes go to a temporary file in the same directory, are flushed to disk, and are then
 * moved into place atomically. A crash mid-write therefore leaves either the previous
 * complete file or the new complete file, never a truncated one — which for a trust store
 * would mean silently forgetting which tools were approved.
 *
 * <h2>Failure is not emptiness</h2>
 * If the file exists but cannot be parsed, startup fails. The tempting alternative —
 * shrug and start with no pins — re-trusts every tool the next time it is advertised, so
 * a corrupted file would quietly do exactly what an attacker wants.
 */
@Component
public class FilePinStorage implements PinStorage {

    private static final Logger log = LoggerFactory.getLogger(FilePinStorage.class);

    /** Bumped when the on-disk shape changes incompatibly. */
    private static final int SCHEMA_VERSION = 1;

    private static final Set<PosixFilePermission> UNSAFE = Set.of(
            PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);

    private final PinProperties props;
    private final ObjectMapper mapper;

    public FilePinStorage(PinProperties props) {
        this.props = props;
        this.mapper = new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT); // meant to be read by people
    }

    /** On-disk shape. Versioned so a future change can migrate rather than misread. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Document(int schemaVersion, Instant savedAt, List<Entry> pins) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Entry(String serverId, String toolName, String fingerprint, Instant pinnedAt) {}

    public boolean enabled() {
        return !props.getFile().isBlank();
    }

    @Override
    public Map<String, ToolPinStore.Pin> load() {
        if (!enabled()) return new LinkedHashMap<>();

        Path path = path();
        if (!Files.exists(path)) {
            log.info("No pin file at {} — starting with an empty trust store", path);
            return new LinkedHashMap<>();
        }

        checkPermissions(path);

        try {
            Document doc = mapper.readValue(Files.readString(path), Document.class);
            if (doc.schemaVersion() != SCHEMA_VERSION) {
                throw new PinStorageException(
                        "pin file %s has schema version %d, this build understands %d"
                                .formatted(path, doc.schemaVersion(), SCHEMA_VERSION));
            }
            Map<String, ToolPinStore.Pin> pins = new LinkedHashMap<>();
            if (doc.pins() != null) {
                for (Entry e : doc.pins()) {
                    pins.put(e.serverId() + "/" + e.toolName(),
                            new ToolPinStore.Pin(e.serverId(), e.toolName(),
                                    e.fingerprint(), e.pinnedAt()));
                }
            }
            log.info("Loaded {} tool pins from {}", pins.size(), path);
            return pins;
        } catch (PinStorageException e) {
            throw e;
        } catch (Exception e) {
            // Deliberately fatal. See the class comment: an unreadable trust store must
            // not be mistaken for an empty one.
            throw new PinStorageException(
                    "pin file %s exists but could not be read; refusing to start with an "
                            + "empty trust store. Inspect or delete it deliberately.".formatted(path), e);
        }
    }

    @Override
    public synchronized void save(Map<String, ToolPinStore.Pin> pins) {
        if (!enabled()) return;

        Path path = path();
        try {
            Files.createDirectories(path.toAbsolutePath().getParent());

            // Sorted so the file is stable across saves and diffs cleanly in review.
            Map<String, ToolPinStore.Pin> sorted = new TreeMap<>(pins);
            List<Entry> entries = sorted.values().stream()
                    .map(p -> new Entry(p.serverId(), p.toolName(), p.fingerprint(), p.pinnedAt()))
                    .toList();

            String json = mapper.writeValueAsString(
                    new Document(SCHEMA_VERSION, Instant.now(), entries));

            Path tmp = Files.createTempFile(path.toAbsolutePath().getParent(), ".pins", ".tmp");
            try {
                Files.writeString(tmp, json, StandardOpenOption.TRUNCATE_EXISTING);
                fsync(tmp);
                restrictPermissions(tmp);
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                // Some filesystems cannot do it; a non-atomic replace is worse but better
                // than refusing to persist at all. Worth knowing about, hence the warning.
                log.warn("Atomic move unsupported on this filesystem; pin write is not crash-safe");
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        } catch (Exception e) {
            throw new PinStorageException("failed to persist pins to " + path, e);
        }
    }

    /** Forces the bytes to disk so an atomic rename cannot expose an empty file. */
    private static void fsync(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
    }

    private static void restrictPermissions(Path file) {
        try {
            Files.setPosixFilePermissions(file, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException e) {
            log.debug("Could not set permissions on {}: {}", file, e.toString());
        }
    }

    /**
     * Refuses to start on a group- or world-writable pin file.
     *
     * <p>Write access to this file is the ability to declare a poisoned tool definition
     * trusted before it is ever seen. That is a more direct path to compromise than any of
     * the attacks the gateway defends against, so it is treated as fatal rather than
     * logged and ignored.
     */
    private void checkPermissions(Path path) {
        if (!props.isRequireSecurePermissions()) return;
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            Set<PosixFilePermission> offending = perms.stream()
                    .filter(UNSAFE::contains)
                    .collect(java.util.stream.Collectors.toSet());
            if (!offending.isEmpty()) {
                throw new PinStorageException(
                        ("pin file %s is writable by %s. Anyone who can write it can pre-approve "
                         + "a poisoned tool. Run: chmod 600 %s")
                                .formatted(path, offending, path));
            }
        } catch (UnsupportedOperationException e) {
            log.debug("Filesystem does not report POSIX permissions; skipping check");
        } catch (IOException e) {
            throw new PinStorageException("could not check permissions on " + path, e);
        }
    }

    private Path path() {
        String configured = props.getFile();
        if (configured.startsWith("~/")) {
            configured = System.getProperty("user.home") + configured.substring(1);
        }
        return Path.of(configured);
    }
}
