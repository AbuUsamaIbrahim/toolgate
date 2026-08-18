package dev.mahadi.toolgate.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Reading and writing the gateway's trust files, done once.
 *
 * <p>This exists because the alternative was a second copy. The pin store already had an
 * atomic write, an fsync, an owner-only chmod and a refusal to load a group-writable file,
 * and the resource pins needed exactly the same four things. Two copies of a
 * security-critical write path is how one of them quietly stops doing the fsync, and
 * nobody finds out until a machine loses power mid-write and comes back trusting an empty
 * trust store.
 *
 * <p>Each rule is here for a specific failure:
 *
 * <ul>
 *   <li><b>Write to a temp file, fsync, then rename.</b> A rename within a filesystem is
 *       atomic, so a reader sees either the old file or the new one. Writing in place means
 *       a crash halfway leaves a truncated trust store, which parses as "trust nothing" or,
 *       worse, "trust the half that survived".</li>
 *   <li><b>fsync before the rename.</b> The rename can otherwise reach the disk before the
 *       contents do, leaving a correctly named empty file after a power loss.</li>
 *   <li><b>Owner-only permissions.</b> These files decide which tool definitions are
 *       trusted. Write access to one is the ability to pre-approve a poisoned tool.</li>
 *   <li><b>Refuse a group- or world-writable file.</b> Not a warning. If someone else can
 *       write it, its contents prove nothing, and enforcing against it would be theatre.</li>
 * </ul>
 */
public final class SecureJsonFile {

    private static final Logger log = LoggerFactory.getLogger(SecureJsonFile.class);

    private static final Set<PosixFilePermission> UNSAFE = Set.of(
            PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);

    private SecureJsonFile() {}

    public static class InsecureFileException extends RuntimeException {
        public InsecureFileException(String message) { super(message); }
    }

    /**
     * Aborts if anyone but the owner can write the file.
     *
     * @param what a human name for the file, used in the message someone has to act on
     */
    public static void requireOwnerOnly(Path path, String what) {
        try {
            if (!Files.exists(path)) return;
            Set<PosixFilePermission> offending = Files.getPosixFilePermissions(path).stream()
                    .filter(UNSAFE::contains).collect(java.util.stream.Collectors.toSet());
            if (!offending.isEmpty()) {
                throw new InsecureFileException(
                        ("%s at %s is writable by %s. Anyone who can write it can pre-approve "
                         + "a poisoned definition. Fix with: chmod 600 %s")
                                .formatted(what, path, offending, path));
            }
        } catch (UnsupportedOperationException e) {
            log.debug("Filesystem does not report POSIX permissions; skipping check on {}", path);
        } catch (IOException e) {
            throw new InsecureFileException("could not check permissions on " + path);
        }
    }

    /** Writes JSON so that a reader sees the whole previous file or the whole new one. */
    public static void writeAtomically(Path path, ObjectMapper mapper, Object value)
            throws IOException {
        Files.createDirectories(path.getParent());
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");

        Files.write(tmp, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));
        fsync(tmp);
        FilePaths.restrictToOwner(tmp);

        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        FilePaths.restrictToOwner(path);
    }

    private static void fsync(Path file) throws IOException {
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
    }
}
