package dev.mahadi.toolgate.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Shared handling for the gateway's on-disk state.
 *
 * <p>Both files this covers — the pin store and the audit trail — are sensitive for the
 * same reason and were growing the same code twice, which is how two copies of a
 * permission check end up disagreeing about what "safe" means.
 */
public final class FilePaths {

    private static final Logger log = LoggerFactory.getLogger(FilePaths.class);

    private FilePaths() {}

    /**
     * Resolves a configured path, expanding a leading {@code ~}.
     *
     * <p>The shell expands tildes; a YAML file does not, and a gateway that quietly
     * creates a directory literally named {@code ~} in its working directory is a support
     * ticket waiting to happen.
     */
    public static Path expandUser(String configured) {
        String s = configured.trim();
        if (s.startsWith("~")) {
            s = System.getProperty("user.home") + s.substring(1);
        }
        return Path.of(s).toAbsolutePath().normalize();
    }

    /** Best effort 0600. Silently skipped on filesystems without POSIX permissions. */
    public static void restrictToOwner(Path file) {
        try {
            Files.setPosixFilePermissions(file, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException e) {
            log.debug("Could not set permissions on {}: {}", file, e.toString());
        }
    }
}
