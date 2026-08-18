package dev.mahadi.toolgate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parses the configuration file the jar actually ships with.
 *
 * <p>This exists because of a defect it would have caught. The test suite has its own
 * {@code application.yml} on the test classpath, and Spring loads the first one it finds —
 * so every test ran green while the shipped default contained a duplicate {@code
 * management} key that made the application refuse to start. The suite was thoroughly
 * testing a configuration no user will ever have.
 *
 * <p>A default config is a shipped artifact. It deserves a test like any other.
 */
class ShippedConfigTest {

    private static final Path CONFIG = Path.of("src/main/resources/application.yml");

    private List<PropertySource<?>> load() throws Exception {
        assertThat(Files.exists(CONFIG)).as("shipped config exists").isTrue();
        return new YamlPropertySourceLoader()
                .load("shipped", new FileSystemResource(CONFIG.toFile()));
    }

    @Test
    @DisplayName("the shipped configuration parses")
    void itParses() throws Exception {
        // Duplicate keys, bad indentation and tabs all fail here rather than on a user's
        // first run.
        assertThat(load()).isNotEmpty();
    }

    @Test
    @DisplayName("the shipped defaults are the safe ones")
    void defaultsAreSafe() throws Exception {
        var source = load().get(0);

        // Each of these has been wrong at some point in this project's history, and each
        // is the kind of wrong that looks like it is working.
        assertThat(source.getProperty("toolgate.auth.enabled"))
                .as("a security gateway that ships open has the wrong default").isEqualTo(true);
        assertThat(source.getProperty("toolgate.operator.enabled"))
                .as("the operator API can approve anything").isEqualTo(true);
        assertThat(source.getProperty("toolgate.operator.loopback-only")).isEqualTo(true);
        assertThat(source.getProperty("toolgate.operator.token-sha256"))
                .as("no default operator credential; unconfigured must mean closed").isEqualTo("");
        assertThat(source.getProperty("toolgate.pins.require-secure-permissions")).isEqualTo(true);
        assertThat(source.getProperty("toolgate.audit.fail-closed"))
                .as("off by default: do not disable the protection to protect the paperwork")
                .isEqualTo(false);
    }

    @Test
    @DisplayName("the shipped config points at no upstreams and no bundle")
    void noPhantomDefaults() throws Exception {
        var source = load().get(0);

        // A default pointing at a server that does not exist produces confusing errors on
        // first run, and one pointing at a server that does exist is worse.
        assertThat(source.getProperty("toolgate.servers")).isNull();
        assertThat(source.getProperty("toolgate.bundle.source")).isEqualTo("");
        assertThat(source.getProperty("toolgate.otlp.endpoint")).isEqualTo("");
        assertThat(source.getProperty("toolgate.auth.oidc.issuer")).isEqualTo("");
    }

    @Test
    @DisplayName("the placeholder token hash matches the value its comment names")
    void placeholderHashIsHonest() throws Exception {
        var source = load().get(0);
        var digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest("change-me".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        // A placeholder that does not match its own comment sends whoever is trying it out
        // debugging their setup instead of the config.
        assertThat(source.getProperty("toolgate.auth.callers.example-agent.token-sha256"))
                .isEqualTo(java.util.HexFormat.of().formatHex(digest));
    }
}
