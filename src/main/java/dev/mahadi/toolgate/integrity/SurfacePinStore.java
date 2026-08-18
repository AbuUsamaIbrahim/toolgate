package dev.mahadi.toolgate.integrity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.util.FilePaths;
import dev.mahadi.toolgate.util.SecureJsonFile;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Trust-on-first-use pinning for resources and prompts.
 *
 * <h2>Why this exists when the annotation clamp already runs</h2>
 * The clamp stops an unreviewed resource declaring itself required <em>right now</em>. It
 * does nothing about a server that behaves for a fortnight and then quietly changes what it
 * already had permission to offer. A resource approved as "Project README, priority 0.3"
 * can be re-advertised as "Project README, priority 1.0, audience assistant" with an
 * entirely different description, and without a pin the only thing standing in the way is a
 * clamp that a reviewed resource is exempt from.
 *
 * <p>That is the same mutation-after-approval attack tool pinning was built for, on a
 * surface where the payload is the content itself rather than a persuasive description.
 *
 * <h2>Why it is a separate store from tool pins</h2>
 * Tools, resources and prompts are different shapes, and a single record with three
 * optional definition fields would be worse than two files. What is emphatically
 * <em>not</em> duplicated is the part that matters: both stores write through
 * {@link SecureJsonFile}, so the atomic write, the fsync, the owner-only permissions and
 * the refusal to load a group-writable file are one implementation. Two copies of that is
 * how one of them quietly stops fsyncing.
 */
@Component
public class SurfacePinStore {

    private static final Logger log = LoggerFactory.getLogger(SurfacePinStore.class);

    private static final int SCHEMA_VERSION = 1;

    public enum Kind { RESOURCE, PROMPT }

    /**
     * A definition a human — or trust on first use — accepted.
     *
     * <p>The whole definition is kept, not just its hash, for the same reason tool pins
     * keep theirs: a hash proves something changed and can never show what, and "what" is
     * the only question an operator can act on.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Pin(Kind kind, String serverId, String id, String fingerprint,
                      Instant pinnedAt, Map<String, Object> definition) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Document(int schemaVersion, Map<String, Pin> pins) {}

    public sealed interface Verdict {
        record Known(Pin pin) implements Verdict {}
        record FirstSighting(Pin pin) implements Verdict {}
        record Drifted(Pin pin, String actualFingerprint) implements Verdict {}
    }

    private final Map<String, Pin> pins = new ConcurrentHashMap<>();
    private final PinProperties props;
    private final ObjectMapper mapper;

    public SurfacePinStore(PinProperties props, ObjectMapper mapper) {
        this.props = props;
        this.mapper = mapper;
    }

    public Verdict check(Kind kind, String serverId, String id, String fingerprint,
                         Map<String, Object> definition) {
        String key = key(kind, serverId, id);
        Pin existing = pins.get(key);

        if (existing == null) {
            Pin created = new Pin(kind, serverId, id, fingerprint, Instant.now(), definition);
            pins.put(key, created);
            persist();
            return new Verdict.FirstSighting(created);
        }
        if (existing.fingerprint().equals(fingerprint)) {
            return new Verdict.Known(existing);
        }
        // Never auto-healed, for the reason tool pins are not: an attacker who can mutate
        // twice would otherwise simply mutate twice.
        log.warn("{} definition drift for {} pinned={} actual={}",
                kind, key, shortHash(existing.fingerprint()), shortHash(fingerprint));
        return new Verdict.Drifted(existing, fingerprint);
    }

    public Verdict check(String serverId, Mcp.Resource resource) {
        return check(Kind.RESOURCE, serverId, resource.uri(), ToolFingerprint.of(resource),
                mapper.convertValue(resource, new TypeReference<Map<String, Object>>() {}));
    }

    public Verdict check(String serverId, Mcp.Prompt prompt) {
        return check(Kind.PROMPT, serverId, prompt.name(), ToolFingerprint.of(prompt),
                mapper.convertValue(prompt, new TypeReference<Map<String, Object>>() {}));
    }

    /** Discards a pin created by a sighting that was then refused for another reason. */
    public void forget(Kind kind, String serverId, String id) {
        if (pins.remove(key(kind, serverId, id)) != null) persist();
    }

    /** Accepts a changed definition as the new baseline. Deliberate operator action only. */
    public Pin accept(Kind kind, String serverId, String id, String fingerprint,
                      Map<String, Object> definition) {
        log.warn("Operator re-pinned {} {} — previous baseline discarded", kind,
                key(kind, serverId, id));
        Pin pin = new Pin(kind, serverId, id, fingerprint, Instant.now(), definition);
        pins.put(key(kind, serverId, id), pin);
        persist();
        return pin;
    }

    public Optional<Pin> get(Kind kind, String serverId, String id) {
        return Optional.ofNullable(pins.get(key(kind, serverId, id)));
    }

    public Map<String, Pin> all() {
        return Map.copyOf(pins);
    }

    /** Blank pin file means memory only — the same escape hatch the other stores have. */
    private boolean persistent() {
        return props.getFile() != null && !props.getFile().isBlank();
    }

    @PostConstruct
    void restore() {
        if (!persistent()) return;
        Path path = path();
        if (!Files.exists(path)) return;
        if (props.isRequireSecurePermissions()) {
            SecureJsonFile.requireOwnerOnly(path, "The surface pin file");
        }
        try {
            Document doc = mapper.readValue(Files.readAllBytes(path), Document.class);
            if (doc.schemaVersion() != SCHEMA_VERSION) {
                // Refuse rather than guess. Loading a shape this build does not understand
                // and treating the gaps as "nothing pinned" would re-trust everything.
                throw new PinStorage.PinStorageException(
                        "surface pin file schema %d is not readable by this build (expects %d)"
                                .formatted(doc.schemaVersion(), SCHEMA_VERSION));
            }
            if (doc.pins() != null) pins.putAll(doc.pins());
            log.info("Restored {} resource/prompt pin(s)", pins.size());
        } catch (PinStorage.PinStorageException e) {
            throw e;
        } catch (Exception e) {
            throw new PinStorage.PinStorageException(
                    "surface pin file at " + path + " could not be read", e);
        }
    }

    /**
     * A persistence failure is logged, not thrown.
     *
     * <p>The in-memory pin is already correct and still enforcing; refusing the request
     * would turn a disk problem into an outage. The log line is the operator's signal that
     * restarts are no longer safe.
     */
    private void persist() {
        if (!persistent()) return;
        try {
            SecureJsonFile.writeAtomically(path(), mapper,
                    new Document(SCHEMA_VERSION, Map.copyOf(pins)));
        } catch (Exception e) {
            log.error("Failed to persist resource/prompt pins — enforcement continues in "
                    + "memory, but a restart will lose this state: {}", e.toString());
        }
    }

    private Path path() {
        String pinFile = props.getFile();
        String surfaces = pinFile.endsWith(".json")
                ? pinFile.substring(0, pinFile.length() - 5) + "-surfaces.json"
                : pinFile + "-surfaces";
        return FilePaths.expandUser(surfaces);
    }

    private static String key(Kind kind, String serverId, String id) {
        return kind + ":" + serverId + "/" + id;
    }

    private static String shortHash(String hash) {
        return hash.length() <= 12 ? hash : hash.substring(0, 12);
    }
}
