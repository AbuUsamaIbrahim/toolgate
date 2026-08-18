package dev.mahadi.toolgate.integrity;

import dev.mahadi.toolgate.protocol.Mcp;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Trust-on-first-use pinning for tool definitions.
 *
 * <p>The first time the gateway sees a tool it records its fingerprint. Every later
 * sighting is compared against that pin. A changed fingerprint means the upstream server
 * altered something the model reads — which is either a legitimate release or an attack,
 * and the gateway cannot tell the difference. It therefore refuses and asks a human,
 * which is the only honest answer.
 *
 * <p>TOFU is a real trade-off and worth stating plainly: it assumes the first sighting is
 * clean. If a server is already compromised when first pinned, the malicious definition
 * becomes the trusted baseline. TOFU buys detection of <em>change</em>, not proof of
 * <em>goodness</em>. The mitigation is to seed pins from a reviewed manifest in
 * environments where that matters — see {@link #pin(String, Mcp.Tool)}.
 *
 * <p>Pins are held in memory for lookup and written through to {@link PinStorage} on every
 * change. Without persistence the control is theatre: each restart makes every tool a
 * first sighting, so a poisoned definition introduced across a restart boundary is simply
 * adopted as the new baseline.
 */
@Component
public class ToolPinStore {

    private static final Logger log = LoggerFactory.getLogger(ToolPinStore.class);

    /** Key is {@code serverId/toolName}; tool names are only unique within a server. */
    private final Map<String, Pin> pins = new ConcurrentHashMap<>();

    private final PinStorage storage;

    public ToolPinStore(PinStorage storage) {
        this.storage = storage;
    }

    /**
     * Loads persisted pins at startup.
     *
     * <p>A failure here is deliberately allowed to abort startup. Continuing with an empty
     * trust store after failing to read the real one would re-trust every tool, which is
     * the outcome the pin file exists to prevent.
     */
    @PostConstruct
    void restore() {
        pins.putAll(storage.load());
    }

    /**
     * A trusted tool definition.
     *
     * <p>The full {@code definition} is kept, not just its fingerprint. A hash can prove
     * that something changed but can never show <em>what</em>, and "what" is the only
     * question an operator can act on. Pins written before this was stored carry a null
     * definition; drift is still detected for them, it simply cannot be diffed.
     */
    public record Pin(String serverId, String toolName, String fingerprint,
                      Instant pinnedAt, Mcp.Tool definition) {}

    /** Outcome of checking a tool against its pin. */
    public sealed interface Verdict {
        /** Fingerprint matches the existing pin. */
        record Known(Pin pin) implements Verdict {}

        /** No pin existed; one has now been recorded. */
        record FirstSighting(Pin pin) implements Verdict {}

        /** Fingerprint differs from the pin. The definition changed under us. */
        record Drifted(Pin pin, String actualFingerprint) implements Verdict {}
    }

    /**
     * Checks a tool against its pin, recording one if this is the first sighting.
     *
     * <p>Note that a drifted tool does <em>not</em> update the pin. Auto-healing would
     * defeat the control entirely: an attacker would simply mutate twice.
     */
    public Verdict check(String serverId, Mcp.Tool tool) {
        String key = key(serverId, tool.name());
        String actual = ToolFingerprint.of(tool);
        Pin existing = pins.get(key);

        if (existing == null) {
            Pin created = new Pin(serverId, tool.name(), actual, Instant.now(), tool);
            pins.put(key, created);
            persist();
            log.info("Pinned new tool {} fingerprint={}", key, shortHash(actual));
            return new Verdict.FirstSighting(created);
        }
        if (existing.fingerprint().equals(actual)) {
            return new Verdict.Known(existing);
        }
        log.warn("Tool definition drift for {} pinned={} actual={}",
                key, shortHash(existing.fingerprint()), shortHash(actual));
        return new Verdict.Drifted(existing, actual);
    }

    /** Seeds a pin explicitly, for operators who review definitions before first use. */
    public Pin pin(String serverId, Mcp.Tool tool) {
        Pin p = new Pin(serverId, tool.name(), ToolFingerprint.of(tool), Instant.now(), tool);
        pins.put(key(serverId, tool.name()), p);
        persist();
        return p;
    }

    /**
     * Writes the current set through to storage.
     *
     * <p>A persistence failure is logged rather than thrown. The in-memory pin is already
     * correct and still enforcing; refusing the request would turn a disk problem into an
     * outage. The log line is the operator's signal that restarts are no longer safe.
     */
    private void persist() {
        try {
            storage.save(pins);
        } catch (Exception e) {
            log.error("Failed to persist pins — enforcement continues in memory, but a "
                    + "restart will lose this state: {}", e.toString());
        }
    }

    /** Accepts a drifted definition as the new baseline. Deliberate operator action only. */
    public Pin repin(String serverId, Mcp.Tool tool) {
        log.warn("Operator re-pinned {} — previous baseline discarded", key(serverId, tool.name()));
        return pin(serverId, tool);
    }

    /**
     * Discards a pin.
     *
     * <p>Used when a definition is pinned on first sighting and then refused by a later
     * check. A pin is meant to record the definition <em>in force</em>; keeping one for a
     * tool the gateway never advertised has an unpleasant consequence — when the upstream
     * fixes the poisoned description, the repair reads as drift and stays blocked until a
     * human accepts it. Remediation should not need permission.
     */
    public void forget(String serverId, String toolName) {
        if (pins.remove(key(serverId, toolName)) != null) {
            persist();
        }
    }

    public Optional<Pin> get(String serverId, String toolName) {
        return Optional.ofNullable(pins.get(key(serverId, toolName)));
    }

    public Map<String, Pin> all() {
        return Map.copyOf(pins);
    }

    private static String key(String serverId, String toolName) {
        return serverId + "/" + toolName;
    }

    private static String shortHash(String hash) {
        return hash.length() <= 12 ? hash : hash.substring(0, 12);
    }
}
