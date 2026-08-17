package dev.mahadi.toolgate.integrity;

import dev.mahadi.toolgate.protocol.Mcp;
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
 */
@Component
public class ToolPinStore {

    private static final Logger log = LoggerFactory.getLogger(ToolPinStore.class);

    /** Key is {@code serverId/toolName}; tool names are only unique within a server. */
    private final Map<String, Pin> pins = new ConcurrentHashMap<>();

    public record Pin(String serverId, String toolName, String fingerprint, Instant pinnedAt) {}

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
            Pin created = new Pin(serverId, tool.name(), actual, Instant.now());
            pins.put(key, created);
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
        Pin p = new Pin(serverId, tool.name(), ToolFingerprint.of(tool), Instant.now());
        pins.put(key(serverId, tool.name()), p);
        return p;
    }

    /** Accepts a drifted definition as the new baseline. Deliberate operator action only. */
    public Pin repin(String serverId, Mcp.Tool tool) {
        log.warn("Operator re-pinned {} — previous baseline discarded", key(serverId, tool.name()));
        return pin(serverId, tool);
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
