package dev.mahadi.toolgate.integrity;

import java.util.Map;

/**
 * Persistence for tool pins.
 *
 * <p>Pins are the gateway's trust store. Losing them is not a cache miss — it silently
 * disarms the control, because every tool becomes a first sighting and the poisoning
 * defence has nothing to compare against until it has seen the same definition twice.
 */
public interface PinStorage {

    /**
     * Loads all pins.
     *
     * @throws PinStorageException if the store exists but cannot be read or trusted. The
     *         caller must not treat this as "no pins": that is precisely the silent
     *         disarm this interface exists to prevent.
     */
    Map<String, ToolPinStore.Pin> load();

    /** Persists the complete set, replacing whatever was there. */
    void save(Map<String, ToolPinStore.Pin> pins);

    /** Raised when the store is unreadable, malformed, or of an unknown schema version. */
    class PinStorageException extends RuntimeException {
        public PinStorageException(String message, Throwable cause) {
            super(message, cause);
        }
        public PinStorageException(String message) {
            super(message);
        }
    }
}
