package dev.mahadi.toolgate.integrity;

import java.util.LinkedHashMap;
import java.util.Map;

/** Non-durable storage, for tests whose subject is policy rather than persistence. */
public class InMemoryPinStorage implements PinStorage {

    private Map<String, ToolPinStore.Pin> saved = new LinkedHashMap<>();

    @Override
    public Map<String, ToolPinStore.Pin> load() {
        return new LinkedHashMap<>(saved);
    }

    @Override
    public void save(Map<String, ToolPinStore.Pin> pins) {
        saved = new LinkedHashMap<>(pins);
    }
}
