package dev.mahadi.toolgate.api;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

/**
 * Fanout bus for operator dashboard events.
 *
 * <p>Every connected SSE client subscribes to this bus. Publishers (AuditLog,
 * ApprovalStore, DriftStore) call {@link #publish} whenever something changes.
 * The bus uses a warm multicast so late subscribers miss events that fired before
 * they connected — that is fine, because each new SSE connection starts with a
 * snapshot of current state before subscribing.
 */
@Component
public class DashboardEventBus {

    private final Sinks.Many<DashboardEvent> sink = Sinks.many().multicast()
            .onBackpressureBuffer(256, false);

    public void publish(DashboardEvent event) {
        sink.tryEmitNext(event);
    }

    public Flux<DashboardEvent> subscribe() {
        return sink.asFlux();
    }
}
