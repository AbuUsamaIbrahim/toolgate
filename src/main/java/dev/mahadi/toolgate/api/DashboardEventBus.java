package dev.mahadi.toolgate.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.time.Duration;

/**
 * Fanout bus for operator dashboard events.
 *
 * <p>Every connected SSE client subscribes to this bus. Publishers (AuditLog,
 * ApprovalStore, DriftStore) call {@link #publish} whenever something changes.
 * A subscriber sees what happens after it connects and nothing before it — that is the
 * design, not a limitation, because each new SSE connection is served a snapshot of
 * current state first, and replaying history on top of a snapshot shows it twice.
 *
 * <h2>Why emission is retried rather than attempted</h2>
 * A {@code Sinks.Many} refuses concurrent emission: two threads calling
 * {@code tryEmitNext} at the same instant get {@code FAIL_NON_SERIALIZED}, and the loser's
 * event is gone. The publishers here are the audit log and the approval store, called from
 * whichever event-loop thread happened to be handling a refusal — concurrent by
 * construction. Discarding the return value cost a measured fifth of the events under
 * thirty parallel refusals, and the shape of the loss is the dangerous part: the durable
 * audit trail keeps every refusal while the operator's live view quietly shows fewer, so
 * the two disagree and the screen is the one being believed. Busy-looping is safe because
 * the contended window is the duration of one queue offer.
 */
@Component
public class DashboardEventBus {

    private static final Logger log = LoggerFactory.getLogger(DashboardEventBus.class);

    private final Sinks.Many<DashboardEvent> sink = Sinks.many().multicast()
            .onBackpressureBuffer(256, false);

    /**
     * A subscriber that exists so the sink is never cold.
     *
     * <p>{@code onBackpressureBuffer} holds emissions until its <em>first</em> subscriber
     * arrives and then replays them — warm-up behaviour that is useful in general and wrong
     * here. Every refusal between process start and the first browser would arrive on that
     * browser as a live event, on top of the same refusals already rendered into the table
     * it was served: the operator's first sight of the console would be every entry twice.
     * Draining from construction makes "you see what happens from now on" true for the first
     * connection as well as the rest, which is what the snapshot-then-stream design assumes.
     * The buffer still does its real job, absorbing bursts for subscribers that are behind.
     */
    @SuppressWarnings("unused")
    private final reactor.core.Disposable warmUp = sink.asFlux().subscribe();

    public void publish(DashboardEvent event) {
        Sinks.EmitResult result = sink.tryEmitNext(event);
        if (result.isSuccess()) return;

        if (result == Sinks.EmitResult.FAIL_NON_SERIALIZED) {
            // Contention, not failure: retry until the other emitter is done. Bounded, and
            // the throw on expiry is caught — this runs inside the audit path, and a
            // dashboard that cannot be updated must never be able to fail a tool call.
            try {
                sink.emitNext(event, Sinks.EmitFailureHandler.busyLooping(Duration.ofMillis(100)));
            } catch (RuntimeException e) {
                log.warn("Dashboard event dropped after contending for 100ms: {}", e.toString());
            }
            return;
        }
        // Overflow means a browser stopped reading; zero subscribers means nobody is
        // watching. Neither can be retried into success, and neither may fail a tool call —
        // but a dropped event is not allowed to be silent, because the dashboard's whole
        // claim is that it shows what happened.
        if (result != Sinks.EmitResult.FAIL_ZERO_SUBSCRIBER) {
            log.warn("Dashboard event dropped ({}); the live view is now behind the audit "
                    + "trail until the page is reloaded", result);
        }
    }

    public Flux<DashboardEvent> subscribe() {
        return sink.asFlux();
    }
}
