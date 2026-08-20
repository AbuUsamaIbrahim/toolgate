package dev.mahadi.toolgate;

import dev.mahadi.toolgate.api.DashboardEvent;
import dev.mahadi.toolgate.api.DashboardEventBus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the operator's screen says has to match what the audit trail says.
 *
 * <h2>The failure this exists for</h2>
 * A {@code Sinks.Many} refuses concurrent emission: two threads calling
 * {@code tryEmitNext} in the same instant, and the loser gets {@code FAIL_NON_SERIALIZED}
 * back. The first version of the bus discarded that return value. The publishers are the
 * audit log and the approval store, called from whichever event-loop thread is handling a
 * refusal — so they are concurrent by construction, and under load the dashboard quietly
 * showed fewer refusals than had happened. Measured against a running gateway: sixty
 * refusals at thirty in parallel produced sixty durable audit records and thirty-nine to
 * forty-nine rows on the live view, varying per run. Twenty refusals one at a time produced
 * twenty of each, which is why nothing noticed.
 *
 * <p>A monitoring surface that drops events under exactly the conditions worth monitoring —
 * a burst of refusals — is worse than one that admits it cannot keep up, because the number
 * on the screen still looks authoritative.
 */
class DashboardEventBusTest {

    private static final int THREADS = 8;
    private static final int PER_THREAD = 60;
    private static final int TOTAL = THREADS * PER_THREAD;

    @Test
    @DisplayName("no event is lost when publishers run in parallel")
    void concurrentPublishersLoseNothing() throws Exception {
        DashboardEventBus bus = new DashboardEventBus();
        List<DashboardEvent> received = new CopyOnWriteArrayList<>();
        var subscription = bus.subscribe().subscribe(received::add);

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(THREADS);
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        try {
            for (int t = 0; t < THREADS; t++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        for (int i = 0; i < PER_THREAD; i++) {
                            bus.publish(new DashboardEvent.DriftChanged());
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();   // everyone contends at once, which is the point
            assertThat(done.await(20, TimeUnit.SECONDS)).isTrue();
        } finally {
            pool.shutdownNow();
        }

        // Give the subscriber a moment to drain, then require every single one.
        for (int i = 0; i < 100 && received.size() < TOTAL; i++) Thread.sleep(10);
        assertThat(received)
                .as("every published event reaches the live view, or the dashboard "
                        + "disagrees with the audit trail")
                .hasSize(TOTAL);

        subscription.dispose();
    }

    @Test
    @DisplayName("publishing with nobody watching is not an error")
    void noSubscriberIsFine() {
        DashboardEventBus bus = new DashboardEventBus();

        // The common case: no browser open. This must not throw, and must not be retried
        // into a busy loop either — it runs inside the audit path.
        bus.publish(new DashboardEvent.ApprovalsChanged());
        bus.publish(new DashboardEvent.DriftChanged());
    }

    @Test
    @DisplayName("the first browser to connect is not replayed everything it missed")
    void subscribersStartFromNow() throws Exception {
        DashboardEventBus bus = new DashboardEventBus();
        // Refusals between process start and the first console being opened. A buffering
        // sink replays these to whoever subscribes first — so the operator's first view
        // would show them live, on top of the same entries already rendered in the table
        // the page was served with. Every row twice.
        bus.publish(new DashboardEvent.DriftChanged());          // nobody listening yet

        List<DashboardEvent> received = new CopyOnWriteArrayList<>();
        var subscription = bus.subscribe().subscribe(received::add);
        bus.publish(new DashboardEvent.ApprovalsChanged());

        for (int i = 0; i < 100 && received.isEmpty(); i++) Thread.sleep(10);

        // Deliberate: each new connection is sent a fresh snapshot of current state, so
        // replaying history would show the operator events twice.
        assertThat(received).hasSize(1);
        assertThat(received.get(0)).isInstanceOf(DashboardEvent.ApprovalsChanged.class);

        subscription.dispose();
    }
}
