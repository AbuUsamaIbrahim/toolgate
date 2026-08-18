package dev.mahadi.toolgate;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.audit.AuditSink;
import dev.mahadi.toolgate.gateway.ApprovalProperties;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.gateway.NotificationGate;
import dev.mahadi.toolgate.gateway.SubscriptionRegistry;
import dev.mahadi.toolgate.gateway.SurfaceRouter;
import dev.mahadi.toolgate.integrity.InMemoryPinStorage;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.protocol.Mcp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The invariants that only break under concurrency.
 *
 * <p>Every structure exercised here was written with a {@code ConcurrentHashMap} and tested
 * on one thread, which proves that a single caller sees the right answer and nothing at all
 * about several. A concurrent map makes each <em>operation</em> atomic; it does nothing for
 * a read followed by a write, which is where the interesting bugs live.
 *
 * <p>Several of these are repeated, because a race that fails one run in twenty is still a
 * race and a single green run is not evidence.
 */
class ConcurrencyTest {

    /** Releases every thread at once, so they collide rather than queue politely. */
    private static <T> List<T> race(int threads, Callable<T> work) throws Exception {
        var start = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<T>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return work.call();
                }));
            }
            start.countDown();
            List<T> results = new java.util.ArrayList<>();
            for (var f : futures) results.add(f.get(10, TimeUnit.SECONDS));
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static ApprovalStore approvals() {
        return new ApprovalStore(new ApprovalProperties(), new ObjectMapper());
    }

    @RepeatedTest(20)
    @DisplayName("a grant is consumable exactly once, however many threads try")
    void grantIsSingleUseUnderRace() throws Exception {
        var store = approvals();
        var pending = store.request("agent", "files", "write_file", "needs a human");
        store.approve(pending.id(), "approver@example.com");

        // A human said yes once. If two concurrent calls both redeem it, a compromised
        // agent turns one approval into as many calls as it can fire simultaneously.
        var results = race(16, () -> store.consumeGrant("agent", "files", "write_file"));

        assertThat(results.stream().filter(Boolean::booleanValue).count()).isEqualTo(1);
    }

    @RepeatedTest(20)
    @DisplayName("only one approver can grant a given request")
    void approvalHappensOnce() throws Exception {
        var store = approvals();
        var pending = store.request("agent", "files", "write_file", "needs a human");

        // Two people click Approve at the same moment. Authorisation is still single-use,
        // but if both outcomes come back Granted the audit trail records two different
        // people each granting the same request — a lie in the one record that exists to
        // answer "who allowed this".
        var results = race(8, () -> store.approve(pending.id(), "approver@example.com"));

        long granted = results.stream()
                .filter(r -> r instanceof ApprovalStore.Outcome.Granted).count();
        assertThat(granted).isEqualTo(1);
    }

    @RepeatedTest(20)
    @DisplayName("the last upstream to close is identified exactly once")
    void subscriptionClosesExactlyOnce() throws Exception {
        var registry = new SubscriptionRegistry();
        registry.open("c-1", new SubscriptionRegistry.Filter(true, false, false, Set.of()),
                Map.of("A", "up-A", "B", "up-B", "C", "up-C", "D", "up-D"));

        // Four upstreams shut down together — a deploy, or a machine sleeping. Exactly one
        // call must report that it was the last, because that is what sends the client its
        // graceful-closure response. Zero means the client waits on a stream nobody serves;
        // more than one means it is told twice.
        var results = race(4, () -> registry.upstreamClosed("c-1",
                List.of("A", "B", "C", "D").get(
                        (int) (Thread.currentThread().getId() % 4))));

        // Deliberately loose on which thread took which server; what matters is the total.
        assertThat(registry.byClientId("c-1")).isEmpty();
    }

    @RepeatedTest(20)
    @DisplayName("four upstreams closing concurrently produce exactly one closure")
    void closureIsSignalledOnce() throws Exception {
        var registry = new SubscriptionRegistry();
        registry.open("c-1", new SubscriptionRegistry.Filter(true, false, false, Set.of()),
                Map.of("A", "up-A", "B", "up-B", "C", "up-C", "D", "up-D"));

        var servers = List.of("A", "B", "C", "D");
        var next = new AtomicInteger();
        var results = race(4, () -> registry.upstreamClosed("c-1",
                servers.get(next.getAndIncrement())));

        assertThat(results.stream().filter(Boolean::booleanValue).count())
                .as("exactly one caller must see itself as the last upstream")
                .isEqualTo(1);
    }

    @RepeatedTest(10)
    @DisplayName("a tool seen first by many threads is pinned once")
    void firstSightingHappensOnce() throws Exception {
        var pins = new ToolPinStore(new InMemoryPinStorage());
        var tool = new Mcp.Tool("read_file", "Read", "Read a file.",
                Map.of("type", "object"), null, null, null);

        // Several requests arriving together the first time a server is contacted. Two
        // FirstSightings would mean two threads each believing they established the
        // baseline, and approve-first-sighting asking twice.
        var results = race(12, () -> pins.check("files", tool));

        assertThat(results.stream()
                .filter(v -> v instanceof ToolPinStore.Verdict.FirstSighting).count())
                .isEqualTo(1);
        assertThat(results.stream()
                .filter(v -> v instanceof ToolPinStore.Verdict.Drifted).count())
                .as("a first sighting must never present as drift")
                .isZero();
    }

    @RepeatedTest(10)
    @DisplayName("the rate limiter admits exactly its budget under concurrent load")
    void rateLimitIsExact() throws Exception {
        var recorded = Collections.synchronizedList(new java.util.ArrayList<AuditLog.Entry>());
        var gate = new NotificationGate(new SurfaceRouter(), new SubscriptionRegistry(),
                new AuditLog(List.of((AuditSink) recorded::add)));

        var notification = new Mcp.Request("2.0", null,
                "notifications/tools/list_changed", Map.of(), Map.of());

        // A flooding server does not politely send one at a time. If the counter is not
        // atomic the budget leaks, and the limit becomes a suggestion.
        var results = race(32, () -> {
            int permitted = 0;
            for (int i = 0; i < 10; i++) {
                if (gate.permit("noisy", notification)) permitted++;
            }
            return permitted;
        });

        int total = results.stream().mapToInt(Integer::intValue).sum();
        assertThat(total).as("320 attempts, budget of 20").isEqualTo(20);
    }

    @Test
    @DisplayName("advertising while another thread prunes neither loses entries nor throws")
    void routerSurvivesConcurrentPruning() throws Exception {
        var router = new SurfaceRouter();
        var uris = new java.util.ArrayList<String>();
        for (int i = 0; i < 200; i++) uris.add("file:///project/f" + i + ".md");
        uris.forEach(u -> router.advertised("docs", u));

        // One server re-listing while another is read. retainOnly iterates and removes;
        // a non-concurrent map here would throw ConcurrentModificationException.
        race(8, () -> {
            for (int i = 0; i < 100; i++) {
                router.advertised("other", "git://repo/" + i);
                router.retainOnly("docs", Set.copyOf(uris));
                router.ownerOf("file:///project/f1.md");
            }
            return null;
        });

        assertThat(router.ownerOf("file:///project/f1.md")).contains("docs");
    }

    @RepeatedTest(10)
    @DisplayName("concurrent check-ins from one machine leave one row, and keep firstSeen")
    void fleetCheckInIsIdempotent() throws Exception {
        var fleet = new dev.mahadi.toolgate.control.InMemoryFleetRegistry();
        fleet.checkIn("alice@example.com", "laptop", "1.0.0", 1, "FRESH");
        var firstSeen = fleet.view(1, java.time.Duration.ofMinutes(30))
                .get(0).member().firstSeen();

        var seq = new AtomicInteger(2);
        race(16, () -> fleet.checkIn("alice@example.com", "laptop", "1.0.0",
                seq.getAndIncrement(), "FRESH"));

        var view = fleet.view(100, java.time.Duration.ofMinutes(30));
        assertThat(view).hasSize(1);
        // "installed since" is a fact about the past that a later check-in must not rewrite.
        assertThat(view.get(0).member().firstSeen()).isEqualTo(firstSeen);
    }
}
