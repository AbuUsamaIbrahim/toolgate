package dev.mahadi.toolgate.control;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Coverage reporting. The value of this is entirely in what it flags, so these tests are
 * about the four ways a gateway can be wrong rather than the one way it can be right.
 */
class FleetRegistryTest {

    private FleetRegistry fleet;

    @BeforeEach
    void setUp() {
        fleet = new InMemoryFleetRegistry();
    }

    @Test
    @DisplayName("a healthy gateway on the current bundle is unremarkable")
    void healthyMember() {
        fleet.checkIn("alice@example.com", "alice-mbp", "1.3.0", 200, "FRESH");

        var view = fleet.view(200, Duration.ofMinutes(30));

        assertThat(view).hasSize(1);
        assertThat(view.get(0).status()).isEqualTo(FleetRegistry.Status.HEALTHY);
    }

    @Test
    @DisplayName("a gateway on an older bundle is flagged as behind")
    void behindOnPolicy() {
        fleet.checkIn("bob@example.com", "bob-mbp", "1.3.0", 198, "FRESH");

        assertThat(fleet.view(200, Duration.ofMinutes(30)).get(0).status())
                .isEqualTo(FleetRegistry.Status.BEHIND);
    }

    @Test
    @DisplayName("a gateway whose own policy has expired is degraded, not merely behind")
    void degradedPolicy() {
        // Reporting the current sequence, but its bundle aged out. It is enforcing rules
        // it can no longer refresh, which is a different problem from being one version old.
        fleet.checkIn("carol@example.com", "carol-mbp", "1.3.0", 200, "STALE");

        assertThat(fleet.view(200, Duration.ofMinutes(30)).get(0).status())
                .isEqualTo(FleetRegistry.Status.DEGRADED);
    }

    @Test
    @DisplayName("a gateway that has stopped reporting is silent")
    void silentMember() {
        fleet.checkIn("dave@example.com", "dave-mbp", "1.3.0", 200, "FRESH");

        // Everything is fine except that nobody has heard from it.
        assertThat(fleet.view(200, Duration.ofNanos(1)).get(0).status())
                .isEqualTo(FleetRegistry.Status.SILENT);
    }

    @Test
    @DisplayName("a gateway with no bundle configured is not treated as broken")
    void disabledIsNotDegraded() {
        // Someone running it locally against their own YAML. Not a coverage failure.
        fleet.checkIn("eve@example.com", "eve-mbp", "1.3.0", -1, "DISABLED");

        assertThat(fleet.view(-1, Duration.ofMinutes(30)).get(0).status())
                .isEqualTo(FleetRegistry.Status.HEALTHY);
    }

    @Test
    @DisplayName("the report is ordered worst first")
    void worstFirst() {
        fleet.checkIn("healthy@example.com", "m1", "1.3.0", 200, "FRESH");
        fleet.checkIn("behind@example.com", "m2", "1.3.0", 100, "FRESH");
        fleet.checkIn("degraded@example.com", "m3", "1.3.0", 200, "FAILED");

        var statuses = fleet.view(200, Duration.ofMinutes(30)).stream()
                .map(FleetRegistry.FleetView::status).toList();

        // A coverage report sorted alphabetically is one nobody reads to the bottom.
        assertThat(statuses).containsExactly(
                FleetRegistry.Status.DEGRADED,
                FleetRegistry.Status.BEHIND,
                FleetRegistry.Status.HEALTHY);
    }

    @Test
    @DisplayName("one person may run several machines, tracked separately")
    void multipleMachinesPerPerson() {
        fleet.checkIn("alice@example.com", "laptop", "1.3.0", 200, "FRESH");
        fleet.checkIn("alice@example.com", "desktop", "1.3.0", 150, "FRESH");

        var view = fleet.view(200, Duration.ofMinutes(30));

        assertThat(view).hasSize(2);
        assertThat(view).anyMatch(v -> v.status() == FleetRegistry.Status.BEHIND);
    }

    @Test
    @DisplayName("repeated check-ins update state without creating duplicates")
    void checkInIsIdempotentPerMachine() {
        fleet.checkIn("alice@example.com", "laptop", "1.3.0", 100, "FRESH");
        var first = fleet.view(200, Duration.ofMinutes(30)).get(0).member().firstSeen();

        fleet.checkIn("alice@example.com", "laptop", "1.3.0", 200, "FRESH");
        var view = fleet.view(200, Duration.ofMinutes(30));

        assertThat(view).hasSize(1);
        assertThat(view.get(0).member().bundleSequence()).isEqualTo(200);
        // firstSeen survives, so "installed since" stays answerable.
        assertThat(view.get(0).member().firstSeen()).isEqualTo(first);
    }

    @Test
    @DisplayName("forgetting is explicit, because silence is the finding")
    void forgetIsManual() {
        fleet.checkIn("gone@example.com", "old-laptop", "1.0.0", 1, "FRESH");

        // Nothing prunes on its own: a machine vanishing from the report because it went
        // quiet is the report answering a question it was not asked.
        assertThat(fleet.view(200, Duration.ofMinutes(30))).hasSize(1);
        assertThat(fleet.forget(Duration.ofNanos(1))).isEqualTo(1);
        assertThat(fleet.view(200, Duration.ofMinutes(30))).isEmpty();
    }
}
