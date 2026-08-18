package dev.mahadi.toolgate.control;

import dev.mahadi.toolgate.bundle.BundleStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Reports this gateway's existence and state to the control plane.
 *
 * <p>What it sends is deliberately thin: who (from the token), which machine, which build,
 * which policy sequence, and whether that policy is healthy. Not what tools were called,
 * not by whom, not how often. A coverage mechanism that quietly becomes a
 * developer-activity feed is a different product, and one people are right to resent —
 * the audit trail already exists for the questions that need answering, and it goes to the
 * SIEM rather than to a service whose job is counting installations.
 *
 * <p>Failures are logged and forgotten. A control plane that is down must not stop a
 * developer working; the consequence of a missed check-in is that this machine shows as
 * silent in a report, which is exactly the signal the report exists to give.
 */
@Component
@Profile("!control")
public class ControlPlaneReporter {

    private static final Logger log = LoggerFactory.getLogger(ControlPlaneReporter.class);

    private final ControlProperties props;
    private final BundleStore bundles;
    private final ObjectMapper mapper;
    private final String version;

    private HttpClient http;
    private ScheduledExecutorService scheduler;

    public ControlPlaneReporter(ControlProperties props, BundleStore bundles, ObjectMapper mapper,
                                @Value("${toolgate.version:dev}") String version) {
        this.props = props;
        this.bundles = bundles;
        this.mapper = mapper;
        this.version = version;
    }

    /**
     * The credential used to check in.
     *
     * <p>Read from the environment rather than configuration, because on a developer
     * machine it is whatever their login flow deposited and it changes every few hours.
     * Absent, the gateway simply does not report — it does not fail, and it does not
     * degrade. Coverage reporting is not a precondition for enforcement.
     */
    private String token() {
        String t = System.getenv("TOOLGATE_CONTROL_TOKEN");
        return t == null ? "" : t.trim();
    }

    @PostConstruct
    void start() {
        if (!props.reportingEnabled()) return;

        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "toolgate-checkin");
            t.setDaemon(true);
            return t;
        });

        long seconds = Math.max(30, props.getCheckInInterval().toSeconds());
        // A small initial delay, not zero: at startup the bundle is still loading, and
        // reporting sequence -1 before it settles would show the whole fleet as degraded
        // every time it restarts.
        scheduler.scheduleAtFixedRate(this::checkIn, 10, seconds, TimeUnit.SECONDS);
        log.info("Reporting to the control plane at {} every {}s", props.getUrl(), seconds);
    }

    @PreDestroy
    void stop() {
        if (scheduler != null) scheduler.shutdownNow();
    }

    void checkIn() {
        try {
            var body = new ControlController.CheckInRequest(
                    instanceId(), version,
                    bundles.current().map(b -> b.sequence()).orElse(-1L),
                    bundles.health().name());

            var builder = HttpRequest.newBuilder(URI.create(props.getUrl() + "/control/v1/checkin"))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body)));

            String token = token();
            if (!token.isEmpty()) builder.header("Authorization", "Bearer " + token);

            HttpResponse<String> response = http.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 401) {
                log.warn("Check-in refused: no valid credential. This machine will show as "
                        + "silent in coverage reports until that is fixed.");
            } else if (response.statusCode() != 200) {
                log.debug("Check-in returned HTTP {}", response.statusCode());
            }
        } catch (Exception e) {
            log.debug("Check-in failed: {}", e.toString());
        }
    }

    private String instanceId() {
        if (props.getInstanceId() != null && !props.getInstanceId().isBlank()) {
            return props.getInstanceId();
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown";
        }
    }
}
