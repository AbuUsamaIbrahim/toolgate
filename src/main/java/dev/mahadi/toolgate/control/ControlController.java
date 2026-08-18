package dev.mahadi.toolgate.control;

import dev.mahadi.toolgate.auth.AccessToken;
import dev.mahadi.toolgate.auth.AuthProperties;
import dev.mahadi.toolgate.auth.TokenValidator;
import dev.mahadi.toolgate.bundle.BundleVerifier;
import dev.mahadi.toolgate.util.FilePaths;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * The control plane: serves policy to the fleet and records who is enforcing it.
 *
 * <p>Runs under the {@code control} profile, from the same image as the gateway. One
 * artifact means the bundle types used to sign here and to verify there cannot drift apart
 * — which is worth more than the tidiness of a separate deployable, because a signer and a
 * verifier that disagree about the format is a failure that presents as "policy stopped
 * applying" and takes a day to find.
 *
 * <p>Every route requires an OIDC token. Check-in is attributed to the token's subject
 * rather than to anything in the request body, so a coverage report is a statement about
 * people, and one person cannot report on another's behalf.
 */
@RestController
@RequestMapping("/control/v1")
@Profile("control")
public class ControlController {

    private static final Logger log = LoggerFactory.getLogger(ControlController.class);

    private final FleetRegistry fleet;
    private final ControlProperties props;
    private final TokenValidator tokens;
    private final AuthProperties authProps;
    private final ObjectMapper mapper;

    public ControlController(FleetRegistry fleet, ControlProperties props,
                             TokenValidator tokens, AuthProperties authProps,
                             ObjectMapper mapper) {
        this.fleet = fleet;
        this.props = props;
        this.tokens = tokens;
        this.authProps = authProps;
        this.mapper = mapper;
    }

    public record CheckInRequest(String instanceId, String version,
                                 long bundleSequence, String bundleHealth) {}

    public record CheckInResponse(String status, long publishedSequence, String message) {}

    @PostMapping("/checkin")
    public ResponseEntity<?> checkIn(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                                     @RequestBody CheckInRequest body) {
        AccessToken caller = authenticate(authorization);
        if (caller == null) return unauthorized();

        String instanceId = body.instanceId() == null || body.instanceId().isBlank()
                ? "unknown" : body.instanceId();

        fleet.checkIn(caller.subject(), instanceId,
                body.version() == null ? "unknown" : body.version(),
                body.bundleSequence(), body.bundleHealth());

        long published = publishedSequence();
        String message = published > 0 && body.bundleSequence() < published
                ? "a newer policy bundle is available"
                : "up to date";

        return ResponseEntity.ok(new CheckInResponse("ok", published, message));
    }

    /**
     * Serves the signed bundle.
     *
     * <p>The bytes are served as they are on disk, signature and all. This endpoint is not
     * a trust boundary and must not behave like one: the gateway verifies the signature
     * itself, so a compromised control plane can withhold policy or serve a stale one, but
     * it cannot forge a new one without the signing key — which lives wherever bundles are
     * signed, and should not be here.
     */
    @GetMapping(value = "/bundle", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> bundle(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authenticate(authorization) == null) return unauthorized();

        if (props.getBundleFile() == null || props.getBundleFile().isBlank()) {
            return ResponseEntity.status(503).body(Map.of("error", "no bundle configured"));
        }
        try {
            byte[] bytes = Files.readAllBytes(FilePaths.expandUser(props.getBundleFile()));
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(bytes);
        } catch (Exception e) {
            log.error("Could not read the bundle at {}: {}", props.getBundleFile(), e.toString());
            return ResponseEntity.status(503).body(Map.of("error", "bundle unavailable"));
        }
    }

    @GetMapping("/fleet")
    public ResponseEntity<?> fleetJson(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authenticate(authorization) == null) return unauthorized();
        return ResponseEntity.ok(fleet.view(publishedSequence(), props.getSilentAfter()));
    }

    /** The same, for a terminal. Coverage reports get read when they are easy to read. */
    @GetMapping(value = "/fleet.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<?> fleetText(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authenticate(authorization) == null) return unauthorized();

        long published = publishedSequence();
        var rows = fleet.view(published, props.getSilentAfter());

        StringBuilder out = new StringBuilder();
        out.append("published bundle sequence: ").append(published < 0 ? "none" : published)
                .append("\ngateways reporting: ").append(rows.size()).append("\n\n");
        out.append(String.format("%-10s %-26s %-18s %-8s %s%n",
                "STATUS", "WHO", "MACHINE", "BUNDLE", "LAST SEEN"));

        for (var row : rows) {
            out.append(String.format("%-10s %-26s %-18s %-8s %s ago%n",
                    row.status(), row.member().subject(), row.member().instanceId(),
                    row.member().bundleSequence(), human(row.since())));
        }
        if (rows.isEmpty()) {
            out.append("(nobody has checked in)\n");
        }
        out.append("\nNote: this lists gateways that reported. It cannot show someone who\n")
                .append("never ran one — compare against your IdP or MDM roster for that.\n");

        return ResponseEntity.ok(out.toString());
    }

    private static String human(Duration d) {
        long minutes = d.toMinutes();
        if (minutes < 1) return d.toSeconds() + "s";
        if (minutes < 60) return minutes + "m";
        long hours = d.toHours();
        return hours < 48 ? hours + "h" : d.toDays() + "d";
    }

    /** Sequence of the bundle currently being served, or -1 if there is none. */
    private long publishedSequence() {
        if (props.getBundleFile() == null || props.getBundleFile().isBlank()) return -1;
        try {
            Path path = FilePaths.expandUser(props.getBundleFile());
            // Parsed without verifying: this is a display value, and the control plane is
            // not the thing that decides whether a bundle is trustworthy. Nothing is
            // enforced on the basis of this number.
            var envelope = mapper.readValue(Files.readAllBytes(path),
                    dev.mahadi.toolgate.bundle.BundleEnvelope.class);
            var payload = java.util.Base64.getDecoder().decode(envelope.payload());
            return mapper.readValue(payload, dev.mahadi.toolgate.bundle.PolicyBundle.class).sequence();
        } catch (Exception e) {
            return -1;
        }
    }

    private AccessToken authenticate(String authorization) {
        if (!authProps.isEnabled()) {
            return new AccessToken("auth-disabled", java.util.Set.of(), null, null);
        }
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        return tokens.validate(authorization.substring(7).trim())
                instanceof TokenValidator.Result.Valid v ? v.token() : null;
    }

    private ResponseEntity<?> unauthorized() {
        return ResponseEntity.status(401)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"toolgate-control\"")
                .body(Map.of("error", "authentication required"));
    }
}
