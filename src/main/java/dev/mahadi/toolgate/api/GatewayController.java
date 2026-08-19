package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.auth.AccessToken;
import dev.mahadi.toolgate.auth.AuthProperties;
import dev.mahadi.toolgate.auth.TokenValidator;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.gateway.GatewayService;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import reactor.core.publisher.Flux;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * HTTP surface: one authenticated MCP endpoint for agents, and an operator API.
 *
 * <p>The two are deliberately separate paths. Anything that can change policy — approving
 * a call, inspecting pins — must never be reachable through the door the agent uses, or a
 * sufficiently capable agent approves itself.
 */
@RestController
public class GatewayController {

    /** Scope required to see the tool catalogue. */
    private static final String SCOPE_READ = "tools:read";
    /** Scope required to invoke anything. */
    private static final String SCOPE_CALL = "tools:call";

    private final GatewayService gateway;
    private final AuditLog audit;
    private final ApprovalStore approvals;
    private final ToolPinStore pins;
    private final DriftStore drifts;
    private final TokenValidator tokens;
    private final AuthProperties authProps;

    public GatewayController(GatewayService gateway, AuditLog audit, ApprovalStore approvals,
                             ToolPinStore pins, DriftStore drifts,
                             TokenValidator tokens, AuthProperties authProps) {
        this.gateway = gateway;
        this.audit = audit;
        this.approvals = approvals;
        this.pins = pins;
        this.drifts = drifts;
        this.tokens = tokens;
        this.authProps = authProps;
    }

    /**
     * This revision removed the GET stream endpoint and protocol-level sessions.
     * A client one revision behind will try both, and the spec says to answer 405 rather
     * than 404 — 404 would look like a server that does not host MCP at all, sending the
     * client down a legacy-transport fallback that will not work either.
     */
    @RequestMapping(path = "/mcp", method = {RequestMethod.GET, RequestMethod.DELETE})
    public ResponseEntity<?> removedMethods() {
        return ResponseEntity.status(405).body(Map.of(
                "error", "this revision defines only POST on the MCP endpoint",
                "protocolVersion", Mcp.PROTOCOL_VERSION));
    }

    /** The MCP endpoint an agent points at instead of the real servers. */
    @PostMapping(path = "/mcp", consumes = "application/json")
    public Mono<ResponseEntity<?>> mcp(
            @RequestBody Mcp.Request request,
            @RequestHeader(value = "MCP-Protocol-Version", required = false) String version,
            @RequestHeader(value = "Origin", required = false) String origin,
            @RequestHeader(value = "Mcp-Method", required = false) String mcpMethod,
            @RequestHeader(value = "Mcp-Name", required = false) String mcpName,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {

        // Origin first, and as a bare 403: a DNS-rebinding request from a hostile page
        // should never become an MCP message at all, let alone one that is authenticated
        // and audited as a caller.
        var originRejection = HttpTransportRules.checkOrigin(origin, authProps.getAllowedOrigins());
        if (originRejection.isPresent()) {
            audit.record("browser", "-", "-", request.method(), AuditLog.Outcome.DENIED,
                    originRejection.get().message(), List.of("origin=" + origin));
            return Mono.just(ResponseEntity.status(403).body(Map.of(
                    "error", originRejection.get().message())));
        }

        // Headers that disagree with the body are a request built to be judged by one
        // component and executed by another — and this gateway is exactly the component
        // the specification has in mind when it requires this check.
        var headerRejection = HttpTransportRules.checkMirroredHeaders(request, mcpMethod, mcpName);
        if (headerRejection.isPresent()) {
            audit.record("-", "-", "-", request.method(), AuditLog.Outcome.DENIED,
                    headerRejection.get().message(),
                    List.of("mcpMethod=" + mcpMethod, "mcpName=" + mcpName));
            return Mono.just(ResponseEntity.badRequest().body(Mcp.Response.error(request.id(),
                    headerRejection.get().jsonRpcCode(), headerRejection.get().message(), null)));
        }

        // The header carries the version negotiated at initialize, so it must accept every
        // revision the handshake is willing to agree to. Comparing against one revision
        // meant the gateway could settle on a version and then reject every request made
        // under it — a handshake that succeeds and a session that cannot proceed.
        if (version != null && !Mcp.SUPPORTED_PROTOCOL_VERSIONS.contains(version)) {
            return Mono.just(ResponseEntity.ok(Mcp.Response.error(request.id(),
                    Mcp.Codes.INVALID_PARAMS, "unsupported protocol version: " + version,
                    Map.of("supported", Mcp.SUPPORTED_PROTOCOL_VERSIONS))));
        }

        AccessToken caller;
        if (authProps.isEnabled()) {
            String bearer = extractBearer(authorization);
            var result = tokens.validate(bearer);
            if (result instanceof TokenValidator.Result.Invalid invalid) {
                audit.record("unauthenticated", "-", "-", request.method(),
                        AuditLog.Outcome.DENIED,
                        "authentication failed: " + invalid.detail(),
                        List.of("failure=" + invalid.failure()));
                return Mono.just(unauthorized(request, requiredScope(request.method())));
            }
            caller = ((TokenValidator.Result.Valid) result).token();

            String needed = requiredScope(request.method());
            if (needed != null && !caller.hasScope(needed)) {
                audit.record(caller.subject(), "-", "-", request.method(),
                        AuditLog.Outcome.DENIED, "insufficient scope",
                        List.of("required=" + needed, "granted=" + caller.scopes()));
                return Mono.just(insufficientScope(request, needed));
            }
        } else {
            // Explicitly opted out. Named so it is obvious in the audit trail that these
            // events carry no identity worth trusting.
            caller = new AccessToken("auth-disabled", Set.of(SCOPE_READ, SCOPE_CALL), null, null);
        }

        // Notifications get no response body. stdio has always dropped them; over HTTP
        // they fell through to the method switch and came back as an error carrying a null
        // id — a reply to something that cannot be replied to, and the first thing a
        // client sends after a successful handshake.
        if (request.isNotification()) {
            if (Mcp.NOTIFICATION_CANCELLED.equals(request.method()) && request.params() != null) {
                Object cancelled = request.params().get("requestId");
                if (cancelled != null) gateway.cancelSubscription(String.valueOf(cancelled));
            }
            return Mono.just(ResponseEntity.accepted().build());
        }

        // A subscription's response IS its stream: it stays open and carries the
        // notifications the client opted in to, and closing it is how the client cancels.
        if (Mcp.METHOD_SUBSCRIPTIONS_LISTEN.equals(request.method())) {
            return Mono.just(subscriptionStream(caller, request));
        }

        return gateway.handle(caller, request).map(r -> ResponseEntity.ok((Object) r));
    }

    /**
     * Serves a {@code subscriptions/listen} as a long-lived SSE stream.
     *
     * <p>Two headers matter more than they look. {@code X-Accel-Buffering: no} stops a
     * reverse proxy accumulating events and delivering them in a batch, which would make a
     * change notification arrive long after the change. And a periodic comment line keeps
     * intermediaries from closing an idle stream — a subscription that is quiet for ten
     * minutes because nothing changed is working correctly, and should not be mistaken for
     * a dead connection.
     *
     * <p>Cancellation needs no message: the client closes the stream, the publisher is
     * cancelled, and the upstream subscriptions are torn down in {@code doFinally}.
     */
    private ResponseEntity<?> subscriptionStream(AccessToken caller, Mcp.Request request) {
        String clientId = String.valueOf(request.id());

        Flux<ServerSentEvent<Object>> events = Flux.<ServerSentEvent<Object>>create(sink -> {
                    gateway.streamSubscription(caller, request,
                            message -> sink.next(ServerSentEvent.builder(message).build()));
                    sink.onCancel(() -> gateway.cancelSubscription(clientId));
                    sink.onDispose(() -> gateway.cancelSubscription(clientId));
                })
                // Comment-only events. The SSE specification says a line beginning with a
                // colon carries no data and clients must ignore it.
                .mergeWith(Flux.interval(java.time.Duration.ofSeconds(20))
                        .map(t -> ServerSentEvent.<Object>builder().comment("keep-alive").build()));

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_EVENT_STREAM)
                .header("X-Accel-Buffering", "no")
                .header(HttpHeaders.CACHE_CONTROL, "no-cache")
                .body(events);
    }

    private static String requiredScope(String method) {
        if (method == null) return null;
        return switch (method) {
            case Mcp.METHOD_TOOLS_LIST -> SCOPE_READ;
            case Mcp.METHOD_TOOLS_CALL -> SCOPE_CALL;
            // Discovery carries no tool data and must stay reachable, otherwise a client
            // cannot learn which protocol versions the gateway speaks.
            default -> null;
        };
    }

    private static String extractBearer(String header) {
        if (header == null) return null;
        // Scheme is case-insensitive per RFC 7235.
        if (header.length() < 7 || !header.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        return header.substring(7).trim();
    }

    /** 401 with the discovery pointer a client needs to go and get a token. */
    private ResponseEntity<Mcp.Response> unauthorized(Mcp.Request request, String scope) {
        String challenge = "Bearer resource_metadata=\"%s/.well-known/oauth-protected-resource\""
                .formatted(baseOf(tokens.resourceUri()))
                + (scope == null ? "" : ", scope=\"%s\"".formatted(scope));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
                .body(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                        "authentication required", null));
    }

    /** 403 with the scopes needed, so the client can step up in one round trip. */
    private ResponseEntity<Mcp.Response> insufficientScope(Mcp.Request request, String scope) {
        String challenge = ("Bearer error=\"insufficient_scope\", scope=\"%s\", "
                + "resource_metadata=\"%s/.well-known/oauth-protected-resource\"")
                .formatted(scope, baseOf(tokens.resourceUri()));

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
                .body(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                        "insufficient scope: " + scope, Map.of("required_scope", scope)));
    }

    /** Strips any path from the resource URI to build the well-known location. */
    private static String baseOf(String resourceUri) {
        try {
            var u = java.net.URI.create(resourceUri);
            String port = u.getPort() == -1 ? "" : ":" + u.getPort();
            return u.getScheme() + "://" + u.getHost() + port;
        } catch (Exception e) {
            return resourceUri;
        }
    }

    // ---------------- operator API ----------------

    @GetMapping("/toolgate/audit")
    public List<AuditLog.Entry> auditLog(@RequestParam(defaultValue = "100") int limit) {
        return audit.recent(Math.min(limit, 1000));
    }

    @GetMapping("/toolgate/pins")
    public Map<String, ToolPinStore.Pin> pins() {
        return pins.all();
    }

    /**
     * Outstanding drift, with a field-level diff of what changed.
     *
     * <p>This is the endpoint that makes the pin check usable. Two fingerprints tell an
     * operator that something moved; only the diff tells them whether to accept it.
     */
    @GetMapping("/toolgate/drift")
    public List<Map<String, Object>> drift() {
        return drifts.list().stream().map(d -> {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("server", d.serverId());
            m.put("tool", d.toolName());
            m.put("detectedAt", d.detectedAt());
            m.put("pinnedFingerprint", d.pinnedFingerprint());
            m.put("currentFingerprint", d.currentFingerprint());
            var diff = d.diff();
            m.put("changes", diff == null ? null : diff.changes());
            m.put("diffAvailable", diff != null);
            return m;
        }).toList();
    }

    /** The same drift rendered for a terminal, which is where it will actually be read. */
    @GetMapping(path = "/toolgate/drift.txt", produces = "text/plain")
    public String driftText() {
        if (drifts.list().isEmpty()) return "no outstanding drift\n";
        StringBuilder sb = new StringBuilder();
        drifts.list().forEach(d -> sb.append(DriftStore.renderText(d)).append('\n'));
        return sb.toString();
    }

    /**
     * Accepts a drifted definition as the new baseline.
     *
     * <p>Only reachable after the operator has been able to see the diff, and deliberately
     * a separate deliberate action rather than something the gateway ever does on its own.
     */
    @PostMapping("/toolgate/drift/{server}/{tool}/accept")
    public ResponseEntity<?> acceptDrift(@PathVariable String server, @PathVariable String tool) {
        return drifts.get(server, tool)
                .<ResponseEntity<?>>map(d -> {
                    pins.repin(server, d.currentDefinition());
                    drifts.clear(server, tool);
                    audit.record("operator", server, tool, "repin",
                            AuditLog.Outcome.APPROVED,
                            "operator accepted the changed definition as the new baseline",
                            List.of("was=" + d.pinnedFingerprint(), "now=" + d.currentFingerprint()));
                    return ResponseEntity.ok(Map.of("repinned", true, "tool", tool));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/toolgate/approvals")
    public Map<String, ApprovalStore.Pending> approvals() {
        return approvals.outstanding();
    }

    /**
     * Approves a blocked call from the operator API.
     *
     * <p>{@code approver} is required and cannot be verified here: the operator API is
     * guarded by a shared token, which identifies a deployment rather than a person. So it
     * is recorded as <em>asserted</em>, and the audit line says so. That is not a
     * satisfying answer, and it is why the Slack path exists — there the approver is
     * whoever Slack says clicked the button, on a request the gateway has cryptographically
     * verified came from Slack.
     *
     * <p>It is still required rather than optional. Forcing whoever runs the curl to type a
     * name makes the gap visible at the moment of use, instead of producing a tidy audit
     * line that quietly means nobody.
     */
    @PostMapping("/toolgate/approvals/{id}/approve")
    public ResponseEntity<?> approve(@PathVariable String id,
                                     @RequestParam(required = false) String approver) {
        if (approver == null || approver.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "approver is required",
                    "hint", "POST /toolgate/approvals/" + id + "/approve?approver=you@example.com"));
        }

        return switch (approvals.approve(id, approver)) {
            case ApprovalStore.Outcome.Granted g -> {
                audit.record(g.request().caller(), g.request().serverId(), g.request().tool(),
                        "approval", AuditLog.Outcome.APPROVED,
                        "granted by " + g.approver(),
                        List.of("id=" + id, "approver=" + g.approver(), "approverSource=asserted"));
                yield ResponseEntity.ok(Map.of("approved", true, "tool", g.request().tool(),
                        "approver", g.approver()));
            }
            case ApprovalStore.Outcome.SelfApproval self -> {
                audit.record(self.request().caller(), self.request().serverId(),
                        self.request().tool(), "approval", AuditLog.Outcome.DENIED,
                        "refused: requester cannot approve their own call",
                        List.of("id=" + id, "approver=" + approver));
                yield ResponseEntity.status(403).body(Map.of(
                        "error", "the requester cannot approve their own call",
                        "requester", self.request().caller()));
            }
            case ApprovalStore.Outcome.Unknown ignored ->
                    ResponseEntity.notFound().build();
        };
    }

    @PostMapping("/toolgate/approvals/{id}/deny")
    public ResponseEntity<?> deny(@PathVariable String id,
                                  @RequestParam(required = false) String approver) {
        return approvals.deny(id, approver == null ? "operator" : approver)
                .<ResponseEntity<?>>map(p -> {
                    audit.record(p.caller(), p.serverId(), p.tool(), "approval",
                            AuditLog.Outcome.DENIED,
                            "denied by " + (approver == null ? "operator" : approver),
                            List.of("id=" + id));
                    return ResponseEntity.ok(Map.of("approved", false));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
