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

    /** The MCP endpoint an agent points at instead of the real servers. */
    @PostMapping(path = "/mcp", consumes = "application/json", produces = "application/json")
    public Mono<ResponseEntity<Mcp.Response>> mcp(
            @RequestBody Mcp.Request request,
            @RequestHeader(value = "MCP-Protocol-Version", required = false) String version,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {

        if (version != null && !Mcp.PROTOCOL_VERSION.equals(version)) {
            return Mono.just(ResponseEntity.ok(Mcp.Response.error(request.id(),
                    Mcp.Codes.INVALID_PARAMS, "unsupported protocol version: " + version,
                    Map.of("supported", List.of(Mcp.PROTOCOL_VERSION)))));
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

        return gateway.handle(caller, request).map(ResponseEntity::ok);
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

    @PostMapping("/toolgate/approvals/{id}/approve")
    public ResponseEntity<?> approve(@PathVariable String id) {
        return approvals.approve(id)
                .<ResponseEntity<?>>map(p -> {
                    audit.record(p.caller(), p.serverId(), p.tool(), "approval",
                            AuditLog.Outcome.APPROVED, "granted by operator", List.of("id=" + id));
                    return ResponseEntity.ok(Map.of("approved", true, "tool", p.tool()));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/toolgate/approvals/{id}/deny")
    public ResponseEntity<?> deny(@PathVariable String id) {
        return approvals.deny(id)
                .<ResponseEntity<?>>map(p -> {
                    audit.record(p.caller(), p.serverId(), p.tool(), "approval",
                            AuditLog.Outcome.DENIED, "denied by operator", List.of("id=" + id));
                    return ResponseEntity.ok(Map.of("approved", false));
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
