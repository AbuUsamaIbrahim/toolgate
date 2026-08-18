package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.gateway.GatewayService;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.protocol.Mcp;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * HTTP surface: one MCP endpoint for agents, and an operator API for everything else.
 *
 * <p>The two are deliberately separate paths. Anything that can change policy — approving
 * a call, re-pinning a definition — must never be reachable through the same door the
 * agent uses, or a sufficiently clever agent can approve itself.
 */
@RestController
public class GatewayController {

    private final GatewayService gateway;
    private final AuditLog audit;
    private final ApprovalStore approvals;
    private final ToolPinStore pins;

    public GatewayController(GatewayService gateway, AuditLog audit,
                             ApprovalStore approvals, ToolPinStore pins) {
        this.gateway = gateway;
        this.audit = audit;
        this.approvals = approvals;
        this.pins = pins;
    }

    /** The MCP endpoint an agent points at instead of the real servers. */
    @PostMapping(path = "/mcp", consumes = "application/json", produces = "application/json")
    public Mono<Mcp.Response> mcp(
            @RequestBody Mcp.Request request,
            @RequestHeader(value = "MCP-Protocol-Version", required = false) String version,
            @RequestHeader(value = "X-Toolgate-Caller", defaultValue = "anonymous") String caller) {

        if (version != null && !Mcp.PROTOCOL_VERSION.equals(version)) {
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INVALID_PARAMS,
                    "unsupported protocol version: " + version,
                    Map.of("supported", List.of(Mcp.PROTOCOL_VERSION))));
        }
        return gateway.handle(caller, request);
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
