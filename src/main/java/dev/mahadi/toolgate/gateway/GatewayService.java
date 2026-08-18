package dev.mahadi.toolgate.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.policy.PolicyEngine;
import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.notify.Notifier;
import dev.mahadi.toolgate.protocol.HeaderMirror;
import dev.mahadi.toolgate.scanner.InjectionScanner;
import dev.mahadi.toolgate.upstream.UpstreamClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The proxy itself: fans requests out to upstream servers and applies policy in the path.
 *
 * <h2>Where filtering happens, and why it matters</h2>
 * Denied tools are removed at {@code tools/list}, so a poisoned definition never reaches
 * the model's context. Filtering only at call time would be far too late — by then the
 * model has already read the injected instructions and may be acting on them through some
 * entirely different tool. The call-time check exists as well, but as a second line: a
 * client may invoke a tool it was never offered, and a gateway that assumes otherwise is
 * trusting the caller to enforce its own restrictions.
 */
@Service
public class GatewayService {

    private static final Logger log = LoggerFactory.getLogger(GatewayService.class);

    /**
     * Separator for namespacing tool names across servers. The spec notes that proxies
     * aggregating multiple servers SHOULD disambiguate, and that {@code serverInfo.name}
     * is not unique enough to rely on. Server ids are validated to exclude underscores so
     * splitting on the first occurrence is unambiguous.
     */
    public static final String NS = "__";

    private final ToolPolicyProperties props;
    private final PolicyEngine policy;
    private final UpstreamClient upstream;
    private final InjectionScanner scanner;
    private final ApprovalStore approvals;
    private final AuditLog audit;
    private final Notifier notifier;
    private final ObjectMapper mapper;

    public GatewayService(ToolPolicyProperties props, PolicyEngine policy,
                          UpstreamClient upstream, InjectionScanner scanner,
                          ApprovalStore approvals, AuditLog audit,
                          Notifier notifier, ObjectMapper mapper) {
        this.props = props;
        this.policy = policy;
        this.upstream = upstream;
        this.scanner = scanner;
        this.approvals = approvals;
        this.audit = audit;
        this.notifier = notifier;
        this.mapper = mapper;
    }

    public Mono<Mcp.Response> handle(String caller, Mcp.Request request) {
        return switch (request.method()) {
            case Mcp.METHOD_DISCOVER -> discover(request);
            case Mcp.METHOD_TOOLS_LIST -> toolsList(caller, request);
            case Mcp.METHOD_TOOLS_CALL -> toolsCall(caller, request);
            case null -> Mono.just(Mcp.Response.error(request.id(),
                    Mcp.Codes.INVALID_PARAMS, "missing method", null));
            default -> Mono.just(Mcp.Response.error(request.id(),
                    Mcp.Codes.INVALID_PARAMS, "method not proxied: " + request.method(), null));
        };
    }

    /** The gateway answers discovery itself; it is the server the agent is talking to. */
    private Mono<Mcp.Response> discover(Mcp.Request request) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("resultType", "complete");
        result.put("protocolVersions", List.of(Mcp.PROTOCOL_VERSION));
        result.put("serverInfo", Map.of("name", "toolgate", "version", "0.1.0"));
        result.put("capabilities", Map.of("tools", Map.of("listChanged", false)));
        return Mono.just(Mcp.Response.ok(request.id(), result));
    }

    /**
     * Aggregates tools from every configured upstream, applying policy to each.
     *
     * <p>An upstream that errors contributes nothing rather than failing the whole call:
     * one broken server should not blind the agent to the others. The failure is audited.
     */
    private Mono<Mcp.Response> toolsList(String caller, Mcp.Request request) {
        List<String> serverIds = props.serverIds();

        return Flux.fromIterable(serverIds)
                .flatMap(serverId -> fetchTools(serverId)
                        .map(tools -> screen(caller, serverId, tools))
                        .onErrorResume(e -> {
                            audit.record(caller, serverId, "*", "tools/list",
                                    AuditLog.Outcome.FAILED, "upstream error: " + e.getMessage(), List.of());
                            log.warn("upstream {} failed during tools/list: {}", serverId, e.toString());
                            return Mono.just(List.<Mcp.Tool>of());
                        }))
                .collectList()
                .map(lists -> {
                    List<Mcp.Tool> all = new ArrayList<>();
                    lists.forEach(all::addAll);
                    return Mcp.Response.ok(request.id(),
                            new Mcp.ToolsListResult("complete", all, null, null, null));
                });
    }

    private Mono<List<Mcp.Tool>> fetchTools(String serverId) {
        Mcp.Request req = new Mcp.Request("2.0", "tg-list-" + serverId,
                Mcp.METHOD_TOOLS_LIST, Map.of(),
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));

        return upstream.send(serverId, req).map(resp -> {
            if (resp.error() != null || resp.result() == null) return List.<Mcp.Tool>of();
            Mcp.ToolsListResult parsed = mapper.convertValue(resp.result(), Mcp.ToolsListResult.class);
            return parsed.tools() == null ? List.<Mcp.Tool>of() : parsed.tools();
        });
    }

    /** Applies policy to each advertised tool and namespaces the survivors. */
    private List<Mcp.Tool> screen(String caller, String serverId, List<Mcp.Tool> tools) {
        List<Mcp.Tool> allowed = new ArrayList<>();
        for (Mcp.Tool tool : tools) {
            PolicyEngine.Decision decision = policy.evaluateAdvertisement(serverId, tool);

            switch (decision) {
                case PolicyEngine.Decision.Allow a -> {
                    audit.record(caller, serverId, tool.name(), "advertise",
                            AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                    allowed.add(namespaced(serverId, tool));
                }
                case PolicyEngine.Decision.Deny d -> {
                    audit.record(caller, serverId, tool.name(), "advertise",
                            AuditLog.Outcome.DENIED, d.reason(), d.evidence());
                    if (d.reason().contains("changed since it was pinned")) {
                        notifier.notify(Notifier.Kind.DRIFT_DETECTED,
                                "%s/%s was withheld from the agent".formatted(serverId, tool.name()),
                                "Review: GET /toolgate/drift.txt");
                    }
                }
                case PolicyEngine.Decision.NeedsApproval n -> {
                    // Withheld from the model until a human says otherwise. Advertising it
                    // with a warning would not help: the model reads the description either way.
                    var p = approvals.request(caller, serverId, tool.name(), n.reason());
                    audit.record(caller, serverId, tool.name(), "advertise",
                            AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(),
                            List.of("approvalId=" + p.id()));
                    notifier.notify(Notifier.Kind.APPROVAL_REQUIRED,
                            "%s/%s is waiting for approval".formatted(serverId, tool.name()),
                            n.reason() + " — approve: POST /toolgate/approvals/" + p.id() + "/approve");
                }
            }
        }
        return allowed;
    }

    private Mcp.Tool namespaced(String serverId, Mcp.Tool tool) {
        return new Mcp.Tool(serverId + NS + tool.name(), tool.title(), tool.description(),
                tool.inputSchema(), tool.outputSchema(), tool.annotations(), tool.icons());
    }

    private Mono<Mcp.Response> toolsCall(String caller, Mcp.Request request) {
        String qualified = request.toolName();
        if (qualified == null || !qualified.contains(NS)) {
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INVALID_PARAMS,
                    "tool name must be namespaced as serverId" + NS + "toolName", null));
        }
        int idx = qualified.indexOf(NS);
        String serverId = qualified.substring(0, idx);
        String toolName = qualified.substring(idx + NS.length());

        PolicyEngine.Decision decision = policy.evaluateCall(serverId, toolName);

        // A prior human approval converts NeedsApproval into a one-shot Allow.
        if (decision instanceof PolicyEngine.Decision.NeedsApproval
                && approvals.consumeGrant(caller, serverId, toolName)) {
            audit.record(caller, serverId, toolName, "tools/call",
                    AuditLog.Outcome.APPROVED, "human approval consumed", List.of());
            decision = new PolicyEngine.Decision.Allow("approved by operator");
        }

        switch (decision) {
            case PolicyEngine.Decision.Deny d -> {
                audit.record(caller, serverId, toolName, "tools/call",
                        AuditLog.Outcome.DENIED, d.reason(), d.evidence());
                return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                        "refused by toolgate: " + d.reason(), Map.of("evidence", d.evidence())));
            }
            case PolicyEngine.Decision.NeedsApproval n -> {
                var p = approvals.request(caller, serverId, toolName, n.reason());
                audit.record(caller, serverId, toolName, "tools/call",
                        AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(),
                        List.of("approvalId=" + p.id()));
                notifier.notify(Notifier.Kind.APPROVAL_REQUIRED,
                        "%s wants to call %s/%s".formatted(caller, serverId, toolName),
                        n.reason() + " — approve: POST /toolgate/approvals/" + p.id() + "/approve");
                return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.APPROVAL_REQUIRED,
                        "human approval required: " + n.reason(),
                        Map.of("approvalId", p.id())));
            }
            case PolicyEngine.Decision.Allow a -> {
                audit.record(caller, serverId, toolName, "tools/call",
                        AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                return forwardCall(caller, serverId, toolName, request);
            }
        }
    }

    /** Forwards the call upstream with the namespace stripped, then screens the result. */
    private Mono<Mcp.Response> forwardCall(String caller, String serverId, String toolName,
                                           Mcp.Request original) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", toolName);
        params.put("arguments", original.arguments());

        Mcp.Request forwarded = new Mcp.Request("2.0", original.id(), Mcp.METHOD_TOOLS_CALL,
                params, Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));

        // Mirrored headers come from the pinned definition — the one a human approved —
        // not from whatever the upstream is advertising at this moment.
        Map<String, String> mirrored = policy.mirroredHeaders(
                serverId, toolName, original.arguments());

        return upstream.send(serverId, forwarded, mirrored)
                .map(resp -> screenResult(caller, serverId, toolName, resp))
                .onErrorResume(e -> {
                    audit.record(caller, serverId, toolName, "tools/call",
                            AuditLog.Outcome.FAILED, "upstream error: " + e.getMessage(), List.of());
                    return Mono.just(Mcp.Response.error(original.id(), Mcp.Codes.INTERNAL_ERROR,
                            "upstream call failed", null));
                });
    }

    /**
     * Scans what comes back.
     *
     * <p>Tool <em>output</em> reaches the model exactly as directly as a tool description
     * does. A server that cannot poison its own metadata past the pin check can still try
     * to return instructions in a result, so the return path needs the same scrutiny as
     * the request path.
     */
    @SuppressWarnings("unchecked")
    private Mcp.Response screenResult(String caller, String serverId, String toolName,
                                      Mcp.Response resp) {
        if (resp.result() == null) return resp;

        String text;
        try {
            text = mapper.writeValueAsString(resp.result());
        } catch (Exception e) {
            return resp;
        }

        var scan = scanner.scanContent(text);
        if (scan.score() >= props.getBlockThreshold()) {
            List<String> evidence = scan.findings().stream()
                    .map(f -> f.rule() + ": " + f.evidence()).toList();
            audit.record(caller, serverId, toolName, "tools/call result",
                    AuditLog.Outcome.DENIED,
                    "tool result contains adversarial content (score %d)".formatted(scan.score()),
                    evidence);
            return Mcp.Response.error(resp.id(), Mcp.Codes.POLICY_DENIED,
                    "refused by toolgate: tool result contains adversarial content",
                    Map.of("evidence", evidence));
        }
        return resp;
    }
}
