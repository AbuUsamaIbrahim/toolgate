package dev.mahadi.toolgate.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.auth.AccessToken;
import dev.mahadi.toolgate.policy.PolicyEngine;
import dev.mahadi.toolgate.policy.ToolPolicyProperties;
import dev.mahadi.toolgate.protocol.Mcp;
import dev.mahadi.toolgate.notify.Notifier;
import dev.mahadi.toolgate.policy.ResourceGuard;
import dev.mahadi.toolgate.protocol.HeaderMirror;
import dev.mahadi.toolgate.slack.SlackNotifier;
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
    private final SlackNotifier slack;
    private final SurfaceRouter router;
    private final ObjectMapper mapper;

    public GatewayService(ToolPolicyProperties props, PolicyEngine policy,
                          UpstreamClient upstream, InjectionScanner scanner,
                          ApprovalStore approvals, AuditLog audit,
                          Notifier notifier, SlackNotifier slack, SurfaceRouter router,
                          ObjectMapper mapper) {
        this.props = props;
        this.policy = policy;
        this.upstream = upstream;
        this.scanner = scanner;
        this.approvals = approvals;
        this.audit = audit;
        this.notifier = notifier;
        this.slack = slack;
        this.router = router;
        this.mapper = mapper;
    }

    public Mono<Mcp.Response> handle(AccessToken caller, Mcp.Request request) {
        return switch (request.method()) {
            case Mcp.METHOD_DISCOVER -> discover(request);
            case Mcp.METHOD_TOOLS_LIST -> toolsList(caller, request);
            case Mcp.METHOD_TOOLS_CALL -> toolsCall(caller, request);
            case Mcp.METHOD_RESOURCES_LIST -> resourcesList(caller, request);
            case Mcp.METHOD_RESOURCES_READ -> resourcesRead(caller, request);
            case Mcp.METHOD_RESOURCE_TEMPLATES_LIST -> templatesList(caller, request);
            case Mcp.METHOD_PROMPTS_LIST -> promptsList(caller, request);
            case Mcp.METHOD_PROMPTS_GET -> promptsGet(caller, request);
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
    private Mono<Mcp.Response> toolsList(AccessToken caller, Mcp.Request request) {
        List<String> serverIds = props.serverIds();

        return Flux.fromIterable(serverIds)
                .flatMap(serverId -> fetchTools(serverId)
                        .map(tools -> screen(caller, serverId, tools))
                        .onErrorResume(e -> {
                            audit.record(caller.subject(), serverId, "*", "tools/list",
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

    /** Aggregates resources from every upstream, applying policy to each. */
    private Mono<Mcp.Response> resourcesList(AccessToken caller, Mcp.Request request) {
        return Flux.fromIterable(props.serverIds())
                .flatMap(serverId -> fetchList(serverId, Mcp.METHOD_RESOURCES_LIST,
                        Mcp.ResourcesListResult.class, Mcp.ResourcesListResult::resources)
                        .map(list -> screenResources(caller, serverId, list))
                        .onErrorResume(e -> upstreamFailed(caller, serverId,
                                "resources/list", e, List.<Mcp.Resource>of())))
                .collectList()
                .map(lists -> {
                    List<Mcp.Resource> all = new ArrayList<>();
                    lists.forEach(all::addAll);
                    return Mcp.Response.ok(request.id(),
                            new Mcp.ResourcesListResult("complete", all, null, null, null));
                });
    }

    /**
     * Applies policy to each advertised resource.
     *
     * <p>URIs are not namespaced the way tool names are — a URI means something to the
     * server and mangling it would change what it refers to — so the survivors are recorded
     * in {@link SurfaceRouter} instead, which is also what makes an unadvertised read
     * refusable.
     */
    private List<Mcp.Resource> screenResources(AccessToken caller, String serverId,
                                               List<Mcp.Resource> resources) {
        List<Mcp.Resource> allowed = new ArrayList<>();
        java.util.Set<String> advertised = new java.util.LinkedHashSet<>();

        for (Mcp.Resource resource : resources) {
            var decision = policy.evaluateResource(caller, serverId, resource);
            switch (decision) {
                case PolicyEngine.Decision.Allow a -> {
                    // Clamped before the model sees it: an unreviewed server does not get
                    // to declare its own content mandatory.
                    Mcp.Resource clamped = ResourceGuard.clampAnnotations(resource, false);
                    List<String> evidence = ResourceGuard.clampEvidence(resource, clamped);

                    audit.record(caller.subject(), serverId, resource.uri(), "advertise resource",
                            AuditLog.Outcome.ALLOWED, a.reason(), evidence);
                    allowed.add(clamped);
                    advertised.add(resource.uri());
                    router.advertised(serverId, resource.uri());
                }
                case PolicyEngine.Decision.Deny d -> audit.record(caller.subject(), serverId,
                        resource.uri(), "advertise resource", AuditLog.Outcome.DENIED,
                        d.reason(), d.evidence());
                case PolicyEngine.Decision.NeedsApproval n -> audit.record(caller.subject(),
                        serverId, resource.uri(), "advertise resource",
                        AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(), List.of());
            }
        }
        // A resource the server has stopped offering stops resolving here too.
        router.retainOnly(serverId, advertised);
        return allowed;
    }

    /**
     * Reads a resource, from the server that advertised it and no other.
     *
     * <p>The owner lookup is the control. A model can be talked into constructing a URI —
     * a poisoned tool description saying "then read file:///etc/shadow" produces one that
     * was never on any list — and a gateway that forwards whatever URI it is handed would
     * pass that straight through.
     */
    private Mono<Mcp.Response> resourcesRead(AccessToken caller, Mcp.Request request) {
        Object uriParam = request.params() == null ? null : request.params().get("uri");
        String uri = uriParam == null ? null : String.valueOf(uriParam);

        // Resolves an exact advertisement first, then an approved template. A template
        // expansion was never advertised and never could be, so supporting templates means
        // this gate necessarily softens — which is why the allowlist and the traversal
        // check below are not optional. They are what remains.
        var owner = router.ownerOf(uri);
        if (owner.isEmpty()) {
            audit.record(caller.subject(), "-", String.valueOf(uri), "resources/read",
                    AuditLog.Outcome.DENIED,
                    "resource was neither advertised nor covered by an approved template",
                    List.of());
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                    "resource was neither advertised nor covered by an approved template", null));
        }
        String serverId = owner.get();

        // Re-checked at read time. Policy may have changed since the listing, and a client
        // may read a URI it was offered an hour ago.
        if (policy.evaluateResourceRead(caller, serverId, uri)
                instanceof PolicyEngine.Decision.Deny d) {
            audit.record(caller.subject(), serverId, uri, "resources/read",
                    AuditLog.Outcome.DENIED, d.reason(), d.evidence());
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                    d.reason(), null));
        }

        Mcp.Request forwarded = new Mcp.Request("2.0", request.id(), Mcp.METHOD_RESOURCES_READ,
                Map.of("uri", uri),
                Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));

        return upstream.send(serverId, forwarded)
                .map(resp -> screenResourceContent(caller, serverId, uri, resp))
                .onErrorResume(e -> {
                    audit.record(caller.subject(), serverId, uri, "resources/read",
                            AuditLog.Outcome.FAILED, "upstream error: " + e.getMessage(), List.of());
                    return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INTERNAL_ERROR,
                            "upstream read failed", null));
                });
    }

    /**
     * Screens resource content on the way back.
     *
     * <p>Content reaches the model exactly as directly as a tool result does, and a server
     * that cannot get instructions past the metadata scan will put them in the body.
     */
    private Mcp.Response screenResourceContent(AccessToken caller, String serverId,
                                               String uri, Mcp.Response response) {
        if (response.error() != null || response.result() == null) return response;

        Mcp.ResourcesReadResult parsed;
        try {
            parsed = mapper.convertValue(response.result(), Mcp.ResourcesReadResult.class);
        } catch (Exception e) {
            return response;
        }
        if (parsed.contents() == null) return response;

        for (Mcp.ResourceContents c : parsed.contents()) {
            if (c.text() == null) continue;      // blobs are not scanned; see the README
            var scan = scanner.scanContent(c.text());
            if (!scan.clean() && scan.score() >= 50) {
                audit.record(caller.subject(), serverId, uri, "resources/read result",
                        AuditLog.Outcome.DENIED,
                        "resource content contains adversarial instructions (score %d)"
                                .formatted(scan.score()),
                        scan.findings().stream().map(f -> f.rule() + ": " + f.evidence()).toList());
                return Mcp.Response.error(response.id(), Mcp.Codes.POLICY_DENIED,
                        "resource content was withheld: it contains injected instructions", null);
            }
        }
        audit.record(caller.subject(), serverId, uri, "resources/read",
                AuditLog.Outcome.ALLOWED, "content screened", List.of());
        return response;
    }

    /** Aggregates resource templates, refusing any that could expand out of bounds. */
    private Mono<Mcp.Response> templatesList(AccessToken caller, Mcp.Request request) {
        return Flux.fromIterable(props.serverIds())
                .flatMap(serverId -> fetchList(serverId, Mcp.METHOD_RESOURCE_TEMPLATES_LIST,
                        Mcp.ResourceTemplatesListResult.class,
                        Mcp.ResourceTemplatesListResult::resourceTemplates)
                        .map(list -> screenTemplates(caller, serverId, list))
                        .onErrorResume(e -> upstreamFailed(caller, serverId,
                                "resources/templates/list", e, List.<Mcp.ResourceTemplate>of())))
                .collectList()
                .map(lists -> {
                    List<Mcp.ResourceTemplate> all = new ArrayList<>();
                    lists.forEach(all::addAll);
                    return Mcp.Response.ok(request.id(),
                            new Mcp.ResourceTemplatesListResult("complete", all, null, null, null));
                });
    }

    private List<Mcp.ResourceTemplate> screenTemplates(AccessToken caller, String serverId,
                                                       List<Mcp.ResourceTemplate> templates) {
        List<Mcp.ResourceTemplate> allowed = new ArrayList<>();
        java.util.Set<String> advertised = new java.util.LinkedHashSet<>();

        for (Mcp.ResourceTemplate template : templates) {
            var decision = policy.evaluateTemplate(caller, serverId, template);
            switch (decision) {
                case PolicyEngine.Decision.Allow a -> {
                    audit.record(caller.subject(), serverId, template.uriTemplate(),
                            "advertise template", AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                    allowed.add(template);
                    router.templateAdvertised(serverId, template.uriTemplate());
                    int firstVar = template.uriTemplate().indexOf('{');
                    advertised.add(firstVar < 0 ? template.uriTemplate()
                            : template.uriTemplate().substring(0, firstVar));
                }
                case PolicyEngine.Decision.Deny d -> audit.record(caller.subject(), serverId,
                        template.uriTemplate(), "advertise template", AuditLog.Outcome.DENIED,
                        d.reason(), d.evidence());
                case PolicyEngine.Decision.NeedsApproval n -> audit.record(caller.subject(),
                        serverId, template.uriTemplate(), "advertise template",
                        AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(), List.of());
            }
        }
        router.retainOnlyTemplates(serverId, advertised);
        return allowed;
    }

    /** Aggregates prompts from every upstream, applying policy to each. */
    private Mono<Mcp.Response> promptsList(AccessToken caller, Mcp.Request request) {
        return Flux.fromIterable(props.serverIds())
                .flatMap(serverId -> fetchList(serverId, Mcp.METHOD_PROMPTS_LIST,
                        Mcp.PromptsListResult.class, Mcp.PromptsListResult::prompts)
                        .map(list -> screenPrompts(caller, serverId, list))
                        .onErrorResume(e -> upstreamFailed(caller, serverId,
                                "prompts/list", e, List.<Mcp.Prompt>of())))
                .collectList()
                .map(lists -> {
                    List<Mcp.Prompt> all = new ArrayList<>();
                    lists.forEach(all::addAll);
                    return Mcp.Response.ok(request.id(),
                            new Mcp.PromptsListResult("complete", all, null, null, null));
                });
    }

    private List<Mcp.Prompt> screenPrompts(AccessToken caller, String serverId,
                                           List<Mcp.Prompt> prompts) {
        List<Mcp.Prompt> allowed = new ArrayList<>();
        for (Mcp.Prompt prompt : prompts) {
            var decision = policy.evaluatePrompt(caller, serverId, prompt);
            switch (decision) {
                case PolicyEngine.Decision.Allow a -> {
                    audit.record(caller.subject(), serverId, prompt.name(), "advertise prompt",
                            AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                    // Namespaced like tools, because a prompt name is an opaque identifier
                    // the gateway chooses how to present.
                    allowed.add(new Mcp.Prompt(serverId + NS + prompt.name(), prompt.title(),
                            prompt.description(), prompt.arguments(), prompt.icons()));
                }
                case PolicyEngine.Decision.Deny d -> audit.record(caller.subject(), serverId,
                        prompt.name(), "advertise prompt", AuditLog.Outcome.DENIED,
                        d.reason(), d.evidence());
                case PolicyEngine.Decision.NeedsApproval n -> audit.record(caller.subject(),
                        serverId, prompt.name(), "advertise prompt",
                        AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(), List.of());
            }
        }
        return allowed;
    }

    /**
     * Fetches a prompt, which returns messages that go straight into the conversation.
     *
     * <p>The most direct injection surface in the protocol: the result is not data the
     * model reasons about, it is instructions the model was asked to follow.
     */
    private Mono<Mcp.Response> promptsGet(AccessToken caller, Mcp.Request request) {
        Object nameParam = request.params() == null ? null : request.params().get("name");
        String qualified = nameParam == null ? null : String.valueOf(nameParam);

        int idx = qualified == null ? -1 : qualified.indexOf(NS);
        if (idx <= 0) {
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INVALID_PARAMS,
                    "prompt name must be namespaced as serverId" + NS + "promptName", null));
        }
        String serverId = qualified.substring(0, idx);
        String name = qualified.substring(idx + NS.length());

        if (!policy.isPromptPermitted(caller, serverId, name)) {
            audit.record(caller.subject(), serverId, name, "prompts/get",
                    AuditLog.Outcome.DENIED, "prompt not in allowlist", List.of());
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                    "prompt not in allowlist", null));
        }

        Map<String, Object> params = new LinkedHashMap<>(request.params());
        params.put("name", name);

        Mcp.Request forwarded = new Mcp.Request("2.0", request.id(), Mcp.METHOD_PROMPTS_GET,
                params, Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));

        return upstream.send(serverId, forwarded)
                .map(resp -> {
                    if (resp.error() == null && resp.result() != null) {
                        var scan = scanner.scanContent(String.valueOf(resp.result()));
                        if (!scan.clean() && scan.score() >= 50) {
                            audit.record(caller.subject(), serverId, name, "prompts/get result",
                                    AuditLog.Outcome.DENIED,
                                    "prompt body contains adversarial instructions (score %d)"
                                            .formatted(scan.score()), List.of());
                            return Mcp.Response.error(resp.id(), Mcp.Codes.POLICY_DENIED,
                                    "prompt was withheld: it contains injected instructions", null);
                        }
                    }
                    audit.record(caller.subject(), serverId, name, "prompts/get",
                            AuditLog.Outcome.ALLOWED, "screened", List.of());
                    return resp;
                })
                .onErrorResume(e -> {
                    audit.record(caller.subject(), serverId, name, "prompts/get",
                            AuditLog.Outcome.FAILED, "upstream error: " + e.getMessage(), List.of());
                    return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INTERNAL_ERROR,
                            "upstream prompt fetch failed", null));
                });
    }

    /** Shared list-fetch for the surfaces that follow the same list/get shape. */
    private <R, T> Mono<List<T>> fetchList(String serverId, String method, Class<R> resultType,
                                           java.util.function.Function<R, List<T>> extract) {
        Mcp.Request req = new Mcp.Request("2.0", "tg-" + method.replace('/', '-') + "-" + serverId,
                method, Map.of(), Map.of(Mcp.META_PROTOCOL_VERSION, Mcp.PROTOCOL_VERSION));

        return upstream.send(serverId, req).map(resp -> {
            if (resp.error() != null || resp.result() == null) return List.<T>of();
            List<T> items = extract.apply(mapper.convertValue(resp.result(), resultType));
            return items == null ? List.<T>of() : items;
        });
    }

    private <T> Mono<List<T>> upstreamFailed(AccessToken caller, String serverId, String action,
                                             Throwable e, List<T> empty) {
        audit.record(caller.subject(), serverId, "*", action, AuditLog.Outcome.FAILED,
                "upstream error: " + e.getMessage(), List.of());
        log.warn("upstream {} failed during {}: {}", serverId, action, e.toString());
        return Mono.just(empty);
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
    private List<Mcp.Tool> screen(AccessToken caller, String serverId, List<Mcp.Tool> tools) {
        List<Mcp.Tool> allowed = new ArrayList<>();
        for (Mcp.Tool tool : tools) {
            PolicyEngine.Decision decision = policy.evaluateAdvertisement(caller, serverId, tool);

            switch (decision) {
                case PolicyEngine.Decision.Allow a -> {
                    audit.record(caller.subject(), serverId, tool.name(), "advertise",
                            AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                    allowed.add(namespaced(serverId, tool));
                }
                case PolicyEngine.Decision.Deny d -> {
                    audit.record(caller.subject(), serverId, tool.name(), "advertise",
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
                    var p = approvals.request(caller.subject(), serverId, tool.name(), n.reason());
                    audit.record(caller.subject(), serverId, tool.name(), "advertise",
                            AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(),
                            List.of("approvalId=" + p.id()));
                    notifier.notify(Notifier.Kind.APPROVAL_REQUIRED,
                            "%s/%s is waiting for approval".formatted(serverId, tool.name()),
                            n.reason() + " — approve: POST /toolgate/approvals/" + p.id() + "/approve");
                    slack.requestApproval(p, n.reason());
                }
            }
        }
        return allowed;
    }

    private Mcp.Tool namespaced(String serverId, Mcp.Tool tool) {
        return new Mcp.Tool(serverId + NS + tool.name(), tool.title(), tool.description(),
                tool.inputSchema(), tool.outputSchema(), tool.annotations(), tool.icons());
    }

    private Mono<Mcp.Response> toolsCall(AccessToken caller, Mcp.Request request) {
        String qualified = request.toolName();
        if (qualified == null || !qualified.contains(NS)) {
            return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.INVALID_PARAMS,
                    "tool name must be namespaced as serverId" + NS + "toolName", null));
        }
        int idx = qualified.indexOf(NS);
        String serverId = qualified.substring(0, idx);
        String toolName = qualified.substring(idx + NS.length());

        PolicyEngine.Decision decision = policy.evaluateCall(caller, serverId, toolName);

        // A prior human approval converts NeedsApproval into a one-shot Allow.
        if (decision instanceof PolicyEngine.Decision.NeedsApproval
                && approvals.consumeGrant(caller.subject(), serverId, toolName)) {
            audit.record(caller.subject(), serverId, toolName, "tools/call",
                    AuditLog.Outcome.APPROVED, "human approval consumed", List.of());
            decision = new PolicyEngine.Decision.Allow("approved by operator");
        }

        switch (decision) {
            case PolicyEngine.Decision.Deny d -> {
                audit.record(caller.subject(), serverId, toolName, "tools/call",
                        AuditLog.Outcome.DENIED, d.reason(), d.evidence());
                return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.POLICY_DENIED,
                        "refused by toolgate: " + d.reason(), Map.of("evidence", d.evidence())));
            }
            case PolicyEngine.Decision.NeedsApproval n -> {
                var p = approvals.request(caller.subject(), serverId, toolName, n.reason());
                audit.record(caller.subject(), serverId, toolName, "tools/call",
                        AuditLog.Outcome.APPROVAL_REQUIRED, n.reason(),
                        List.of("approvalId=" + p.id()));
                notifier.notify(Notifier.Kind.APPROVAL_REQUIRED,
                        "%s wants to call %s/%s".formatted(caller.subject(), serverId, toolName),
                        n.reason() + " — approve: POST /toolgate/approvals/" + p.id() + "/approve");
                slack.requestApproval(p, n.reason());
                return Mono.just(Mcp.Response.error(request.id(), Mcp.Codes.APPROVAL_REQUIRED,
                        "human approval required: " + n.reason(),
                        Map.of("approvalId", p.id())));
            }
            case PolicyEngine.Decision.Allow a -> {
                audit.record(caller.subject(), serverId, toolName, "tools/call",
                        AuditLog.Outcome.ALLOWED, a.reason(), List.of());
                return forwardCall(caller, serverId, toolName, request);
            }
        }
    }

    /** Forwards the call upstream with the namespace stripped, then screens the result. */
    private Mono<Mcp.Response> forwardCall(AccessToken caller, String serverId, String toolName,
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
                    audit.record(caller.subject(), serverId, toolName, "tools/call",
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
    private Mcp.Response screenResult(AccessToken caller, String serverId, String toolName,
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
            audit.record(caller.subject(), serverId, toolName, "tools/call result",
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
