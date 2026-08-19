package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.scanner.ScannerRulesStore;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static dev.mahadi.toolgate.api.DashboardRenderer.escape;
import static dev.mahadi.toolgate.api.DashboardRenderer.page;

/**
 * The dashboard's write side: sign in, accept drift, approve or deny.
 *
 * <h2>Every state change is checked twice</h2>
 * A session cookie travels automatically, which is what makes buttons possible and what
 * makes cross-site request forgery possible. Both defences are applied to every POST:
 * {@code SameSite=Strict} stops the browser sending the cookie cross-site at all, and a
 * CSRF token in the form body stops anything that gets past it — an attacker can cause a
 * request but cannot read the token to put in it.
 *
 * <p>Neither is novel. The reason they are here rather than skipped is that this is the API
 * that approves blocked tool calls, so a forged request is not an inconvenience; it is a
 * poisoned definition accepted in the operator's name, appearing in the audit trail as
 * their deliberate decision.
 */
@RestController
public class DashboardActionController {

    private final OperatorSessions sessions;
    private final dev.mahadi.toolgate.auth.OperatorProperties props;
    private final DriftStore drifts;
    private final ToolPinStore pins;
    private final ApprovalStore approvals;
    private final AuditLog audit;
    private final ScannerRulesStore scannerRules;

    public DashboardActionController(OperatorSessions sessions,
                                     dev.mahadi.toolgate.auth.OperatorProperties props,
                                     DriftStore drifts, ToolPinStore pins,
                                     ApprovalStore approvals, AuditLog audit,
                                     ScannerRulesStore scannerRules) {
        this.sessions = sessions;
        this.props = props;
        this.drifts = drifts;
        this.pins = pins;
        this.approvals = approvals;
        this.audit = audit;
        this.scannerRules = scannerRules;
    }

    // ---------------------------------------------------------------- sign in

    @GetMapping(value = "/toolgate/login", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> loginForm(@RequestParam(required = false) String error) {
        String message = error == null ? ""
                : "<div class=\"empty bad\">That token was not accepted.</div>";
        return html("""
            <h1>toolgate</h1>
            <div class="sub">Operator console</div>
            <div class="panel" style="max-width:420px">
              <form method="post" action="/toolgate/login">
                <label class="k">Operator token</label>
                <input type="password" name="token" autocomplete="current-password"
                       autofocus style="width:100%%;margin:8px 0 12px;padding:9px 11px;
                       background:#0d1117;border:1px solid var(--line);border-radius:6px;
                       color:var(--ink);font-family:ui-monospace,Menlo,monospace">
                <button type="submit">Sign in</button>
              </form>
              %s
              <div class="note">The same credential as the operator API. It is exchanged for
              a session cookie scoped to <code>/toolgate</code>, so it is never sent to the
              endpoint agents use.</div>
            </div>
            """.formatted(message));
    }

    @PostMapping(value = "/toolgate/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> login(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> doLogin(form, exchange));
    }

    private ResponseEntity<?> doLogin(MultiValueMap<String, String> form, ServerWebExchange exchange) {
        String token = form.getFirst("token");

        String expected = props.getTokenSha256();
        if (expected == null || expected.isBlank() || token == null
                || !constantTimeEquals(sha256(token), expected.toLowerCase())) {
            // Audited, because someone guessing at the operator console is worth knowing
            // about, and deliberately not distinguishing "no token configured" from "wrong
            // token" in the response.
            audit.record("browser", "-", "-", "operator login", AuditLog.Outcome.DENIED,
                    "operator sign-in refused", List.of());
            return ResponseEntity.status(HttpStatus.SEE_OTHER)
                    .header(HttpHeaders.LOCATION, "/toolgate/login?error=1").build();
        }

        var session = sessions.create("operator");
        audit.record("operator", "-", "-", "operator login", AuditLog.Outcome.ALLOWED,
                "operator signed in to the dashboard", List.of());

        ResponseCookie cookie = ResponseCookie.from(OperatorSessions.COOKIE, session.id())
                .httpOnly(true)                 // script cannot read it, so XSS is not theft
                .sameSite("Strict")             // the control that actually stops CSRF
                .path("/toolgate")              // never sent to /mcp, where agents talk
                .maxAge(Duration.ofHours(8))
                .secure(isHttps(exchange))      // set over TLS; omitted on localhost http
                .build();

        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .header(HttpHeaders.LOCATION, "/toolgate").build();
    }

    @PostMapping(value = "/toolgate/logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> logout(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
        var session = requireSession(exchange);
        if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
            return forbidden();
        }
        sessions.invalidate(session.id());
        return (ResponseEntity<?>) ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.SET_COOKIE, ResponseCookie.from(OperatorSessions.COOKIE, "")
                        .path("/toolgate").maxAge(0).build().toString())
                .header(HttpHeaders.LOCATION, "/toolgate/login").build();
        });
    }

    // ---------------------------------------------------------------- actions

    @PostMapping(value = "/toolgate/ui/drift/accept",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> acceptDrift(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
        var session = requireSession(exchange);
        if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
            return forbidden();
        }

        String server = form.getFirst("server");
        String tool = form.getFirst("tool");

        return drifts.get(server, tool)
                .<ResponseEntity<?>>map(d -> {
                    pins.repin(server, d.currentDefinition());
                    drifts.clear(server, tool);
                    audit.record("operator", server, tool, "drift accepted",
                            AuditLog.Outcome.APPROVED,
                            "changed definition accepted as the new baseline from the dashboard",
                            List.of("accepted=" + d.currentFingerprint()));
                    return redirectHome();
                })
                .orElseGet(this::redirectHome);
        });
    }

    @PostMapping(value = "/toolgate/ui/approval",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> decideApproval(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
        var session = requireSession(exchange);
        if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
            return forbidden();
        }

        String id = form.getFirst("id");
        String decision = form.getFirst("decision");
        String approver = form.getFirst("approver");

        if (approver == null || approver.isBlank()) {
            // Required for the same reason the API requires it: "granted by operator" names
            // a shared token, and after an incident the only question is who allowed it.
            return redirectHome();
        }

        if ("deny".equals(decision)) {
            approvals.deny(id, approver).ifPresent(p -> audit.record(p.caller(), p.serverId(),
                    p.tool(), "approval", AuditLog.Outcome.DENIED,
                    "denied by " + approver + " from the dashboard", List.of("id=" + id)));
            return redirectHome();
        }

        switch (approvals.approve(id, approver)) {
            case ApprovalStore.Outcome.Granted g -> audit.record(g.request().caller(),
                    g.request().serverId(), g.request().tool(), "approval",
                    AuditLog.Outcome.APPROVED, "granted by " + approver + " from the dashboard",
                    List.of("id=" + id, "approver=" + approver, "approverSource=asserted"));
            case ApprovalStore.Outcome.SelfApproval self -> audit.record(self.request().caller(),
                    self.request().serverId(), self.request().tool(), "approval",
                    AuditLog.Outcome.DENIED,
                    "refused: requester cannot approve their own call", List.of("id=" + id));
            case ApprovalStore.Outcome.Unknown ignored -> { }
        }
        return redirectHome();
        });
    }

    // ---------------------------------------------------------- scanner rules

    @PostMapping(value = "/toolgate/ui/scanner/rule",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> addScannerRule(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
            var session = requireSession(exchange);
            if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
                return forbidden();
            }
            String category = form.getFirst("category");
            String pattern  = form.getFirst("pattern");
            String weightRaw = form.getFirst("weight");
            String description = form.getFirst("description");

            if (pattern == null || pattern.isBlank()) return redirectHome();
            int weight = 30;
            try { if (weightRaw != null) weight = Math.max(1, Math.min(100, Integer.parseInt(weightRaw))); }
            catch (NumberFormatException ignored) {}

            // Reject an invalid regex before persisting it — a bad pattern is silently
            // skipped at scan time, so the admin would add a rule that never fires.
            try { java.util.regex.Pattern.compile(pattern); }
            catch (java.util.regex.PatternSyntaxException e) {
                return redirectHome();
            }

            var rule = scannerRules.add(
                    category != null ? category : "imperative_instruction",
                    pattern, weight,
                    description != null ? description : "");
            audit.record("operator", "-", "-", "scanner rule added",
                    AuditLog.Outcome.APPROVED,
                    "custom scanner rule added from the dashboard",
                    List.of("id=" + rule.id(), "category=" + rule.category(),
                            "weight=" + rule.weight()));
            return redirectHome();
        });
    }

    @PostMapping(value = "/toolgate/ui/scanner/toggle",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> toggleScannerRule(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
            var session = requireSession(exchange);
            if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
                return forbidden();
            }
            String id = form.getFirst("id");
            scannerRules.toggle(id).ifPresent(r ->
                    audit.record("operator", "-", "-", "scanner rule toggled",
                            AuditLog.Outcome.APPROVED,
                            "rule " + (r.enabled() ? "enabled" : "disabled") + " from the dashboard",
                            List.of("id=" + r.id(), "category=" + r.category())));
            return redirectHome();
        });
    }

    @PostMapping(value = "/toolgate/ui/scanner/delete",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<?>> deleteScannerRule(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> {
            var session = requireSession(exchange);
            if (session == null || !sessions.csrfValid(session, form.getFirst(OperatorSessions.CSRF_FIELD))) {
                return forbidden();
            }
            String id = form.getFirst("id");
            boolean deleted = scannerRules.delete(id);
            if (deleted) {
                audit.record("operator", "-", "-", "scanner rule deleted",
                        AuditLog.Outcome.APPROVED,
                        "custom scanner rule deleted from the dashboard",
                        List.of("id=" + id));
            }
            return redirectHome();
        });
    }

    // ---------------------------------------------------------------- helpers

    private OperatorSessions.Session requireSession(ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().getFirst(OperatorSessions.COOKIE);
        return cookie == null ? null : sessions.lookup(cookie.getValue()).orElse(null);
    }

    private ResponseEntity<?> redirectHome() {
        // Redirect after POST, so a refresh does not repeat the action.
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, "/toolgate").build();
    }

    private ResponseEntity<?> forbidden() {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.TEXT_HTML)
                .body(page("Refused", "<h1>Refused</h1><div class=\"sub\">Session missing or "
                        + "the request could not be verified as coming from this page.</div>"));
    }

    private ResponseEntity<String> html(String body) {
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                // form-action 'self' rather than 'none': the buttons post back here, and
                // nowhere else is permitted as a destination.
                .header("Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                + "frame-ancestors 'none'; base-uri 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .body(page("Sign in", body));
    }

    private static boolean isHttps(ServerWebExchange exchange) {
        var uri = exchange.getRequest().getURI();
        return "https".equalsIgnoreCase(uri.getScheme());
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
