package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.bundle.BundleStore;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.SurfacePinStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import dev.mahadi.toolgate.scanner.ScannerRule;
import dev.mahadi.toolgate.scanner.ScannerRulesStore;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static dev.mahadi.toolgate.api.DashboardRenderer.*;

/**
 * A page that answers the four questions an operator actually has.
 *
 * <p>Everything here already existed as JSON. It was reachable with {@code curl} and
 * {@code jq}, which meant that in practice nobody looked — and this project's own comments
 * argue repeatedly that a control nobody can act on is not a control. A drift alert is
 * worthless unless someone reads the diff; an approval queue is worthless unless someone
 * sees it is waiting.
 *
 * <p>It sits under {@code /toolgate/}, so it inherits the operator authentication filter:
 * loopback-only by default, its own credential, and closed when unconfigured. The dashboard
 * adds no new way in.
 *
 * <p>Read-only, deliberately. Acting on something requires a POST, and a browser form
 * cannot send the bearer header the operator API expects — so making the buttons work would
 * mean a session cookie, which means CSRF protection, on the one API that can approve
 * anything. Not worth it for a first version. Each item shows the exact command instead,
 * which is also the thing you would paste into a ticket.
 */
@RestController
public class DashboardController {

    // No meta-refresh — the SSE stream keeps the page live without full reloads.

    private final AuditLog audit;
    private final DriftStore drifts;
    private final ApprovalStore approvals;
    private final ToolPinStore pins;
    private final SurfacePinStore surfacePins;
    private final BundleStore bundles;
    private final OperatorSessions sessions;
    private final dev.mahadi.toolgate.advisor.DriftAdvisor advisor;
    private final ScannerRulesStore scannerRules;
    private final DashboardEventBus eventBus;
    private static final SecureRandom RANDOM = new SecureRandom();

    public DashboardController(AuditLog audit, DriftStore drifts, ApprovalStore approvals,
                               ToolPinStore pins, SurfacePinStore surfacePins,
                               BundleStore bundles, OperatorSessions sessions,
                               dev.mahadi.toolgate.advisor.DriftAdvisor advisor,
                               ScannerRulesStore scannerRules, DashboardEventBus eventBus) {
        this.sessions = sessions;
        this.advisor = advisor;
        this.audit = audit;
        this.drifts = drifts;
        this.approvals = approvals;
        this.pins = pins;
        this.surfacePins = surfacePins;
        this.bundles = bundles;
        this.scannerRules = scannerRules;
        this.eventBus = eventBus;
    }

    private static final int AUDIT_PAGE_SIZE = 20;

    // ---------------------------------------------------------------- SSE stream

    /**
     * Live event stream for connected operator browsers.
     *
     * <p>Sends an initial counts snapshot so the browser sees current state immediately,
     * then pushes targeted updates as things change. A heartbeat comment every 25 s keeps
     * the connection alive through proxies that close idle streams.
     */
    @GetMapping(value = "/toolgate/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> events(org.springframework.web.server.ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().getFirst(OperatorSessions.COOKIE);
        var session = cookie == null ? null : sessions.lookup(cookie.getValue()).orElse(null);
        String csrf = session == null ? null : session.csrfToken();

        Flux<ServerSentEvent<String>> initial = Flux.just(countsEvent());

        Flux<ServerSentEvent<String>> updates = eventBus.subscribe()
                .flatMapIterable(event -> switch (event) {
                    case DashboardEvent.AuditEntryAdded a -> List.of(
                            ServerSentEvent.<String>builder()
                                    .event("audit-row").data(auditRow(a.entry())).build());
                    case DashboardEvent.ApprovalsChanged ignored -> List.of(
                            countsEvent(),
                            ServerSentEvent.<String>builder()
                                    .event("approvals-html")
                                    .data(approvalSection(csrf)).build());
                    case DashboardEvent.DriftChanged ignored -> List.of(
                            countsEvent(),
                            ServerSentEvent.<String>builder()
                                    .event("drift-html")
                                    .data(driftSection(csrf)).build());
                });

        Flux<ServerSentEvent<String>> heartbeat = Flux.interval(Duration.ofSeconds(25))
                .map(i -> ServerSentEvent.<String>builder().comment("heartbeat").build());

        return Flux.merge(initial, updates, heartbeat);
    }

    private ServerSentEvent<String> countsEvent() {
        return ServerSentEvent.<String>builder().event("counts")
                .data("{\"drift\":" + drifts.all().size()
                        + ",\"approvals\":" + approvals.outstanding().size() + "}")
                .build();
    }

    // ---------------------------------------------------------------- dashboard page

    @GetMapping(value = "/toolgate", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> dashboard(org.springframework.web.server.ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().get(OperatorSessions.COOKIE);
        var session = cookie == null || cookie.isEmpty() ? null
                : sessions.lookup(cookie.get(0).getValue()).orElse(null);

        // Reached with a bearer token rather than a browser session: render it read-only.
        // The buttons need a CSRF token, and a CSRF token needs a session to be bound to.
        String csrf = session == null ? null : session.csrfToken();

        int auditPage = 0;
        try {
            var raw = exchange.getRequest().getQueryParams().getFirst("auditPage");
            if (raw != null) auditPage = Math.max(0, Integer.parseInt(raw));
        } catch (NumberFormatException ignored) {}

        StringBuilder b = new StringBuilder();
        b.append("<h1>toolgate</h1><div class=\"sub\">")
                .append(escape(status()))
                .append(" · <span id=\"live-badge\" style=\"display:inline-flex;align-items:center;gap:5px;font-size:11px\">")
                .append("<span id=\"live-dot\" style=\"width:7px;height:7px;border-radius:50%;background:#6b7a90;display:inline-block\"></span>")
                .append("<span id=\"live-text\" style=\"color:var(--faint)\">connecting…</span>")
                .append("</span>");
        if (session != null) {
            b.append(" · <form method=\"post\" action=\"/toolgate/logout\" class=\"inline\">")
                    .append(csrfField(csrf))
                    .append("<button class=\"link\" type=\"submit\">sign out</button></form>");
        }
        b.append("</div>");

        // Nonce lets the live-update script run while keeping the policy tight. A random
        // nonce per request means an injected <script> tag — which cannot know the nonce —
        // will not execute even if it somehow reaches the page.
        byte[] nonceBytes = new byte[18];
        RANDOM.nextBytes(nonceBytes);
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        b.append(cards());
        b.append("<div id=\"drift-section\">").append(driftSection(csrf)).append("</div>");
        b.append("<div id=\"approvals-section\">").append(approvalSection(csrf)).append("</div>");
        b.append(scannerRulesSection(csrf));
        b.append(recentRefusals(auditPage));
        b.append(liveScript(nonce));

        return ResponseEntity.ok()
                .header("Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline' 'nonce-" + nonce + "'; "
                                + "script-src 'nonce-" + nonce + "'; "
                                + "connect-src 'self'; "
                                + "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .body(DashboardRenderer.page("Dashboard", b.toString(), 0, nonce));
    }

    private String status() {
        return switch (bundles.health()) {
            case DISABLED -> "local configuration — no signed policy bundle";
            case FRESH -> "signed policy in force";
            case STALE -> "policy has expired but is inside the grace period";
            case FAILED -> "no current policy — every request is being denied";
        };
    }

    private String cards() {
        var health = bundles.health();
        String cls = switch (health) {
            case FRESH -> "ok";
            case DISABLED -> "dim";
            case STALE -> "warn";
            case FAILED -> "bad";
        };
        int outstanding = drifts.all().size();
        int waiting = approvals.outstanding().size();

        return """
            <div class="cards">
              <div class="card"><div class="k">Policy</div><div class="v %s">%s</div></div>
              <div class="card"><div class="k">Bundle sequence</div><div class="v dim">%s</div></div>
              <div class="card"><div class="k">Drift to review</div><div id="card-drift" class="v %s">%d</div></div>
              <div class="card"><div class="k">Awaiting approval</div><div id="card-approvals" class="v %s">%d</div></div>
              <div class="card"><div class="k">Pinned definitions</div><div class="v dim">%d</div></div>
            </div>
            """.formatted(
                cls, escape(health.name().toLowerCase()),
                bundles.current().map(c -> String.valueOf(c.sequence())).orElse("—"),
                outstanding > 0 ? "warn" : "dim", outstanding,
                waiting > 0 ? "warn" : "dim", waiting,
                pins.all().size() + surfacePins.all().size());
    }

    /**
     * The reason this page exists.
     *
     * <p>A hash proves something changed and can never show what. The diff is the only form
     * in which a human can decide "release or attack", and invisible characters are marked
     * in red because that decision turns on being able to see them.
     */
    /** The token is bound to the session, so a forged form cannot supply a valid one. */
    private static String csrfField(String csrf) {
        return csrf == null ? "" : "<input type=\"hidden\" name=\"" + OperatorSessions.CSRF_FIELD
                + "\" value=\"" + escape(csrf) + "\">";
    }

    private String driftSection(String csrf) {
        var all = drifts.list();
        StringBuilder b = new StringBuilder("<h2>Definitions that changed after approval</h2>");
        if (all.isEmpty()) {
            return b.append("<div class=\"empty\">Nothing waiting. Every definition matches "
                    + "the version that was approved.</div>").toString();
        }
        for (var d : all) {
            b.append("<div class=\"panel\"><h3>")
                    .append(escape(d.serverId())).append('/').append(escape(d.toolName()))
                    .append("</h3><div class=\"sub\">detected ").append(escape(ago(d.detectedAt())))
                    .append("</div>")
                    .append(diff(DriftStore.renderText(d)))
                    .append(advice(d))
                    .append("<div class=\"note\">Accept only if this reads as a product change. "
                            + "Instructions aimed at the model, unexpected paths, or characters "
                            + "marked in red are the attack this exists to catch.</div>");
            if (csrf != null) {
                b.append("<form method=\"post\" action=\"/toolgate/ui/drift/accept\">")
                        .append(csrfField(csrf))
                        .append("<input type=\"hidden\" name=\"server\" value=\"")
                        .append(escape(d.serverId())).append("\">")
                        .append("<input type=\"hidden\" name=\"tool\" value=\"")
                        .append(escape(d.toolName())).append("\">")
                        .append("<button type=\"submit\" class=\"danger\">Accept as the new baseline</button>")
                        .append("</form>");
            } else {
                b.append("<code>curl -X POST localhost:8090/toolgate/drift/")
                        .append(escape(d.serverId())).append('/').append(escape(d.toolName()))
                        .append("/accept -H \"Authorization: Bearer $TOKEN\"</code>");
            }
            b.append("</div>");
        }
        return b.toString();
    }

    /**
     * The advisor's note, shown beside the diff and never in place of it.
     *
     * <p>Marked as untrusted in the interface rather than only in the documentation,
     * because the model read the same attacker-controlled text the operator is reading and
     * can be talked into saying reassuring things about it. Its output is escaped like any
     * other hostile string: a model can be induced to emit markup as readily as a server
     * can.
     */
    private String advice(DriftStore.Drift d) {
        if (!advisor.enabled()) return "";

        return advisor.adviseOn(d).map(a -> {
            String cls = switch (a.risk()) {
                case "high" -> "p-bad";
                case "medium" -> "p-warn";
                case "low" -> "p-ok";
                default -> "p-warn";
            };
            StringBuilder o = new StringBuilder("<div class=\"advice\">")
                    .append("<div class=\"advice-head\"><span class=\"pill ").append(cls)
                    .append("\">").append(escape(a.risk())).append(" risk</span>")
                    .append("<span class=\"warnlabel\">assistant — advisory, and readable by "
                            + "the same text it is describing</span></div>")
                    .append("<div class=\"dim\">").append(escape(a.summary())).append("</div>");
            if (!a.observations().isEmpty()) {
                o.append("<ul>");
                a.observations().forEach(x -> o.append("<li>").append(escape(x)).append("</li>"));
                o.append("</ul>");
            }
            return o.append("<div class=\"note\">This is a second pair of eyes, not a "
                    + "verdict. The diff above is the thing to decide on.</div></div>").toString();
        }).orElse("");
    }

    private String approvalSection(String csrf) {
        var waiting = approvals.outstanding();
        StringBuilder b = new StringBuilder("<h2>Waiting for a human</h2>");
        if (waiting.isEmpty()) {
            return b.append("<div class=\"empty\">No pending approvals.</div>").toString();
        }
        b.append("<table><tr><th>Who</th><th>Tool</th><th>Why</th><th>Raised</th>")
                .append(csrf == null ? "" : "<th>Decide</th>").append("</tr>");
        waiting.values().forEach(p -> {
            b.append("<tr><td class=\"mono\">").append(escape(p.caller()))
                    .append("</td><td class=\"mono\">").append(escape(p.serverId()))
                    .append('/').append(escape(p.tool()))
                    .append("</td><td class=\"dim\">").append(escape(p.reason()))
                    .append("</td><td class=\"dim\">").append(escape(ago(p.createdAt())))
                    .append("</td>");
            if (csrf != null) {
                b.append("<td><form method=\"post\" action=\"/toolgate/ui/approval\" class=\"inline\">")
                        .append(csrfField(csrf))
                        .append("<input type=\"hidden\" name=\"id\" value=\"")
                        .append(escape(p.id())).append("\">")
                        // Typed, not defaulted: an approval must name a person, and the
                        // requester is refused by the store rather than by this form.
                        .append("<input name=\"approver\" placeholder=\"you@example.com\" ")
                        .append("required class=\"who\">")
                        .append("<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>")
                        .append("<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"danger\">Deny</button>")
                        .append("</form></td>");
            }
            b.append("</tr>");
        });
        b.append("</table><div class=\"note\">The requester cannot approve their own call. "
                + "Approving names you in the audit trail.</div>");
        return b.toString();
    }

    /**
     * The live set of injection scanner rules an admin can tune without a redeploy.
     *
     * <p>Built-in rules can be disabled (to suppress a false-positive category) but not
     * deleted — removing them permanently requires a code change, which is deliberate.
     * Custom rules added here can be deleted freely.
     */
    private String scannerRulesSection(String csrf) {
        List<ScannerRule> all = scannerRules.all();
        StringBuilder b = new StringBuilder("<h2 id=\"scanner-rules\">Scanner rules</h2>");
        b.append("<div class=\"sub\">Regex patterns scored against every tool definition at "
                + "tools/list. Score ≥ block-threshold → tool is withheld from the model.</div>");

        b.append("<table><tr><th>Category</th><th>Pattern</th><th>Weight</th>"
                + "<th>Description</th><th>Status</th>");
        if (csrf != null) b.append("<th>Actions</th>");
        b.append("</tr>");

        for (ScannerRule r : all) {
            String statusPill = r.enabled()
                    ? "<span class=\"pill p-ok\">enabled</span>"
                    : "<span class=\"pill p-bad\">disabled</span>";
            String builtInBadge = r.builtIn()
                    ? " <span class=\"pill dim\" style=\"font-size:10px\">built-in</span>" : "";

            b.append("<tr>")
             .append("<td class=\"mono\">").append(escape(r.category())).append("</td>")
             .append("<td class=\"mono\" style=\"word-break:break-all;max-width:260px\">")
             .append(escape(r.pattern())).append("</td>")
             .append("<td class=\"mono\">").append(r.weight()).append("</td>")
             .append("<td class=\"dim\">").append(escape(r.description())).append(builtInBadge)
             .append("</td>")
             .append("<td>").append(statusPill).append("</td>");

            if (csrf != null) {
                // Toggle button (available for all rules)
                b.append("<td style=\"white-space:nowrap\">")
                 .append("<form method=\"post\" action=\"/toolgate/ui/scanner/toggle\" "
                         + "class=\"inline\">")
                 .append(csrfField(csrf))
                 .append("<input type=\"hidden\" name=\"id\" value=\"").append(escape(r.id()))
                 .append("\">")
                 .append("<button type=\"submit\">")
                 .append(r.enabled() ? "Disable" : "Enable")
                 .append("</button></form>");

                // Delete button only for custom rules
                if (!r.builtIn()) {
                    b.append(" <form method=\"post\" action=\"/toolgate/ui/scanner/delete\" "
                             + "class=\"inline\">")
                     .append(csrfField(csrf))
                     .append("<input type=\"hidden\" name=\"id\" value=\"").append(escape(r.id()))
                     .append("\">")
                     .append("<button type=\"submit\" class=\"danger\">Delete</button>")
                     .append("</form>");
                }
                b.append("</td>");
            }
            b.append("</tr>");
        }
        b.append("</table>");

        // Add-rule form — only when logged in with a session
        if (csrf != null) {
            b.append("<details style=\"margin-top:14px\"><summary style=\"cursor:pointer;"
                     + "color:var(--dim);font-size:12px\">Add a custom rule</summary>");
            b.append("<form method=\"post\" action=\"/toolgate/ui/scanner/rule\" "
                     + "style=\"margin-top:10px;display:grid;gap:8px;max-width:560px\">")
             .append(csrfField(csrf))
             .append("<div><label class=\"k\">Category</label>"
                     + "<select name=\"category\" style=\"margin-top:4px;width:100%;"
                     + "background:#0d1117;border:1px solid var(--line);border-radius:6px;"
                     + "color:var(--ink);padding:7px 10px\">")
             .append("<option value=\"imperative_instruction\">imperative_instruction</option>")
             .append("<option value=\"credential_target\">credential_target</option>")
             .append("<option value=\"exfiltration_shape\">exfiltration_shape</option>")
             .append("<option value=\"hidden_unicode\">hidden_unicode</option>")
             .append("</select></div>")
             .append("<div><label class=\"k\">Regex pattern (Java, case-insensitive)</label>"
                     + "<input name=\"pattern\" required placeholder=\"e.g. exfiltrate\\\\s+to\" "
                     + "style=\"margin-top:4px;width:100%;background:#0d1117;border:1px solid "
                     + "var(--line);border-radius:6px;color:var(--ink);font-family:"
                     + "ui-monospace,Menlo,monospace;padding:7px 10px\"></div>")
             .append("<div style=\"display:grid;grid-template-columns:1fr 1fr;gap:8px\">")
             .append("<div><label class=\"k\">Weight (added to score on match)</label>"
                     + "<input name=\"weight\" type=\"number\" value=\"30\" min=\"1\" max=\"100\" "
                     + "style=\"margin-top:4px;width:100%;background:#0d1117;border:1px solid "
                     + "var(--line);border-radius:6px;color:var(--ink);padding:7px 10px\"></div>")
             .append("<div><label class=\"k\">Description (shown in this table)</label>"
                     + "<input name=\"description\" placeholder=\"What this pattern catches\" "
                     + "style=\"margin-top:4px;width:100%;background:#0d1117;border:1px solid "
                     + "var(--line);border-radius:6px;color:var(--ink);padding:7px 10px\"></div>")
             .append("</div>")
             .append("<div><button type=\"submit\">Add rule</button></div>")
             .append("</form></details>");
        }

        b.append("<div class=\"note\">Scores are additive. A single match at weight 40 plus "
                + "one at weight 30 = score 70. Block threshold is set in "
                + "<code>toolgate.block-threshold</code> (currently blocks at ≥ 50).</div>");
        return b.toString();
    }

    /** Renders one audit entry as a `<tr>` for SSE push and initial table render. */
    String auditRow(AuditLog.Entry e) {
        String pill = switch (e.outcome()) {
            case DENIED -> "p-bad";
            case APPROVAL_REQUIRED -> "p-warn";
            case FAILED -> "p-warn";
            default -> "p-ok";
        };
        StringBuilder why = new StringBuilder();
        why.append("<span class=\"mono\">").append(escape(e.caller()))
           .append("</span> tried to call <span class=\"mono\">")
           .append(escape(e.serverId())).append('/').append(escape(e.tool()))
           .append("</span><br><span class=\"dim\">").append(escape(e.reason()))
           .append("</span>");
        if (!e.evidence().isEmpty()) {
            why.append("<br><span class=\"dim\" style=\"font-size:0.85em\">")
               .append(escape(String.join(" · ", e.evidence()))).append("</span>");
        }
        return "<tr><td class=\"dim mono\">" + escape(ago(e.at()))
                + "</td><td><span class=\"pill " + pill + "\">"
                + escape(e.outcome().name()) + "</span></td>"
                + "<td class=\"mono\">" + escape(e.serverId()) + '/' + escape(e.tool())
                + "</td><td>" + why + "</td></tr>";
    }

    /**
     * The inline script that keeps the page live.
     *
     * <p>Opens an EventSource to /toolgate/events and patches the DOM on each event rather
     * than replacing the whole page. The nonce is matched against the CSP header so only
     * this exact script block can execute — any injected markup that reaches the page
     * cannot run without a valid nonce.
     */
    private String liveScript(String nonce) {
        return """
            <style nonce="%s">
            @keyframes live-pulse {
              0%%,100%%{opacity:1} 50%%{opacity:.35}
            }
            #live-dot.connected { background:#4ade80; animation:live-pulse 2s ease-in-out infinite }
            #live-dot.error     { background:#f87171; animation:none }
            </style>
            <script nonce="%s">
            (function() {
              var dot  = document.getElementById('live-dot');
              var txt  = document.getElementById('live-text');

              function setStatus(state, label) {
                if (dot) { dot.className = state; }
                if (txt) { txt.textContent = label; txt.style.color = state === 'connected' ? 'var(--ok)' : state === 'error' ? 'var(--bad)' : 'var(--faint)'; }
              }

              var es = new EventSource('/toolgate/events');

              es.onopen = function() { setStatus('connected', 'live'); };

              es.addEventListener('counts', function(e) {
                var d = JSON.parse(e.data);
                var drift = document.getElementById('card-drift');
                var approvals = document.getElementById('card-approvals');
                if (drift) drift.textContent = d.drift;
                if (approvals) approvals.textContent = d.approvals;
              });

              es.addEventListener('audit-row', function(e) {
                var tbody = document.getElementById('audit-tbody');
                if (!tbody) return;
                var tmp = document.createElement('tbody');
                tmp.innerHTML = e.data;
                var row = tmp.firstChild;
                if (row) {
                  row.style.animation = 'live-pulse 0.6s ease-out 1';
                  tbody.insertBefore(row, tbody.firstChild);
                }
                while (tbody.rows.length > %d) tbody.deleteRow(tbody.rows.length - 1);
              });

              es.addEventListener('approvals-html', function(e) {
                var el = document.getElementById('approvals-section');
                if (el) el.innerHTML = e.data;
              });

              es.addEventListener('drift-html', function(e) {
                var el = document.getElementById('drift-section');
                if (el) el.innerHTML = e.data;
              });

              es.onerror = function() {
                setStatus('error', 'reconnecting…');
              };
            })();
            </script>
            """.formatted(nonce, nonce, AUDIT_PAGE_SIZE);
    }

    /**
     * Refusals only, paginated.
     *
     * <p>Showing everything would bury the interesting lines under routine ones, which is
     * how a log stops being read. What the gateway <em>allowed</em> is in the audit file for
     * whoever needs it.
     */
    private String recentRefusals(int page) {
        List<AuditLog.Entry> all = audit.recent(1000).stream()
                .filter(e -> e.outcome() != AuditLog.Outcome.ALLOWED)
                .toList();

        int total = all.size();
        int totalPages = Math.max(1, (int) Math.ceil((double) total / AUDIT_PAGE_SIZE));
        page = Math.min(page, totalPages - 1);
        List<AuditLog.Entry> refusals = all.stream()
                .skip((long) page * AUDIT_PAGE_SIZE)
                .limit(AUDIT_PAGE_SIZE)
                .toList();

        StringBuilder b = new StringBuilder("<h2 id=\"recently-refused\">Recently refused</h2>");
        if (total == 0) {
            return b.append("<div class=\"empty\">Nothing has been refused.</div>").toString();
        }

        b.append("<table><tr><th>When</th><th></th><th>What</th><th>Why</th></tr>")
         .append("<tbody id=\"audit-tbody\">");
        for (var e : refusals) {
            b.append(auditRow(e));
        }
        b.append("</tbody></table>");

        // Pagination controls
        b.append("<div class=\"pagination\">");
        if (page > 0) {
            b.append("<a href=\"/toolgate?auditPage=").append(page - 1)
             .append("#recently-refused\">&#8592; newer</a> ");
        }
        b.append("<span class=\"dim\">page ").append(page + 1)
         .append(" of ").append(totalPages)
         .append(" (").append(total).append(" total)</span>");
        if (page < totalPages - 1) {
            b.append(" <a href=\"/toolgate?auditPage=").append(page + 1)
             .append("#recently-refused\">older &#8594;</a>");
        }
        b.append("</div>");

        return b.toString();
    }
}
