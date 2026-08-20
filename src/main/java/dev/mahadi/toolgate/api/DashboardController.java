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

import java.time.Duration;
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
    private final dev.mahadi.toolgate.auth.OperatorProperties operatorProps;

    public DashboardController(AuditLog audit, DriftStore drifts, ApprovalStore approvals,
                               ToolPinStore pins, SurfacePinStore surfacePins,
                               BundleStore bundles, OperatorSessions sessions,
                               dev.mahadi.toolgate.advisor.DriftAdvisor advisor,
                               ScannerRulesStore scannerRules, DashboardEventBus eventBus,
                               dev.mahadi.toolgate.auth.OperatorProperties operatorProps) {
        this.operatorProps = operatorProps;
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

        // The nonce admits exactly one stylesheet and one script — the ones this method
        // renders. Markup an upstream wrote cannot carry a matching attribute, and
        // 'unsafe-inline' is absent from the policy rather than present and ignored.
        String nonce = DashboardRenderer.newNonce();

        StringBuilder top = new StringBuilder();
        top.append("<div class=\"brand\"><span class=\"brand-mark\" aria-hidden=\"true\"></span>")
                .append("toolgate<span class=\"brand-sub\">operator console</span></div>")
                .append("<div class=\"topbar-spacer\"></div>")
                .append("<div class=\"topbar-meta\">")
                .append("<span class=\"status status-").append(statusTone()).append("\">")
                .append("<span class=\"status-dot\" aria-hidden=\"true\"></span>")
                .append(escape(status())).append("</span>")
                .append("<span class=\"live\" id=\"live-badge\">")
                .append("<span class=\"live-dot\" id=\"live-dot\" aria-hidden=\"true\"></span>")
                .append("<span class=\"live-text\" id=\"live-text\">connecting…</span></span>");
        if (session != null) {
            top.append("<form method=\"post\" action=\"/toolgate/logout\" class=\"inline\">")
                    .append(csrfField(csrf))
                    .append("<button class=\"link\" type=\"submit\">sign out</button></form>");
        }
        top.append("</div>");

        StringBuilder b = new StringBuilder();
        b.append(demoBanner());
        b.append(cards());
        b.append("<div id=\"drift-section\">").append(driftSection(csrf)).append("</div>");
        b.append("<div id=\"approvals-section\">").append(approvalSection(csrf)).append("</div>");
        b.append(scannerRulesSection(csrf));
        b.append(recentRefusals(auditPage));
        b.append(liveScript(nonce));

        return ResponseEntity.ok()
                .header("Content-Security-Policy", DashboardRenderer.csp(nonce))
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .body(DashboardRenderer.page("Dashboard",
                        DashboardRenderer.shell(top.toString(), b.toString()), 0, nonce));
    }

    /**
     * What a visitor to the public demonstration is looking at.
     *
     * <p>Without this the page is ambiguous in the worst direction: a stranger sees a live
     * console full of refusals and cannot tell whether it is a real deployment somebody
     * left open. Saying that the state is generated, and that nothing here can be acted on,
     * is the difference between a demonstration and an incident.
     */
    private String demoBanner() {
        if (!operatorProps.isPublicReadOnly()) return "";
        return """
            <div class="banner">
              <div class="banner-mark" aria-hidden="true">▮</div>
              <div>
                <div class="banner-head">This is a public demonstration, and it is read-only</div>
                <div class="banner-body">A hostile MCP server runs beside this gateway and
                attacks it on a loop — poisoned tool descriptions, a definition changed after
                approval, a tool that was never advertised, an exfiltration URL in metadata.
                Everything below is the gateway's real reaction to it, live. No button here
                does anything: every write is refused for everyone, including whoever
                deployed it. The code is at
                <a href="https://github.com/AbuUsamaIbrahim/toolgate">github.com/AbuUsamaIbrahim/toolgate</a>.</div>
              </div>
            </div>
            """;
    }

    /** The status line's colour, so "every request is being denied" does not read as neutral. */
    private String statusTone() {
        return switch (bundles.health()) {
            case FRESH -> "ok";
            case DISABLED -> "dim";
            case STALE -> "warn";
            case FAILED -> "bad";
        };
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
        // Not health.name(): "DISABLED" is the bundle feature's state, and on a card headed
        // "Policy" it reads as though the gateway itself is switched off — which is the
        // opposite of the truth, since local policy is being enforced.
        String policyWord = switch (health) {
            case FRESH -> "signed";
            case DISABLED -> "local";
            case STALE -> "stale";
            case FAILED -> "failed";
        };

        // The two counts that mean somebody has to do something are links, and carry an
        // accent stripe when non-zero. A number that needs a human should not look the same
        // as one that does not.
        return """
            <div class="cards">
              <div class="card"><div class="k">Policy</div><div class="v %s">%s</div>
                <div class="h">%s</div></div>
              <div class="card"><div class="k">Bundle sequence</div><div class="v dim">%s</div>
                <div class="h">%s</div></div>
              <a class="card%s" href="#drift"><div class="k">Drift to review</div>
                <div id="card-drift" class="v %s">%d</div>
                <div class="h">%s</div></a>
              <a class="card%s" href="#approvals"><div class="k">Awaiting approval</div>
                <div id="card-approvals" class="v %s">%d</div>
                <div class="h">%s</div></a>
              <div class="card"><div class="k">Pinned definitions</div><div class="v dim">%d</div>
                <div class="h">tools, resources and prompts</div></div>
            </div>
            """.formatted(
                cls, escape(policyWord),
                escape(status()),
                bundles.current().map(c -> String.valueOf(c.sequence())).orElse("—"),
                bundles.current().map(c -> "rollback floor held").orElse("no bundle configured"),
                outstanding > 0 ? " attn" : "",
                outstanding > 0 ? "warn" : "dim", outstanding,
                outstanding > 0 ? "definitions changed after approval" : "all definitions match",
                waiting > 0 ? " attn" : "",
                waiting > 0 ? "warn" : "dim", waiting,
                waiting > 0 ? "a call is blocked until someone decides" : "nothing blocked",
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
        StringBuilder b = new StringBuilder(sectionHead("drift",
                "Definitions that changed after approval",
                all.isEmpty() ? null : String.valueOf(all.size()),
                "warn",
                "A pinned definition no longer matches what the server is advertising. "
                        + "The tool stays blocked until someone decides which version is real."));
        if (all.isEmpty()) {
            return b.append(emptyState("No drift outstanding",
                    "Every definition matches the version that was approved.")).toString();
        }
        for (var d : all) {
            b.append("<div class=\"panel\"><div class=\"panel-head\"><h3>")
                    .append(escape(d.serverId())).append('/').append(escape(d.toolName()))
                    .append("</h3><span class=\"pill p-warn\">blocked</span>")
                    .append("<span class=\"meta\">detected ").append(escape(ago(d.detectedAt())))
                    .append("</span></div><div class=\"panel-body\">")
                    .append(DIFF_LEGEND)
                    .append("<div class=\"diff\">").append(diff(DriftStore.renderText(d)))
                    .append("</div>")
                    .append(advice(d))
                    .append("<div class=\"note-block\">Accept only if this reads as a product "
                            + "change. Instructions aimed at the model, unexpected paths, or "
                            + "characters marked in red are the attack this exists to catch."
                            + "</div></div>");
            b.append("<div class=\"panel-foot\">");
            if (csrf != null) {
                b.append("<form method=\"post\" action=\"/toolgate/ui/drift/accept\" class=\"inline\">")
                        .append(csrfField(csrf))
                        .append("<input type=\"hidden\" name=\"server\" value=\"")
                        .append(escape(d.serverId())).append("\">")
                        .append("<input type=\"hidden\" name=\"tool\" value=\"")
                        .append(escape(d.toolName())).append("\">")
                        .append("<button type=\"submit\" class=\"danger\">Accept as the new baseline</button>")
                        .append("</form>")
                        .append("<span class=\"sub\">This re-pins the current definition and "
                                + "names you in the audit trail.</span>");
            } else if (operatorProps.isPublicReadOnly()) {
                // Printing the curl command here would be an instruction that returns 403.
                b.append("<span class=\"sub\">Accepting this definition is refused on this "
                        + "deployment. Run it yourself to make the decision.</span>");
            } else {
                b.append("<code>curl -X POST localhost:8090/toolgate/drift/")
                        .append(escape(d.serverId())).append('/').append(escape(d.toolName()))
                        .append("/accept -H \"Authorization: Bearer $TOKEN\"</code>");
            }
            b.append("</div></div>");
        }
        return b.toString();
    }

    /**
     * The key to the diff, next to the diff.
     *
     * <p>The red marker is the one that matters — a reviewer who does not know that
     * {@code ⟨U+200B⟩} means "there is a character here you cannot see" reads the diff as
     * clean.
     */
    private static final String DIFF_LEGEND = """
        <div class="diff-legend">
          <span><i class="swatch swatch-del"></i>was approved</span>
          <span><i class="swatch swatch-add"></i>now advertised</span>
          <span><mark class="hidden-char">⟨U+200B⟩</mark>a character you cannot otherwise see</span>
        </div>""";

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
        StringBuilder b = new StringBuilder(sectionHead("approvals", "Waiting for a human",
                waiting.isEmpty() ? null : String.valueOf(waiting.size()), "warn",
                "A call the policy will not make on its own. The agent is blocked on each of "
                        + "these until someone decides, and the grant is single-use."));
        if (waiting.isEmpty()) {
            return b.append(emptyState("Nothing is waiting",
                    "No call is currently blocked on a human decision.")).toString();
        }
        b.append("<div class=\"table-wrap\"><table><thead><tr><th>Who</th><th>Tool</th>"
                        + "<th>Why</th><th>Raised</th>")
                .append(csrf == null ? "" : "<th>Decide</th>").append("</tr></thead><tbody>");
        waiting.values().forEach(p -> {
            b.append("<tr><td class=\"mono\">").append(escape(p.caller()))
                    .append("</td><td class=\"mono\">").append(escape(p.serverId()))
                    .append('/').append(escape(p.tool()))
                    .append("</td><td class=\"dim\">").append(escape(p.reason()))
                    .append("</td><td class=\"dim cell-nowrap\">").append(escape(ago(p.createdAt())))
                    .append("</td>");
            if (csrf != null) {
                b.append("<td class=\"cell-nowrap\">")
                        .append("<form method=\"post\" action=\"/toolgate/ui/approval\" class=\"inline\">")
                        .append(csrfField(csrf))
                        .append("<input type=\"hidden\" name=\"id\" value=\"")
                        .append(escape(p.id())).append("\">")
                        // Typed, not defaulted: an approval must name a person, and the
                        // requester is refused by the store rather than by this form.
                        .append("<input name=\"approver\" placeholder=\"you@example.com\" ")
                        .append("required class=\"who\" aria-label=\"your identity\">")
                        .append("<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>")
                        .append("<button type=\"submit\" name=\"decision\" value=\"deny\" class=\"danger\">Deny</button>")
                        .append("</form></td>");
            }
            b.append("</tr>");
        });
        b.append("</tbody></table></div><div class=\"note\">The requester cannot approve their "
                + "own call. Approving names you in the audit trail.</div>");
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
        long enabled = all.stream().filter(ScannerRule::enabled).count();
        StringBuilder b = new StringBuilder(sectionHead("scanner-rules", "Scanner rules",
                enabled + " of " + all.size() + " active", "dim",
                "Regex patterns scored against every tool definition at <code>tools/list</code>. "
                        + "Scores are additive; a tool reaching the block threshold is withheld "
                        + "from the model rather than shown to it."));

        b.append("<div class=\"table-wrap\"><table><thead><tr><th>Category</th><th>Pattern</th>"
                + "<th>Weight</th><th>Description</th><th>Status</th>");
        if (csrf != null) b.append("<th>Actions</th>");
        b.append("</tr></thead><tbody>");

        for (ScannerRule r : all) {
            String statusPill = r.enabled()
                    ? "<span class=\"pill p-ok\">enabled</span>"
                    : "<span class=\"pill p-bad\">disabled</span>";
            String builtInBadge = r.builtIn()
                    ? " <span class=\"pill dim tiny\">built-in</span>" : "";

            b.append("<tr>")
             .append("<td class=\"mono\">").append(escape(r.category())).append("</td>")
             .append("<td class=\"mono cell-pattern\">")
             .append(escape(r.pattern())).append("</td>")
             .append("<td class=\"mono\">").append(r.weight()).append("</td>")
             .append("<td class=\"dim\">").append(escape(r.description())).append(builtInBadge)
             .append("</td>")
             .append("<td>").append(statusPill).append("</td>");

            if (csrf != null) {
                // Toggle button (available for all rules)
                b.append("<td class=\"cell-nowrap\">")
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
        b.append("</tbody></table></div>");

        // Add-rule form — only when logged in with a session
        if (csrf != null) {
            b.append("<details class=\"adder\"><summary>Add a custom rule</summary>");
            b.append("<form method=\"post\" action=\"/toolgate/ui/scanner/rule\" class=\"form-grid\">")
             .append(csrfField(csrf))
             .append("<div class=\"field\"><label class=\"field-label\" for=\"rule-category\">"
                     + "Category</label>"
                     + "<select id=\"rule-category\" name=\"category\" class=\"select\">")
             .append("<option value=\"imperative_instruction\">imperative_instruction</option>")
             .append("<option value=\"credential_target\">credential_target</option>")
             .append("<option value=\"exfiltration_shape\">exfiltration_shape</option>")
             .append("<option value=\"hidden_unicode\">hidden_unicode</option>")
             .append("</select></div>")
             .append("<div class=\"field\"><label class=\"field-label\" for=\"rule-pattern\">"
                     + "Regex pattern (Java, case-insensitive)</label>"
                     + "<input id=\"rule-pattern\" name=\"pattern\" required class=\"input\" "
                     + "placeholder=\"e.g. exfiltrate\\\\s+to\"></div>")
             .append("<div class=\"form-cols\">")
             .append("<div class=\"field\"><label class=\"field-label\" for=\"rule-weight\">"
                     + "Weight (added to score on match)</label>"
                     + "<input id=\"rule-weight\" name=\"weight\" type=\"number\" value=\"30\" "
                     + "min=\"1\" max=\"100\" class=\"input\"></div>")
             .append("<div class=\"field\"><label class=\"field-label\" for=\"rule-description\">"
                     + "Description (shown in this table)</label>"
                     + "<input id=\"rule-description\" name=\"description\" class=\"input\" "
                     + "placeholder=\"What this pattern catches\"></div>")
             .append("</div>")
             .append("<div><button type=\"submit\">Add rule</button></div>")
             .append("</form></details>");
        }

        b.append("<div class=\"note\">Scores are additive. A single match at weight 40 plus "
                + "one at weight 30 = score 70. Block threshold is set in "
                + "<code>toolgate.block-threshold</code> (currently blocks at ≥ 50). "
                + "Built-in rules can be disabled but not deleted — removing one permanently "
                + "takes a code change, deliberately.</div>");
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
        // The reason leads, and the caller and tool each get their own column. The first
        // version restated "X tried to call Y" inside the reason cell while the same tool
        // sat in the column beside it, so the one piece of information that differs between
        // two rows — why this one was refused — was the last thing read.
        StringBuilder why = new StringBuilder("<span class=\"dim\">")
                .append(escape(e.reason())).append("</span>");
        if (!e.evidence().isEmpty()) {
            why.append("<br><span class=\"evidence\">")
               .append(escape(String.join(" · ", e.evidence()))).append("</span>");
        }
        return "<tr><td class=\"dim mono cell-nowrap\">" + escape(ago(e.at()))
                + "</td><td><span class=\"pill " + pill + "\">"
                + escape(e.outcome().name()) + "</span></td>"
                + "<td class=\"mono\">" + escape(e.caller()) + "</td>"
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
            <script nonce="%s">
            (function() {
              var badge = document.getElementById('live-badge');
              var dot   = document.getElementById('live-dot');
              var txt   = document.getElementById('live-text');

              // Class names only — the stylesheet owns the colours, and with a nonce in
              // style-src an inline style attribute would not be applied anyway.
              function setStatus(state, label) {
                if (dot) { dot.className = 'live-dot' + (state ? ' ' + state : ''); }
                if (badge) { badge.className = 'live' + (state ? ' ' + state : ''); }
                if (txt) { txt.textContent = label; }
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
                  row.className = 'flash';
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
            """.formatted(nonce, AUDIT_PAGE_SIZE);
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

        StringBuilder b = new StringBuilder(sectionHead("recently-refused", "Recently refused",
                total == 0 ? null : String.valueOf(total), "dim",
                "Only refusals, and only the last thousand held in memory. What the gateway "
                        + "allowed is in the audit file. New entries arrive here live."));
        if (total == 0) {
            return b.append(emptyState("Nothing has been refused",
                    "No tool, resource or prompt has been withheld since this process started."))
                    .toString();
        }

        b.append("<div class=\"table-wrap\"><table><thead><tr><th>When</th><th>Outcome</th>"
                        + "<th>Caller</th><th>Tool</th><th>Why</th></tr></thead>")
         .append("<tbody id=\"audit-tbody\">");
        for (var e : refusals) {
            b.append(auditRow(e));
        }
        b.append("</tbody></table></div>");

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
