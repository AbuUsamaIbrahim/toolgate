package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.audit.AuditLog;
import dev.mahadi.toolgate.bundle.BundleStore;
import dev.mahadi.toolgate.gateway.ApprovalStore;
import dev.mahadi.toolgate.integrity.DriftStore;
import dev.mahadi.toolgate.integrity.SurfacePinStore;
import dev.mahadi.toolgate.integrity.ToolPinStore;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

    private final AuditLog audit;
    private final DriftStore drifts;
    private final ApprovalStore approvals;
    private final ToolPinStore pins;
    private final SurfacePinStore surfacePins;
    private final BundleStore bundles;
    private final OperatorSessions sessions;
    private final dev.mahadi.toolgate.advisor.DriftAdvisor advisor;

    public DashboardController(AuditLog audit, DriftStore drifts, ApprovalStore approvals,
                               ToolPinStore pins, SurfacePinStore surfacePins,
                               BundleStore bundles, OperatorSessions sessions,
                               dev.mahadi.toolgate.advisor.DriftAdvisor advisor) {
        this.sessions = sessions;
        this.advisor = advisor;
        this.audit = audit;
        this.drifts = drifts;
        this.approvals = approvals;
        this.pins = pins;
        this.surfacePins = surfacePins;
        this.bundles = bundles;
    }

    @GetMapping(value = "/toolgate", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> dashboard(org.springframework.web.server.ServerWebExchange exchange) {
        var cookie = exchange.getRequest().getCookies().get(OperatorSessions.COOKIE);
        var session = cookie == null || cookie.isEmpty() ? null
                : sessions.lookup(cookie.get(0).getValue()).orElse(null);

        // Reached with a bearer token rather than a browser session: render it read-only.
        // The buttons need a CSRF token, and a CSRF token needs a session to be bound to.
        String csrf = session == null ? null : session.csrfToken();

        StringBuilder b = new StringBuilder();
        b.append("<h1>toolgate</h1><div class=\"sub\">")
                .append(escape(status())).append(" · refreshes every 15s");
        if (session != null) {
            b.append(" · <form method=\"post\" action=\"/toolgate/logout\" class=\"inline\">")
                    .append(csrfField(csrf))
                    .append("<button class=\"link\" type=\"submit\">sign out</button></form>");
        }
        b.append("</div>");

        b.append(cards());
        b.append(driftSection(csrf));
        b.append(approvalSection(csrf));
        b.append(recentRefusals());

        return ResponseEntity.ok()
                // No script at all, from anywhere. The page renders text an attacker wrote,
                // for the person holding a token that can approve anything, so the policy
                // is the belt to the escaping's braces.
                .header("Content-Security-Policy",
                        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                                + "frame-ancestors 'none'; base-uri 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .header("Referrer-Policy", "no-referrer")
                .body(page("Dashboard", b.toString()));
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
              <div class="card"><div class="k">Drift to review</div><div class="v %s">%d</div></div>
              <div class="card"><div class="k">Awaiting approval</div><div class="v %s">%d</div></div>
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
                b.append("<code>curl -X POST localhost:8080/toolgate/drift/")
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
     * Refusals only.
     *
     * <p>Showing everything would bury the interesting lines under routine ones, which is
     * how a log stops being read. What the gateway <em>allowed</em> is in the audit file for
     * whoever needs it.
     */
    private String recentRefusals() {
        List<AuditLog.Entry> refusals = audit.recent(400).stream()
                .filter(e -> e.outcome() != AuditLog.Outcome.ALLOWED)
                .limit(40)
                .toList();

        StringBuilder b = new StringBuilder("<h2>Recently refused</h2>");
        if (refusals.isEmpty()) {
            return b.append("<div class=\"empty\">Nothing has been refused.</div>").toString();
        }
        b.append("<table><tr><th>When</th><th></th><th>What</th><th>Why</th></tr>");
        for (var e : refusals) {
            String pill = switch (e.outcome()) {
                case DENIED -> "p-bad";
                case APPROVAL_REQUIRED -> "p-warn";
                case FAILED -> "p-warn";
                default -> "p-ok";
            };
            b.append("<tr><td class=\"dim mono\">").append(escape(ago(e.at())))
                    .append("</td><td><span class=\"pill ").append(pill).append("\">")
                    .append(escape(e.outcome().name())).append("</span></td>")
                    .append("<td class=\"mono\">").append(escape(e.serverId()))
                    .append('/').append(escape(e.tool()))
                    .append("</td><td class=\"dim\">").append(escape(e.reason()))
                    .append("</td></tr>");
        }
        return b.append("</table>").toString();
    }
}
