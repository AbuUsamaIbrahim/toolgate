package dev.mahadi.toolgate.api;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

/**
 * Turns gateway state into HTML.
 *
 * <h2>Everything rendered here was written by the party under suspicion</h2>
 * This is not an ordinary admin page. A drift diff shows a tool description a compromised
 * server wrote. An audit line quotes scanner evidence — the exact text that looked like an
 * attack. A resource URI is chosen by the upstream. All of it is attacker-controlled by
 * definition, because the gateway's entire job is handling hostile input.
 *
 * <p>Putting that in a browser without escaping would hand a stored cross-site scripting
 * vector to the one person holding a token that can approve anything. A tool description of
 * {@code <img src=x onerror="fetch('/toolgate/drift/files/read_file/accept',{method:'POST'})">}
 * would approve its own poisoning the moment an operator opened the page to look at it.
 *
 * <p>So: everything goes through {@link #escape}, invisible characters are rendered visibly
 * rather than passed through, and the page carries a content-security policy that admits
 * exactly one script and one stylesheet — the ones carrying a per-request {@link #newNonce()
 * nonce}. Nothing an upstream wrote can supply that. Making the visible-invisibles work is
 * not defence, it is the point: a reviewer deciding whether a diff is a release or an attack
 * has to be able to see a zero-width space.
 *
 * <h2>Why there is not one inline style attribute in this package</h2>
 * A nonce in {@code style-src} makes a browser ignore {@code 'unsafe-inline'} — that is the
 * CSP specification, not a quirk — so the moment anything here needed a nonce, every
 * {@code style="…"} attribute on the page stopped being applied, along with any
 * {@code <style>} tag that had not been given the nonce too. The console rendered as
 * unstyled markup. So presentation lives in {@link #CSS} under a class name, the shell
 * stamps the nonce on the one stylesheet, and {@code 'unsafe-inline'} is gone from the
 * policy rather than merely present and ignored. {@code DashboardStylingTest} fails the
 * build if an inline style creeps back in.
 */
public final class DashboardRenderer {

    private DashboardRenderer() {}

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A fresh nonce for one response.
     *
     * <p>Per-request and unpredictable, so markup an upstream wrote cannot carry a matching
     * attribute however it reaches the page. Every operator page needs one, which is why it
     * lives here rather than in one of the two controllers that render them.
     */
    public static String newNonce() {
        byte[] bytes = new byte[18];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * The policy every operator page is served under.
     *
     * <p>One place, because a second copy is a second thing to forget: the sign-in page
     * once carried a policy of its own that had drifted from the dashboard's.
     */
    public static String csp(String nonce) {
        return "default-src 'none'; "
                + "style-src 'nonce-" + nonce + "'; "
                + "script-src 'nonce-" + nonce + "'; "
                + "connect-src 'self'; "
                + "form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    }

    /**
     * HTML-escapes, and makes invisible characters visible.
     *
     * <p>The five entity replacements are the ordinary part. Rendering format characters as
     * {@code ⟨U+200B⟩} is the part specific to this page: text that hides from a human while
     * remaining legible to a model is exactly what the scanner flags, and a review UI that
     * silently swallowed it would be worse than no UI.
     */
    public static String escape(String raw) {
        if (raw == null) return "";
        StringBuilder out = new StringBuilder(raw.length() + 16);
        raw.codePoints().forEach(cp -> {
            switch (cp) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#x27;");
                default -> {
                    int type = Character.getType(cp);
                    boolean invisible = type == Character.FORMAT
                            || type == Character.CONTROL
                            || type == Character.PRIVATE_USE
                            || type == Character.UNASSIGNED
                            || cp == 0x00AD || cp == 0x2028 || cp == 0x2029;
                    if (invisible && cp != '\n' && cp != '\t') {
                        out.append("<mark class=\"hidden-char\">⟨U+")
                                .append(String.format(Locale.ROOT, "%04X", cp))
                                .append("⟩</mark>");
                    } else {
                        out.appendCodePoint(cp);
                    }
                }
            }
        });
        return out.toString();
    }

    /** Escapes, then colours a unified diff so additions and removals are obvious. */
    public static String diff(String rendered) {
        StringBuilder out = new StringBuilder();
        for (String line : escape(rendered).split("\n", -1)) {
            String css = line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "ctx";
            out.append("<div class=\"d ").append(css).append("\">")
                    .append(line.isEmpty() ? "&nbsp;" : line).append("</div>");
        }
        return out.toString();
    }

    /** A short, readable "3m ago" rather than a timestamp nobody subtracts in their head. */
    public static String ago(java.time.Instant then) {
        if (then == null) return "—";
        var d = java.time.Duration.between(then, java.time.Instant.now());
        long s = d.getSeconds();
        if (s < 60) return s + "s ago";
        if (s < 3600) return d.toMinutes() + "m ago";
        if (s < 172800) return d.toHours() + "h ago";
        return d.toDays() + "d ago";
    }

    /**
     * The page shell.
     *
     * <p>No framework, no build step, no external requests — partly to keep the project's
     * dependencies honest, and partly because the content security policy below forbids
     * them anyway. A security tool that pulls a script from a CDN to draw its own dashboard
     * is making an argument it would not accept from anyone else.
     */
    public static String page(String title, String body) {
        return page(title, body, 0, null);
    }

    public static String page(String title, String body, int refreshSeconds) {
        return page(title, body, refreshSeconds, null);
    }

    /**
     * The page shell.
     *
     * <p>The {@code nonce}, when set, is stamped on the stylesheet and named in the policy
     * header, which is what makes the page's own CSS the only CSS that applies. Pass the
     * same value to {@link #csp(String)} — the two are a pair, and a page that nonces one
     * without the other renders unstyled.
     */
    public static String page(String title, String body, int refreshSeconds, String nonce) {
        String refresh = refreshSeconds > 0
                ? "<meta http-equiv=\"refresh\" content=\"" + refreshSeconds + "\">\n"
                : "";
        String styleAttr = nonce == null ? "" : " nonce=\"" + escape(nonce) + "\"";
        return """
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>%s — toolgate</title>
            %s<style%s>%s</style>
            </head><body>%s</body></html>
            """.formatted(escape(title), refresh, styleAttr, CSS, body);
    }

    // ---------------------------------------------------------------- components
    //
    // Small builders rather than markup repeated at each call site: an empty state written
    // five ways reads as five different states.

    /** The page frame: a sticky bar carrying identity and status, then the content column. */
    public static String shell(String topbar, String content) {
        return "<header class=\"topbar\"><div class=\"topbar-inner\">" + topbar
                + "</div></header><main class=\"wrap\">" + content + "</main>";
    }

    /**
     * A section heading with its count and its one-line explanation.
     *
     * <p>The count is in the heading because "Waiting for a human" and "Waiting for a
     * human · 3" are different states and the operator is scanning, not reading.
     *
     * <p><strong>{@code sub} is emitted as markup and is not escaped</strong> — it carries
     * the odd {@code <code>} tag in a fixed sentence this class's callers wrote. Nothing
     * derived from an upstream may be passed to it; {@code title} and {@code count} are
     * escaped and are the parameters to use for anything that came off the wire.
     */
    public static String sectionHead(String id, String title, String count, String tone, String sub) {
        StringBuilder b = new StringBuilder("<div class=\"section\" id=\"" + escape(id) + "\">"
                + "<div class=\"section-title\"><h2>" + escape(title) + "</h2>");
        if (count != null) {
            b.append("<span class=\"chip chip-").append(escape(tone)).append("\">")
                    .append(escape(count)).append("</span>");
        }
        b.append("</div>");
        if (sub != null) b.append("<p class=\"section-sub\">").append(sub).append("</p>");
        return b.append("</div>").toString();
    }

    /** The all-clear state, which is the one an operator sees most and should be able to trust. */
    public static String emptyState(String headline, String detail) {
        return "<div class=\"empty\"><div class=\"empty-mark\" aria-hidden=\"true\">✓</div>"
                + "<div><div class=\"empty-head\">" + escape(headline) + "</div>"
                + "<div class=\"empty-detail\">" + escape(detail) + "</div></div></div>";
    }

    private static final String CSS = """
        :root{
          --bg:#080b11;--bg-soft:#0c1017;--panel:#10151e;--panel-2:#0c111a;--line:#1c2532;
          --line-soft:#161e29;--ink:#e9eff8;--dim:#9db0c8;--faint:#68798f;
          --ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--accent:#38bdf8;
          --ok-bg:rgba(74,222,128,.12);--warn-bg:rgba(251,191,36,.12);
          --bad-bg:rgba(248,113,113,.12);--accent-bg:rgba(56,189,248,.12);
          --radius:12px;--mono:ui-monospace,SFMono-Regular,Menlo,"Cascadia Mono",monospace;
          --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif}
        *{box-sizing:border-box}
        html{-webkit-text-size-adjust:100%}
        body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 var(--sans);
             -webkit-font-smoothing:antialiased}
        a{color:var(--accent);text-decoration:none}
        a:hover{text-decoration:underline}
        :focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}

        /* ---- frame ---- */
        .topbar{position:sticky;top:0;z-index:20;background:rgba(8,11,17,.86);
                backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
        .topbar-inner{max-width:1180px;margin:0 auto;padding:0 22px;height:56px;
                      display:flex;align-items:center;gap:14px}
        .brand{display:flex;align-items:center;gap:9px;font:600 15px/1 var(--sans);
               letter-spacing:-.2px;margin-right:2px}
        .brand-mark{width:9px;height:18px;border-radius:2px;
                    background:linear-gradient(180deg,var(--accent),#0ea5e9);
                    box-shadow:0 0 14px rgba(56,189,248,.5)}
        .brand-sub{color:var(--faint);font:500 11px/1 var(--sans);letter-spacing:.09em;
                   text-transform:uppercase;padding-left:11px;margin-left:2px;
                   border-left:1px solid var(--line)}
        .topbar-spacer{flex:1}
        .topbar-meta{display:flex;align-items:center;gap:14px;flex-wrap:wrap;
                     font-size:12px;color:var(--dim)}
        .wrap{max-width:1180px;margin:0 auto;padding:26px 22px 72px}

        /* ---- status + live badge ---- */
        .status{display:inline-flex;align-items:center;gap:7px}
        .status-dot{width:7px;height:7px;border-radius:50%;background:var(--faint);flex:none}
        .status-ok .status-dot{background:var(--ok)}
        .status-warn .status-dot{background:var(--warn)}
        .status-bad .status-dot{background:var(--bad)}
        .live{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:var(--faint)}
        .live-dot{width:7px;height:7px;border-radius:50%;background:var(--faint);
                  display:inline-block;flex:none}
        .live-dot.connected{background:var(--ok);animation:live-pulse 2s ease-in-out infinite}
        .live-dot.error{background:var(--bad);animation:none}
        .live.connected .live-text{color:var(--ok)}
        .live.error .live-text{color:var(--bad)}
        @keyframes live-pulse{0%,100%{opacity:1}50%{opacity:.3}}
        @keyframes row-flash{from{background:var(--accent-bg)}to{background:transparent}}
        .flash td{animation:row-flash 1.1s ease-out 1}

        /* ---- stat cards ---- */
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));
               gap:10px;margin-bottom:6px}
        .card{position:relative;background:linear-gradient(180deg,var(--panel),var(--panel-2));
              border:1px solid var(--line);border-radius:var(--radius);padding:15px 16px 16px;
              overflow:hidden}
        .card::before{content:"";position:absolute;inset:0 0 auto;height:2px;background:transparent}
        .card.attn::before{background:linear-gradient(90deg,var(--warn),transparent)}
        .card.alarm::before{background:linear-gradient(90deg,var(--bad),transparent)}
        .card .k{font-size:10px;text-transform:uppercase;letter-spacing:.11em;color:var(--faint);
                 font-weight:600}
        .card .v{font:600 24px/1.2 var(--mono);margin-top:7px;letter-spacing:-.5px}
        .card .h{font-size:11.5px;color:var(--faint);margin-top:4px}
        a.card{display:block;color:inherit}
        a.card:hover{border-color:#26364a;text-decoration:none}

        /* ---- sections ---- */
        .section{margin:34px 0 12px}
        .section-title{display:flex;align-items:center;gap:9px}
        .section h2{font-size:13px;text-transform:uppercase;letter-spacing:.12em;
                    color:var(--dim);margin:0;font-weight:600}
        .section-sub{color:var(--faint);font-size:12.5px;margin:5px 0 0;max-width:76ch}
        .chip{font:600 10.5px/1.7 var(--sans);padding:0 8px;border-radius:20px;
              letter-spacing:.03em}
        .chip-dim{background:var(--line);color:var(--dim)}
        .chip-warn{background:var(--warn-bg);color:var(--warn)}
        .chip-bad{background:var(--bad-bg);color:var(--bad)}
        .chip-ok{background:var(--ok-bg);color:var(--ok)}

        /* ---- panels ---- */
        .panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
               padding:0;margin-bottom:12px;overflow:hidden}
        .panel-head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;
                    padding:14px 16px;border-bottom:1px solid var(--line-soft);
                    background:rgba(255,255,255,.012)}
        .panel-head h3{margin:0;font:600 13.5px/1.4 var(--mono);color:var(--accent)}
        .panel-head .meta{font-size:11.5px;color:var(--faint);margin-left:auto}
        .panel-body{padding:15px 16px}
        .panel-foot{padding:12px 16px;border-top:1px solid var(--line-soft);
                    display:flex;align-items:center;gap:10px;flex-wrap:wrap;
                    background:rgba(255,255,255,.012)}
        .panel-narrow{max-width:430px;margin:0 auto}

        /* ---- diff ---- */
        .diff{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:9px;
              padding:9px 0;overflow-x:auto}
        .diff-legend{display:flex;gap:14px;font-size:10.5px;color:var(--faint);
                     margin:0 0 8px;letter-spacing:.05em;text-transform:uppercase}
        .diff-legend span{display:inline-flex;align-items:center;gap:5px}
        .swatch{width:8px;height:8px;border-radius:2px;display:inline-block}
        .swatch-add{background:var(--ok)}.swatch-del{background:var(--bad)}
        .swatch-hidden{background:var(--bad);box-shadow:0 0 0 1px var(--bad)}
        .d{font-family:var(--mono);font-size:12px;white-space:pre-wrap;padding:1px 12px;
           border-left:2px solid transparent;word-break:break-word}
        .d.add{background:rgba(74,222,128,.09);border-left-color:var(--ok)}
        .d.del{background:rgba(248,113,113,.09);border-left-color:var(--bad)}
        .d.ctx{color:var(--dim)}
        .hidden-char{background:var(--bad);color:#04121c;border-radius:3px;padding:0 3px;
                     font:600 11px var(--mono)}

        /* ---- tables ---- */
        .table-wrap{border:1px solid var(--line);border-radius:var(--radius);overflow-x:auto;
                    background:var(--panel)}
        table{width:100%;border-collapse:collapse;font-size:13px}
        th{text-align:left;font:600 10px/1 var(--sans);text-transform:uppercase;
           letter-spacing:.1em;color:var(--faint);padding:12px 14px;
           border-bottom:1px solid var(--line);background:var(--panel-2);white-space:nowrap}
        td{padding:11px 14px;border-bottom:1px solid var(--line-soft);vertical-align:top}
        tbody tr:last-child td{border-bottom:0}
        tbody tr:hover{background:rgba(255,255,255,.018)}
        .cell-nowrap{white-space:nowrap}
        .cell-pattern{max-width:280px;word-break:break-all}
        .evidence{font-size:11px;color:var(--faint)}

        /* ---- pills, text ---- */
        .mono{font-family:var(--mono);font-size:12px}
        .pill{display:inline-block;padding:1px 8px;border-radius:20px;
              font:600 10px/1.8 var(--sans);letter-spacing:.04em;white-space:nowrap}
        .p-ok{background:var(--ok-bg);color:var(--ok)}
        .p-warn{background:var(--warn-bg);color:var(--warn)}
        .p-bad{background:var(--bad-bg);color:var(--bad)}
        .pill.dim{background:var(--line);color:var(--faint)}
        .pill.tiny{font-size:9.5px;padding:0 6px}
        .ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.dim{color:var(--dim)}
        .sub{color:var(--faint);font-size:12px}
        .note{color:var(--faint);font-size:11.5px;margin-top:10px;line-height:1.65}
        .note-block{border-left:2px solid var(--line);padding:2px 0 2px 11px;margin-top:12px;
                    color:var(--faint);font-size:11.5px;line-height:1.65}
        code{background:var(--panel-2);border:1px solid var(--line);border-radius:6px;
             padding:3px 8px;font-family:var(--mono);font-size:11.5px;color:var(--dim);
             display:inline-block;word-break:break-all}

        /* ---- empty states ---- */
        .empty{display:flex;align-items:center;gap:12px;border:1px dashed var(--line);
               border-radius:var(--radius);padding:16px 18px;background:rgba(255,255,255,.012)}
        .empty-mark{width:24px;height:24px;border-radius:50%;background:var(--ok-bg);
                    color:var(--ok);display:flex;align-items:center;justify-content:center;
                    font-size:12px;flex:none}
        .empty-head{font-size:13px;color:var(--dim)}
        .empty-detail{font-size:12px;color:var(--faint);margin-top:2px}
        .empty.warn-state .empty-mark{background:var(--bad-bg);color:var(--bad)}

        /* ---- controls ---- */
        button,.btn{font:600 12px var(--sans);padding:7px 13px;border-radius:7px;cursor:pointer;
                    background:var(--accent);color:#04121c;border:1px solid transparent;
                    transition:filter .12s ease,border-color .12s ease}
        button:hover{filter:brightness(1.1)}
        button.ghost{background:transparent;color:var(--dim);border-color:var(--line)}
        button.ghost:hover{color:var(--ink);border-color:#2a3a4d;filter:none}
        button.danger{background:transparent;color:var(--bad);border-color:rgba(248,113,113,.45)}
        button.danger:hover{background:var(--bad-bg);filter:none}
        button.link{background:none;border:0;color:var(--faint);padding:0;font-weight:500;
                    text-decoration:underline;font-size:12px}
        button.link:hover{color:var(--ink);filter:none}
        form.inline{display:inline-flex;align-items:center;gap:6px;margin:0}
        .input,input.who{background:var(--panel-2);border:1px solid var(--line);border-radius:7px;
                         color:var(--ink);padding:8px 10px;font:12.5px var(--mono);width:100%}
        .input:focus,input.who:focus{border-color:var(--accent);outline:none}
        input.who{width:170px;font-size:12px}
        .select{background:var(--panel-2);border:1px solid var(--line);border-radius:7px;
                color:var(--ink);padding:8px 10px;font:12.5px var(--sans);width:100%}
        label.k,.field-label{font-size:10px;text-transform:uppercase;letter-spacing:.1em;
                             color:var(--faint);font-weight:600;display:block;margin-bottom:5px}
        .field{margin-bottom:2px}
        .form-grid{display:grid;gap:12px;max-width:600px;margin-top:12px}
        .form-cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}
        details.adder{margin-top:14px}
        details.adder>summary{cursor:pointer;color:var(--dim);font-size:12px;
                              list-style:none;display:inline-flex;align-items:center;gap:6px}
        details.adder>summary::-webkit-details-marker{display:none}
        details.adder>summary::before{content:"+";font:600 13px var(--mono);color:var(--accent)}
        details.adder[open]>summary::before{content:"−"}

        /* ---- advisor ---- */
        .advice{margin-top:14px;padding:12px 14px;background:var(--panel-2);
                border:1px dashed var(--line);border-radius:9px}
        .advice-head{display:flex;align-items:center;gap:9px;margin-bottom:7px;flex-wrap:wrap}
        .warnlabel{font-size:10.5px;color:var(--warn);text-transform:uppercase;letter-spacing:.07em}
        .advice ul{margin:8px 0 0;padding-left:17px;color:var(--dim);font-size:12.5px}
        .advice li{margin:3px 0}

        /* ---- pagination ---- */
        .pagination{margin-top:12px;font-size:12px;color:var(--faint);
                    display:flex;align-items:center;gap:12px}
        .pagination a{color:var(--dim)}

        /* ---- sign-in ---- */
        .signin{min-height:82vh;display:flex;align-items:center;justify-content:center;
                padding:40px 20px}
        .signin .brand{justify-content:center;margin:0 0 6px;font-size:17px}
        .signin-sub{text-align:center;color:var(--faint);font-size:12px;margin-bottom:20px}
        .signin-error{background:var(--bad-bg);color:var(--bad);border-radius:7px;
                      padding:8px 11px;font-size:12px;margin-top:12px}

        @media (max-width:720px){
          .topbar-inner{padding:0 16px;height:auto;min-height:56px;flex-wrap:wrap;gap:8px;
                        padding-top:10px;padding-bottom:10px}
          .wrap{padding:20px 16px 56px}
          .brand-sub{display:none}
          .form-cols{grid-template-columns:1fr}
        }
        @media (prefers-reduced-motion:reduce){
          *{animation:none!important;transition:none!important}
        }
        """;
}
