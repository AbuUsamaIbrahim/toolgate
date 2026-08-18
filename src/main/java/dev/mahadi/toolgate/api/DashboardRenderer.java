package dev.mahadi.toolgate.api;

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
 * <p>So: everything goes through {@link #escape}, there is no {@code innerHTML} anywhere,
 * the page carries a content-security policy that forbids inline and remote script, and
 * invisible characters are rendered visibly rather than passed through. That last one is
 * not defence — it is the point. A reviewer deciding whether a diff is a release or an
 * attack has to be able to see a zero-width space.
 */
public final class DashboardRenderer {

    private DashboardRenderer() {}

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
        return page(title, body, 0);
    }

    /**
     * The page shell, with an optional auto-refresh.
     *
     * <p>Refreshing defaults to off, and pages opt in. It used to be unconditional, which
     * was fine for the dashboard and quietly broken everywhere else: the sign-in form
     * inherited it too, so the browser reloaded the page — and discarded the half-typed
     * token — every fifteen seconds. Anyone typing a credential by hand, or waiting on a
     * password manager, lost it mid-entry. A console that reloads while you are
     * authenticating to it is not a console you can get into.
     *
     * <p>Only a browser could find that. Every test and every {@code curl} fetched the page
     * once and read the markup, which is exactly the usage a meta refresh does not affect.
     */
    public static String page(String title, String body, int refreshSeconds) {
        String refresh = refreshSeconds > 0
                ? "<meta http-equiv=\"refresh\" content=\"" + refreshSeconds + "\">\n"
                : "";
        return """
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title>%s — toolgate</title>
            %s<style>%s</style>
            </head><body><div class="wrap">%s</div></body></html>
            """.formatted(escape(title), refresh, CSS, body);
    }

    private static final String CSS = """
        :root{--bg:#0b0e14;--panel:#11161f;--line:#1f2733;--ink:#e8edf5;--dim:#9aa7ba;
              --faint:#6b7a90;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--accent:#38bdf8}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--ink);
             font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        .wrap{max-width:1100px;margin:0 auto;padding:28px 20px 60px}
        h1{font-size:20px;margin:0 0 4px;letter-spacing:-.3px}
        h2{font-size:13px;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);
           margin:34px 0 12px;font-weight:600}
        .sub{color:var(--faint);font-size:12px;margin-bottom:24px}
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:1px;
               background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden}
        .card{background:var(--panel);padding:14px 16px}
        .card .k{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint)}
        .card .v{font:600 19px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:5px}
        .ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.dim{color:var(--dim)}
        .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;
               padding:16px;margin-bottom:12px}
        .panel h3{margin:0 0 4px;font:600 14px/1.4 ui-monospace,Menlo,monospace;color:var(--accent)}
        table{width:100%;border-collapse:collapse;font-size:13px}
        th{text-align:left;font:600 10px/1 system-ui;text-transform:uppercase;letter-spacing:.1em;
           color:var(--faint);padding:0 10px 8px 0;border-bottom:1px solid var(--line)}
        td{padding:7px 10px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
        tr:last-child td{border-bottom:0}
        .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
        .pill{display:inline-block;padding:1px 7px;border-radius:20px;font:600 10px/1.7 system-ui;
              letter-spacing:.04em}
        .p-ok{background:rgba(74,222,128,.13);color:var(--ok)}
        .p-warn{background:rgba(251,191,36,.13);color:var(--warn)}
        .p-bad{background:rgba(248,113,113,.13);color:var(--bad)}
        .d{font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:pre-wrap;
           padding:1px 8px;border-left:2px solid transparent;word-break:break-word}
        .d.add{background:rgba(74,222,128,.09);border-left-color:var(--ok)}
        .d.del{background:rgba(248,113,113,.09);border-left-color:var(--bad)}
        .d.ctx{color:var(--dim)}
        .hidden-char{background:var(--bad);color:#000;border-radius:3px;padding:0 3px;
                     font:600 11px ui-monospace,Menlo,monospace}
        code{background:#0d1117;border:1px solid var(--line);border-radius:5px;padding:2px 7px;
             font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--dim);
             display:inline-block;margin-top:8px;word-break:break-all}
        .empty{color:var(--faint);font-size:13px;padding:6px 0}
        .note{color:var(--faint);font-size:11.5px;margin-top:10px;line-height:1.6}
        button{font:600 12px system-ui;padding:6px 12px;border-radius:6px;cursor:pointer;
               background:var(--accent);color:#04121c;border:0;margin-right:6px}
        button:hover{filter:brightness(1.12)}
        button.danger{background:transparent;color:var(--bad);border:1px solid var(--bad)}
        button.link{background:none;border:0;color:var(--faint);padding:0;font-weight:400;
                    text-decoration:underline;font-size:12px}
        form.inline{display:inline-flex;align-items:center;gap:0;margin:0}
        input.who{background:#0d1117;border:1px solid var(--line);border-radius:6px;
                  color:var(--ink);padding:5px 8px;margin-right:6px;width:150px;
                  font:12px ui-monospace,Menlo,monospace}
        label.k{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--faint)}
        .bad{color:var(--bad)}
        .advice{margin-top:12px;padding:11px 13px;background:#0d1117;border:1px dashed var(--line);
                border-radius:8px}
        .advice-head{display:flex;align-items:center;gap:9px;margin-bottom:7px;flex-wrap:wrap}
        .warnlabel{font-size:10.5px;color:var(--warn);text-transform:uppercase;letter-spacing:.07em}
        .advice ul{margin:8px 0 0;padding-left:17px;color:var(--dim);font-size:12.5px}
        .advice li{margin:3px 0}
        """;
}
