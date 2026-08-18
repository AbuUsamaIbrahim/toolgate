package dev.mahadi.toolgate.policy;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks {@code elicitation/create} requests, where a server asks a <em>human</em> a
 * question through the client's own interface.
 *
 * <h2>Why this is the worst surface in the protocol</h2>
 * Everywhere else, a compromised server is trying to fool a model. Here it is trying to
 * fool a person, using the client's trusted UI to do it. The user sees a dialog from
 * software they installed, not from the server that composed it, and the request arrives
 * mid-task when they are inclined to get past it.
 *
 * <p>The specification is unusually direct about the danger and unusually powerless about
 * it. Almost every rule is a <b>MUST</b> aimed at servers:
 *
 * <ul>
 *   <li>Servers <b>MUST NOT</b> use form mode to request passwords, API keys, access
 *       tokens or payment credentials.</li>
 *   <li>Servers <b>MUST NOT</b> put sensitive information about the user in a URL-mode URL,
 *       or supply a URL pre-authenticated to a protected resource.</li>
 *   <li>Servers <b>SHOULD NOT</b> include clickable URLs anywhere in a form-mode request.</li>
 * </ul>
 *
 * <p>Every one of those is addressed to the party you are defending against. That is the
 * gap this whole project exists in, and here it is at its widest — because the thing being
 * protected is a person's credential rather than a model's context.
 */
public final class ElicitationGuard {

    /**
     * Terms whose presence means a form is asking for a secret.
     *
     * <p>Deliberately short and specific. A generous list catches "pin" in "pinned" and
     * "token" in "tokenise", and a control that refuses honest servers is a control that
     * gets switched off. Each entry here names something the spec explicitly forbids
     * requesting in form mode.
     */
    private static final List<Pattern> CREDENTIAL_TERMS = List.of(
            Pattern.compile("\\bpasswords?\\b"),
            Pattern.compile("\\bpasswd\\b"),
            Pattern.compile("\\bpassphrase\\b"),
            Pattern.compile("\\bapi[\\s_-]?keys?\\b"),
            Pattern.compile("\\bsecret[\\s_-]?(key|access)\\b"),
            Pattern.compile("\\baccess[\\s_-]?tokens?\\b"),
            Pattern.compile("\\bbearer[\\s_-]?tokens?\\b"),
            Pattern.compile("\\brefresh[\\s_-]?tokens?\\b"),
            Pattern.compile("\\bprivate[\\s_-]?key\\b"),
            Pattern.compile("\\bssh[\\s_-]?key\\b"),
            Pattern.compile("\\bseed[\\s_-]?phrase\\b"),
            Pattern.compile("\\bmnemonic\\b"),
            Pattern.compile("\\bcredit[\\s_-]?card\\b"),
            Pattern.compile("\\bcard[\\s_-]?numbers?\\b"),
            Pattern.compile("\\bcvv\\b|\\bcvc\\b"),
            Pattern.compile("\\bsort[\\s_-]?code\\b"),
            Pattern.compile("\\bcredentials?\\b"));

    private static final Pattern URL_IN_TEXT =
            Pattern.compile("\\bhttps?://[\\w.-]+", Pattern.CASE_INSENSITIVE);

    /** Query parameters that carry something already authenticating. */
    private static final Set<String> PREAUTH_PARAMS = Set.of(
            "token", "access_token", "id_token", "auth", "authorization", "apikey",
            "api_key", "key", "secret", "password", "sig", "signature", "session",
            "sessionid", "jwt");

    private ElicitationGuard() {}

    public record Verdict(boolean allowed, String reason, List<String> evidence) {
        static Verdict ok() { return new Verdict(true, "acceptable", List.of()); }
        static Verdict refuse(String reason, List<String> evidence) {
            return new Verdict(false, reason, List.copyOf(evidence));
        }
    }

    /**
     * Checks a form-mode elicitation.
     *
     * <p>Every string a human will read is examined — the message, and each property's
     * name, title and description — because the field asking for the secret may be
     * innocuously named and explained in its description, or the reverse.
     */
    @SuppressWarnings("unchecked")
    public static Verdict checkForm(String message, Map<String, Object> requestedSchema) {
        List<String> evidence = new ArrayList<>();

        List<String> humanText = new ArrayList<>();
        if (message != null) humanText.add(message);

        Object properties = requestedSchema == null ? null : requestedSchema.get("properties");
        if (properties instanceof Map<?, ?> props) {
            for (Map.Entry<?, ?> entry : props.entrySet()) {
                humanText.add(String.valueOf(entry.getKey()));
                if (entry.getValue() instanceof Map<?, ?> field) {
                    for (String key : List.of("title", "description")) {
                        Object v = field.get(key);
                        if (v != null) humanText.add(String.valueOf(v));
                    }
                    // Flat primitives only, per the spec. A nested object is both
                    // out of spec and a way to hide a field from a client that only
                    // renders the top level.
                    Object type = field.get("type");
                    if ("object".equals(type)) {
                        return Verdict.refuse(
                                "form schema contains a nested object, which the specification "
                                        + "does not permit and a client may not render",
                                List.of("field=" + entry.getKey()));
                    }
                }
            }
        }

        for (String text : humanText) {
            String lower = text.toLowerCase(Locale.ROOT);
            for (Pattern term : CREDENTIAL_TERMS) {
                if (term.matcher(lower).find()) {
                    return Verdict.refuse(
                            "form-mode elicitation is asking for a credential, which the "
                                    + "specification forbids — sensitive input must go through "
                                    + "URL mode so it never passes through the client",
                            List.of("matched=" + term.pattern(),
                                    "in=" + abbreviate(text)));
                }
            }
            // A clickable link inside a form is a phishing vector wearing the client's UI.
            if (URL_IN_TEXT.matcher(text).find()) {
                evidence.add("url in form text: " + abbreviate(text));
            }
        }

        if (!evidence.isEmpty()) {
            return Verdict.refuse(
                    "form-mode elicitation contains a URL, which the specification says it "
                            + "should not — a link inside a trusted dialog is a phishing vector",
                    evidence);
        }
        return Verdict.ok();
    }

    /**
     * Checks a URL-mode elicitation.
     *
     * @param allowedHosts hosts an operator has accepted for this server; empty means none,
     *                     because a gateway that lets any server send a user anywhere is
     *                     not adding anything to the situation
     */
    public static Verdict checkUrl(String url, Set<String> allowedHosts) {
        if (url == null || url.isBlank()) {
            return Verdict.refuse("URL-mode elicitation with no URL", List.of());
        }

        URI uri;
        try {
            uri = URI.create(url.trim());
        } catch (IllegalArgumentException e) {
            return Verdict.refuse("URL-mode elicitation with an unparseable URL",
                    List.of("url=" + abbreviate(url)));
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);

        if (!"https".equals(scheme) && !isLoopback(host)) {
            return Verdict.refuse(
                    "URL-mode elicitation must use https — the user is about to type "
                            + "something sensitive into whatever this opens",
                    List.of("url=" + abbreviate(url)));
        }

        // user:password@host. Rare, deprecated, and overwhelmingly used to make a URL
        // read as one host while resolving to another.
        if (uri.getUserInfo() != null) {
            return Verdict.refuse("URL contains embedded credentials in its userinfo",
                    List.of("url=" + abbreviate(url)));
        }

        // Punycode. Renders as a familiar name and resolves somewhere else entirely; the
        // spec asks clients to warn, which is weaker than not showing it at all.
        if (host.contains("xn--")) {
            return Verdict.refuse(
                    "URL host uses punycode, which can render as a lookalike domain",
                    List.of("host=" + host));
        }

        String query = uri.getQuery() == null ? "" : uri.getQuery().toLowerCase(Locale.ROOT);
        for (String param : PREAUTH_PARAMS) {
            if (query.matches(".*\\b" + Pattern.quote(param) + "=.+")) {
                return Verdict.refuse(
                        "URL appears to be pre-authenticated, which the specification "
                                + "forbids — such a URL can be replayed to impersonate the user",
                        List.of("param=" + param));
            }
        }

        if (allowedHosts.isEmpty()) {
            return Verdict.refuse(
                    "no elicitation hosts are configured for this server, so it may not "
                            + "send the user anywhere",
                    List.of("host=" + host));
        }
        if (!allowedHosts.contains(host)) {
            return Verdict.refuse(
                    "URL host is not on this server's elicitation allowlist",
                    List.of("host=" + host, "allowed=" + allowedHosts));
        }
        return Verdict.ok();
    }

    private static boolean isLoopback(String host) {
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "[::1]".equals(host);
    }

    private static String abbreviate(String s) {
        return s.length() <= 140 ? s : s.substring(0, 140) + "…";
    }
}
