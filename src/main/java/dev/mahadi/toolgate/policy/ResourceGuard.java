package dev.mahadi.toolgate.policy;

import dev.mahadi.toolgate.protocol.Mcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Controls that exist only for resources, because resources can do two things tools cannot.
 *
 * <h2>1. A resource URI decides who fetches the content</h2>
 * The specification permits a client to fetch an {@code https://} resource directly from
 * the web rather than reading it through the server. Read that from the gateway's side:
 * a compromised upstream can hand the client a URL, the client fetches it, and the bytes
 * enter the model's context <em>without ever traversing this gateway</em>. Nothing is
 * screened, nothing is audited, nothing is pinned. It is also a request the client makes
 * to an attacker-chosen host, which is a server-side request forgery with the agent as the
 * confused deputy.
 *
 * <p>So schemes are allowlisted, and {@code https} is not on the default list. That is a
 * real restriction on legitimate servers, and it is the right default: the alternative is a
 * gateway that can be trivially routed around by any server that would like to be.
 *
 * <h2>2. Annotations are a context-inclusion control the server holds</h2>
 * {@code audience} and {@code priority} look like display hints. They are not. The spec
 * defines priority 1.0 as "effectively required" and audience {@code ["assistant"]} as
 * content intended for the model, and clients are told they may use these to decide
 * <em>what to put in the context window</em>. That makes them an instruction from the least
 * trusted party in the system about how much of the model's attention it gets.
 *
 * <p>They are therefore clamped rather than refused. Refusing outright would break ordinary
 * servers that annotate sensibly; leaving them alone lets a hostile server mark its
 * payload mandatory. Clamping keeps the hint and removes the ability to demand.
 */
public final class ResourceGuard {

    /**
     * Ceiling for {@code priority} on any resource that has not been centrally reviewed.
     *
     * <p>0.5 is deliberately mid-scale: high enough that a genuinely useful resource is
     * still preferred over an indifferent one, low enough that nothing unreviewed can
     * describe itself as required.
     */
    public static final double UNREVIEWED_PRIORITY_CEILING = 0.5;

    private ResourceGuard() {}

    public record Verdict(boolean allowed, String reason, List<String> evidence) {
        static Verdict ok() { return new Verdict(true, "acceptable", List.of()); }
        static Verdict refuse(String reason, List<String> evidence) {
            return new Verdict(false, reason, evidence);
        }
    }

    /**
     * Checks a resource URI against the schemes an operator permits.
     *
     * @param allowedSchemes lower-case scheme names, without the colon
     */
    public static Verdict checkUri(String uri, Set<String> allowedSchemes) {
        if (uri == null || uri.isBlank()) {
            return Verdict.refuse("resource has no URI", List.of());
        }

        int colon = uri.indexOf(':');
        if (colon <= 0) {
            return Verdict.refuse("resource URI has no scheme", List.of("uri=" + abbreviate(uri)));
        }
        String scheme = uri.substring(0, colon).toLowerCase(Locale.ROOT);

        if (!allowedSchemes.contains(scheme)) {
            String why = "https".equals(scheme) || "http".equals(scheme)
                    ? "an http(s) resource is fetched by the client directly, so its content "
                      + "never passes through this gateway"
                    : "scheme is not on the allowed list";
            return Verdict.refuse(
                    "resource URI scheme '%s' is not permitted — %s".formatted(scheme, why),
                    List.of("uri=" + abbreviate(uri)));
        }

        // A file:// resource that climbs out of wherever it claims to be. The spec puts
        // this obligation on servers, which is exactly why a client-side gateway checks it.
        if ("file".equals(scheme) && (uri.contains("..") || uri.contains("%2e%2e")
                || uri.toLowerCase(Locale.ROOT).contains("%2E%2E".toLowerCase(Locale.ROOT)))) {
            return Verdict.refuse("file resource URI contains a traversal sequence",
                    List.of("uri=" + abbreviate(uri)));
        }
        return Verdict.ok();
    }

    /**
     * Returns the resource with its annotations clamped, or the same instance if nothing
     * needed changing.
     *
     * @param reviewed whether a human has approved this exact definition centrally
     */
    public static Mcp.Resource clampAnnotations(Mcp.Resource resource, boolean reviewed) {
        if (reviewed || resource.annotations() == null || resource.annotations().isEmpty()) {
            return resource;
        }
        Map<String, Object> clamped = clamp(resource.annotations());
        return clamped == null ? resource : new Mcp.Resource(
                resource.uri(), resource.name(), resource.title(), resource.description(),
                resource.mimeType(), resource.size(), clamped, resource.icons());
    }

    /** @return a clamped copy, or null when the original was already acceptable */
    private static Map<String, Object> clamp(Map<String, Object> annotations) {
        Object priority = annotations.get("priority");
        if (!(priority instanceof Number n) || n.doubleValue() <= UNREVIEWED_PRIORITY_CEILING) {
            return null;
        }
        Map<String, Object> copy = new LinkedHashMap<>(annotations);
        copy.put("priority", UNREVIEWED_PRIORITY_CEILING);
        return copy;
    }

    /** Describes what a clamp changed, for the audit trail. */
    public static List<String> clampEvidence(Mcp.Resource before, Mcp.Resource after) {
        if (before == after) return List.of();
        List<String> evidence = new ArrayList<>();
        Object was = before.annotations() == null ? null : before.annotations().get("priority");
        if (was != null) {
            evidence.add("priority %s -> %s".formatted(was, UNREVIEWED_PRIORITY_CEILING));
        }
        return evidence;
    }

    private static String abbreviate(String s) {
        return s.length() <= 120 ? s : s.substring(0, 120) + "…";
    }
}
