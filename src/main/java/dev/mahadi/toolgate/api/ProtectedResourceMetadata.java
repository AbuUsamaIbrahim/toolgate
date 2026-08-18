package dev.mahadi.toolgate.api;

import dev.mahadi.toolgate.auth.AuthProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728).
 *
 * <p>The MCP specification makes this a MUST for servers: it is how a client discovers
 * which authorization server to obtain a token from after receiving a 401. Serving it is
 * what makes the 401 actionable rather than merely correct.
 */
@RestController
public class ProtectedResourceMetadata {

    private final AuthProperties props;

    public ProtectedResourceMetadata(AuthProperties props) {
        this.props = props;
    }

    @GetMapping("/.well-known/oauth-protected-resource")
    public Map<String, Object> metadata() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", props.getResourceUri());
        if (!props.getAuthorizationServer().isBlank()) {
            doc.put("authorization_servers", List.of(props.getAuthorizationServer()));
        }
        // The minimal set needed for basic functionality; anything beyond this is
        // requested incrementally through step-up authorization.
        doc.put("scopes_supported", List.of("tools:read", "tools:call"));
        doc.put("bearer_methods_supported", List.of("header"));
        return doc;
    }
}
