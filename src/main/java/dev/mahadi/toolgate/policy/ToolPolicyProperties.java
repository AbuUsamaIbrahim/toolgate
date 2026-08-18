package dev.mahadi.toolgate.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Gateway policy, expressed as configuration rather than code.
 *
 * <p>Security posture belongs in a file an auditor can read and a reviewer can diff. The
 * question "which tools can this agent reach, and which need a human?" should have one
 * answer in one place — not require tracing conditionals through a filter chain.
 */
@Component
@ConfigurationProperties(prefix = "toolgate")
public class ToolPolicyProperties {

    /** Upstream servers, keyed by the identifier used to disambiguate tool names. */
    private Map<String, Server> servers = new LinkedHashMap<>();

    /**
     * Scanner score at or above which a tool is denied outright rather than escalated
     * to a human. Default 50 means a single hidden-unicode finding blocks, while a lone
     * lower-weight signal asks a person.
     */
    private int blockThreshold = 50;

    /** Require approval the first time a tool definition is seen. Off by default. */
    private boolean approveFirstSighting = false;

    public static class Server {
        /** Base URL, for an upstream reached over Streamable HTTP. */
        private String url;
        /**
         * Command and arguments, for an upstream launched as a stdio subprocess.
         * Mutually exclusive with {@link #url}.
         */
        private java.util.List<String> command;
        /** Extra environment for a stdio upstream — typically its own API credentials. */
        private Map<String, String> env = new LinkedHashMap<>();
        /** Tools this agent may see. Empty means none — the gateway denies by default. */
        private Set<String> allow = Set.of();
        /** Subset of {@link #allow} that additionally requires human approval to call. */
        private Set<String> requireApproval = Set.of();
        /**
         * Resource URIs this agent may see. Exact, or a prefix ending in {@code *}.
         *
         * <p>Prefixes rather than regular expressions on purpose: {@code file:///project/*}
         * is a rule a reviewer can evaluate at a glance, and the failure mode of a
         * mis-written prefix is that too little is allowed. A mis-written regex fails the
         * other way, and nobody notices.
         */
        private Set<String> allowResources = Set.of();
        /** Prompt names this agent may see. */
        private Set<String> allowPrompts = Set.of();
        /**
         * URI schemes permitted on resources from this server.
         *
         * <p>{@code https} is absent by default: the spec lets clients fetch those
         * directly, so the content would never pass through this gateway.
         */
        private Set<String> allowedUriSchemes = Set.of("file", "git");
        /**
         * The gateway's own credential for this upstream, if it requires one. Never the
         * caller's token — see {@code UpstreamClient} for why that distinction matters.
         */
        private String token;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public java.util.List<String> getCommand() { return command; }
        public void setCommand(java.util.List<String> command) { this.command = command; }
        public Map<String, String> getEnv() { return env; }
        public void setEnv(Map<String, String> env) { this.env = env; }
        public Set<String> getAllow() { return allow; }
        public void setAllow(Set<String> allow) { this.allow = allow; }
        public Set<String> getRequireApproval() { return requireApproval; }
        public void setRequireApproval(Set<String> requireApproval) { this.requireApproval = requireApproval; }
        public Set<String> getAllowResources() { return allowResources; }
        public void setAllowResources(Set<String> allowResources) { this.allowResources = allowResources; }
        public Set<String> getAllowPrompts() { return allowPrompts; }
        public void setAllowPrompts(Set<String> allowPrompts) { this.allowPrompts = allowPrompts; }
        public Set<String> getAllowedUriSchemes() { return allowedUriSchemes; }
        public void setAllowedUriSchemes(Set<String> allowedUriSchemes) { this.allowedUriSchemes = allowedUriSchemes; }
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    /**
     * Deny by default: an unknown server or an unlisted tool is refused. A gateway that
     * fails open is decoration.
     */
    public boolean isAllowed(String serverId, String toolName) {
        Server server = servers.get(serverId);
        if (server == null || toolName == null) return false;
        return server.getAllow().contains(toolName);
    }

    /**
     * Exact match, or a prefix when the rule ends in {@code *}.
     *
     * <p>Deliberately not a glob or a regex. A resource allowlist is a security control an
     * auditor reads, and the two-rule version can be understood without running it.
     */
    public static boolean matches(Set<String> rules, String value) {
        if (value == null) return false;
        for (String rule : rules) {
            if (rule.endsWith("*")) {
                if (value.startsWith(rule.substring(0, rule.length() - 1))) return true;
            } else if (rule.equals(value)) {
                return true;
            }
        }
        return false;
    }

    public boolean isResourceAllowed(String serverId, String uri) {
        Server server = servers.get(serverId);
        return server != null && matches(server.getAllowResources(), uri);
    }

    public boolean isPromptAllowed(String serverId, String name) {
        Server server = servers.get(serverId);
        return server != null && server.getAllowPrompts().contains(name);
    }

    public Set<String> allowedUriSchemes(String serverId) {
        Server server = servers.get(serverId);
        return server == null ? Set.of() : server.getAllowedUriSchemes();
    }

    public boolean requiresApproval(String serverId, String toolName) {
        Server server = servers.get(serverId);
        return server != null && server.getRequireApproval().contains(toolName);
    }

    public List<String> serverIds() {
        return List.copyOf(servers.keySet());
    }

    public Server server(String serverId) {
        return servers.get(serverId);
    }

    public Map<String, Server> getServers() { return servers; }
    public void setServers(Map<String, Server> servers) { this.servers = servers; }
    public int getBlockThreshold() { return blockThreshold; }
    public void setBlockThreshold(int blockThreshold) { this.blockThreshold = blockThreshold; }
    public boolean isApproveFirstSighting() { return approveFirstSighting; }
    public void setApproveFirstSighting(boolean approveFirstSighting) { this.approveFirstSighting = approveFirstSighting; }
}
