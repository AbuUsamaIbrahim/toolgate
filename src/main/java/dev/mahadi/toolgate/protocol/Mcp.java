package dev.mahadi.toolgate.protocol;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

/**
 * Wire types for Model Context Protocol revision {@code 2026-07-28}.
 *
 * <p>Only the subset the gateway needs to reason about is modelled. Everything else is
 * forwarded verbatim, because a security proxy that silently drops fields it does not
 * understand is a security proxy that breaks the protocol as new revisions land.
 */
public final class Mcp {

    /** Protocol revision this gateway is written against. */
    public static final String PROTOCOL_VERSION = "2026-07-28";

    /** Required {@code _meta} key carrying the per-request protocol version. */
    public static final String META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";

    public static final String METHOD_DISCOVER = "server/discover";
    public static final String METHOD_TOOLS_LIST = "tools/list";
    public static final String METHOD_TOOLS_CALL = "tools/call";

    private Mcp() {}

    /** A JSON-RPC 2.0 request. {@code id} is absent for notifications. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Request(
            String jsonrpc,
            Object id,
            String method,
            Map<String, Object> params,
            Map<String, Object> _meta) {

        public boolean isNotification() {
            return id == null;
        }

        /** Tool name from a {@code tools/call}, or null if absent or malformed. */
        public String toolName() {
            if (params == null) return null;
            return params.get("name") instanceof String s ? s : null;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> arguments() {
            if (params == null) return Map.of();
            return params.get("arguments") instanceof Map<?, ?> m
                    ? (Map<String, Object>) m
                    : Map.of();
        }
    }

    /** A JSON-RPC 2.0 response. Exactly one of {@code result} / {@code error} is set. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Response(String jsonrpc, Object id, Object result, Error error) {

        public static Response ok(Object id, Object result) {
            return new Response("2.0", id, result, null);
        }

        public static Response error(Object id, int code, String message, Object data) {
            return new Response("2.0", id, null, new Error(code, message, data));
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Error(int code, String message, Object data) {}

    /**
     * A tool as advertised by an upstream server.
     *
     * <p>Every field here is attacker-controlled if the upstream server is compromised.
     * The spec is explicit: clients <em>MUST</em> consider annotations untrusted unless
     * they come from a trusted server — but offers no mechanism to establish that trust.
     * That mechanism is what this gateway supplies.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Tool(
            String name,
            String title,
            String description,
            Map<String, Object> inputSchema,
            Map<String, Object> outputSchema,
            Map<String, Object> annotations,
            List<Map<String, Object>> icons) {}

    /** Result of {@code tools/list}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ToolsListResult(
            String resultType,
            List<Tool> tools,
            String nextCursor,
            Long ttlMs,
            String cacheScope) {}

    /** JSON-RPC error codes used by the gateway. */
    public static final class Codes {
        /** Standard JSON-RPC: the method exists but the params are wrong. */
        public static final int INVALID_PARAMS = -32602;
        /** Standard JSON-RPC: internal error. */
        public static final int INTERNAL_ERROR = -32603;
        /** Gateway-specific: the call was refused by policy. */
        public static final int POLICY_DENIED = -32000;
        /** Gateway-specific: awaiting human approval. */
        public static final int APPROVAL_REQUIRED = -32001;

        private Codes() {}
    }
}
