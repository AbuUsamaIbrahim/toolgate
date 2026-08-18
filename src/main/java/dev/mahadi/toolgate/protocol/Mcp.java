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
    public static final String METHOD_RESOURCES_LIST = "resources/list";
    public static final String METHOD_RESOURCES_READ = "resources/read";
    public static final String METHOD_RESOURCE_TEMPLATES_LIST = "resources/templates/list";
    public static final String METHOD_PROMPTS_LIST = "prompts/list";
    public static final String METHOD_PROMPTS_GET = "prompts/get";

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

    /**
     * A resource a server offers as context.
     *
     * <p>Every field is model-visible or governs how the client treats the content, so all
     * of it is attacker-controlled when the server is compromised — the same position tool
     * definitions are in. Two fields are worse than they look:
     *
     * <ul>
     *   <li>{@code annotations.audience} and {@code annotations.priority} are not
     *       decoration. The specification defines priority 1.0 as "effectively required",
     *       and audience {@code ["assistant"]} as content meant for the model. Together
     *       they are a server-side control over what enters the model's context, asserted
     *       by the least trusted party in the system.</li>
     *   <li>{@code uri} decides who fetches the content. An {@code https://} URI is one the
     *       spec permits the client to fetch directly — so the bytes never traverse this
     *       gateway and nothing screens them.</li>
     * </ul>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Resource(
            String uri,
            String name,
            String title,
            String description,
            String mimeType,
            Long size,
            Map<String, Object> annotations,
            List<Map<String, Object>> icons) {}

    /** A parameterised resource, expanded by the client from an RFC 6570 template. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ResourceTemplate(
            String uriTemplate,
            String name,
            String title,
            String description,
            String mimeType,
            Map<String, Object> annotations,
            List<Map<String, Object>> icons) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ResourcesListResult(
            String resultType,
            List<Resource> resources,
            String nextCursor,
            Long ttlMs,
            String cacheScope) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ResourceTemplatesListResult(
            String resultType,
            List<ResourceTemplate> resourceTemplates,
            String nextCursor,
            Long ttlMs,
            String cacheScope) {}

    /** One piece of resource content: text, or base64 in {@code blob}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ResourceContents(
            String uri,
            String mimeType,
            String text,
            String blob,
            Map<String, Object> annotations) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ResourcesReadResult(
            String resultType,
            List<ResourceContents> contents,
            Long ttlMs,
            String cacheScope) {}

    /**
     * A prompt template.
     *
     * <p>The most direct injection surface in the protocol, and the one with the least
     * ceremony around it: a prompt <em>is</em> instructions, so a poisoned one needs no
     * cleverness to be obeyed. Tool descriptions have to persuade the model to act; a
     * prompt is already the thing the model was asked to follow.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Prompt(
            String name,
            String title,
            String description,
            List<Map<String, Object>> arguments,
            List<Map<String, Object>> icons) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PromptsListResult(
            String resultType,
            List<Prompt> prompts,
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
