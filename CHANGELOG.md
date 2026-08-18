# Changelog

Pre-1.0. Interfaces may change between minor versions, and nothing here has been reviewed
by anyone outside the project — see [SECURITY.md](SECURITY.md#status).

## 0.1.0 — 2026-08-18

First tagged release. Governs every surface MCP revision `2026-07-28` exposes, over both
standard transports, in both directions.

### Tools
- Deny-by-default allowlist, evaluated at `tools/list` so a poisoned definition never
  enters the model's context.
- Trust-on-first-use fingerprint pinning; drift is refused and never auto-heals.
- Injection scanning of metadata and of tool output, scored rather than absolute.
- `x-mcp-header` confined to the reserved `Mcp-Param-` namespace.
- Human approval for destructive tools; grants are single-use and expire.

### Resources, templates and prompts
- Allowlisting by exact URI or prefix; scheme confinement, with `https` excluded by
  default because such content is fetched by the client and never traverses the gateway.
- Annotation clamping, so an unreviewed resource cannot declare itself required.
- Templates checked for containment before advertisement, since the client expands them.
- Reads routed only to the upstream that advertised the URI.
- Definitions pinned, so escalation after approval is caught as drift.

### Subscriptions and notifications
- One client subscription fans out across upstreams; subscription ids are rewritten, never
  relayed, and resolution is keyed on the sender as well as the id.
- The client's notification filter is enforced against the server.
- Rate limiting per server and per kind; graceful closure when the last upstream ends.

### Elicitation
- Form mode refused when it asks for credentials, contains a URL, or nests its schema.
- URL mode restricted to allowlisted hosts, https, no punycode, no pre-authenticated URLs.

### Identity, policy and operations
- OIDC bearer tokens with JWKS, audience checking, and no algorithm confusion; static
  tokens retained for non-human callers.
- Ed25519-signed policy bundles distributed without a server, with rollback protection and
  a staleness deadline; team-scoped policy from the IdP's group claim.
- Durable pins, audit trail and approval queue; grants deliberately not persisted.
- Control plane for fleet coverage; Prometheus metrics and OTLP export.
- Origin validation and header/body agreement on the HTTP binding.

### Measured
- `tools/call` adds 4.0ms at p50; `tools/list` over 50 tools adds 14.1ms. Screening is
  sub-linear: ~6.4ms fixed plus ~0.066ms per tool. See `demo/load`.

### Fixed after concurrency testing
- A subscription whose upstreams closed simultaneously would never signal closure, leaving
  the client waiting on a stream nobody served.
- Two approvers clicking at the same moment both came back granted, so the audit trail
  named two people as having approved one request.
- Two threads could each record a first sighting of the same definition.

### Also fixed
- `/actuator/health/liveness` and `/readiness` returned 404 outside Kubernetes, because
  Spring Boot enables those groups only on auto-detecting a cluster. Any health check
  pointed at them under systemd, docker compose or ECS would have failed permanently.

### Known limitations
See [Honest limitations](README.md#honest-limitations). The significant ones: binary
resource content is not scanned, coverage is reported rather than enforced, revocation lags
token expiry, and performance is unmeasured.
