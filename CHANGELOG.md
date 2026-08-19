# Changelog

Pre-1.0. Interfaces may change between minor versions, and nothing here has been reviewed
by anyone outside the project — see [SECURITY.md](SECURITY.md#status).

## Unreleased

### Fixed — no MCP client could connect

- **`initialize` was not handled, over either transport.** The gateway answered
  `server/discover` and refused everything else, so the first message any real client sends
  came back as `-32602 method not proxied: initialize`. Both transports share one method
  switch, so stdio — the path the README recommends for desktop clients — was equally
  unreachable. Found by pointing Claude Code at a running gateway; 434 tests passed
  throughout, because the suite and the demo script both post `tools/list` straight in and
  never perform a handshake. This is the same defect class as the interop fix in 0.1.0, one
  layer out: there, the gateway was the client that skipped what real clients do; here, so
  were its own tests.
- **The negotiated protocol version was then rejected on every subsequent request.** The
  `MCP-Protocol-Version` header was compared against the single revision the gateway is
  written against, so a session could be agreed at one revision and refused at every
  request made under it. The handshake now negotiates — echoing the client's revision when
  it is servable, otherwise naming its own and leaving the choice to the client, which is
  the party that knows what it can accept. `Mcp.SUPPORTED_PROTOCOL_VERSIONS` lists only
  revisions verified against a live client speaking them.
- **Notifications received a reply over HTTP.** `notifications/initialized` — sent
  immediately after a successful handshake — fell through to the method switch and returned
  an error object carrying a null id, which cannot be correlated and must not be sent. HTTP
  now answers `202` with no body, as stdio already did.

### Changed
- **The default port is 8090, not 8080.** 8080 is the default for enough developer tooling
  that a collision is the norm, and under a VM-based Docker runtime it does not fail
  loudly: the published port is swallowed by whatever already holds it and the gateway
  appears to answer with someone else's errors. Anyone running on the old default must move
  their clients and `toolgate.auth.resource-uri` together, since that URI is the token
  audience.
- `serverInfo.version` is defined once rather than in two payloads, where it had drifted a
  minor release behind the jar.

### Added
- A copy-paste Claude Code / Cursor configuration in the README, verified against a running
  gateway rather than written from the specification.

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

### Added
- An optional drift advisor: an assistant note beside each diff, off by default, advisory
  only — no credential, no action endpoint, and no store it could mutate.
- An operator dashboard at `/toolgate`, behind the same credential as the rest of the
  operator API. Read-only; renders the drift diff, the approval queue and recent refusals.

### Also fixed
- **`/slack/interactions` returned 415 to every real request.** WebFlux's form reader claims
  `application/x-www-form-urlencoded` and decodes to a `MultiValueMap`, so the `byte[]`
  parameter was rejected before the method was entered. Every unit test passed because they
  called the controller directly and never crossed the HTTP layer. The body is now read from
  the exchange, which is also the only way to be sure the bytes verified are the bytes
  parsed.
- The operator auth filter guarded `/toolgate/` but not `/toolgate`, so the dashboard was
  reachable without a credential. Both forms are now covered.
- `/actuator/health/liveness` and `/readiness` returned 404 outside Kubernetes, because
  Spring Boot enables those groups only on auto-detecting a cluster. Any health check
  pointed at them under systemd, docker compose or ECS would have failed permanently.

### Known limitations
See [Honest limitations](README.md#honest-limitations). The significant ones: binary
resource content is not scanned, coverage is reported rather than enforced, revocation lags
token expiry, and performance is unmeasured.
