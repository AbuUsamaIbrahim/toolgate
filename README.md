# toolgate

A security gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers.

An AI agent points at toolgate instead of at its MCP servers. Toolgate decides which tools
the agent is allowed to see, verifies that those tools have not changed since they were
approved, scans their metadata and their output for injected instructions, and writes down
every decision it made.

Written against MCP revision **2026-07-28**. Java 21, Spring Boot, WebFlux.

---

## Why

The MCP specification is unusually direct about the risk:

> Clients **MUST** consider tool annotations to be untrusted unless they come from trusted
> servers.

and, in the same document:

> While MCP itself **cannot enforce these security principles at the protocol level**,
> implementors **SHOULD** \[…\] implement appropriate access controls.

So the spec names the threat and then, correctly, admits it has no mechanism for it. In
2026 that gap stopped being theoretical: researchers disclosed a systemic MCP vulnerability
affecting an estimated 200,000 instances, and hijacked several mainstream coding agents by
planting instructions in places those agents treated as trusted context.

The attack does not require code execution. A tool's `description` is read by the model as
operational instruction. Change the description and you change the agent's behaviour, with
nothing in the protocol to notice.

Toolgate is the missing mechanism.

## What it does

| Control | Problem it addresses |
|---|---|
| **Allowlist** | An upstream advertising tools nobody authorised. Deny by default. |
| **Fingerprint pinning** | A tool definition mutating *after* it was approved. |
| **Injection scanning** | A definition that is hostile the first time it is seen. |
| **Result scanning** | Instructions injected into tool *output* rather than metadata. |
| **Human approval** | Destructive operations proceeding without a person in the loop. |
| **Audit log** | "What did the gateway decide, and on what evidence?" |
| **Namespacing** | Tool-name collisions across servers, which the spec warns proxies must handle. |

### Where the filtering happens

Policy is applied at `tools/list`, not only at `tools/call`.

This is the central design decision. If a poisoned description reaches the model and is
only blocked when that specific tool is invoked, the defence has already failed — the model
read the injected instructions when the tool list entered its context, and may now be
acting on them through some entirely different tool. Denied tools are removed before the
model ever sees them.

Call-time checks still run, because a client may invoke a tool it was never offered, and a
gateway that assumes otherwise is trusting the caller to enforce its own restrictions.

## Honest limitations

Worth stating plainly, because a security tool that oversells itself is worse than none:

- **Trust on first use.** Pinning detects *change*, not *goodness*. A server already
  compromised at first sighting becomes the trusted baseline. Seed pins from a reviewed
  manifest where that matters.
- **Pattern matching loses on its own.** The injection scanner catches the unsophisticated
  majority. An attacker who knows the rules can phrase around them. It scores rather than
  blocks, and exists as defence in depth — not as an oracle.
- **In-memory state.** Pins, approvals and the audit log do not survive a restart. Fine for
  a reference implementation; production needs a durable, append-only sink the gateway
  itself cannot rewrite.
- **No authentication of callers yet.** `X-Toolgate-Caller` is asserted, not proved.

## Running

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) mvn spring-boot:run
```

Configure upstreams in `application.yml`:

```yaml
toolgate:
  block-threshold: 50          # scanner score at which a tool is denied outright
  approve-first-sighting: false
  servers:
    files:                     # server ids must not contain underscores
      url: http://localhost:9001
      allow:                   # anything absent from this list is never advertised
        - read_file
        - write_file
      require-approval:        # allowlisted, but a human must say yes per call
        - write_file
```

Point your agent at `POST /mcp`. Tools arrive namespaced as `files__read_file`.

### Operator API

| Endpoint | Purpose |
|---|---|
| `GET /toolgate/audit` | Every decision, most recent first |
| `GET /toolgate/pins` | Current fingerprints and when they were pinned |
| `GET /toolgate/approvals` | Outstanding approval requests |
| `POST /toolgate/approvals/{id}/approve` | Grant a single-use approval |
| `POST /toolgate/approvals/{id}/deny` | Refuse it |

Operator routes are deliberately separate from `/mcp`: anything that can change policy must
not be reachable through the door the agent uses.

## Tests

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 21) mvn test
```

The suite is adversarial. `MaliciousUpstream` is a real HTTP MCP server that turns hostile
on command — not a mocked client, because the bugs live in the transport and the wiring,
not in the parts a mock would replace.

It covers: description rewritten after approval, poisoned on first sighting, instructions
buried in a nested schema field, zero-width-unicode smuggling, an unlisted tool appearing
in `tools/list`, a call to a tool that was never advertised, destructive-tool approval,
poisoned tool *output*, protocol-version rejection, and fingerprint canonicalisation
(key reordering must not alter the hash; `"1"` and `1` must not collide).

## Licence

MIT.
