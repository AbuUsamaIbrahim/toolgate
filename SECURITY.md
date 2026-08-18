# Security policy

## Reporting a vulnerability

Report privately through [GitHub's security advisory
form](https://github.com/AbuUsamaIbrahim/toolgate/security/advisories/new) rather than by
opening an issue. Please do not disclose publicly until there has been a chance to respond.

Useful things to include: the protocol revision, which surface is involved (tools,
resources, prompts, subscriptions, elicitation), and a minimal server that reproduces it —
the repository already contains several under `demo/` that can be adapted.

## What counts as a vulnerability here

This is a security gateway, so the interesting bugs are ones where **something reaches the
model, the user, or an upstream that policy should have stopped**. For example:

- Metadata or content reaching the model's context that the allowlist, pinning, scanner or
  header confinement should have refused.
- A resource read, prompt fetch or tool call the gateway had no record of advertising.
- A notification delivered into the wrong subscription, or carrying an upstream's
  subscription id.
- An elicitation reaching a user that the credential or URL rules should have refused.
- Any path that leaks the caller's bearer token to an upstream. The gateway is built so
  that passthrough is unrepresentable rather than merely discouraged; a way around that is
  a serious finding.

## What does not

The [Honest limitations](README.md#honest-limitations) section documents the things this
deliberately does not do, and reports of those are not vulnerabilities — though arguments
that a limitation is worse than stated are welcome as issues.

The most commonly mistaken one: **the injection scanner is not an oracle.** It scores
rather than decides, and is documented as defence in depth behind the allowlist and the
pins. Finding a phrasing it does not catch is expected. Finding a phrasing that defeats the
*allowlist* or the *fingerprint* is not.

## Status

Pre-1.0 and **not independently reviewed**. The threat model, the controls and the tests
that verify them were all written by the same person, which is a closed loop. Treat it
accordingly: it is worth running, and it is not worth assuming.
