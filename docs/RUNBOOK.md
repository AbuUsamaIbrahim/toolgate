# Runbook

For whoever is on call. Every symptom below is one this gateway actually produces; every
metric and string was checked against a live scrape rather than written from memory — which
is how the missing `probes.enabled` was found before anyone was paged for it.

The single most useful orientation: **this thing fails closed.** Almost every failure mode
ends in *the agent can do less than it should*, not *more*. That is deliberate, and it
means the usual pressure — "just switch it off to unblock the release" — is almost always
the wrong move and occasionally a catastrophic one. The exceptions are called out.

---

## First 60 seconds

```bash
curl -s localhost:8080/actuator/health | jq '.components.policy'
curl -s localhost:8080/actuator/prometheus | grep '^toolgate_'
tail -50 ~/.toolgate/audit.jsonl | jq -r 'select(.outcome!="ALLOWED")
  | "\(.at) \(.outcome) \(.serverId)/\(.tool) — \(.reason)"'
```

`toolgate_bundle_health` is the fastest single signal:

| value | meaning | action |
|---|---|---|
| `0` | no bundle configured; local YAML is policy | fine for one developer, wrong for a fleet |
| `1` | signed bundle in force | healthy |
| `2` | past expiry, inside the grace period | **investigate now** — publishing has stopped |
| `3` | past grace, or never loaded | **everything is being denied** |

Alert on `toolgate_bundle_health >= 2`. Two is the actionable one: three means users are
already blocked and you will hear about it anyway.

---

## "The agent suddenly can't see any tools"

**Check first:** `toolgate_bundle_health`.

If it is `3`, policy has gone stale past `stale-grace` and the gateway is refusing
everything. That is the designed behaviour — a gateway that cannot say what is permitted
must not guess. The fault is upstream of here: the bundle stopped being published, or this
machine lost access to it.

```bash
# what it last had, and how old
curl -s localhost:8080/actuator/health | jq '.components.policy.details'
# can this machine still reach the bundle at all?
curl -sI "$(grep -A1 'bundle:' /config/application.yml | grep source | awk '{print $2}')"
```

**Fix:** restore publishing, or extend `stale-grace` deliberately and temporarily. Do not
"fix" it by clearing `toolgate.bundle.required` — that silently reverts the fleet to
whatever YAML happens to be on each laptop, which is the failure the bundle exists to
prevent.

If health is `1`, it is not policy distribution. Look at the audit:

```bash
tail -200 ~/.toolgate/audit.jsonl | jq -r 'select(.action=="advertise")
  | "\(.outcome) \(.tool) — \(.reason)"' | sort | uniq -c | sort -rn
```

The `reason` tells you which control fired. `not_allowlisted` means policy genuinely does
not permit it. `drift` means something changed — see below.

---

## "A tool that worked yesterday is being refused"

Almost always drift: the definition changed after it was pinned.

```bash
curl -s localhost:8080/toolgate/drift.txt -H "Authorization: Bearer $OPERATOR_TOKEN"
```

That prints a field-level diff. **Read it before doing anything.** The gateway cannot tell
a legitimate release from a compromise, which is exactly why it asks a person — and you are
the person.

- The diff is a plausible product change → accept it:
  ```bash
  curl -sX POST localhost:8080/toolgate/drift/<server>/<tool>/accept \
    -H "Authorization: Bearer $OPERATOR_TOKEN"
  ```
- The diff adds instructions aimed at the model, references credentials or paths the tool
  has no business touching, or contains invisible characters (rendered as `⟨U+200B⟩`) →
  **this is the attack the gateway was installed to catch.** Do not accept. Escalate,
  and treat that upstream as compromised.

> **Never delete the pin file to clear drift.** Every tool becomes a first sighting and
> whatever the server is currently advertising — including the poisoned version — becomes
> the new trusted baseline. It looks like it fixed the problem because the alert stops.

---

## "Requests are being refused with 401 or 403"

| status | meaning | look at |
|---|---|---|
| 401 | token missing, expired, or not from the configured issuer | `toolgate_decisions_total{reason="auth_failed"}` |
| 403 with `insufficient_scope` | token is valid, scope is not | the caller's `scopes` claim |
| 403 with no JSON-RPC body | **Origin rejected** — a browser called this | `reason="origin not permitted"` in the audit |

That last one is worth pausing on. A 403 on an `Origin` the gateway does not recognise
means something in a browser called it. On a developer laptop that is a **DNS rebinding
attempt**, not a misconfiguration, unless someone is deliberately building a browser client.
Check the origin in the audit line before adding it to `allowed-origins`.

`-32020 HeaderMismatch` means the HTTP headers disagreed with the body. A non-conforming
client causes it; so does something rewriting requests in flight.

---

## "The gateway is in CrashLoopBackOff"

```bash
kubectl -n toolgate logs deploy/toolgate-control --previous | tail -40
kubectl -n toolgate describe pod -l app.kubernetes.io/name=toolgate-control | grep -A8 Events:
```

Read the **exit code** first:

- **137** — SIGKILL, almost always OOMKilled by the cgroup limit. Raise `limits.memory` or
  find what grew. Memory is not throttled; it is killed.
- **143** — SIGTERM. Something asked it to stop and it went. If this repeats, look for a
  failing **liveness** probe in the events.

Startup refuses, deliberately, in three cases. All three are the gateway declining to run
in a state where it would look healthy and enforce nothing:

| log line | meaning |
|---|---|
| `policy bundle is required but none could be loaded` | `required: true` and nothing loadable |
| `pin file … exists but could not be read; refusing to start with an empty trust store` | corrupt trust store — **inspect it, do not delete it** |
| `is writable by [GROUP_WRITE]` | someone else can write the pin file; `chmod 600` it |

> If a liveness probe is killing the pod, check it is pointing at `/actuator/health/liveness`
> and **not** `/actuator/health`. The latter reports DOWN when policy goes stale, which a
> restart cannot fix — producing an infinite loop that also destroys the in-memory fleet
> registry on every cycle.

---

## "The coverage report looks wrong"

```bash
curl -s localhost:8090/control/v1/fleet.txt -H "Authorization: Bearer $OPERATOR_TOKEN"
```

| status | meaning |
|---|---|
| `SILENT` | not heard from within `silent-after`. Machine off, asleep, or the gateway stopped |
| `DEGRADED` | reporting, but *its* policy is stale or failed — see the bundle section |
| `BEHIND` | running an older bundle than the one being published |
| `HEALTHY` | current |

**If two queries return different numbers, the control plane is running more than one
replica without a database.** Each pod holds a fraction of the check-ins. Either configure
`toolgate.control.database-url` or scale to one replica; the log says so at startup:

```
No database configured — fleet state is in memory. Run exactly one replica…
```

Remember what this report can and cannot say: it lists gateways that **reported**. It
cannot see a machine that never installed one. A shrinking fleet is a signal; a complete
one is not proof.

---

## "Notifications stopped arriving"

Check the rate limiter first — a server that floods gets cut off, by design:

```bash
grep 'rate exceeded' ~/.toolgate/audit.jsonl | tail -5
```

Then check transport. Notifications require a channel to the client: **stdio**, or an
**SSE stream from a `subscriptions/listen`**. A client that polls with ordinary POSTs and
never opens a subscription will never receive one, and nothing is broken.

---

## Backup and restore

The pin file is a **trust store**, not a cache. Losing it is not a cache miss: every tool
becomes a first sighting and the poisoning defence stops enforcing until each definition has
been seen twice.

```bash
# back up (it is small; do it before upgrades)
cp ~/.toolgate/pins.json ~/.toolgate/pins.json.$(date +%F)

# restore
systemctl stop toolgate       # or scale the deployment to 0
cp ~/.toolgate/pins.json.2026-08-18 ~/.toolgate/pins.json
chmod 600 ~/.toolgate/pins.json
```

The permissions matter as much as the contents. Anyone who can write this file can
pre-approve a poisoned definition, which is why the gateway refuses to start if it is
group- or world-writable.

**Restoring has never been exercised under failure conditions.** Rehearse it before you
need it.

---

## Alerts worth having

```promql
# policy is stale or absent — the actionable one
toolgate_bundle_health >= 2

# drift nobody has looked at
toolgate_drift_outstanding > 0

# approvals piling up: either a workflow nobody is watching, or something is asking a lot
toolgate_approvals_pending > 5

# a spike in a control firing — could be an attack, could be a bad release
sum(rate(toolgate_decisions_total{outcome="DENIED", reason="drift"}[15m])) > 0
sum(rate(toolgate_decisions_total{outcome="DENIED", reason="injection"}[15m])) > 0

# the fleet drifting off current policy
count(toolgate_bundle_sequence < on() group_left max(toolgate_bundle_sequence))
```

`reason="injection"` and `reason="drift"` are the two that mean *something tried something*.
The rest mean *something is misconfigured*. Page on the former; ticket the latter.

---

## What is not covered

Honest gaps, so nobody discovers them at 3am:

- **No sustained-load data.** Everything has been measured in minutes. Memory behaviour over
  days is unknown.
- **Restore is untested under failure.** See above.
- **No upgrade rehearsal.** Pin and bundle schemas are versioned and refuse what they cannot
  read, so an upgrade should fail loudly rather than silently — but that has not been
  exercised across a real version boundary.
- **Nothing here has been reviewed by anyone outside the project.**
- **No incident has actually happened.** Every procedure here was derived from a failure
  mode the code has, and several were reproduced deliberately during development — but none
  has been walked through under real pressure, which is the only test that counts.
