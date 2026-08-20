# The hosted demonstration

A running toolgate with a hostile MCP server beside it, published so that seeing the
controls fire does not require cloning anything. Everything on the page is the gateway's
real reaction to a real attacker over a real socket — no fixtures, no recording.

## What this deployment is, and is not

It runs in a mode nothing else should: `toolgate.operator.public-read-only`. The console is
served to anyone, and **every unsafe method under `/toolgate` is refused before
authentication is considered** — including with a correct operator token, and including
signing in. There is no credential on this instance that can accept a drifted definition,
approve a blocked call, or edit a scanner rule.

That is enforced in `OperatorAuthFilter`, not by hiding buttons. Hiding a button is a
statement about one page; the accept and approve routes take a POST from anything that can
reach them. `PublicReadOnlyConsoleTest` asserts each of these, including the one that
matters most: the operator token is refused too.

The agent endpoint `/mcp` stays authenticated. The console is the demonstration; `/mcp` is
a working gateway, and leaving it open would let anyone proxy through this instance to the
hostile server and fill the audit trail with their traffic.

The hostile server binds loopback inside the container and is not published. A visitor who
could reach its `/poison` endpoint would be operating the attacker rather than watching it
be refused.

## Why it attacks itself

A gateway with nothing to refuse looks exactly like a gateway that does not work. Drift
only exists after a definition changes; an approval queue only fills when something asks
for one. So `DemoScenarioDriver` (on only when `toolgate.demo.enabled` is set) runs a
scenario on a loop — one step every thirty seconds, eight steps a lap:

| Step | What happens | Control it shows |
|------|--------------|------------------|
| 0 | reset the upstream, list tools | pinning on first sighting |
| 1 | call a tool that was never advertised | the allowlist, and routing refusing a name the model invented |
| 2 | call the tool marked as needing approval | the human gate; the queue fills |
| 3–4 | upstream rewords a description | drift — the genuinely hard case, held for two steps |
| 5 | upstream poisons the description | the scanner; the pin is forgotten so the fix is not drift |
| 6 | ask to read `/etc/shadow` | path checks |
| 7 | list again | steady state |

The driver calls `GatewayService` in-process, through the same `PolicyEngine` that would
decide on anyone's laptop. It does not hold a credential and does not bypass policy — which
is the only reason the screen means anything.

## Deploying it on Render

No command line and no card. In the [Render](https://render.com) dashboard:

1. Sign up with the GitHub account that owns this repository.
2. **New → Blueprint**, choose this repository. It reads [`render.yaml`](../../render.yaml)
   and needs nothing else filled in.
3. **Apply**. The first build compiles the gateway from source and takes a few minutes.

The URL appears at the top of the service page — `https://<name>.onrender.com/toolgate`.
Render appends a suffix if the name is taken, so read it there rather than assuming it.
Nothing in the configuration hardcodes the hostname: the token audience comes from
`RENDER_EXTERNAL_URL`, which Render injects.

Two things the free plan changes, both fine here and neither hidden:

- **It sleeps after fifteen minutes idle**, and the next visitor waits roughly a minute for
  the container to start. That is the cost of free.
- **There is no persistent disk**, so pins do not survive a restart. On a real deployment
  that would be serious — the pin file is the trust store, and losing it means every
  definition is trusted again as a first sighting. Here it is harmless because the scenario
  driver re-establishes the whole state after every start: it pins the current definitions,
  then makes the upstream change one. The demonstration rebuilds itself rather than
  depending on anything surviving.

Because a sleeping service wakes with an empty console, the driver runs its first five
steps at two-second intervals before dropping to the slow cadence. Real drift, a pending
approval and a list of refusals are on the page within about twenty seconds of the process
starting, rather than several minutes.

## Deploying it on Fly instead

Better for visitors — it wakes in about a second rather than a minute — but it needs a
Fly.io account, a card on file, and the `flyctl` command-line tool. These run from the
repository root.

```sh
fly launch --no-deploy --copy-config       # creates the app from fly.toml
fly volumes create toolgate_state --size 1 --region sin
fly deploy
fly open                                    # or: https://<app>.fly.dev/toolgate
```

Fly app names are globally unique, so `toolgate-demo` may already be taken. If `fly launch`
assigns a different one, three places name it and all three should agree: `app` in
`fly.toml`, `toolgate.auth.resource-uri` in `application-hosted.yml` (it is the token
audience, so a wrong value fails authentication rather than merely looking untidy), and the
link at the top of the root `README.md`.

Optionally, to make `/mcp` usable by an agent you control:

```sh
fly secrets set TOOLGATE_DEMO_AGENT_SHA256=$(printf %s 'your-token' | shasum -a 256 | cut -d' ' -f1)
```

Without it the placeholder hash matches nothing, which is the intended default: the
demonstration does not depend on a published credential.

**The volume is not optional.** Pins have to outlive a restart or the demonstration
inverts — a mutated definition arriving at an empty pin store is a first sighting, and a
first sighting is trusted, so the console would show a poisoned tool being accepted rather
than caught.

`fly.toml` sets `min_machines_running = 0`. The gateway starts in about 1.3 seconds, which
is what makes scale-to-zero right here rather than a compromise: a visitor arriving at a
stopped machine waits about as long as a page load, and an idle demonstration costs
nothing to keep published.

## Running it locally first

```sh
docker build -f demo/hosted/Dockerfile -t toolgate-demo .
docker run --rm -p 8090:8090 toolgate-demo
```

Or without Docker, from the repository root — note the profile flag:

```sh
mvn -DskipTests package
HOSTILE_HOST=127.0.0.1 python3 demo/hostile-server.py &
java -jar target/toolgate-*.jar \
  --spring.config.additional-location=file:demo/hosted/ \
  --spring.profiles.active=hosted \
  --toolgate.pins.file=/tmp/tg/pins.json \
  --toolgate.audit.file=/tmp/tg/audit.jsonl \
  --toolgate.approvals.file=/tmp/tg/approvals.json \
  --toolgate.scanner.rules-file=/tmp/tg/scanner-rules.json
```

`--spring.profiles.active=hosted` is required outside the image because the file is named
`application-hosted.yml`; Spring reads a profile-suffixed file only when that profile is
active. The Dockerfile copies it to `/config/application.yml`, where it loads
unconditionally. Without the flag the process starts cleanly on shipped defaults and the
console is closed, which is a confusing way to find out the config was ignored — the
startup log is the tell, and it should carry both of these:

```
Operator console is PUBLIC and READ-ONLY: ...
Demo scenario driver active against http://127.0.0.1:9001 ...
```

## After a deploy, check

- `GET /toolgate` returns 200 with no credential, and shows the banner.
- `POST /toolgate/drift/demo/read_file/accept` returns 403 — with and without a token.
- `POST /toolgate/login` returns 403.
- `POST /mcp` without a token returns 401.
- Within a few minutes the console holds drift, a pending approval and a list of refusals.

## Housekeeping

The audit trail appends to the volume and is never rewritten — roughly a megabyte a day at
this scenario's rate. Delete the volume and recreate it if it ever matters; there is
nothing on this instance worth keeping.
