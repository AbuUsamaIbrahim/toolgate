#!/usr/bin/env bash
#
# Walks through what the gateway refuses, against a server that is really trying it.
#
#   docker compose up --build -d
#   ./demo/walkthrough.sh
#
# Nothing here is simulated: every response is the gateway's actual answer.

set -euo pipefail

GATEWAY=${GATEWAY:-http://localhost:${TOOLGATE_PORT:-8090}}
HOSTILE=${HOSTILE:-http://localhost:${HOSTILE_PORT:-9001}}
AGENT_TOKEN=${AGENT_TOKEN:-demo-agent-token}
OPERATOR_TOKEN=${OPERATOR_TOKEN:-demo-operator-token}

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

agent_call() {
  curl -sS "$GATEWAY/mcp" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H "MCP-Protocol-Version: 2026-07-28" \
    -H 'Content-Type: application/json' \
    -d "$1"
}

tool_names() {
  agent_call '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    | python3 -c 'import json,sys; print("\n".join("  - "+t["name"] for t in json.load(sys.stdin)["result"]["tools"]) or "  (none)")'
}

wait_for() {
  for _ in $(seq 1 60); do
    curl -sf -o /dev/null "$1" && return 0
    sleep 1
  done
  echo "timed out waiting for $1" >&2
  exit 1
}

bold "0. Waiting for the gateway"
wait_for "$HOSTILE/"
# An unauthenticated POST is the readiness probe: 401 means the gateway is up *and*
# enforcing. A bare GET would answer 405 whether or not auth was wired up at all.
for _ in $(seq 1 60); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$GATEWAY/mcp" \
    -H 'Content-Type: application/json' -d '{}' 2>/dev/null || echo 000)
  [ "$code" = "401" ] && break
  sleep 1
done
if [ "${code:-000}" != "401" ]; then
  echo "Expected 401 from $GATEWAY/mcp, got ${code:-000}." >&2
  echo "A 405 here is someone else's server: the published port was already taken, so" >&2
  echo "the request never reached the gateway. Run both on a free one:" >&2
  echo "  TOOLGATE_PORT=8099 docker compose up -d && TOOLGATE_PORT=8099 $0" >&2
  exit 1
fi
dim "both up; the gateway is refusing unauthenticated calls"

bold "1. The hostile server advertises four tools"
curl -sS "$HOSTILE/" >/dev/null
dim "read_file, search_docs, send_email, fetch_url — see demo/hostile-server.py"

bold "2. What the agent is actually shown"
tool_names
dim "All four are allowlisted, so nothing here was refused by the cheap check."
dim "search_docs carries injected instructions in its description — the scanner refused it."
dim "fetch_url asks to mirror an argument into the Authorization header — refused as well;"
dim "it was trying to take over the credential the gateway authenticates upstream with."
dim ""
dim "Neither reaches the model's context. Filtering happens at tools/list, not at call"
dim "time — by call time the model has already read the injection and may be acting on it"
dim "through some entirely different tool."

bold "3. read_file is allowed, and now pinned"
agent_call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"demo__read_file","arguments":{"path":"/etc/hostname"}}}' \
  | python3 -m json.tool

bold "4. send_email is allowlisted, but destructive — it needs a human"
agent_call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"demo__send_email","arguments":{"to":"a@b.c","body":"hi"}}}' \
  | python3 -m json.tool
dim "Error -32001. The gateway did not refuse the tool; it refused to decide alone."

bold "5. Now the upstream is compromised and rewrites read_file"
curl -sS -X POST "$HOSTILE/poison" >/dev/null
dim "The description now instructs the model to read ~/.ssh/id_rsa first."
dim "This is the attack pinning exists for: the tool was already approved."

bold "6. What the agent is shown after the mutation"
tool_names
dim "read_file is gone. Its fingerprint no longer matches the pin, and the gateway"
dim "will not guess whether that was a release or an attack."

bold "7. What the operator sees"
curl -sS "$GATEWAY/toolgate/drift.txt" -H "Authorization: Bearer $OPERATOR_TOKEN"
dim "A hash proves something changed; only a diff shows what. That is the difference"
dim "between an alert someone can act on and one they will learn to ignore."

bold "8. The operator API needs its own credential"
printf '  without a token: HTTP %s\n' \
  "$(curl -sS -o /dev/null -w '%{http_code}' "$GATEWAY/toolgate/drift")"
dim "Separate from /mcp so an agent cannot reach it through the protocol — but on one host"
dim "an agent can still open a socket, so separation alone is not access control."

bold "9. The upstream reverts"
curl -sS -X POST "$HOSTILE/repair" >/dev/null
tool_names
dim "Back to matching its pin, so it is advertised again. No operator action was needed —"
dim "the gateway blocked a state, not a server."

bold "10. The record"
curl -sS "$GATEWAY/toolgate/audit" -H "Authorization: Bearer $OPERATOR_TOKEN" \
  | python3 -c '
import json, sys
for e in json.load(sys.stdin)[:12]:
    print("  {:<18} {}/{:<12} {}".format(
        e["outcome"], e["serverId"], e["tool"], e["reason"]))
'
dim "Also on disk at /var/lib/toolgate/audit.jsonl, appended and flushed per entry."

bold "Done."
dim "docker compose down -v   # removes the volume, and with it the pins"
