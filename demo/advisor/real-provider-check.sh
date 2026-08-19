#!/usr/bin/env bash
#
# Exercises the advisor against a real provider.
#
# The key is read from a file the operator owns and is never passed on a command line,
# never echoed, and never written to a log — a value in `ps` output or a shell history is
# a leaked value. Everything this script prints is derived from the response, not the
# request.
#
# The key comes from the macOS Keychain by default, which is strictly better than a file:
# it is encrypted at rest, unlocked with the login session, and never readable by a stray
# `cat` of the home directory. Add it once, interactively, so the value never appears in a
# command line or in shell history:
#
#     security add-generic-password -a "$USER" -s toolgate-deepseek -w
#
# (with -w and no value, `security` prompts for it — nothing is echoed)
#
# Usage:  demo/advisor/real-provider-check.sh              # Keychain, service toolgate-deepseek
#         KEY_SOURCE=file demo/advisor/real-provider-check.sh [key-file]
#
set -uo pipefail

KEY_SOURCE="${KEY_SOURCE:-keychain}"
KEY_SERVICE="${KEY_SERVICE:-toolgate-deepseek}"
KEY_FILE="${1:-$HOME/.deepseek-key}"
ENDPOINT="${ENDPOINT:-https://api.deepseek.com/chat/completions}"
MODEL="${MODEL:-deepseek-chat}"
DIALECT="${DIALECT:-OPENAI}"
PORT=8474
JAR="$(cd "$(dirname "$0")/../.." && pwd)/target/toolgate-0.2.0-SNAPSHOT.jar"
CONFIG="${CONFIG:-}"

fail() { printf '  FAIL  %s\n' "$1"; exit 1; }
ok()   { printf '  ok    %s\n' "$1"; }

echo "== preflight =="
# read_key writes to stdout and is only ever consumed by a command substitution that feeds
# an environment variable — the value is never printed, logged, or passed as an argument.
read_key() {
  if [ "$KEY_SOURCE" = "keychain" ]; then
    security find-generic-password -a "$USER" -s "$KEY_SERVICE" -w 2>/dev/null
  else
    cat "$KEY_FILE"
  fi
}

if [ "$KEY_SOURCE" = "keychain" ]; then
  BYTES=$(read_key | wc -c | tr -d ' ')
  [ "$BYTES" -gt 8 ] || fail "no Keychain item '$KEY_SERVICE' for $USER — add it with:
          security add-generic-password -a \"\$USER\" -s $KEY_SERVICE -w"
  ok "key found in Keychain (service $KEY_SERVICE, $BYTES bytes)"
else
  [ -f "$KEY_FILE" ] || fail "no key file at $KEY_FILE"
  MODE=$(stat -f %Lp "$KEY_FILE" 2>/dev/null || stat -c %a "$KEY_FILE")
  [ "$MODE" = "600" ] || echo "  warn  $KEY_FILE is mode $MODE, expected 600"
  BYTES=$(wc -c < "$KEY_FILE" | tr -d ' ')
  [ "$BYTES" -gt 8 ] || fail "key file looks empty ($BYTES bytes)"
  ok "key file present, $BYTES bytes, mode $MODE"
fi
[ -f "$JAR" ] || fail "no jar — run: mvn -DskipTests clean package"
ok "jar present"
[ -n "$CONFIG" ] || fail "set CONFIG=<dir with application.yml>"

cleanup() {
  pkill -f "hostile-server.py" 2>/dev/null
  P=$(lsof -tnP -iTCP:$PORT -sTCP:LISTEN 2>/dev/null | head -1)
  if [ -n "$P" ] && ps -o command= -p "$P" | grep -q "toolgate-0.2.0-SNAPSHOT.jar"; then kill "$P"; fi
}
trap cleanup EXIT
cleanup; sleep 1

echo
echo "== starting =="
python3 "$(dirname "$0")/../hostile-server.py" >/dev/null 2>&1 &
sleep 2
# Never assume a fresh upstream: a survivor from an earlier run still holding `revised`
# would make the first sighting pin the revised text, so /revise becomes a no-op and no
# drift is ever produced.
curl -sS -o /dev/null -X POST http://localhost:9001/reset || fail "upstream not reachable"
rm -f "$CONFIG"/pins.json "$CONFIG"/audit.jsonl "$CONFIG"/approvals.json

# The key enters the JVM as an environment variable read from the file, so it appears in
# neither this script's argv nor the JVM's.
DEEPSEEK_API_KEY="$(read_key)" \
  "$JAVA_HOME/bin/java" -jar "$JAR" \
  --spring.config.additional-location="file:$CONFIG/" --server.port=$PORT \
  --toolgate.advisor.enabled=true \
  --toolgate.advisor.api="$DIALECT" \
  --toolgate.advisor.endpoint="$ENDPOINT" \
  --toolgate.advisor.model="$MODEL" \
  --toolgate.advisor.api-key-env=DEEPSEEK_API_KEY \
  --logging.level.dev.mahadi.toolgate.advisor=DEBUG > /tmp/real-provider.log 2>&1 &

for i in $(seq 1 60); do curl -sf -o /dev/null "http://localhost:$PORT/actuator/health" && break; sleep 1; done
curl -sf -o /dev/null "http://localhost:$PORT/actuator/health" || fail "gateway did not start — see /tmp/real-provider.log"
ok "gateway up on :$PORT ($DIALECT, $MODEL)"

echo
echo "== producing real drift =="
A='Authorization: Bearer demo-agent-token'; C='Content-Type: application/json'
U="http://localhost:$PORT/mcp"
curl -sS -o /dev/null -X POST $U -H "$A" -H "$C" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
curl -sS -o /dev/null -X POST http://localhost:9001/revise
curl -sS -o /dev/null -X POST $U -H "$A" -H "$C" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
O='Authorization: Bearer demo-operator-token'
N=$(curl -sS -H "$O" "http://localhost:$PORT/toolgate/drift" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')
[ "$N" -ge 1 ] || fail "no drift produced"
ok "$N drift entry waiting"

echo
echo "== calling the provider =="
START=$(python3 -c 'import time;print(int(time.time()*1000))')
curl -sS -o /dev/null -H "$O" "http://localhost:$PORT/toolgate"     # triggers background fetch
ELAPSED=$(( $(python3 -c 'import time;print(int(time.time()*1000))') - START ))
ok "first page render: ${ELAPSED}ms (must not block on the provider)"
[ "$ELAPSED" -lt 2000 ] || echo "  warn  page took ${ELAPSED}ms — advisor may be blocking"

for i in $(seq 1 30); do
  curl -sS -H "$O" "http://localhost:$PORT/toolgate" > /tmp/real-dash.html
  grep -q "advisory, and readable" /tmp/real-dash.html && break
  sleep 2
done

echo
echo "== result =="
if grep -q "advisory, and readable" /tmp/real-dash.html; then
  ok "provider replied and the note rendered"
  echo
  python3 - <<'PY'
import html, re
page = open("/tmp/real-dash.html").read()
m = re.search(r'advisory, and readable.*?</div>\s*</div>', page, re.S)
block = m.group(0) if m else ""
risk = re.search(r'>(low|medium|high|unknown) risk<', page)
print("  risk:", risk.group(1) if risk else "not shown")
for t in re.findall(r'<(?:div class="advice-summary"|li)[^>]*>(.*?)</', block, re.S)[:6]:
    clean = html.unescape(re.sub(r'<[^>]+>', '', t)).strip()
    if clean: print("   ", clean[:110])
print()
# The safety property that matters: nothing the model returned became live markup.
live = re.findall(r'<(script|img|iframe|svg|object)\b', block, re.I)
print("  live tags from model output:", live if live else "none")
print("  escaped entities present:  ", bool(re.search(r'&lt;|&gt;|&amp;', block)))
PY
else
  echo "  no note rendered — provider error or timeout"
  echo
  echo "  advisor log lines:"
  grep -i "advisor" /tmp/real-provider.log | tail -10 | sed 's/^/    /'
fi

echo
echo "== the request never carried the key anywhere visible =="
grep -ci "sk-" /tmp/real-provider.log | xargs -I{} echo "  occurrences of 'sk-' in the gateway log: {}"
