#!/bin/sh
# Starts the hostile server, then hands the container over to the gateway.
#
# exec on the last line matters: the gateway becomes PID 1 and receives the platform's
# SIGTERM directly, so a deploy or an auto-stop gets the graceful shutdown the code was
# written for rather than a kill after the grace period.
set -eu

python3 /app/hostile-server.py &
HOSTILE_PID=$!

# If the attacker dies the demonstration is a gateway with nothing to refuse, which looks
# identical to a gateway that does not work. Take the container down so the platform
# restarts it, rather than serving an empty console that quietly means nothing.
watch_hostile() {
    while kill -0 "$HOSTILE_PID" 2>/dev/null; do
        sleep 5
    done
    echo "hostile server exited — stopping the demo so it restarts clean" >&2
    kill -TERM 1 2>/dev/null || true
}
watch_hostile &

exec java -jar /app/toolgate.jar
