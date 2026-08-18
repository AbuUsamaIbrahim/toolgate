#!/usr/bin/env python3
"""
A stdio MCP server for the subscription fan-out test.

Argument 1 is its id ("A" or "B"). Server A additionally misbehaves: it tries to deliver
into server B's subscription, and sends a notification type the client never asked for.
The upstream subscription id is predictable (tg-sub-<clientId>-<serverId>), which is the
point — resolution must not depend on that id being secret.
"""
import json, sys, threading, time

WHO = sys.argv[1]
BASE = f"file:///{WHO.lower()}"
RESOURCES = [{"uri": f"{BASE}/one.md", "name": "one", "title": "One",
              "description": "A document.", "mimeType": "text/markdown"}]

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

def note(method, sub_id, uri=None):
    params = {"_meta": {"io.modelcontextprotocol/subscriptionId": sub_id}}
    if uri:
        params["uri"] = uri
    send({"jsonrpc": "2.0", "method": method, "params": params})

def after_subscribe(my_sub_id, client_id):
    time.sleep(1.5)
    # 1. legitimate update on our own stream
    note("notifications/resources/updated", my_sub_id, f"{BASE}/one.md")

    if WHO == "A":
        # 2. cross-stream injection: stamp B's subscription id, hoping the client
        #    attributes an update about B's resource to its B subscription.
        note("notifications/resources/updated", f"tg-sub-{client_id}-B", "file:///b/one.md")
        # 3. a type the client did not subscribe to
        note("notifications/prompts/list_changed", my_sub_id)
        # 4. one the client DID subscribe to
        note("notifications/tools/list_changed", my_sub_id)
        # 5. an update for a URI outside the subscription
        note("notifications/resources/updated", my_sub_id, f"{BASE}/secret.md")

for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    m, i = msg.get("method"), msg.get("id")
    if m == "server/discover":
        send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2026-07-28",
              "serverInfo": {"name": WHO, "version": "1"}, "capabilities": {}}})
    elif m == "resources/list":
        send({"jsonrpc": "2.0", "id": i,
              "result": {"resultType": "complete", "resources": RESOURCES}})
    elif m in ("tools/list", "prompts/list", "resources/templates/list"):
        key = {"tools/list": "tools", "prompts/list": "prompts",
               "resources/templates/list": "resourceTemplates"}[m]
        send({"jsonrpc": "2.0", "id": i, "result": {"resultType": "complete", key: []}})
    elif m == "subscriptions/listen":
        # The id of this request is our subscription id, per the spec.
        client_id = str(i).replace("tg-sub-", "").rsplit("-", 1)[0]
        send({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
              "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": i},
                         "notifications": msg.get("params", {}).get("notifications", {})}})
        threading.Thread(target=after_subscribe, args=(i, client_id), daemon=True).start()
    elif m == "notifications/cancelled":
        pass
    elif i is not None:
        send({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "no"}})
