#!/usr/bin/env python3
"""
A Streamable HTTP MCP server.

Answers ordinary requests with application/json, and subscriptions/listen with a
text/event-stream that stays open — which is the shape this revision defines, and the
reason a client cannot decide in advance how to read a reply.
"""
import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESOURCES = [{"uri": "file:///http/one.md", "name": "one", "title": "One",
              "description": "Served over HTTP.", "mimeType": "text/markdown"}]

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse_event(self, obj):
        self.wfile.write(("data:" + json.dumps(obj) + "\n\n").encode())
        self.wfile.flush()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(n) or b"{}")
        m, i = msg.get("method"), msg.get("id")

        if m == "server/discover":
            return self._json({"jsonrpc": "2.0", "id": i, "result": {
                "protocolVersion": "2026-07-28",
                "serverInfo": {"name": "http-upstream", "version": "1"}, "capabilities": {}}})
        if m == "resources/list":
            return self._json({"jsonrpc": "2.0", "id": i,
                               "result": {"resultType": "complete", "resources": RESOURCES}})
        if m in ("tools/list", "prompts/list", "resources/templates/list"):
            key = {"tools/list": "tools", "prompts/list": "prompts",
                   "resources/templates/list": "resourceTemplates"}[m]
            return self._json({"jsonrpc": "2.0", "id": i,
                               "result": {"resultType": "complete", key: []}})

        if m == "subscriptions/listen":
            # The reply IS the stream. It stays open and carries notifications.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            sub = {"io.modelcontextprotocol/subscriptionId": i}
            self._sse_event({"jsonrpc": "2.0",
                             "method": "notifications/subscriptions/acknowledged",
                             "params": {"_meta": sub,
                                        "notifications": msg.get("params", {}).get("notifications", {})}})
            time.sleep(1.5)
            self._sse_event({"jsonrpc": "2.0", "method": "notifications/resources/updated",
                             "params": {"_meta": sub, "uri": "file:///http/one.md"}})
            self._sse_event({"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
                             "params": {"_meta": sub}})
            # An update for something never advertised — should not reach the client.
            self._sse_event({"jsonrpc": "2.0", "method": "notifications/resources/updated",
                             "params": {"_meta": sub, "uri": "file:///etc/shadow"}})
            time.sleep(4)
            return

        return self._json({"jsonrpc": "2.0", "id": i,
                           "error": {"code": -32601, "message": "no"}})

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    print("http upstream on :9200", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 9200), H).serve_forever()
