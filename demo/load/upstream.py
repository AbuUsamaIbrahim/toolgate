#!/usr/bin/env python3
"""
A fast, honest MCP server, for measuring what the gateway costs.

It does as little as possible so that the difference between calling it directly and
calling it through the gateway is the gateway. TOOL_COUNT is settable because screening is
per-tool: fingerprinting and scanning fifty definitions is fifty times the work of one, and
a benchmark against a single trivial tool would flatter the result.
"""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingMixIn

TOOL_COUNT = int(os.environ.get("TOOL_COUNT", "50"))

TOOLS = [{
    "name": f"tool_{i:03d}",
    "title": f"Tool {i}",
    "description": "Reads a value from the store and returns it unchanged.",
    "inputSchema": {"type": "object",
                    "properties": {"key": {"type": "string", "description": "Which key."}},
                    "required": ["key"]},
} for i in range(TOOL_COUNT)]

RESULT = {"content": [{"type": "text", "text": "value"}], "isError": False}

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(n) or b"{}")
        m, i = msg.get("method"), msg.get("id")

        if m == "tools/list":
            result = {"resultType": "complete", "tools": TOOLS}
        elif m == "tools/call":
            result = RESULT
        elif m == "server/discover":
            result = {"protocolVersion": "2026-07-28",
                      "serverInfo": {"name": "fast", "version": "1"}, "capabilities": {}}
        elif m in ("resources/list", "prompts/list", "resources/templates/list"):
            key = {"resources/list": "resources", "prompts/list": "prompts",
                   "resources/templates/list": "resourceTemplates"}[m]
            result = {"resultType": "complete", key: []}
        else:
            result = None

        body = json.dumps({"jsonrpc": "2.0", "id": i,
                           "result": result} if result is not None else
                          {"jsonrpc": "2.0", "id": i,
                           "error": {"code": -32601, "message": "no"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"fast upstream on :9300 with {TOOL_COUNT} tools", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 9300), H).serve_forever()
