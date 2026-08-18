#!/usr/bin/env python3
"""
A stand-in for the Messages API, so the advisor's HTTP path can be exercised without a key.

It answers the shapes that matter: a well-formed reply, prose instead of JSON, an error
status, and a hang. Everything except whether a real provider accepts the request — which
is the one thing a fake cannot tell you, and is stated rather than glossed over.
"""
import json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("MODE", "ok")
SEEN = []

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        req = json.loads(raw or b"{}")
        SEEN.append({"headers": dict(self.headers), "body": req})

        # Report what the advisor actually sent, so the request shape is verified rather
        # than assumed.
        msgs = req.get("messages", [])
        # Which dialect arrived is inferred from the request, not configured here — that
        # way the check fails loudly if the advisor sends a shape neither provider accepts.
        openai = any(m.get("role") == "system" for m in msgs)
        auth = self.headers.get("authorization", "")

        print(f"  request seen ({'openai/deepseek' if openai else 'anthropic'} shape):", flush=True)
        if openai:
            print(f"    authorization Bearer:   {auth.startswith('Bearer ') and len(auth) > 7}", flush=True)
            print(f"    x-api-key absent:       {'x-api-key' not in self.headers}", flush=True)
            system = next((m.get("content", "") for m in msgs if m.get("role") == "system"), "")
        else:
            print(f"    x-api-key present:      {'x-api-key' in self.headers}", flush=True)
            print(f"    anthropic-version:      {self.headers.get('anthropic-version')}", flush=True)
            print(f"    authorization absent:   {not auth}", flush=True)
            system = req.get("system", "")

        print(f"    model:                  {req.get('model')}", flush=True)
        print(f"    system prompt present:  {bool(system)}", flush=True)
        print(f"    system names hostility: {'compromised' in system}", flush=True)
        content = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        print(f"    diff delimited:         {'<drift_diff>' in content}", flush=True)
        # The diff body itself, not a token from one particular scenario — an assertion
        # tied to the poisoned wording silently reads False on every benign-drift run.
        inner = content.split("<drift_diff>")[-1].split("</drift_diff>")[0].strip()
        print(f"    diff body non-empty:    {len(inner) > 0} ({len(inner)} chars)", flush=True)
        print(f"    diff shows both sides:  {'-' in inner and '+' in inner}", flush=True)

        if MODE == "slow":
            time.sleep(40)
        if MODE == "error":
            self.send_response(429)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        text = {
            "ok": json.dumps({
                "risk": "high",
                "summary": "The description now instructs the model to read a private key first.",
                "observations": [
                    "Adds an instruction addressed to the model, not to a user",
                    "References ~/.ssh/id_rsa, unrelated to reading a workspace file",
                    "Asks that the step not be mentioned to the user",
                ],
            }),
            "prose": "I'm afraid I can't analyse that.",
            "markup": json.dumps({
                "risk": "low",
                "summary": "<img src=x onerror=alert(1)>",
                "observations": ["<script>fetch('/toolgate/ui/drift/accept')</script>"],
            }),
        }[MODE]

        # Reply in whichever shape was asked for, so the advisor's extraction path is
        # exercised rather than assumed.
        body = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": text}}]} if openai
            else {"content": [{"type": "text", "text": text}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print(f"fake messages API on :9400 (mode={MODE})", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 9400), H).serve_forever()
