#!/usr/bin/env python3
"""
Measures what the gateway adds.

Runs the same requests against the upstream directly and through the gateway, so the
difference is the gateway rather than the machine, the JSON library or the network. That
comparison is the point: an absolute latency number says nothing about whether anyone will
tolerate having this in the path.
"""
import json, statistics, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

def post(url, payload, timeout=30):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": payload["method"],
    })
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()
    return (time.perf_counter() - start) * 1000

def measure(label, url, payload, n, concurrency):
    # Warm up: the JVM is interpreted until it is not, and a benchmark that includes the
    # first few hundred calls measures the compiler rather than the code.
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        list(pool.map(lambda _: post(url, payload), range(min(n // 4, 200))))

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        samples = list(pool.map(lambda _: post(url, payload), range(n)))
    wall = time.perf_counter() - started

    samples.sort()
    return {
        "label": label, "n": n, "concurrency": concurrency,
        "p50": statistics.median(samples),
        "p95": samples[int(len(samples) * 0.95)],
        "p99": samples[int(len(samples) * 0.99)],
        "max": samples[-1],
        "rps": n / wall,
    }

def report(direct, through):
    print(f"\n  {'':<22}{'p50':>9}{'p95':>9}{'p99':>9}{'max':>9}{'req/s':>10}")
    for r in (direct, through):
        print(f"  {r['label']:<22}{r['p50']:>8.1f}ms{r['p95']:>8.1f}ms"
              f"{r['p99']:>8.1f}ms{r['max']:>8.1f}ms{r['rps']:>10.0f}")
    print(f"  {'gateway adds':<22}{through['p50'] - direct['p50']:>8.1f}ms"
          f"{through['p95'] - direct['p95']:>8.1f}ms"
          f"{through['p99'] - direct['p99']:>8.1f}ms")

if __name__ == "__main__":
    upstream = "http://127.0.0.1:9300"
    gateway = "http://127.0.0.1:8097/mcp"
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 16

    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    print(f"\n=== tools/list — every tool fingerprinted and scanned "
          f"(n={n}, concurrency={concurrency}) ===")
    report(measure("direct to upstream", upstream, listing, n, concurrency),
           measure("through the gateway", gateway, listing, n, concurrency))

    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "tool_000", "arguments": {"key": "k"}}}
    call_via_gateway = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "fast__tool_000", "arguments": {"key": "k"}}}
    print(f"\n=== tools/call — the common path (n={n}, concurrency={concurrency}) ===")
    report(measure("direct to upstream", upstream, call, n, concurrency),
           measure("through the gateway", gateway, call_via_gateway, n, concurrency))
    print()
