# What the gateway costs

Performance was unmeasured for the whole of v1–v3, which meant the case for adopting this
rested on an assumption. It sits on the critical path of every tool call, so if it adds
enough latency to be noticed, engineers will remove it and every control here goes with it.

The measurement is a comparison rather than an absolute: the same requests, against the same
upstream, with and without the gateway in the path. An absolute number would say more about
the machine than about the software.

```bash
python3 demo/load/upstream.py &
java -jar target/toolgate-*.jar --spring.config.additional-location=demo/load/ --server.port=8097 &
python3 demo/load/loadtest.py 2000 16
```

## Results

Apple M4, both processes local, 2000 requests at concurrency 16, after warm-up.

```
tools/call — the common path
                            p50      p95    req/s
  direct to upstream       1.0ms    2.7ms    6463
  through the gateway      5.0ms   11.2ms    2741
  gateway adds             4.0ms    8.5ms

tools/list — every tool fingerprinted and scanned (50 tools)
                            p50      p95    req/s
  direct to upstream       1.2ms    2.9ms    1835
  through the gateway     15.2ms   29.5ms     960
  gateway adds            14.1ms   26.5ms
```

## The shape matters more than the numbers

Screening cost is **sub-linear** in the number of tools, which is the question an adopter
actually has:

| tools | added (p50) | per tool |
|---|---|---|
| 10 | 7.1ms | 0.714ms |
| 50 | 9.8ms | 0.196ms |
| 200 | 19.7ms | 0.098ms |

Fitting the two components gives a **fixed cost of ~6.4ms** for being in the path at all —
an extra HTTP hop, a JSON parse and a re-serialise — and a **marginal cost of ~0.066ms per
tool** for the actual work: a canonical SHA-256 fingerprint plus a regex scan of every
model-visible field.

That extrapolates to roughly 40ms for 500 tools and 73ms for 1000, on a listing that
typically happens once per session.

## Reading it honestly

**`tools/call` is the number that matters, and 4ms is noise.** A real tool call does file
I/O or an API request taking tens to hundreds of milliseconds; 4ms on top of that is not
something anyone will notice, let alone remove the gateway over.

**`tools/list` costs more and matters less.** It runs once when a session starts, or when a
server announces a change. 14ms once is not a problem; it would become one if a server
emitted `list_changed` in a loop, which is why the notification gate rate-limits that.

**Throughput roughly halves**, and that is expected rather than alarming: every request
crosses two hops instead of one. 2700 tool calls a second from one sidecar is far beyond
what a single developer's agent will generate.

## What this does not measure

Stated because a benchmark that does not say what it left out is a sales document.

- **The baseline is a Python `ThreadingHTTPServer`**, and it is the bottleneck at high
  percentiles — the p99 and max columns are dominated by its stalls, not by the gateway.
  Only p50 and p95 should be read as meaningful. A proper baseline needs a fast upstream.
- **Nothing sustained.** Minutes, not hours. No memory-growth or GC behaviour over time.
- **No concurrent subscriptions.** Long-lived SSE streams are the newest code and hold
  per-subscription state; a hundred simultaneous streams is untested.
- **No Postgres in the path.** The control plane's fleet registry was not exercised.
- **Localhost only.** No real network latency, TLS, or a proxy in between.
