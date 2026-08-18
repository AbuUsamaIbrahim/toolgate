# An HTTP upstream pushing notifications over SSE

The last transport gap. The gateway could *serve* SSE to its own clients, but consumed
upstream notifications only over stdio — so an HTTP upstream that pushed anything was
talking to nobody.

`upstream.py` is a Streamable HTTP MCP server. It answers ordinary requests with
`application/json` and `subscriptions/listen` with a `text/event-stream` that stays open,
which is the shape this revision defines — and the reason a client cannot decide in advance
how to read a reply.

```bash
mvn -q package -DskipTests
python3 demo/http-upstream/upstream.py &
java -jar target/toolgate-*.jar --spring.config.additional-location=demo/http-upstream/ \
     --server.port=8098 &

curl -sS -o /dev/null -X POST http://localhost:8098/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}'

curl -sS -N -X POST http://localhost:8098/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":"c-1","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true,"resourceSubscriptions":["file:///http/one.md"]}}}'
```

## Result

```
notifications/subscriptions/acknowledged      subId='c-1'
notifications/resources/updated               subId='c-1'  file:///http/one.md
notifications/tools/list_changed              subId='c-1'
```

HTTP upstream → gateway → HTTP client, SSE on both ends. Every message carries `c-1`, the
id the *client* issued — the upstream's own id never reaches it.

The upstream also pushes an update for `file:///etc/shadow`, which it never advertised:

```
DENIED  remote  file:///etc/shadow  server sent a notification type the client did not subscribe to
```

## Why the timeout is conditional

An ordinary request that has not answered in twenty seconds is a problem. A subscription
that has said nothing for an hour is a server with nothing to report. The same timeout
cannot serve both, so `subscriptions/listen` is exempt and everything else is not.

## A stream that ends without a response

An SSE reply that closes without a final JSON-RPC response completes **empty** — neither an
`onNext` nor an `onError` callback ever fires. That is exactly what graceful closure of a
subscription looks like, so the end-of-subscription hook is `doFinally`, which sees all
three outcomes. Attaching it to `onNext`/`onError` would have left the client waiting on a
stream nobody was serving, and nothing would have logged.
