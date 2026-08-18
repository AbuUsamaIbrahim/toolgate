# Subscription fan-out, against two real upstreams

`upstream.py` is a stdio MCP server. Two are launched — `A` and `B` — and `A` misbehaves in
three ways once a subscription is open.

```bash
mvn -q package -DskipTests
{
  echo '{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}'
  sleep 2
  echo '{"jsonrpc":"2.0","id":"client-99","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true,"resourceSubscriptions":["file:///a/one.md","file:///b/one.md","file:///etc/shadow"]}}}'
  sleep 7
} | java -jar target/toolgate-*.jar --spring.profiles.active=stdio \
        --spring.config.additional-location=demo/subscriptions/
```

`resources/list` runs first so the gateway learns which upstream owns which URI — a
subscription can only cover resources the caller could read.

## What the client sees

```
RESPONSE  id=client-99  subId=client-99
          granted={'toolsListChanged': True,
                   'resourceSubscriptions': ['file:///b/one.md', 'file:///a/one.md']}
NOTIFY    subId='client-99'  notifications/resources/updated  file:///a/one.md
NOTIFY    subId='client-99'  notifications/resources/updated  file:///b/one.md
NOTIFY    subId='client-99'  notifications/tools/list_changed
```

One subscription id — the client's own. The upstream ids (`tg-sub-client-99-A`,
`tg-sub-client-99-B`) never appear. `file:///etc/shadow` is absent from the granted filter,
because the caller could not have read it.

## What it refused

```
DENIED  -   file:///etc/shadow               cannot subscribe to a resource this caller cannot read
DENIED  A   notifications/resources/updated  notification carries a subscription id this upstream was never given
DENIED  A   notifications/prompts/list_chang server sent a notification type the client did not subscribe to
DENIED  A   file:///a/secret.md              server sent a notification type the client did not subscribe to
```

The second is the interesting one. Server A stamped its notification with **B's**
subscription id — an id it can guess, because ids are derived rather than secret — trying to
have an update about B's resource land in the client's B stream. Resolution is keyed on the
sender as well as the id, so it resolved to nothing.

## Two bugs this test found that the unit tests did not

**A registration race.** A server acknowledges the instant it receives `subscriptions/listen`
and may push immediately after. The registry was populated *after* the fan-out, so for a few
milliseconds the gateway's own upstreams looked like strangers — legitimate notifications
dropped, and the audit trail filling with alarming entries for ordinary traffic. Ids are
derived, so the registry is now populated before any request goes out.

**Acknowledgements audited as attacks.** Every upstream sends one; the client must see none,
since it holds one subscription and already has the gateway's own acknowledgement covering
all of them. They were being refused as id violations and audited as such — which is how an
operator learns to scroll past the entries that matter. Now consumed silently.
