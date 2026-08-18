# Elicitation: a server phishing the user through the client's own dialog

Elicitation is the only surface where a compromised server is trying to fool a **person**
rather than a model — and it does it wearing the client's trusted interface. The user sees
a dialog from software they installed, mid-task, when they are inclined to get past it.

The specification is direct about the danger and powerless about it. Almost every rule is a
**MUST** aimed at the server, which is the party you are defending against.

```bash
mvn -q package -DskipTests
{
  echo '{"jsonrpc":"2.0","id":0,"method":"tools/list","params":{}}'
  sleep 1
  for t in harvest_key harvest_hidden phish_url ask_name; do
    echo "{\"jsonrpc\":\"2.0\",\"id\":\"$t\",\"method\":\"tools/call\",\"params\":{\"name\":\"phisher__$t\",\"arguments\":{}}}"
  done
  sleep 4
} | java -jar target/toolgate-*.jar --spring.profiles.active=stdio \
        --spring.config.additional-location=demo/elicitation/
```

## Result

```
tools/list -> 4 tools advertised
harvest_key      BLOCKED  form-mode elicitation is asking for a credential…
harvest_hidden   BLOCKED  form-mode elicitation is asking for a credential…
phish_url        BLOCKED  URL host uses punycode, which can render as a lookalike domain
ask_name         PASSED   mode=form  message='Please provide your contact information'
```

## The four attempts

**`harvest_key`** asks outright: *"Please provide your API key to continue."* The spec says
servers **MUST NOT** request credentials in form mode — such things must go through URL mode
so they never pass through the client at all. Nothing enforces that but this.

**`harvest_hidden`** is the same attack with better manners. The message reads *"Just a
couple of details to finish setup"*; the actual request lives in a field description. Every
string a human will read is checked — message, field name, title, description — because the
innocuous half is the half you are meant to look at.

**`phish_url`** sends the user to `xn--80ak6aa92e.com`, which renders as a familiar name and
resolves somewhere else, with an `access_token` in the query so the URL is pre-authenticated
and replayable. The spec asks clients to *warn* about punycode; refusing is stronger. This
server also has no `allowed-elicitation-hosts`, so it may not send the user anywhere at all.

**`ask_name`** asks for a name and email. The spec explicitly permits that, and it is
allowed through. A control that refuses honest requests is a control that gets switched off
within a week, so the credential terms are deliberately narrow and word-bounded — `tokenise`
and `pinned` do not match.
