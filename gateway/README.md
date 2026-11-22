# provared-gateway

**This is the gateway's record of what an agent asked for through it, and
what the gateway did with each call. It proves nothing about calls that do
not go through it.** It counts only if the agent has no other way to the
systems behind it: the company must take the systems' credentials away
from the agent, so that the gateway alone holds them, and block every
other route to those systems at the network. An agent that still holds a
credential, or can reach a system directly, can act without a receipt.

A reverse proxy for AI agents that act through web interfaces. It sits in
front of each system an agent uses (an "upstream"), and for every call:

1. checks who is calling, by a secret of the agent's own;
2. works out which action the call is, and its amount, from a rules file
   the company writes, not from anything the agent says;
3. asks the agent's stub writer whether the person's signed permission (the
   slip) allows it: the check before acting of the Provared library;
4. if it does, removes the agent's own credentials, adds the upstream's,
   sends the call, and writes a signed receipt (a stub) that binds the
   request and the answer by their fingerprints;
5. if it does not, sends nothing, answers `403` with the checker's own
   words, and writes a signed denial.

Where the settings give the gateway a key set of its own, and the slip
names the gateway in `with` (an entry of its own, `gateway` unless the
settings give another id, with that key set), every receipt of the agent
names the gateway in `with`, and the gateway countersigns each call it lets
through and keeps its own copy of the agent's calls apart from the book;
`provared-gateway
compare` holds the copy against the book (below, "The gateway's
countersignature, and its own copy").

The gateway holds each agent's keys (in memory, or through signers that
reach a key service) and each upstream's credential. The agent holds
neither, so it cannot write, change or skip a receipt.

Evidence, not a verdict. The format is described in the Provared format
description (`spec/provared-format.md` in the repository); the library is
the npm package `provared`.

## Install

```
npm install -g provared-gateway
```

It needs Node.js 24.7 or later, and depends only on the `provared` library
(0.9.0).

## Try it

On one computer, with any web server of your own on 127.0.0.1 as the
upstream:

1. Follow "Set it up" below with one upstream whose `base` is that server's
   address (`http://127.0.0.1:<port>`), one rule for a `GET` path it
   answers, and one agent. Make the gateway's own keys too (`keys
   --gateway`), and put the `with` entry and `requires` it prints into the
   slip before you sign it.
2. Start the gateway, and call it as the agent would:

   ```
   curl -H "Authorization: Bearer <the agent's secret>" http://127.0.0.1:8795/<upstream>/<path>
   ```

   The answer is the upstream's, with the stub's fingerprint in the
   `Provared-Stub` header. A call no rule names is answered `403`.
3. Check the agent's book with the library's checker, and hold the
   gateway's copy against it:

   ```
   npx --package=provared@0.9.0 provared-check books/patching.jsonl --issuer <the passkey's thumbprint>
   provared-gateway compare --config gateway.json --agent patching
   ```

   The checker is the library's command, which `npx` fetches with the
   library. It shows each receipt, the party it names in `with` (here the
   gateway's own entry), and whether its countersignature checks against the
   keys the slip gives that entry. It cannot show who holds those keys.
   `compare` says whether the copy and the book agree.

What the checker and `compare` give is evidence, not a verdict: they show
what the records say and that they were not changed, not that what the
agent did was right.

## Set it up

1. Make a secret for each agent, and one for the administrator. Each
   command prints a secret and its hash; the settings keep only the hash.

   ```
   provared-gateway secret
   ```

2. Write the settings, `gateway.json` (an example is in
   `gateway.example.json`). Paths are read from the folder the settings
   file is in.

3. Make each agent's keys, and the recorder's keys for sealing:

   ```
   provared-gateway keys --config gateway.json --agent patching
   provared-gateway keys --config gateway.json --recorder
   ```

   The first prints the agent's two public keys. They go into the slip, as
   `agent.keys`, so that the slip names the gateway's keys as the agent's.
   Give the agent a name that says so, for example "Patching agent, through
   the gateway at gateway.example.internal".

   For the gateway's own countersignature, make its key set too:

   ```
   provared-gateway keys --config gateway.json --gateway
   ```

   It prints the slip's `with` entry for the gateway (its id, its name and
   its two public keys), and `"requires": [{"need": "countersignature"}]`.
   Put both into the slip. The upstreams' own entries stay as they are,
   for their own keys where they have any.

4. The person signs the slip with their passkey (on the signing page at
   https://sign.prova.red, or with the library) and the file is saved where the
   settings say. Its passkey's thumbprint goes into `issuerKeys`.

5. Check the settings. This reads every rule and says what it maps to, and
   what is wrong. It prints no credential.

   ```
   provared-gateway check --config gateway.json
   ```

6. Start it:

   ```
   provared-gateway start --config gateway.json
   ```

The agent then calls `http://<gateway>/<upstream>/<path>` where it called
the upstream itself, with `Authorization: Bearer <its secret>`.

## The settings

```json
{
  "listen": { "host": "127.0.0.1", "port": 8795 },
  "bodyLimit": 10485760,
  "timeout": 30000,
  "unlisted": "refuse",
  "stripHeaders": ["X-Team-Token"],
  "stripQuery": ["key"],
  "admin": { "secretHash": "<hash of the administrator's secret>" },
  "recorder": { "name": "Provared gateway at gateway.example.internal", "keys": "keys/recorder.jwk" },
  "gateway": { "name": "Provared gateway at gateway.example.internal", "keys": "keys/gateway.jwk" },
  "upstreams": {
    "tickets": {
      "base": "https://tickets.example.internal",
      "service": "tickets",
      "credential": { "header": "Authorization", "file": "/run/secrets/tickets", "prefix": "Bearer " },
      "eventIdHeader": "X-Request-Id"
    },
    "patch": {
      "base": "https://patch.example.internal/api",
      "service": "patch",
      "credential": { "header": "X-Api-Key", "env": "PATCH_TOKEN" },
      "requestIdHeader": "X-Gateway-Call",
      "countersign": "/provared/countersign"
    }
  },
  "rules": [
    { "upstream": "tickets", "method": "GET", "path": "/api/now/table/:table", "action": "provared.data.read" },
    { "upstream": "tickets", "method": "PATCH", "path": "/api/now/table/change_request/:id", "action": "ticket.update" },
    { "upstream": "patch", "method": "POST", "path": "/v1/waves", "action": "patch.apply", "amount": { "unit": "hosts", "count": "/hosts" } },
    { "upstream": "patch", "method": "POST", "path": "/v1/hosts/:id/reboot", "action": "host.reboot", "amount": { "unit": "hosts", "value": 1 } }
  ],
  "agents": {
    "patching": {
      "secretHash": "<hash of the agent's secret>",
      "slip": "slips/patching.json",
      "book": "books/patching.jsonl",
      "keys": "keys/patching.jwk",
      "issuerKeys": ["<thumbprint of the person's passkey>"]
    }
  }
}
```

**The gateway's own keys** (`gateway`, optional): `keys`, the gateway's
key file (Ed25519 and ML-DSA-87, made by `provared-gateway keys
--gateway`); `id`, the gateway's `id` in a slip's `with` (`gateway` if left
out; it has the form of a service's id, and may not be any upstream's
`service`); and `name`, the name the printed `with` entry gives it
("Provared gateway" if left out). In a program, `privateKeys` (two signers)
and `keySet` may be given in place of `keys`. Without `gateway`, nothing
below about the gateway's countersignature and copy applies.

A setting the gateway does not know, at the top of the settings or in an
agent's entry, is a problem: the gateway does not start, and `check` says
so. A mis-spelt `gateway` would otherwise leave every call one-sided
without a word.

**Upstreams.** Each has a name, which is the first part of the path the
agent calls (`/tickets/…`), and:

- `base`: its address; any path in it is kept in front of the agent's.
- `service`: the slip's `id` for the system, written into each stub's
  `with`, except for an agent whose slip names the gateway, whose stubs
  name the gateway.
- `credential`: the header the gateway adds, and where its value is read
  from at start: a file (`file`; one line ending at its end is dropped) or
  the environment (`env`); `prefix` goes in front, such as `Bearer `.
- `eventIdHeader`: a header of the upstream's answer that holds its own
  identifier for the call. Its fingerprint goes into the stub as
  `provared.event-id`, so that the stub can be matched with the
  upstream's own log.
- `requestIdHeader`: a header in which the gateway sends a new identifier
  of its own with each call; its fingerprint goes into the stub as
  `provared.request-id`.
- `countersign`: a path on the upstream's own address to which the gateway
  posts each stub (a JSON Web Signature in its JSON form,
  `application/jose+json`, with the upstream's credential), and from which
  it takes a countersignature record back. Only a system the company runs
  can do this, with the library's `countersign`.
- `caseSensitive`: true where the upstream tells capitals from small
  letters in its paths. By default the rules match paths whatever their
  case, so that a call written in capitals cannot slip past a rule.
- `semicolons`: true where the upstream's paths may hold `;`. By default a
  path that holds `;` (or `%3B`) is refused, because many servers set
  aside what follows a `;` in a segment before they route the call
  (`/public/..;/admin` reaches `/admin` on some). Where it is allowed, the
  rules are matched on each segment without what follows its first `;`,
  and a segment that is then empty, `.` or `..` is refused.
- `underscoreHeaders`: true where the agent's calls may have header names
  with `_`. By default such a call is refused, because some servers read
  `_` as `-` (`X_Api_Key` as `X-Api-Key`), so the gateway could not tell
  which headers it removes.
- `timeout` (milliseconds) and `stripHeaders`, for this upstream alone;
  `ca`, a file of certificates to trust for it.

**Rules.** Each names an upstream, one method in capitals, a path, and the
action name the slip uses. Paths are patterns of the WHATWG URL Pattern
standard (`:id`, `:rest*`), matched by the one Node.js has built in; an
optional `search` is a pattern for the query. The first rule that matches
wins. A path is matched with or without one `/` at its end. An amount is
one of:

- `{ "unit": "hosts", "value": 1 }`: always this number;
- `{ "unit": "GBP", "pointer": "/plan/total" }`: the whole number at this
  JSON Pointer (RFC 6901) in the body;
- `{ "unit": "hosts", "count": "/hosts" }`: the length of the list there.

A call whose amount the gateway cannot read is refused: a body that is not
JSON, is not marked as JSON (exactly one `Content-Type` of
`application/json`, or of a type ending `+json`), is marked with a
character set other than UTF-8, is sent compressed (`Content-Encoding`),
or holds nothing at the pointer, or something that is not a whole number
from 0 up (or not a list, for `count`). So is a body that, anywhere in it,
names one member twice in one object, or two that some readers take as one:
names that are the same once put in small letters, then in capitals, then
in small letters again. That joins names that differ only in capitals
(`hosts` and `HOSTS`), and letters that some readers of JSON take as one:
the long s and `s`, the Kelvin sign and `k`, the Greek final sigma and
sigma, the two forms of beta and of theta, the micro sign and mu, the
dotless i and `i`, the dotted capital `İ` and `i` (and `ß` and `ss`). Some readers match names whatever
their case and take the last, so the upstream could act on another value
than the one the stub records. **This also refuses an honest body** that
holds two unrelated names of that kind in one object anywhere in it, such as
`ID` and `id`, where the rule takes its amount from the body.

A call that matches no rule is refused, and written as a denial named
`gateway.unlisted`. With `"unlisted": "forward"` it is sent with no receipt
and noted in the gateway's log instead; the record then leaves those calls
out.

**Waiting calls.** Each agent may have at most `waitingCalls` calls at the
gateway at once (16 by default), holding at most `waitingBytes` bytes of
bodies between them (32 MB by default); past either, a call is refused
(`503`, `too-many-waiting` or `too-much-waiting`) and nothing is written.
An agent's calls wait for one another, so without such a limit one agent
could make the gateway hold many large bodies at once.

**Agents.** Each has the hash of its secret, its slip, its book, its keys,
and the thumbprints of the passkeys whose slips it takes (`issuerKeys`).
The keys are a key file (`keys`, made by `provared-gateway keys`) or a
module of the company's own (`signers`) whose default export is a function
that is given `{ agent: "<name>" }` and gives back two signers, Ed25519 then
ML-DSA-87, as the library describes them (an object with `key` and
`sign(data)`), so that the keys can stay in a key service. The recorder
takes the same, with three signers, and is given `{ recorder: true }`.
`journalKey` names where the agent's journal key is kept, if not beside its
key file (below, "A call the gateway was sending when it stopped"). Where
the gateway has its own keys, `copy` and `copyKey` name where the gateway's
copy of the agent's calls and its key are kept (`copies/<agent>.jsonl` and
the same with `.key` by default). Two agents may not share a secret, or any
of these files: a book, a journal, a list of calls set aside, a journal
key, a key file, a copy, a copy key. Each path is compared by
the real path of its deepest folder that exists, with the rest of the path
after it (so through links and junctions to a folder), in small letters
where that folder can be reached in other capitals as the same folder; and,
where the file itself exists, by its device and file numbers (which a hard
link, or a link to the file, shares, so either is the same file).

## What the gateway does with each call

In this order:

1. **Sign-in.** Exactly one `Authorization: Bearer <secret>` header, whose
   hash is an agent's. Anything else is answered `401`, and nothing is
   written: the gateway cannot tell whose call it is. Then, each answered
   `400` or `503` with nothing written: a websocket upgrade or `CONNECT`;
   a `Connection` header that names anything but `close` or `keep-alive`
   (a header it names would be dropped on the way, though the gateway may
   rely on it); a header name with `_`, unless the upstream allows it; and
   an agent past its waiting calls.
2. **The address.** The first part names the upstream. The rest is written
   in one form, so that the rule matched is the rule the upstream acts on:
   a percent-encoded letter, digit or `-._~` is decoded, and the other
   percent-encodings are written in capitals. What two systems might read
   in two ways is refused (`400`): an encoded `/` or `\`, a
   percent-encoding of a percent-encoding (`%252F`), an encoded control
   character, encoded bytes that are not UTF-8 in its shortest form (an
   "overlong" `%C0%AE` for `.`), encoded characters that some systems read
   as others (any whose NFKC form, Unicode's folding of look-alike
   characters, differs from itself: a full-width `／`, `．`, `＿` or `ｃ`,
   the Kelvin sign; and a run that begins with a combining mark, which joins
   the character before it), `.` or `..` segments, two `/` together, and a
   `;` unless the upstream allows it. Some honest paths are refused by this
   rule, among them a decomposed accent (`cafe%CC%81`; the composed
   `caf%C3%A9` passes), the non-breaking space (`%C2%A0`), `™`, `²`, the
   `ﬁ` ligature, and half-width katakana. Letters of other scripts written
   in their plain form pass: `é`, `ß`, Greek, Cyrillic, Arabic, Hebrew with
   its points, Hindi, Korean, Japanese (full-width katakana and kanji),
   composed Vietnamese, and emoji. There is no setting to allow the refused
   forms.
3. **The rule**, by the method, the path and the query.
4. **The body**, up to `bodyLimit` (10 MB by default). A longer one is
   refused (`413`) and written as a denial.
5. **Credentials, and what would change the call.** Removed from the
   agent's call, whatever their case and however often they are given:
   - the credential headers listed here, and those the settings name
     (`stripHeaders`): `Authorization`, `Proxy-Authorization`, `Cookie`,
     `X-Api-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`,
     `Private-Token`, `X-Goog-Api-Key`, `X-Vault-Token`,
     `X-Amz-Security-Token`, `X-Auth-Key`;
   - the headers with which some servers let a call say another method or
     address: `X-HTTP-Method-Override`, `X-HTTP-Method`,
     `X-Method-Override`, `X-Original-URL`, `X-Rewrite-URL`;
   - the query parameters listed here, and those the settings name
     (`stripQuery`): `access_token`, `api_key`, `apikey`, `api-key`,
     `token`, `auth`, `authorization`, `password`, `passwd`, `secret`,
     `client_secret`, and `_method`. A name is read decoded, without
     anything from its first `[` on, without control characters, and with
     no spaces at its ends; the parts of a query are told apart by `&` and
     by `;`.

   Never sent on either: the headers of one connection (`Connection`,
   `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Transfer-Encoding`,
   `Upgrade`, `Expect`, `Host` and `Content-Length`, which the gateway
   sets), and those with which a call could pose as another address or
   client: `Forwarded`, every `X-Forwarded-*`, `X-Real-IP`, `Via`,
   `True-Client-IP`, `X-Client-IP`, `X-Cluster-Client-IP`,
   `CF-Connecting-IP` and `X-Originating-IP`. Only the names listed here
   are removed: a credential, or a method, in a header or a parameter of
   another name, or in the body (a `_method` field, say), is passed on. The
   names of what was removed (never the values) go into the log. Then the
   upstream's credential is added.
6. **The amount**, as the rule says.
7. **The check before acting**, through the agent's stub writer, opened
   with denials on. A call it refuses is not sent: the agent is answered
   `403`, with the checker's findings (`problems`, `breaches`) in JSON, and
   the stub writer writes a denial with the reasons.
8. **Sending.** The stub names `provared.http-request` (the fingerprint of
   the method, the address as the gateway sends it, and the body), and,
   where they apply, `provared.trace-id` (from a well-formed `traceparent`
   the agent sent) and `provared.request-id`, and a document labelled
   `gateway.call` whose fingerprint is that of the gateway's own identifier
   for the call (a label, not one of the format's reserved names). After the answer it names
   `provared.http-response` (the status and the body) and
   `provared.event-id`, or, where no whole answer came, `provared.error`:
   the fingerprint of the exact error text the agent is given.
9. **A call that was sent always gets its stub**, whatever the upstream did:
   an error status, a connection closed half way, no answer within
   `timeout` (`504`), a stream of events, or an answer larger than
   `bodyLimit` (`502`). Each answer to the agent carries the stub's
   fingerprint in a `Provared-Stub` header. A stub is written even where
   the call never reached the upstream, because the gateway began it: the
   connection was refused, the upstream's name could not be found, or its
   certificate did not check. Where no connection to the upstream was made
   at all, the stub names, beside `provared.error`, a document labelled
   `gateway.not-delivered` (a label, not one of the format's reserved
   names, with the same fingerprint as the error). Where a connection was
   made, the gateway cannot tell whether the upstream received any of the
   call, and names no such label.
10. **The book file** is appended with the new lines, and is checked before
    each call to be as the gateway left it. If something else changed it,
    or it cannot be written, the gateway takes no more calls for that agent
    (`503`) until it is started again.

The answer the agent gets is the upstream's, without its `Set-Cookie`
(the agent's cookies are never sent on, so it has no use for them), without
the headers of one connection or those the upstream's own `Connection`
names, and without any header beginning `Provared-`. A redirect is handed
on as it is: an agent that follows a `Location` that points at the
upstream itself goes round the gateway, unless the network stops it.

**A call the gateway was sending when it stopped.** Before each call is
sent, a line goes into a journal beside the book (`<book>.journal`), made
sure to be on the disk: the call's identifier, its time, the slip it is sent
under, its action, amount and service, and the fingerprints its stub names
before the call. Once the
stub is in the book file (also made sure to be on the disk), a second line
says so. Each line carries a tag: HMAC-SHA-256 (RFC 2104) of the line and
the agent's name, under the agent's **journal key**, 32 random bytes made by
`provared-gateway keys --agent` or at the first start, kept beside the
agent's key file (`<keys>.journal-key`; beside the book where the keys are
held by signers; or where `journalKey` says).

A journal that holds lines and whose key file is missing stops the start,
with a sentence saying so: the gateway never makes a new key for it, since
no line could then be checked. Put the key back, or, having read the
journal, move it away by hand. So does a journal of whole lines none of
which checks under the key in place (a key put back from another copy, say):
setting those lines aside would leave every call they stand for with no
receipt, so put back the key the journal was written with. Where some lines
check and some do not, the gateway starts, and shows those that do not, to
be set aside. Either stop is of the whole gateway, not of that agent alone:
no agent's calls are taken until it is settled. So a program that can write
one agent's journal can stop every agent by putting in a single line that
does not check; protect the journals as the key files are protected.

At start, a call with a first line is done where the book holds a stub that
names its `gateway.call`, whatever the journal says. Any other stops that
agent: its calls are refused (`503`, `agent-stopped`), the log says
`receipt-missing`, and `status` shows each line whole, with whether its
tag checks and, if no stub can be written from it, why. A line can have a
stub written from it only if its tag checks; it names a slip the book holds;
its time is not after this start; its amount and documents are of the forms
the gateway writes, and pass the library's own checks of a request's
fields; and a rule names its action for its service, with its amount in the
rule's unit. Where no rule names it any more (a rule was taken out of the
settings since), the line can still be acknowledged, and the status shows a
warning: its tag shows the gateway wrote it. Where the gateway's clock is
behind the time a line gives, the status says so: put the clock right and
start again, since the library writes nothing dated ahead of the clock. A
line whose tag does not check is never acted on, and the log says
`journal-line-refused`. The administrator acknowledges the calls, and sets
aside the lines that cannot have a stub (by the `call` the status gives
them; a line whose tag does not check is named by its own content, as
`line-<16 characters>`):

```
PROVARED_GATEWAY_ADMIN_SECRET=<secret> provared-gateway acknowledge --config gateway.json --agent patching
PROVARED_GATEWAY_ADMIN_SECRET=<secret> provared-gateway acknowledge --config gateway.json --agent patching --set-aside line-Xq3JmfW0a1b2c3d4,aD7yhCB4glePVsc01zB0Zw
```

For each call acknowledged, a stub is written from its line, under the slip
the call was sent under, dated when it was sent, naming `provared.error`
with the words "The gateway stopped while this call was with the upstream,
so its outcome is not known. …". Where that slip is not the one in force (a
renewed slip was put in place before the start), a stub writer for that
slip is opened on the book as it stands, writes the stub, and the agent's
own writer takes the line into the book only if the book still passes its
check with it; so the stub counts against the limits of the slip it was
sent under, not the new one. A call sent under a slip the book does not
hold cannot be acknowledged, and can only be set aside; a slip that names
other agent keys than the gateway now holds is refused when the stub is
written, and the call stays waiting. Before each stub the gateway looks at
the book again: where the book already holds a stub for the call (written
before a failure, when the journal could not take the line saying the call
was acknowledged), no second stub is written. With a copy, that stub
settles the call only as a stub found at a start does (below), and the copy
notes it `found-in-book`; without one, it settles the call. A call leaves
the list as soon as the line saying so is in the journal; so trying again
after a failure writes no stub twice. A stub written on acknowledgement
goes into the book after every entry that reached the book while the
gateway was stopped: so where a
cancellation of that slip was put into the book meanwhile (only by hand),
the stub reads as made after the cancellation (`after-cancellation`),
because without an outside time-stamp its place in the book is what counts.

**A line set aside gets no stub**, and the journal and the log say so.
**Setting aside a call that was sent leaves it with no receipt**: the book
then does not show it. The calls set aside are kept in
`<book>.journal-set-aside` (each line tagged as the journal's are), which a
clean start does not empty: where the gateway keeps no copy, a line for
such a call that is put back into the journal later is taken as set aside,
and deleting that file brings such lines back to the administrator. Where
it keeps a copy, the copy's own line decides instead (below). The agent
takes calls again once nothing is waiting. A clean start empties the
journal.

**Where the gateway keeps its own copy** (below), the copy decides, not the
journal, since anyone who can write the folder can empty the journal, and
whoever holds the journal key can add to it. A call with a `sending` line in
the copy and no receipt in the book was sent, as far as the gateway knows,
whatever the journal says: it stops the agent and waits for the
administrator, and the stub written for it is written from the copy's own
line (the log says `journal-line-missing` where the journal has no line for
it). A journal line is taken only where the copy holds a `sending` line for
the same call with the same slip, action, amount, service and documents.
One for a call the copy does not hold is passed over where the book holds
one stub for that call and it is the call the line shows, countersigned
where a stub found at a start must be (below): nothing is written or
countersigned for it, and the log says `receipt-found` with
`"inCopy": false`. So a gateway first given keys after calls were made, or
one whose copy was taken away, is not stopped by the calls whose stubs the
book holds. Any other such line is listed, never given a stub, and can only
be set aside (`journal-line-not-in-copy`); one that names a call of the
copy and says otherwise is not acted on (`journal-line-differs`). A call is
set aside only where the copy's own `set-aside` line says so: one that
`<book>.journal-set-aside` names and the copy still shows open stops the
agent and is listed again, the log says `set-aside-not-in-copy`, and
nothing is written to the copy on that file's word. A gateway without keys
of its own (no `gateway` in the settings) keeps no copy and countersigns
nothing: at a start the journal decides, as described
above, as it did before the gateway had keys of its own.

**A book cut part-way through a line.** A stop while a line of the book is
written can leave the file ending part-way through it; the gateway then does
not start, and says so. With the gateway stopped:

```
provared-gateway repair --config gateway.json --agent patching
provared-gateway repair --config gateway.json --agent patching --cut <the number of bytes it showed>
```

The first shows the bytes after the last whole line; the second takes off
exactly those (the number written in digits), keeping them in
`<book>.cut-<time>`. Where the bytes are a whole entry that lost only its
line ending, the first says so, and `--end-line` puts the line ending back
instead. Start the gateway: the
call whose stub was in the cut line, if any, is listed for the
administrator to acknowledge.

## The gateway's countersignature, and its own copy

**When the gateway countersigns.** Where the settings give it a key set of
its own (`gateway`), and an agent's slip names the gateway in `with` (an
entry under the gateway's id, `gateway` unless the settings give another,
with the gateway's keys), every stub of that agent names the gateway's id
in `with`, and the gateway countersigns each call of that agent which it
lets through, to whichever upstream. The upstreams' own entries in the
slip are left for the upstreams' own keys. A stub then does not name the
upstream: the gateway's copy does. It is the countersignature
the format already defines (format description, section 6), made with the
library's `countersign`, and nothing new: `{"stub", "type":
"provared.countersignature.v0", "when"}`, signed by the gateway's Ed25519
and ML-DSA-87 keys, which a checker holds against the keys the slip gives
for the party the stub names, here the gateway. It is made after the upstream answered (or
did not), over the stub that names the answer's or the error's
fingerprint, and the countersignature goes on the stub's line in the book.
What it says: the gateway let this call through to the upstream under this
slip, and what the stub names by fingerprint is what was sent and what
came back, or that nothing came back. It does not say that the upstream did
the work, or that it took the call (an error status is still "what came
back"). A stub written when the administrator acknowledges a call (above)
is countersigned then, where the slip the call was sent under names the
gateway: the stub is dated when the call was sent, its countersignature
when it was acknowledged.

The slip should require a countersignature for every action (`"requires":
[{"need": "countersignature"}]`): then every receipt in the book that
lacks the countersignature of the party it names is a finding
(`countersignature-missing`). The gateway warns, at start and in `check`,
where the slip does not require it for every action, and countersigns
anyway; where the slip does not name the gateway; where it names the
gateway's id with other keys; and where it gives the gateway's keys under
an upstream's service. The gateway does not countersign under an
upstream's service, since its countersignature would read as the
upstream's. For an agent whose slip names the gateway, no upstream is
asked to countersign (its `countersign` setting is not used for that
agent). For an agent whose slip does not, nothing changes: the upstream
countersigns where it says it can, under its own entry, and otherwise the
receipt is one-sided.

The gateway does not start where a slip names the gateway's own keys as the
agent's keys: its countersignature would then add nothing.

**Its own copy.** Where the gateway has its own keys, it keeps for each
agent a copy apart from the book, only ever added to, in the form the MCP
executor's copy has: one line for each step of a call, each numbered from 0
and tagged under the agent's copy key (32 random bytes, made at the first
start). The tag is HMAC-SHA-256 (RFC 2104) of the agent's name in UTF-8,
one line feed (0x0A), then the line's JSON text in UTF-8, written in
base64url without padding; a line of the file is the tag, one space, then
the JSON text. The journal's lines are tagged the same way under the
journal key, so the copy key, the journal key and the other files of one
agent must each be a file of its own (`check` and the start refuse
otherwise). A line added or changed by someone without the key does not
check, and a line taken out, put twice or moved is seen by the numbers.
The lines:

- `sending`: on the disk before the call goes to the upstream (and before
  the journal's line): the call's identifier, the slip, the upstream, the
  action, the amount, the service and the fingerprints the stub names
  before the call;
- `done`: once the stub is in the book, with its fingerprint, whether it was
  countersigned, and the countersignature's fingerprint; where the book
  file could not be written, with the documents added after the call and no
  stub;
- `refused`: a call not sent, with the reason, the codes and the denial's
  fingerprint;
- `set-aside`: a call the administrator set aside.

The gateway writes no `withdrawn` line: a call with a `sending` line and no
receipt is never taken as not sent. `compare` lists by name any such line a
copy holds.

At a start, a call the copy shows as sent and not finished is settled by a
stub the book holds for it only where there is one such stub, it is the
call the `sending` line shows (the same slip, action, amount and service,
the line's documents first, then only documents of an outcome), and, where
the call was sent naming the gateway under a slip that names the gateway's
id with keys (its present keys or any others, such as keys it held
before), it carries a valid countersignature of the gateway. The copy then notes it `found-in-book`, with its countersignature's
fingerprint. Any other such stub stops the agent (`receipt-not-matching`):
the call is listed for the administrator, can only be set aside, and never
gets a stub of the gateway's. At a start the gateway also warns where the
book holds receipts naming the gateway that the copy does not know (a copy
taken away whole, or put back from elsewhere).

It holds names, times, codes and fingerprints: never an address, a body,
an answer or a credential. A copy line that cannot be written stops that
agent (`503`, `agent-stopped`), as a book file that cannot be written does,
and a call whose `sending` line is not on the disk is not sent. The gateway
does not start where a copy holds lines and its key is missing, ends
part-way through a line, has no line that checks under its key, or is not
whole; it says which, and never makes a new key for a copy that holds
lines.

**Where it should live.** The copy counts only where the agent's side
cannot change it: run the gateway under a user of its own, and keep the
copies, their keys and the gateway's key file in a folder that user alone
can write.

**The comparison.**

```
provared-gateway compare --config gateway.json --agent patching [--book <file>] [--sealer <fingerprint>]
```

It reads the agent's copy and its book, asks nobody, and prints in JSON,
as the MCP executor's `compare` does, what it finds for each call the copy
shows: `matched` (the receipt in the book is the one the gateway wrote, it
is the call the copy's `sending` line shows, and it carries the
countersignature the copy records), `differs` (the book holds a receipt for
the call, but another, or one that is not the call the `sending` line
shows: `why` says which), `countersignatures` (a receipt the copy says the
gateway countersigned whose countersignature is missing, does not check, or
is another than the one the copy records; for a stub written at a later
start, whose `done` line names no stub, one missing or not checking),
`moreThanOne` (more than one
receipt for one call), `missing` (the gateway sent the call and wrote its
receipt, and the book has none), `notWritten` (the gateway could not write
the receipt to the book: its own stop), `unfinished` (sent, and the gateway
stopped before the receipt), `setAside`, `withdrawn`, `refused` (with
whether the denial is in the book) and `denialsMissing`; and `notInCopy`:
receipts in the book that name the gateway, which the copy does not know.
Each call is listed by its identifier. A call is found in the book by its
`gateway.call` document. The summary says too whether the copy has a
problem (a line that does not check, a number out of order, a cut last
line) and whether the book was fully checked and is within its slips. The
two agree only where none of these is found, the copy has no problem, and
the book has no problem, was fully checked and is within its slips. It ends
with 0 where they agree, 3 where the calls set aside are the only
disagreement, and 1 otherwise. The recorder whose seals the book must hold
is the one `--sealer` names, or else the one of the settings' key file. It
reads no key file of the gateway: the gateway's id is enough, since the
book's own check holds each countersignature against the keys the slip
gives. It takes `--config`, `--agent`, `--book` and `--sealer` only, and
refuses any other option.

It cannot find a call that never went through the gateway, a call that
matches no rule where `"unlisted"` is `"forward"` (sent with no receipt and
no line in the copy; the gateway warns of this setting at start and in
`check`), whether an upstream did what its answer says, a copy changed by
whoever holds the copy key, or a copy cut at its end; and it does not look
at receipts that do not name the gateway and name no call of the copy.

## Sealing, and what the gateway says about itself

```
PROVARED_GATEWAY_ADMIN_SECRET=<secret> provared-gateway seal --config gateway.json --agent patching
PROVARED_GATEWAY_ADMIN_SECRET=<secret> provared-gateway status --config gateway.json
provared-gateway seal --config gateway.json --agent patching --offline
```

`seal` asks the running gateway to seal an agent's book now, with the
recorder's three keys (`POST /provared/seal`). `--offline` opens the book
itself, for a gateway that is stopped; never use it while one is running
on the same book. `status` (`GET /provared/status`) gives, for each agent,
the slip's fingerprint, the number of entries and bytes in the book, the
last seal, whether the book as it stands passes its check, the calls
waiting and any calls without a receipt; and, where the gateway has its own
keys, the fingerprint of its key set (`countersigner`) and its id in a
slip's `with` (`id`), and for each agent whether it countersigns the
agent's calls (`countersigns`: true where the slip in force names the
gateway) and where its copy is (`copy`). While one of the agent's calls is
with its upstream, the stub writer gives no check, so the check shown is the
last one, with `checkedNow: false` and its time in `checkedAt`. `seal`,
`acknowledge` and `status` ask the running gateway, and need the
administrator's secret; `seal --offline`, `acknowledge --offline` and
`repair` work on the files of a stopped gateway, and need none: whoever can
write those files can do as much. There is no timer: to seal every day, run
`seal` from the system's own scheduler.

**An outside time-stamp on each seal.** Where `recorder.stamp` gives a
time-stamp service (RFC 3161), `{"address": ..., "timeout": ...}`, each
seal's fingerprint is sent to it as the seal is made, and the time-stamp
it gives goes beside the seal in the book, in `stamps`. `address` begins
`http://` or `https://` and holds no user name, password, query or
fragment; `timeout` is from 100 to 20,000 milliseconds, 5,000 if left
out. Given, it must be such an object: `null`, `""` or `false` is
refused, as by `check`. No service is named by this package: the address
is yours to choose. The request and the check are the library's
(`provared/net/timestamp`, in `provared` 0.9.0 or later; with an earlier
release `check` says so and the gateway does not start): the answer is
read up to 12,544 bytes and within the time limit, a redirect is not
followed, and the time-stamp is kept only if the library's `checkStamp`
passes it for this fingerprint, it carries the number used once that was
sent, and the time it states is within 300 seconds of this computer's
clock, no more than 300 seconds before the seal's own `when`, and no more
than 300 seconds before the latest time a service's time-stamp gave a
seal before it in the book. Anything else costs no seal: the seal goes into the book
without a time-stamp, the answer to `seal` gives `stampProblem` (its code
and why), the command prints it, and the log has a `stamp-not-given`
event. A seal that carries one answers `stamped: true` and `stampedBy`,
the fingerprint of the certificate that signed the time-stamp; the
command prints it, and `status` shows it with the last seal. The service sees
the seal's fingerprint, this computer's address and when it asked; nothing
of the book. While it is asked, the agent's calls wait, as for the seal's
own signatures. Without `recorder.stamp`, nothing is asked and nothing
changes.

The check of the answer shows that the time-stamp was made for this seal,
not who made it: over plain `http:`, anyone between this computer and the
service can answer in its place with a key of their own. `"authority"`
in `recorder.stamp` names the certificate the service signs with: its
fingerprint, or a list of up to 16, in the form a checker names a trusted
service (`stampServices`): the SHA-256 of the certificate in base64url,
43 characters. A time-stamp signed by any other is then not kept
(`stamp-not-given`, naming the fingerprint that signed it). Left out, any
signer is taken, and `check` warns where the address begins `http:`.

## Embedding it

```js
import { openGateway } from 'provared-gateway';
import http from 'node:http';

const gateway = await openGateway(settings, { root: '/etc/provared-gateway' });
http.createServer(gateway.handle).listen(8795, '127.0.0.1');
```

In a program, an agent's `privateKeys` (and the recorder's `privateKeys`
with `keySet`) may be given as keys or signers in memory in place of
`keys` or `signers`. `gateway.seal(name)` and `gateway.status()` do what
the commands do. `gateway.copyOf(name)` gives where an agent's copy and its
key are, with the gateway's id (`service`), and `compareCopyWithBook` (from
`provared-gateway/compare`) does what `compare` does. A program that uses `handle` with its own server must
refuse websocket upgrades and `CONNECT` itself, as `listen` does.

## What it does not do, and what it does not prove

- **Calls that do not go through it.** It proves nothing about them. Take
  the credentials away from the agent, and block other routes at the
  network.
- **A wrong rule names a call wrongly.** The action name comes from the
  rules file, not the agent: a better position than a hook in the agent's
  own software, but a rule that names a delete as a read makes the record
  say "read". `provared-gateway check` shows what each rule maps to, and
  warns where a `DELETE` is not named as a kind that destroys, or a call
  that is not a `GET` is named as a read. The gateway does not look into
  the body to tell what a call does, beyond its amount; an upstream that
  takes its action from the body (one address for every operation) needs
  rules the gateway cannot write.
- **One call at a time for each agent.** The stub writer takes one call at
  a time, and holds its turn while the call runs, so one slow upstream
  holds up every other call of that agent. Agents do not wait for one
  another.
- **The gateway's countersignature is the gateway's word, under a key set
  of its own.** It is a second signature, kept with a second record (the
  copy), not a second witness: the same gateway holds the agent's keys and
  its own, so whoever controls the gateway's computer can sign with both.
  It shows more than the agent's signature alone only so far as the
  gateway's key file and copy are kept where the agent's side cannot reach
  them (the agent's keys can be held in a key service, through signers);
  the gateway's own keys are read from a key file only in this version.
  In the book it is the countersignature of the party the stub names, the
  gateway, under the gateway's own entry in the slip: it does not say that
  the upstream took part. A countersignature by the upstream itself, where
  the upstream can give one, is a record of another system.
- **The gateway's keys are not changed for you.** Where its key file is
  replaced, a slip that names the old keys no longer names the gateway's:
  the gateway does not countersign under it, so where it requires a
  countersignature its calls are refused (`countersignature-missing`) until
  a new slip names the new keys. A call sent under the old keys and
  acknowledged after the change is written one-sided, so the book is then
  not within its slips where that slip requires a countersignature; and
  where that stub reaches the book while the journal or the copy cannot say
  so, it does not settle the call when the gateway looks again (a one-sided
  stub under a slip that names the gateway's id with keys), and the call
  can then only be set aside. A stub countersigned with the old keys still
  settles such a call. There is no setting for the keys the gateway held
  before.
- **Every receipt is one-sided** unless the gateway or the upstream
  countersigns. A one-sided stub is the gateway's word. The fingerprints of the request and
  of the answer show that content matches, not that it was the same call;
  only an identifier (`provared.event-id`, `provared.request-id`,
  `provared.trace-id`) picks out one call, and only where the upstream keeps
  it in its own log.
- **A credential inside the body** is not removed: the gateway does not
  rewrite bodies. The agent should hold none.
- **Large or streamed bodies, and long-lived connections** are refused in
  this version: bodies over `bodyLimit`, answers that are a stream of events
  (`text/event-stream`), websockets and `CONNECT` tunnels. Bodies are read
  whole into memory, up to the limit.
- **Paths are matched whatever their case** by default. An upstream that
  tells `/Admin` from `/admin` should say `"caseSensitive": true`.
- **A path with or without a final `/`** matches the same rule, and is
  sent on as the agent wrote it.
- **The gateway listens on plain HTTP.** It has no TLS of its own: listen
  on 127.0.0.1, or put it behind a server that ends TLS. The agents'
  secrets cross the connection in the `Authorization` header.
- **Agents sign in with a secret only.** Client certificates are not built.
- **The keys and the credentials on the gateway are now the prize.** Keep
  the agents' keys in a key service through signers where you can. The
  recorder's sealing keys are on the gateway in this version (a central
  sealer, away from the gateway, is later work).
- **The secrets are kept as SHA-256 hashes.** A short secret could be found
  from its hash; use the ones `provared-gateway secret` makes (32 random
  bytes).
- **No feed to the application yet.** Each agent's book is a file on the
  gateway's disk, appended line by line, written by the gateway alone. A
  feed that hands new lines to the application (step 3 of the plan) is not
  built; an uploader can read the file.
- **Writing the book file is retried for up to ten seconds** where Windows
  holds it busy (a virus scanner, a program reading it). The gateway waits
  meanwhile, for every agent: the writing is done in one step.
- **A call whose receipt cannot be written after it was sent** stops that
  agent, is noted in the log, and the agent is told what the upstream
  answered. The receipt is then missing from the book, and the next start
  asks the administrator about it, as above.
- **A gateway stopped while a call was out** leaves that call with no
  receipt until the administrator acknowledges it, and the receipt then
  written says only that the outcome is not known. A stop part of the way
  through writing a line can leave a book file that does not end with a
  whole line; `provared-gateway repair` takes it off, as above.
- **Protect the journal and its key as the key files are protected.** The
  tag means that a program that can write the journal, and cannot read the
  journal key, cannot make the gateway write a stub of its choosing: a line
  it adds or changes is never acted on, only shown. It does not stop such a
  program from deleting lines, or the whole journal (a call then loses its
  question at start, as it would with no journal), nor from putting back an
  earlier genuine line (its call is then done where the book holds its
  stub, and otherwise is a call that was sent). A program that can read the
  journal key can write lines the gateway takes as its own, as one that can
  read the agent's key file can write stubs. The journal key is not the
  agent's signing key, and signs nothing in the book.
- **A call that matches no rule, or that the gateway refuses for its body,**
  is written as a denial with `source` `rule`. These refusals are not
  written, because the gateway cannot then tell, or name, what was asked,
  or because it is not taking the agent's calls: sign-in (`not-signed-in`),
  the address (`address-refused`), a body that could not be read
  (`body-not-read`), a websocket or tunnel (`upgrade-refused`), a header
  it will not pass (`header-refused`), too many waiting calls or bytes
  (`too-many-waiting`, `too-much-waiting`), and a stopped agent
  (`agent-stopped`). The log notes them.
- **Redirects are handed on.** The gateway does not follow them, and does
  not rewrite `Location`. An agent that follows one to an address it can
  reach goes round the gateway; block that at the network.
- **The key files are written "for the owner alone"** (mode `600`). On
  Windows that mode has no effect: set the folder's own access rights.
- **The gateway's copy** is only as safe as the folder it is in. A copy cut
  at its end is not seen (nothing in a line says it is the last), and
  whoever can read the copy key can write lines the gateway takes as its
  own. A call forwarded with no rule (`"unlisted": "forward"`) has no line
  in the copy, as it has no receipt. The copy is not shipped anywhere else
  in this version.
- **Two agents may not share a secret, or a book, a journal, a list of
  calls set aside, a journal key, a key file, a copy or a copy key**, compared as "Agents"
  above says: the gateway does not start, and `check` says so. A file that
  does not exist yet is compared by its path alone.
- **The log** holds the action names, the status codes, the stubs'
  fingerprints, the names of removed credentials and, for calls forwarded
  with no rule, the method and the path without the query. Never a body, a
  query value, a credential or a secret.

## Working from a copy of the repository

The gateway names its library `provared`, as it is named when installed
from npm. The tests always run against the repository's own library,
whatever `node_modules` holds (`test/local-library.mjs`):

```
node --disable-warning=ExperimentalWarning --test gateway/test/*.test.mjs
```

To run the command on the repository's own library:

```
node --import ./gateway/test/local-library.mjs gateway/bin.mjs check --config gateway.json
```

The tests start a made-up upstream and a made-up agent on 127.0.0.1, sign
slips with the library's development stand-in for a passkey, and reach
nothing outside the computer.

## Licences

The code is under the Apache License 2.0; this file is under the Creative
Commons Attribution 4.0 International licence. Copyright 2026 Pavel
Izmaylov.
