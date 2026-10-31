# provared-mcp-executor: the design

An **executor**, in the words of the Internet-Draft
`draft-izmaylov-agent-permission-receipts-02` (Section 2), is "software,
other than the agent, that takes actions for the agent or holds what they
need, such as a credential, and refuses an action that its check of the
permission does not allow". This package is an executor for tool servers
that speak the Model Context Protocol (MCP). This document describes the
whole executor and says which part stage 1 builds.

Evidence, not a verdict. The record this executor writes shows what went
through it. A tool the agent can reach without it leaves no trace here.

## 1. What it is for

An agent (a program driven by a language model) calls tools on MCP servers:
read a file, change a setting, place an order. The person who runs the
agent wants three things that the agent's own log cannot give:

1. the agent cannot act beyond a permission the person signed, because the
   credentials the tools need are not in the agent's hands;
2. every action the agent did take has a signed receipt, countersigned by
   a party that is not the agent;
3. an action the agent took and left out of its log can be found.

The executor gives all three for the tools behind it. It gives none of them
for a tool the agent can reach some other way.

## 2. Where it stands

```
agent's MCP client  ──stdio──►  executor  ──stdio──►  real tool server
   (the agent)                 holds: the agent's keys,
                                      the executor's keys,
                                      the server's credential,
                                      the book (agent's log),
                                      the executor's own copy
```

The agent's MCP client starts the executor as if it were the tool server
(the client's settings name `provared-mcp-executor stdio --config …` where
they named the server). The executor starts the real server itself, with
the credential in the server's environment, and passes JSON-RPC messages
between the two. The agent never sees the credential and never writes a
receipt: the executor does both.

## 3. Sources, as read on 31 October 2026

- The MCP specification, revision 2026-07-28 (the latest), at
  modelcontextprotocol.io/specification/2026-07-28:
  - stdio transport: "Messages are delimited by newlines, and MUST NOT
    contain embedded newlines"; "The server MUST NOT write anything to its
    stdout that is not a valid MCP message"; "The client MUST NOT write
    anything to the server's stdin that is not a valid MCP message"; the
    server "MAY write UTF-8 strings to stderr for any logging purposes";
    shutdown: the client closes the input stream, waits, then forcibly
    terminates; "Servers SHOULD exit promptly when their standard input is
    closed"; on stdio, cancellation is a `notifications/cancelled`
    notification, and "Servers SHOULD stop work on a cancelled request as
    soon as practical and MUST NOT send any further messages for it";
    "If the server process exits unexpectedly, the client SHOULD restart
    it."
  - Base protocol: "Requests MUST include a string or integer ID", "the ID
    MUST NOT be null"; error codes -32768 to -32000 are reserved and "New
    error codes for purposes not defined by this specification SHOULD be
    allocated outside the JSON-RPC reserved range"; every request carries
    `_meta.io.modelcontextprotocol/protocolVersion` and
    `clientCapabilities`; `_meta` keys with a vendor prefix such as
    `red.prova/` are allowed ("Any prefix where the second label is
    `modelcontextprotocol` or `mcp` is reserved").
  - Versioning: this revision has no `initialize` handshake ("There is no
    negotiation handshake. Every request carries its protocol version");
    revisions 2025-11-25 and earlier ("legacy") do; a dual-era server
    serves both; a client probes with `server/discover`.
  - Tools: `tools/list` (paginated; the set "MAY be empty"), `tools/call`
    with `name` and `arguments`; two kinds of error: protocol errors as
    JSON-RPC errors ("Unknown tool", -32602) and tool execution errors as
    results with `isError: true` ("Clients SHOULD provide tool execution
    errors to language models to enable self-correction"); tool names
    "SHOULD be between 1 and 128 characters" of letters, digits, `_`, `-`
    and `.`; "clients MUST consider tool annotations to be untrusted".
  - Cancellation: "The client SHOULD ignore any response to the cancelled
    request that arrives afterward"; "Implementations SHOULD establish
    timeouts for all sent requests".
  - Authorization: for HTTP only; "Implementations using an STDIO
    transport SHOULD NOT follow this specification, and instead retrieve
    credentials from the environment"; "MCP servers MUST NOT accept or
    transit any other tokens."
- The Internet-Draft `draft-izmaylov-agent-permission-receipts-02`:
  Section 2 (the executor), Section 6 (receipts; "Where an executor is to
  countersign, a receipt names the executor in 'with' … The party beyond
  the executor, if there is one, is then not named in 'with'"), Section 18
  ("An executor's records show the gap only if the action cannot take place
  without the executor, and if the executor keeps them where the agent's
  side cannot change them … A receipt that was never written is found only
  by comparing the executor's own records with the log, which this
  document does not specify"), Open Issue 7 (retries) and Open Issue 8
  (what a countersignature attests).
- The format description `spec/provared-format.md`, sections 6, 17, 20, 27
  and 28, and the library (`src/recorder.js`, `src/stub.js`,
  `src/denial.js`).
- The gateway (`gateway/`), the executor for web calls, as the model for
  credentials held away from the agent, the tagged journal, denials and the
  use of the stub writer.

Nothing from any other project was read (the clean-room rule).

## 4. What stage 1 builds

The stdio transport, whole: start the server; pass everything through;
check and receipt `tools/call`; filter `tools/list`; countersign; keep the
copy; refuse calls the executor cannot record; write the receipt of a call
cut off by a stop at the next start; the comparison of the copy with the
book (`compare`). Not in stage 1: the HTTP transport, several agents on one
executor, sealing, the acknowledgement command, content rules (F-157).

## 5. The flow of one `tools/call`

1. The line is read strictly (X4). A line that cannot be read is answered
   with a JSON-RPC error and goes no further.
2. The tool's name picks the rule (X7). No rule: refused as unlisted, with
   a denial (X15), unless the settings say to forward unlisted tools.
3. The amount, as the rule says (X8). Unreadable: refused, with a denial.
4. The request for the stub writer: the rule's action, the amount, `with`
   = the executor's id, and the documents (X12).
5. The stub writer's `act` (format description, section 20): the check
   before acting over the book so far. Not allowed: a tool result with
   `isError: true` saying why, and a denial with the codes (X14).
6. Allowed: a `sending` line goes into the executor's copy and is made sure
   to be on the disk (X22); only then is the call written to the server,
   with the executor's identifier in `_meta` (X13).
7. The answer: the server's response, an error, no answer within the
   time allowed (X18), the agent's cancellation (X20), or the server's end
   (X21). Whatever it is, the call that was sent gets its stub: the stub is
   signed again with `mcp.result` or `provared.error`, countersigned by
   the executor (X11), and written into the book; a `done` line goes into
   the copy.
8. The server's response goes to the client exactly as the server wrote
   it (X33); where there is none, the client gets a JSON-RPC error of the
   executor's own (X19).

One tool call goes through the writer at a time (X17). Other messages pass
through at once.

## 6. The records

**The receipt (stub).** `action` from the rule; `amount` where the rule
gives one; `with` the executor's id; `details`:

| Name | Fingerprint of | Reserved? |
|---|---|---|
| `provared.arguments` | the call's `arguments`, in the one form of RFC 8785 (`{}` where absent) | yes (section 27) |
| `mcp.tool` | the tool's name | no, a label |
| `executor.call` | the executor's own identifier for the call | no, a label |
| `provared.request-id` | the same identifier, as sent to the server in `_meta` (absent with `callIdInMeta: false`) | yes |
| `provared.trace-id` | the trace-id of a well-formed `traceparent` in the call's `_meta` | yes |
| `mcp.result` | the server's `result`, in the one form of RFC 8785 (added after the call) | no, a label |
| `provared.error` | the error text (added after the call where there was no result) | yes |

**The countersignature.** Signed with the executor's own key set (Ed25519
and ML-DSA-87), which the permission names in `with` under the executor's
id. It is made after the server answered (or did not), over the stub that
names the result's or the error's fingerprint. What it attests, in answer
to Open Issue 8 of the draft: *the executor let this call through to the
tool server under this permission, and what the stub names by fingerprint
is what was sent and what came back, or that nothing came back.* It does
not attest that the tool did the work, nor that the server accepted the
call (an `isError` result is still "what came back").

**The denial** (section 28): source `check` with the codes where the check
before acting refused; source `rule` where no rule names the tool
(`executor.unlisted`) or the amount cannot be read. It names what was
asked for (`provared.arguments`, `mcp.tool`, `provared.trace-id`) and
never `executor.call` or `provared.request-id`, which were never sent.

**The permission** must name the agent's keys as the executor holds them,
and the executor in `with` with its keys. It should require a
countersignature for every action (`"requires": [{"need":
"countersignature"}]`): then, as Section 18 of the draft says, every
receipt in the book that lacks the executor's countersignature is a finding
(`countersignature-missing`), and a receipt that names another party is
`party-not-allowed`. The executor warns at start where the permission does
not require it, and countersigns anyway.

## 7. The executor's own copy, and the comparison

The copy is a file apart from the book, only ever added to, one line for
each call: `sending` (before the call goes to the server; on the disk
first), `done` (once the stub is in the book, with the stub's and the
countersignature's fingerprints), `refused` (with the reason, the codes and
the denial's fingerprint) and `withdrawn` (cancelled before it was sent).
Each line carries HMAC-SHA-256 (RFC 2104) of its text and the executor's
name under the copy key, so that a line added or changed by someone without
the key does not check. It holds names, times, codes and fingerprints:
never a credential, an argument or a result.

**Where it should live.** Section 18 of the draft: the executor's records
show the gap "only if … the executor keeps them where the agent's side
cannot change them". On one computer, that means the executor runs under a
user of its own, and the copy and its key are in a folder that user alone
can write. The settings name the path. Shipping each line on to a place
the executor's operator cannot change either (a sealer, a witness, an
append-only store) is stage 2.

**The comparison** (`compare`): the copy is held against a book. For every
call the copy shows as sent, the book is searched for a stub that names the
executor in `with` and the same `executor.call` fingerprint.

| It finds | Meaning |
|---|---|
| matched | the receipt is in the book, and is the one the executor wrote |
| differs | the book holds a receipt for the call, but not the one the executor wrote |
| missing | the executor sent the call, and the book has no receipt for it: whoever keeps the book left it out, or the book is older than the copy |
| unfinished | the executor sent the call and stopped before the receipt; the next start writes it |
| not in the copy | a receipt in the book names the executor, and the executor's copy does not know it: not written by this executor (its countersignature state says whether it was forged, which cannot succeed without the executor's keys, or left one-sided) |
| denial missing | the executor wrote a denial that the book lacks |

It cannot find: a call that never went through the executor; whether a tool
did what its result says; a copy changed by whoever holds the copy key; a
receipt of this agent that names another service or none. It does not read
the agent's own claims about anything: only the book's records and the
copy's lines.

## 8. What happens when things go wrong

- **The executor cannot record.** Before a call is sent, the copy's line
  must be on the disk and the book file must be as the executor left it.
  If either fails, the call is not sent, the client gets error 1001, and
  the executor takes no more calls until it is started again. If the book
  cannot be written after a call was sent, the client still gets the
  server's answer (the call happened), and the executor stops.
- **The executor stopped with a call in flight.** The copy's `sending` line
  has no `done`. At the next start the receipt is written from that line,
  naming `provared.error` with a fixed text saying the outcome is not
  known, under the permission the call was sent under. Where that
  permission is no longer the one in force, the executor does not start
  and says what to do (put the old permission back for one start). An
  acknowledgement command, as the gateway has, is stage 2.
- **The copy cannot be read** (its key missing with lines present; no line
  checks; a line cut by a stop): the executor does not start.
- **The server ends.** The call in flight gets its receipt with
  `provared.error`; the client gets error 1002; calls still waiting get
  error 1002 and no record (they were never asked of the server); the
  executor exits with the server's code, and the client restarts it.
- **No answer in time** (default 300 seconds): the executor sends
  `notifications/cancelled` to the server, writes the receipt with
  `provared.error`, and answers error 1002.
- **The agent cancels.** A call with the server: the notification is passed
  on, the outcome is settled as not known, the receipt names
  `provared.error`, the client gets error 1002 (which it ignores, as the
  specification says). A call still waiting its turn: nothing is sent, no
  record is written, the copy notes it as withdrawn.

## 9. Threats and limits

- A tool the agent reaches without the executor. Take the credentials away
  from the agent; the executor proves nothing about such calls.
- The agent's environment, which the client passes to the executor. The
  executor passes only a short list of variables to the server; the
  credential comes from the executor's own files. But whoever controls the
  executor's environment and files controls the executor: the agent must
  not be able to write them.
- The action is the rule's reading of the tool's name. A tool that does
  more than its name says is recorded under the rule's action; the
  arguments are fingerprinted, not understood (see section 11).
- Retries (Open Issue 7): each `tools/call` is one receipt, including each
  retry of a multi round-trip call (`resultType: "input_required"`), and
  each counts against totals and counts.
- The clocks: times in receipts are the executor's; a countersignature is
  by the same clock. Seals and outside time-stamps are stage 2.
- One tool call at a time: a long call delays the next.
- A response from the server that is not a message (not JSON, not UTF-8)
  is handed on to the client as it is; a server line over 16 MiB is
  dropped. The call then ends by the timeout.
- `tools/list` is filtered page by page: a page may come back empty with a
  cursor to the next.
- The copy is only as safe as the folder it is in.

## 10. Stage 2: the HTTP transport (design only)

The Streamable HTTP transport (2026-07-28: "each message is an HTTP POST to
a single MCP endpoint; replies arrive as a JSON object or a request-scoped
SSE stream") changes four things:

1. **Who is calling.** On stdio the client is the process that started the
   executor. Over HTTP several agents may call one executor, so each agent
   signs in with a secret of its own, as the gateway's agents do, and has
   its own slip, keys and book. The executor is then an MCP server that
   accepts a token of its own issue, and, as the authorization
   specification requires, "MUST NOT accept or transit any other tokens":
   the agent's `Authorization` header is removed and the upstream's
   credential (a bearer token from a file) is added, exactly as the gateway
   does for web calls.
2. **Framing.** A POST carries one message; the answer is JSON or an SSE
   stream in which the response with the request's id ends the call. The
   executor reads the stream, forwards each event to the client as it
   arrives, and takes the response with the call's id as the outcome.
   Legacy sessions (`Mcp-Session-Id`, the GET stream for server-initiated
   messages, `initialize`) pass through with the session id kept.
3. **Cancellation** is the client closing the response stream. The
   executor then closes its stream to the upstream; the outcome is not
   known, as on stdio.
4. **Mirrored metadata.** The `MCP-Protocol-Version` header and
   `Mcp-Param-*` headers from `x-mcp-header` must agree with the body; the
   executor forwards the body's values and refuses a mismatch as the
   specification says the server would.

The rest is the same: the rules, the check, the documents, the
countersignature, the copy. The gateway's HTTP code (headers never
forwarded, the body limit, the journal) is the starting point.

## 11. F-157: rules on the content of a change (design only)

The question: a call changes a label in a settings file, and the same edit
switches on a `scan` setting. A rule "the `scan` setting in this file stays
false" should stop it before the call is let through.

**Where such rules live.** Three places were weighed:

- *A new member of the permission.* The person would sign the content rules
  with the passkey, and any checker could see them. But it changes the
  format: a slip member that every checker must read, and a new kind of
  finding. The plan has a stop on new kinds of record in the core, and a
  change to the slip needs the founder's decision. Not proposed for now.
- *The executor's own settings, named by fingerprint* (recommended). The
  rules are a file of the executor's (`contentRules`), checked before the
  stub writer is asked. Each stub names a label document `executor.rules`
  whose fingerprint is the SHA-256 of the rules file in the one form of
  RFC 8785, so that a reader knows which rules were in force for each call.
  And, with no change to the format, the person can put that same
  fingerprint into the permission's `agent.software` (format description,
  section 4.1: "the agent's program and settings as the person approved
  them"; a statement, shown as such). A checker then shows that the rules
  in force were the ones the person approved, without judging them.
- *A rule in the permission's `never` list.* The list holds names from a
  short shared list of rules of conduct, which a checker cannot test; a
  content rule is not one of them.

**What a rule can test.** Only what the call carries. The executor sees the
tool's name and its `arguments`; it does not see the file, the database or
the service behind the tool. So:

- A rule over the arguments: a JSON Pointer into `arguments`, and a test
  (`equals`, `matches` a pattern, `oneOf`, `notPresent`), for calls to a
  named tool, optionally only where another pointer has a given value
  (`"when": {"pointer": "/path", "equals": "settings.json"}`).
- A rule over content carried whole: where a tool's argument holds the
  whole new content of a file (`write_file` with `content`), the executor
  can parse it (`"parse": "json"`, or a line-based `key = value` form) and
  test a pointer in it: `{"tool": "write_file", "when": {"pointer":
  "/path", "equals": "settings.json"}, "parse": {"pointer": "/content",
  "as": "json"}, "test": {"pointer": "/scan", "equals": false}}`.
- A rule over a partial edit (an `old_string`/`new_string` pair) cannot
  know the file that results without reading the file. The executor could
  read it through the server's own read tool before the write (one more
  call, under the same permission, recorded as a read) and apply the edit
  itself to test the result; between its read and the server's write the
  file may change. This is the one place a content rule needs the
  executor to act, and it is stated as such.

Each refusal by a content rule is a denial with source `rule`, and the
rule's name goes into the executor's log and copy, never into the record
(the record holds the fingerprint of the rules file).

**What such checks can never promise.**

- That the tool did what the arguments say. The rule tests the call; the
  server does the work.
- That the setting stays false by every path. A rule on `write_file` does
  not see a shell tool that edits the same file, a second tool with
  another name, a change split over two calls each of which passes, or a
  file written under another name and moved.
- That the content was read as the server reads it. A JSON file with a
  repeated member, a comment, a byte-order mark or an encoding the
  executor's parser does not share can read one way here and another
  there (the gateway refuses repeated and folded names for the same
  reason; a content rule must refuse what it cannot read exactly).
- That a pattern over text catches a meaning. `scan: false` can be written
  `scan:false`, `"scan": !0`, or set by a line that the pattern does not
  match.
- Anything about a call to a tool the rule does not name, or a tool whose
  arguments are not plain data.

A content rule is a help to the person who runs the agent, like the check
before acting: nothing in a record shows that it was made, beyond the
fingerprint of the rules file that the stub names.

## 12. Stage 2 and later

- The HTTP transport (section 10) and several agents on one executor.
- An `acknowledge` command for a call sent under a permission no longer in
  force, as the gateway has.
- Sealing the book on a timer or by command, with the recorder's three
  keys; seals held elsewhere and witnesses (library 0.6.0).
- The copy shipped line by line to a place the executor's operator cannot
  change (a sealer, a witness, an append-only store).
- Content rules (section 11), once the founder has chosen where they live.
- Keys held in a key service, through the library's signer interface.
- A reserved document name for a tool's result, if the founder decides the
  format should have one; until then `mcp.result` is a label.
- Listing in the MCP registry, once a published version exists.

## 13. The choices, numbered for review

Each is what, why, and the other way. None changes a record or a rule of
the format: the executor writes ordinary stubs, countersignatures and
denials.

**X1. A package of its own, `mcp-executor/`, named `provared-mcp-executor`,
depending on `provared ^0.6.0`.** Two files are copies of the gateway's
(`files.mjs`; `test/local-library.mjs`), held identical by a test. Why: the
package works by name once installed; copying keeps the two executors from
depending on each other. The other way: an export from the gateway
package.

**X2. Stage 1 is stdio, and the executor is itself started by the agent's
client and starts the server.** Why: that is how every MCP client already
starts a stdio server, so the executor is put in place by changing one
line of the client's settings. The other way: a long-running proxy the
client connects to over a socket (the specification allows the stdio
framing over any byte stream); stage 2 if wanted.

**X3. Everything but `tools/call` and `tools/list` passes through
unchanged, in both directions.** `server/discover`, `initialize`, `ping`,
resources, prompts, progress and log notifications, a legacy server's own
requests to the client (sampling, elicitation) and the client's answers to
them: each line is handed on as it was written. Why: the executor then
needs no knowledge of either era's handshake and does not have to follow
every revision; what it does not read it cannot get wrong. The other way:
to speak MCP to each side and rebuild each message; more code in a
security-critical place.

**X4. A line from the client is read strictly, and a line that cannot be
read is answered with a JSON-RPC error and not forwarded.** Refused: not
UTF-8; not JSON; a list (a batch); not an object with `"jsonrpc": "2.0"`;
a member name given twice anywhere in the message; an id that is not text
or a whole number; a message that is neither request, notification nor
response; `params` that is not an object. Why: the method and the
arguments the executor reads must be the ones the server acts on. A reader
that takes the first of two `method` members, or that still reads batches
(revisions before 2025-06-18 had them), would act on a `tools/call` the
executor never saw. The other way: forward what cannot be read and let the
server refuse it.

**X5. A line from the server that cannot be read strictly is handed on to
the client as it is.** Why: the server is the side the executor acts for;
the client judges its answers, as it would without the executor. A line
over the limit is dropped and logged; a call waiting for it ends by the
timeout.

**X6. A line of 16 MiB at most, both ways.** Why: a bound on memory; a
tool result larger than that is rare. The other way: no limit.

**X7. Rules by tool name: `tools: {"<name>": {"action", "amount"}}`.** The
tool's name alone picks the action; nothing the agent says does. A name is
accepted only in the specification's form (1 to 128 letters, digits, `_`,
`-`, `.`); any other is refused with -32602. Why: the record's action is
the executor's reading, not the agent's; names outside the form (spaces,
control characters, `../`) would make logs and rules ambiguous. The other
way: patterns over names; not built, exact names are plainer.

**X8. The amount: a fixed value, the whole number at a JSON Pointer in
`arguments`, or the length of the list there.** Where the amount is read
from the arguments, an object that names one member twice once folded
(`total` and `TOTAL`; the long s and `s`; the Kelvin sign and `k`) gives
no amount and the call is refused, as the gateway refuses such bodies.
Why: a server written in a language whose JSON reader folds names could
act on the other value. The other way: trust the exact names.

**X9. The executor refuses to start unless the permission fits it.** The
slip's `agent.keys` must be the keys the executor holds for the agent; the
slip's `with` must name the executor's id (`service`, default `executor`)
with the executor's own public keys; the slip's passkey must be in
`agent.issuerKeys`. A slip that does not require a countersignature for
every action gives a warning, not a stop; a rule whose action the slip
does not list gives a warning. Why: a receipt under the wrong keys, or a
countersignature with keys the slip does not name, would fail its check
for every reader. The other way: start and let every call be refused.

**X10. The executor holds the agent's keys and writes the receipts, as
the gateway does.** Why: an agent that holds its own keys could write, or
not write, whatever it likes; held by the executor, the receipt is written
by the party that also refuses. The other way: the agent keeps its own
stub writer and asks the executor only to countersign; that needs a
protocol between the two and gives the agent the choice of writing no
stub. Kept as a stage 2 option for agents that already record.

**X11. The executor countersigns every stub with a key set of its own,
after the server answered, over the stub that names the result.** See
section 6 for what it attests. Why: a countersignature before the outcome
would say less, and the stub writer signs the stub again after the call in
any case (`detailsAfter`), so the countersignature can cover the final
stub at no extra cost. The other way: countersign before sending, as a
record that the executor let the call through; it would then not cover
what came back.

**X12. The documents a stub names** (section 6). `mcp.tool`, `mcp.result`
and `executor.call` are labels, not reserved names, because reserving a
name is a change to the format for the founder (section 27 lists seven).
`mcp.result` is the server's whole `result` member in the one form of RFC
8785, because a tool's result has no other canonical text. The other way:
name only the reserved documents; then nothing in the stub binds the
answer.

**X13. The executor's identifier for the call goes to the server in
`params._meta["red.prova/call-id"]`, and the stub names it as
`provared.request-id`.** Why: section 27 says the best binding to a
system's own log is an identifier both sides keep; a server that logs
`_meta` can be matched line for line. The prefix follows the `_meta`
naming rules (reverse domain, the second label not `mcp`). Off with
`callIdInMeta: false`, for a server that refuses unknown `_meta`; the stub
then names `executor.call` alone. The other way: tell the server nothing.

**X14. A call the check before acting refuses is answered as a tool
execution error (`isError: true`), not a JSON-RPC error.** The text says
"Not taken by the Provared executor" and why; `_meta` carries
`red.prova/refused`, `red.prova/codes` and `red.prova/denial`. Why: the
specification says tool execution errors are what a model can act on
("self-correction"); a refusal by the permission is something the model
should see and choose another call. The other way: JSON-RPC -32602, which
"models are less likely to be able to fix".

**X15. A tool no rule names is refused and written as a denial
(`executor.unlisted`, source `rule`), and is taken out of `tools/list`.**
`unlisted: "forward"` sends such calls with no receipt and no denial, and
the executor warns that the record then leaves them out; `hideUnlisted:
false` shows them in the list while still refusing them. Why: a tool the
model is not shown is one it does not try; a tool it tries and is refused
leaves a denial. The other way: show everything and refuse.

**X16. `tools/list` is filtered page by page, as the pages come.** A page
may come back empty with `nextCursor`, which the specification allows.
The other way: fetch all pages and answer as one; it changes the
protocol flow and the caching the client expects.

**X17. One tool call at a time goes through the stub writer; other
messages pass at once.** Why: the stub writer takes one action at a time
(library choice 129), and the check before acting must see the previous
receipt. The other way: ask the check first and send calls side by side;
the second call would then be checked against a book without the first.

**X18. No answer within `timeout` (default 300 seconds; 1 second to 24
hours): the executor sends `notifications/cancelled` to the server, writes
the receipt with `provared.error`, and answers error 1002.** Why: the
specification says implementations should have timeouts and cancel on
them; the stub writer would otherwise wait for ever. The other way: no
timeout.

**X19. Error codes of the executor's own: 1001 (the call was not taken
because the executor could not record it, or is stopped), 1002 (no answer:
the time ran out, the agent cancelled, or the server ended).** Why: the
specification asks for new codes outside the reserved range -32768 to
-32000. The other way: -32603 (internal error), which could be mistaken
for the server's.

**X20. The agent's cancellation.** With the server: the notification is
passed on, the outcome is settled as not known at once (the specification
says the server then sends nothing more for it), the receipt names
`provared.error`, the client gets error 1002, and a late answer, if the
server had already finished, is dropped and logged. Still waiting its
turn: nothing is sent, no stub and no denial is written, the copy notes
`withdrawn`. The other way: wait a grace period for an answer after
cancelling; stage 2 could add it, with the late answer's fingerprint in the
copy.

**X21. The server ends: the call in flight gets its receipt with
`provared.error`, the client error 1002; calls still waiting get error
1002 and no record; the executor exits with the server's code.** Why: the
specification says the client restarts a server that exits; a call never
asked of the server has nothing to record. The other way: restart the
server inside the executor; the client would then not know.

**X22. The copy** (section 7): tagged lines, `sending` made sure to be on
the disk before the call goes; never emptied. Why: the gateway's journal is
cleared at a clean start, because it is for recovery; the executor's copy
is also the record Section 18 of the draft speaks of, so it is kept whole.
Default path beside the book; the README says to put it under another
user.

**X23. A call sent and never given its receipt is given one at the next
start, from the copy, with a fixed error text, under the permission in
force; where the call was sent under another permission, the executor does
not start and says what to do.** Why: in a stdio session there is no
administrator to acknowledge, as the gateway's has; the copy's tagged line
is the executor's own statement that the call was sent, and the receipt
says plainly that the outcome is not known. The other way: the gateway's
acknowledgement step; an `acknowledge` command for the other-permission
case is stage 2.

**X24. The copy key missing while the copy holds lines, no line that
checks under the key, or a last line cut by a stop: the executor does not
start.** Why: as for the gateway's journal, a new key would leave every
line unchecked, and a cut line hides what was sent last.

**X25. Credentials come from a file, from the executor's own environment,
or (warned against) from the settings; the server's environment is built
from a short list of variables plus the credentials; nothing else of the
executor's environment is passed on.** The default list: `PATH`,
`PATHEXT`, `SYSTEMROOT`, `COMSPEC`, `WINDIR`, `TEMP`, `TMP`, `HOME`,
`USERPROFILE`, `LANG`, `LC_ALL`, `TZ`. Values are read at start, so a
missing one stops the start, and never logged. Why: the client passes the
agent's environment to the executor, and the server must not inherit it.
The other way: inherit everything but a block list.

**X26. The book file is append-only and checked to be as the executor left
it before each call; a change by someone else stops the executor (error
1001 to the client).** Why: as the gateway (library choices 215, 302).

**X27. A stopped executor stays stopped until it is started again.** It
still passes other messages through, so the agent can list tools and read
resources, and every `tools/call` gets error 1001. Why: a stop means the
record cannot be trusted to continue; a person looks. The other way: try
again after a while.

**X28. `compare`** (section 7): by the `executor.call` fingerprint, against
the book's stubs that name the executor in `with`. Exit code 0 only where
everything agrees and every copy line checks.

**X29. The server's standard error passes through to the executor's; the
executor's own log is JSON lines on standard error; standard output holds
MCP messages only.** Why: the specification's rules for stdio. Never a
credential: the log names variables, not values.

**X30. Shutdown: when the client closes the executor's input, the executor
closes the server's input, waits `shutdownWait` (default 5 seconds), then
ends the server; it exits with the server's code.** The specification's
own sequence.

**X31. `initialize` and `server/discover` pass through with nothing added.**
The other way: add the executor's name to `serverInfo` or `instructions`;
the client should see the server as it is, and the executor's presence is
in the client's own settings.

**X32. Absent `arguments` are fingerprinted as `{}`.** Why: RFC 8785 needs
a value, and a call with no arguments means an empty object to every
server. The other way: no `provared.arguments` document.

**X33. The server's response goes to the client exactly as the server
wrote it, result or error; an `isError` result is still a result and gets
`mcp.result`; a JSON-RPC error from the server gets `provared.error` with
the error's JSON as the text.** Why: the agent sees its server unchanged;
nothing about the executor is added to a good answer. The other way: add
the stub's fingerprint to the result's `_meta`; stage 2 could, as the
gateway's `Provared-Stub` header does.

**X34. `keys` prints what goes into the permission (the agent's keys, the
executor's `with` entry, and `requires`); `check` prints a report with no
credential in it; `stdio` runs; `compare` compares.** Named as the
gateway's commands are.

**X35. The test workflow runs the package's tests (`mcp-executor` added to
the JavaScript packages matrix), and ESLint covers the folder.**

**X36. The tests use a made-up MCP server written for them
(`test/fake-server.mjs`), started as a real process, with tools that
answer, fail, err, stall, ask the client something, or end the process.**
Nothing is sent over the network; nothing of anyone else's is run. A test
that starts the executor as a process ends it, and so the server, on
every path (success, failure, time limit), and the test script gives each
test 60 seconds: a child left alive would keep the test process alive.
