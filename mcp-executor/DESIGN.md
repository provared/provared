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

Over HTTP (section 10) the executor is itself an MCP server, in front of
one upstream HTTP MCP server, for several agents at once:

```
agent A ──HTTP, secret A──►                   ──HTTP, the upstream's──►  upstream MCP server
agent B ──HTTP, secret B──►  executor          token, from a file
                             holds: each agent's keys, slip, book and copy,
                                    the executor's keys,
                                    the upstream's token
```

Each agent signs in with a secret of its own and has its own slip, keys,
book and copy; the handling of a call is the same code as on stdio.

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
executor, sealing, the acknowledgement command. The rules on the content of
a change (F-157, F-158; section 11) were built next, as the first piece of
stage 2.

## 5. The flow of one `tools/call`

1. The line is read strictly (X4). A line that cannot be read is answered
   with a JSON-RPC error and goes no further.
2. The tool's name picks the rule (X7). No rule: refused as unlisted, with
   a denial (X15), unless the settings say to forward unlisted tools.
3. The amount, as the rule says (X8). Unreadable: refused, with a denial.
3a. The rules on content, where the settings name a rules file (section
   11, X56 to X77): a call that a rule refuses, or whose content a rule
   cannot read exactly, is refused with a denial that names the rule.
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
   signed again with `provared.tool-result` or `provared.error`, countersigned by
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
| `provared.tool-name` | the tool's name, as the client called it | yes (added after 0.6.0) |
| `executor.call` | the executor's own identifier for the call | no, a label |
| `provared.request-id` | the same identifier, as sent to the server in `_meta` (absent with `callIdInMeta: false`) | yes |
| `provared.trace-id` | the trace-id of a well-formed `traceparent` in the call's `_meta` | yes |
| `executor.rules` | the rules file on content in force (its parsed content in the one form of RFC 8785); only where the settings name one | no, a label |
| `provared.tool-result` | the server's `result`, in the one form of RFC 8785 (added after the call) | yes (added after 0.6.0) |
| `provared.error` | the error text (added after the call where there was no result, or where the result could not be fingerprinted or the answer not read) | yes |
| `executor.written-late` | a fixed text; only in a receipt written at a restart, from the copy | no, a label |

`executor.call` and `executor.written-late` are labels. The tool's name
and the tool's result were labels (`mcp.tool`, `mcp.result`) until the
format reserved `provared.tool-name` and `provared.tool-result` (F-158;
section 27), which the executor now writes; so the executor needs a
library later than 0.6.0, and a checker of 0.5.0 or 0.6.0 refuses its
receipts (0.4.0 and earlier read the names as labels).

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
(`executor.unlisted`), the amount cannot be read, or a rule on content
refused. It names what was asked for (`provared.arguments`,
`provared.tool-name`, `provared.trace-id`, `executor.rules`) and never
`executor.call` or `provared.request-id`, which were never sent. A denial
by a rule on content also names `executor.rule`, the fingerprint of the
refusing rule's name (a label), so that whoever holds the rules file can
tell which rule said no.

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
countersignature's fingerprints and the documents added after the call;
or, where the book could not be written, with those documents and no
stub, so that the call stays unfinished), `refused` (with the reason, the
codes and the denial's fingerprint) and `withdrawn` (cancelled before it
was sent). Each line carries its number from 0 and HMAC-SHA-256 (RFC 2104)
of its text and the executor's name under the copy key, so that a line
added or changed by someone without the key does not check, and a line
taken out, put twice or moved is seen by the numbers. A copy cut at its
end is not seen: nothing in a line says it is the last; shipping each line
elsewhere (stage 2) is the answer to that. It holds names, times, codes
and fingerprints: never a credential, an argument or a result.

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
| missing | the executor sent the call and wrote its receipt, and the book has no receipt for it: whoever keeps the book left it out, or the book is older than the copy |
| not written | the executor sent the call and could not write its receipt to the book (its own stop): told apart from an omission by the book's keeper; the next start of the executor writes it |
| unfinished | the executor sent the call and stopped before the receipt; the next start writes it |
| not in the copy | a receipt in the book names the executor, and the executor's copy does not know it: not written by this executor (its countersignature state says whether it was forged, which cannot succeed without the executor's keys, or left one-sided) |
| denial missing | the executor wrote a denial that the book lacks |

It cannot find: a call that never went through the executor; whether a tool
did what its result says; a copy changed by whoever holds the copy key, or
cut at its end; a receipt of this agent that names another service or
none. It does not read the agent's own claims about anything: only the
book's records and the copy's lines. It does not agree where the book
itself has a problem.

## 8. What happens when things go wrong

- **The executor cannot record.** Before a call is sent, the copy's line
  must be on the disk and the book file must be as the executor left it.
  If either fails, the call is not sent, the client gets error 1001, and
  the executor takes no more calls until it is started again. If the book
  cannot be written after a call was sent, the client still gets the
  server's answer (the call happened), and the executor stops.
- **The executor stopped with a call in flight.** The copy's `sending` line
  has no `done` naming a stub. At the next start the receipt is written
  from that line, under the permission the call was sent under: with the
  result's or the error's fingerprint where a `done` line without a stub
  holds it (the receipt was made and the book could not be written), or
  else naming `provared.error` with a fixed text saying the outcome is not
  known. Where that permission is no longer the one in force, the executor
  does not start and says what to do (put the old permission back for one
  start). Such a receipt names `executor.written-late`, so that the book
  itself says so: its `when` is the time the call was sent, and its
  countersignature is dated at the restart, so a reader sees both times.
  The founder has kept this automatic late receipt (F-158). An
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
  each counts against totals and counts. A retry's `inputResponses` and
  `requestState` are not bound in the stub: only `arguments` are.
- The executor's own environment and `PATH` are set by the agent's client
  that starts it. A credential read from that environment (`env`), or a
  program found through that `PATH`, is only as safe as the client; the
  settings can name the program by its path and the folders to look in.
- The clocks: times in receipts are the executor's; a countersignature is
  by the same clock. Seals and outside time-stamps are stage 2.
- One tool call at a time: a long call delays the next.
- A response from the server that is not a message (not JSON, not UTF-8,
  a batch or any line that is not one object, or `id` twice at the top
  level) is handed on to the client as it is, matched with no call; a
  server line over 16 MiB is dropped. The call then ends by the timeout,
  with a "no answer" receipt.
- `tools/list` is filtered page by page: a page may come back empty with a
  cursor to the next.
- The copy is only as safe as the folder it is in.

## 10. The HTTP transport, and several agents on one executor

`provared-mcp-executor http --config …` runs the executor as a Streamable
HTTP MCP server (2026-07-28: "each message is an HTTP POST to a single MCP
endpoint; replies arrive as a JSON object or a request-scoped SSE stream")
in front of one upstream HTTP MCP server (`http.mjs`). Four things differ
from stdio; the rest (the rules, the check, the documents, the
countersignature, the copy) is the same code, `callCore` in
`executor.mjs`, which each transport reaches through a small link (X101).

1. **Who is calling.** Each agent signs in with a secret of its own, as the
   gateway's agents do: one `Authorization: Bearer <secret>` header, whose
   SHA-256 the settings hold as `secretHash`, compared in constant time
   (X102). Each agent has its own slip, keys, book, copy and copy key
   (X103); its calls go through its own writer, one at a time, and its
   limits are its own. The executor accepts no other token: the agent's
   `Authorization` is removed, and the upstream is sent the executor's
   credential, a bearer token read from a file, as the gateway does for web
   calls (X105). Headers go on by allow-list (X104). Nothing the upstream
   answers reaches an agent with that token in it: the upstream's headers
   come back by allow-list, a refusal of the token (401, 403) and a
   redirection are not relayed, and every byte sent to an agent is checked
   for the token's text (X105).
2. **Framing.** A POST carries one message, read as strictly as a line on
   stdio (X4): a batch or a shape that is not a message goes no further. A
   request goes to the upstream under an id of the executor's own, as on
   stdio; the answer is one JSON body or a stream of events, each event
   forwarded to the agent as it arrives, and the response under the
   executor's id is the outcome, handed back under the agent's id (X106).
   Legacy sessions pass through: the `Mcp-Session-Id` the upstream gives
   comes back as it is and is owned by the agent that received it; the GET
   stream of server messages, `initialize` and DELETE pass through; another
   agent's request under the session, or an unknown id, is answered 404
   (X108).
3. **Cancellation** is the agent closing the response stream. The executor
   then closes its stream to the upstream, and the outcome is settled as
   not known, as on stdio; the receipt names `provared.error`. The agent's
   own `notifications/cancelled` does the same (X111).
4. **Mirrored headers.** The `MCP-Protocol-Version` header must agree with
   the body's `_meta` value where both are given; the body's value is what
   goes on. `Mcp-Method` and `Mcp-Name` go on only where they are the
   body's `method` and `params.name`. An `Mcp-Param-<name>` header goes on
   only where the upstream's `tools/list` annotated a property of the
   tool's `inputSchema` with `x-mcp-header: <name>` and the call's
   argument at that property's path is the header's value, the Base64
   form decoded first. A header that disagrees, or that the executor
   cannot check, is refused with 400 and -32020 (the specification's
   HeaderMismatch) and nothing reaches the upstream; their absence is not
   refused, and the executor adds none (X110, X117). The specification's
   text on the `Origin` rule was not among the sources of section 3, so
   X109 takes the safest reading and names what is to be checked.

Limits (X107): the agent's body up to `bodyLimit` (10 MiB); an upstream
JSON body or one event up to 16 MiB, as a line on stdio; the executor's
`timeout` on every POST exchange; 256 requests of one agent in flight at
once, beside `maxWaiting` for its calls; an `Origin` refused unless the
settings allow it, and the local address listened on unless they say
otherwise (X109). A stop on request with a call in flight settles the call
as the executor's stop, writes its receipt and answers the agent before the
connections close (X115); a stop without warning, followed by a start,
writes the receipt from the agent's copy before the executor listens
(section 8).

What it does not do: it speaks plain HTTP, so the agents' secrets and the
upstream's token are only as safe as the connection (encryption is
something else's); it binds a session to its agent only while it runs; a
token the upstream encodes before echoing is not seen by the check of
X105; and the credential is kept from an agent only for what passes
through the executor.

## 11. F-157: rules on the content of a change

The question: a call changes a label in a settings file, and the same edit
switches on a `scan` setting. A rule "the `scan` setting in this file stays
false" should stop it before the call is let through. A permission allows
kinds of action; being allowed to change a file is not being allowed to
change everything the file controls.

**Decided (the founder, F-158), and built (1 November 2026; choices X56
to X77).** The rules live in a file of the executor's own, named by the
setting `contentRules`; the file's fingerprint goes into every receipt
and denial as the label document `executor.rules`; the person puts the
same fingerprint into the permission's `agent.software`, so the format
does not change. The code is `rules.mjs`.

**How it is used.**

```json
{
  "version": 1,
  "rules": [
    {
      "name": "the scan setting in settings.json stays off",
      "tool": "write_file",
      "when": { "pointer": "/path", "matches": "**settings.json" },
      "content": { "pointer": "/content", "as": "json" },
      "test": { "pointer": "/scan", "equals": false, "orAbsent": true }
    },
    {
      "name": "settings.json is written whole, never edited in part",
      "tool": ["edit_file", "apply_patch"],
      "when": { "pointer": "/path", "matches": "**settings.json" }
    }
  ]
}
```

A rule names a tool (or several); says which calls it applies to
(`when`: conditions on the arguments, all of which must hold; none means
every call); where the proposed content is in the arguments and how to
read it (`content`: a JSON Pointer, and `json` for an argument that is
text holding JSON, or `value` for one that is the content itself as plain
data; none means the tests are on the arguments themselves); and what
must hold (`test`: conditions, all of which must hold). A condition is a
JSON Pointer (RFC 6901) and exactly one of `equals` (the same JSON value),
`oneOf` (one of a list), `absent` (not present) or `matches` (a pattern
over text: `*` within one path part, `**` across parts, `?` one
character); `orAbsent: true` lets a missing value pass. **A rule with no
`test` refuses every call it applies to.** That is how a person closes a
route the executor cannot judge, such as a tool that carries only a
partial edit.

Before the check before acting, the executor tests the call against every
rule that names its tool, in the file's order. The first rule that refuses
gives the denial: `content-rule` where a test did not hold or a rule with
no test applied; `content-unreadable` where the rule could not read what
it tests exactly. The model is told which rule and what it asked for,
never a value from the arguments. The executor reads no file and keeps no
content: it tests only what the call carries.

**Where such rules live.** Three places were weighed:

- *A new member of the permission.* The person would sign the content rules
  with the passkey, and any checker could see them. But it changes the
  format: a slip member that every checker must read, and a new kind of
  finding. The plan has a stop on new kinds of record in the core, and a
  change to the slip needs the founder's decision. Not proposed for now.
- *The executor's own settings, named by fingerprint* (chosen, F-158). The
  rules are a file of the executor's (`contentRules`), checked before the
  stub writer is asked. Each stub names a label document `executor.rules`
  whose fingerprint is the SHA-256 of the rules file in the one form of
  RFC 8785, so that a reader knows which rules were in force for each call.
  And, with no change to the format, the person puts that same
  fingerprint into the permission's `agent.software` (format description,
  section 4.1: "the agent's program and settings as the person approved
  them"; a statement, shown as such). A checker then shows that the rules
  in force were the ones the person approved, without judging them. The
  executor itself holds the two together at start (X62): where the
  permission states software and these rules are not among it, it does
  not start.
- *A rule in the permission's `never` list.* The list holds names from a
  short shared list of rules of conduct, which a checker cannot test; a
  content rule is not one of them.

**What a rule can test.** Only what the call carries. The executor sees the
tool's name and its `arguments`; it does not see the file, the database or
the service behind the tool. So:

- A rule over the arguments (no `content`): the tests read the arguments
  themselves.
- A rule over content carried whole (`content`): where a tool's argument
  holds the whole new content of a file (`write_file` with `content`), the
  executor reads it as JSON text, or takes it as plain data, and tests
  pointers in it.
- A rule over a partial edit (an `old_string`/`new_string` pair) cannot
  know the file that results without reading the file. Two ways were
  weighed and not built: reading the file through the server's own read
  tool before the write (one more call under the same permission; the
  executor's own view, not the server's; a file on another machine out of
  reach; the file may change between the read and the write), and
  comparing with the last content the executor let through (another route
  may have changed the file since, and the executor would then hold
  content, which nothing of its own holds today). Instead a rule with no
  `test` refuses such calls, and the person makes the agent write the
  file whole (X58).

Each refusal by a content rule is a denial with source `rule` that names
the rules file (`executor.rules`) and the rule (`executor.rule`, the
fingerprint of its name); the rule's name in clear goes into the
executor's log, its copy and the tool error the model is given, never
into the record.

**What such checks can never promise.**

- That the tool did what the arguments say. The rule tests the call; the
  server does the work.
- That the setting stays false by every path. A rule on `write_file` does
  not see a shell tool that edits the same file, a second tool with
  another name, the same file named under another argument the rule's
  `when` does not read, a path written another way than the pattern
  expects, a change split over two calls each of which passes, or a file
  written under another name and moved. An edit by any route that does not
  go through the executor is not seen at all.
- That the content was read as the server reads it. The executor refuses
  what it cannot read exactly (not JSON, a member named twice or twice
  once folded, a number beyond 2^53 - 1, a byte-order mark, a comment);
  but a server that reads the same text more loosely, or in another
  encoding, may still act on something the executor did not see. A file
  type the executor cannot read (YAML, TOML, a line-based form) cannot be
  tested at all: only a rule with no `test` can refuse such a write.
- That a tool's arguments show the resulting file. A tool that takes a
  partial edit, a template, a reference to content elsewhere, or a command
  gives the executor nothing to test; only a refusal outright closes it.
- That a pattern over text catches a meaning. `*` and `**` match
  characters, not files: `**settings.json` also matches
  `my-settings.json`, and a path with a trailing space, a different case,
  a trailing full stop (`settings.json.`, which Windows opens as
  `settings.json`) or a symbolic link is another text (X77).
- That a `when` reads a value of another kind: a `matches` is met only by
  text, so a path given as a list does not match and the rule does not
  apply (X77).
- That a member is named as the program reads it: names in the content
  are compared exactly, so a lone `SCAN` passes an `absent` or `orAbsent`
  test on `/scan` (X77).
- That content nested in content is read: `as: "json"` reads one layer,
  so JSON text inside a JSON string is a string to the rule (X77).
- Anything about a call to a tool the rule does not name, or a tool whose
  arguments are not plain data.
- That the rules were right, or were applied. The record holds the
  fingerprint of the rules file in force and, in a denial, of the rule
  that refused; it does not hold the rules, and nothing in a receipt shows
  that a rule was tested, beyond that the executor that wrote it was
  running those rules.

A content rule is a help to the person who runs the agent, like the check
before acting: nothing in a record shows that it was made, beyond the
fingerprint of the rules file that the stub names. The rule writer has to
know the tool: which argument carries the whole new content, under which
name the path is given, and which other tools reach the same file.

## 12. Stage 2 and later

Built so far of stage 2: the rules on the content of a change (section
11), and the HTTP transport with several agents on one executor (section
10). Still to build:

- An `acknowledge` command for a call sent under a permission no longer in
  force, as the gateway has.
- Sealing the book on a timer or by command, with the recorder's three
  keys; seals held elsewhere and witnesses (library 0.6.0).
- The copy shipped line by line to a place the executor's operator cannot
  change (a sealer, a witness, an append-only store).
- Content read in other forms than JSON (YAML, TOML, `key = value`
  lines), as further values of a rule's `content.as` (section 11).
- Keys held in a key service, through the library's signer interface.
- Listing in the MCP registry, once a published version exists.

## 13. The choices, numbered for review

Each is what, why, and the other way. None changes a record or a rule of
the format: the executor writes ordinary stubs, countersignatures and
denials.

**X1. A package of its own, `mcp-executor/`, named `provared-mcp-executor`,
depending on `provared` 0.7.0 (`^0.7.0`; it was `>0.6.0 <0.8.0` until
0.7.0 was cut, and `^0.6.0` until the reserved names of X12 came).** Two files are copies of the gateway's
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

**X12. The documents a stub names** (section 6). The tool's name and the
server's result are named under the reserved names `provared.tool-name`
and `provared.tool-result` (format description, section 27; they were the
labels `mcp.tool` and `mcp.result` until the format reserved them, under
F-158). `executor.call` stays a label: it is the executor's own identifier,
which no other implementation writes. `provared.tool-result` is the
server's whole `result` member in the one form of RFC 8785, because a
tool's result has no other canonical text. The other way: name only the
documents reserved in 0.6.0; then nothing in the stub binds the answer.

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

**X37. A `done` line of the copy names the stub only once it is on the
disk; where the book could not be written, the line holds what the
executor knew of the outcome and no stub, and the call stays unfinished.**
At the next start the receipt is written from the `sending` line and those
documents. Why: before, such a call was marked done and lost its receipt
for good (the first review's S1). The other way: leave the `sending` line
open with no `done`; then the outcome the executor knew would be lost
too.

**X38. Every request goes to the server under an id of the executor's
own, unique for the session and not guessable, and the answer comes back
under the client's id, spliced into the server's raw bytes.** (As first
built after the first review, only tool calls were renamed, the ids were
a plain count, and the answer was re-serialised; the second review found
both faults, R1 and R2.) Cancellations are renamed the same way, and a
late answer under a settled id is dropped (the last 10,000 settled ids are
kept). Why: a server that answers after a timeout or a cancellation would
otherwise have its answer taken for a later call's that reuses the
client's id (M1); a client that guessed an executor id could settle a
call in flight with another request's answer (R2); re-serialising lost
numbers beyond 2^53 - 1 and the spellings of numbers (R1). The other way:
forward the client's ids and refuse to reuse one; it would refuse honest
reuse.

**X39. A notification whose method is not one of the protocol's own
(`notifications/…`) is dropped and logged.** Why: a `tools/call` sent
without an id would reach the server unchecked (M2). The other way: pass it
on, as a server should ignore it; some do not.

**X40. The executor process ends, with the server's code, when the server
has ended and every receipt is written, whether or not the client still
holds its input open.** Why: the client restarts a server that exits; a
process that stays alive with no server serves nothing (M3).

**X41. At most `maxWaiting` tool calls in progress or waiting (default 16;
1 to 1,000), and at most 256 `tools/list` requests waiting; past either,
error 1001 and nothing written.** Why: calls waiting their turn hold their
bodies in memory (M4). The other way: no cap.

**X42. The program is named by its path; a bare name is looked for in
`server.path` or, with a warning, the executor's own `PATH`; on Windows
`.exe` and `.com` only; one not found stops the start.** Why: the
executor's `PATH` is set by the agent's client, which could then choose
which program receives the credential (M5). The other way: let the
operating system find it, as `spawn` does.

**X43. A result that cannot be written in the one form of RFC 8785 gets
`provared.error` with a fixed text, and the executor logs it.** Why: a
countersigned stub naming no outcome at all would say less than it could
(M6). The other way: name no document.

**X44. Every line of the copy carries its number from 0; a copy whose
lines that check do not run in sequence stops the start.** Why: the tag
alone did not show a line taken out, put twice or moved (L1). Stated: a
copy cut at its end is still not seen.

**X45. `compare` does not agree where the book itself has a problem, tells
a receipt the executor could not write apart from one the book lacks,
makes no copy key, and refuses a `--book` that does not exist.** (L2.)

**X46. A line holding a whole number beyond 2^53 - 1, in an id or anywhere
else, is refused.** Why: two readers hold such a number differently, as the
gateway's rule says (L3). The other way: accept it where it is not read.

**X47. `check` writes nothing: no slip line to the book, no copy key.**
(L4.) Why: a check that changes the folder is not a check.

**X48. A permission that names other services beside the executor gets a
warning.** Why: a receipt that names one of them, written by whoever
holds the agent's keys, would not be a finding (L6).

**X49. The server's lines are read without the rule on whole numbers;
the agent's lines are read with it.** A tool result holding a number
beyond 2^53 - 1 (as the ids of many services are) reaches the client in
the server's own bytes, and the receipt names `provared.error` with the
fixed text RESULT_NOT_FINGERPRINTED, because the one form of RFC 8785
cannot hold such a number. Why: the first fix refused such answers, so the
call timed out and the receipt named a false timeout (R1). The other way:
refuse them; a common case would then never work.

**X50. A server line the executor cannot read as a message, whose
top-level id it can still find, goes to the client under the client's id
as the server wrote it; a tool call then gets a receipt naming
`provared.error` with the fixed text UNREADABLE_ANSWER.** Why: the client
is the judge of its server's answers; the record must still say what the
executor saw (R1). The other way: drop the line and let the call time out,
with a false timeout in the receipt.

**X51. A filtered `tools/list` is the one answer the executor rebuilds,
and it keeps every number as the server wrote it** (read with Node.js's
raw-number reader, written back as those digits). The other way: filter
the raw text; more code for one case.

**X52. Requests other than tool calls that the server never answers are
forgotten past 1,000, the oldest first; tool calls never are.** Why: a
server that never answers would otherwise grow the executor's memory
without bound (R3). Stated: a forgotten request's late answer is handed on
under the executor's id, which the client ignores.

**X53. A receipt written at a restart names `executor.written-late`, the
fingerprint of a fixed text, beside what the copy knew of the outcome.**
Its `when` is the time the call was sent; its countersignature is dated
at the restart. Why: the book itself should say that the executor wrote
the receipt late, not only the executor's copy (X37). The other way: a
reserved document name, which is the founder's to add to the format.

**X54. Vendor-prefixed extension notifications from the client (any
notification whose method does not begin `notifications/`) are dropped
and logged, as X39 says.** Stated here because such notifications exist
in extensions; a later version may allow a list of prefixes.

**X55. A server line with `id` twice at its top level matches no call.**
`topLevelId` scans the whole object and gives nothing where `id` appears
twice, so the line is handed on as it is and the call ends by the timeout.
Why: two readers could take either `id`, and splicing one of them could
show the client the executor's id (the final check's F1). A batch, or any
line that is not one object, is handled the same way (F2).

**X56. The rules on content are a JSON file of the executor's own
(`contentRules`), not part of the settings file and not a member of the
permission.** A file of its own has a fingerprint of its own, which the
person can work out independently (the `keys` command prints it) and
which does not change when another setting does. Why not the permission:
F-158, and section 11. The other way: the rules inline in `executor.json`,
fingerprinting a part of the settings.

**X57. The fingerprint is of the rules file's parsed content in the one
form of RFC 8785 (`argumentsFingerprint`), not of its bytes.** So
spacing, the order of members and a byte-order mark do not change it, and
a person who re-saves the file does not have to sign again; a change to
any rule does. The other way: the file's bytes, which the person could
check with any SHA-256 tool, at the cost of a new signature for every
re-save.

**X58. A rule with no `test` refuses every call it applies to; the
executor reads no file and keeps no content.** A rule can only test what
the call carries whole. For a tool whose arguments carry a partial edit,
the person writes a rule with no test and has the agent write the file
whole through a tool the rules can read. Why not reading the file: the
executor's view is not the server's (a file on another machine; a change
between the read and the write), and it would need read access and a
recorded read for every write. Why not comparing with the last content
let through: another route may have changed the file since, and the
executor would hold content, which none of its records do today.

**X59. Content the rule cannot read exactly refuses the call
(`content-unreadable`): not JSON, a member named twice in one object or
twice once folded (as the gateway folds names: capitals, the long s, the
Kelvin sign), a whole number beyond 2^53 - 1, nothing at the content
pointer, something other than text where JSON text is expected, or a text
over 4,096 characters where a pattern would match it.** The same folding
rule is applied to the arguments themselves where any rule names the
tool. Why: a rule that let through what it could not read would be a rule
that any comment in a file evades, and two readers that read one text two
ways is the gateway's reason too. The other way: let such a call through
with a finding in the log; rejected, since nothing in the record would
show it.

**X60. A pattern is a plain glob: `*` matches any run of characters other
than `/` and `\`, `**` any run of any characters, `?` one character other
than `/` and `\`; nothing else is special and nothing can be escaped.**
Both separators count, so one pattern covers paths written either way: a
`/` or a `\` in the pattern matches either in the text (X73). It is
matched by a table over the pattern's tokens and the text's code points,
with no regular expression, so the work grows only with the tokens times
the text's length; a text over 4,096 characters is not matched (X59), and
a rules file holds at most 20,000 tokens in all (X74). The other way: regular
expressions, which can be slow on chosen input and which ESLint's security
rules flag when built from data.

**X61. Conditions: `equals` (the same JSON value, deeply), `oneOf` (1 to
64 values), `absent` (true), `matches` (a pattern of 1 to 1,000
characters), each at a JSON Pointer (RFC 6901; `""` is the whole value);
`orAbsent: true` lets a missing value pass `equals`, `oneOf` or
`matches`.** A missing value fails `equals`, `oneOf` and `matches` unless
`orAbsent` says otherwise: the content must say so, since the executor
cannot know what the program defaults to. "May not change" was asked for
and cannot be tested without reading the file; it is written as "stays
equal to" the approved value. The other way: a `notPresent` name (the
design note had it); `absent` reads as the other conditions do.

**X62. The permission must state the rules in force, or nothing.** At
start, where the slip's `agent.software` is present and no entry has the
rules file's fingerprint, the executor does not start: the person approved
other rules than these. Where the slip states rules on content (an entry
whose name begins `Content rules of `) and the settings name no rules
file, it does not start either (X72). Where the slip states no software,
it starts with a warning that gives the entry to add. `check` reports `contentRules`
(path, fingerprint, the rules' names, `statedInSlip`); `keys` prints the
`agent.software` entry beside the agent's keys. Why a stop and not a
warning: the slip is the person's signed word on what the agent's software
is, and an executor running other rules would write receipts under a
permission that contradicts them. The other way: a warning only.

**X63. Every receipt and every denial names `executor.rules`, the
fingerprint of the rules file in force, where the settings name one; a
denial by a rule also names `executor.rule`, the fingerprint of the
refusing rule's name.** Both are labels, so every checker reads them. A
reader with the rules file can tell which rule said no; without it, the
fingerprint of a short name can be guessed from a list of likely names,
which is stated. The other way: name no rule in the record, as the design
note first had it; then a denial by a rule could not be told from another.

**X64. The rules are tested after the amount and before the check before
acting.** An amount that cannot be read is refused first (the denial then
names no rule); a call the rules let through is still held to the
permission. Why: the amount belongs to what was asked for, and the denial
by a rule names it; the check before acting is the last word.

**X65. The first refusing rule, in the file's order, is the one named.**
Every rule that names the tool and whose `when` holds is tested until one
refuses. The other way: test all and name all; one is enough for the
model to act on and keeps the denial small.

**X66. The rules file is read strictly: UTF-8, JSON, no member named
twice, no whole number beyond 2^53 - 1, `version` 1, no member that is not
part of a rules file, a rule or a condition, rule names unique, at most
1,000 rules, the file at most 1 MiB, at most 20,000 pattern tokens (X74),
JSON Pointers with `~` only as `~0` or `~1` (X76).** The bytes are decoded
with a strict UTF-8 decoder, so a byte that is not part of a character
stops the start rather than becoming U+FFFD (X75). A misspelt member (`tets`) would
otherwise make a rule that refuses everything or nothing silently.
Unknown settings in `executor.json` only warn; here they stop the start,
because a rule is a security control.

**X67. `content` without `test` is a problem, not a rule that refuses:**
a rule that reads content and tests nothing is a mistake the person should
see.

**X68. A rule may name a tool that no rule in `tools` names; where
`unlisted` is `refuse`, the executor warns, and where it is `forward`, the
executor does not start (X71).** With `refuse`, such a call is refused as
unlisted before any content rule is reached, so the content rule is never
tested and nothing is sent. With `forward`, such a call would be sent on
before any content rule is reached, with no receipt and no denial, so the
rule would be passed by; the start stops and says to add the tool to
`tools` or set `unlisted` to `refuse`. (As first built the executor warned
in both cases, and the warning said the call was never sent, which was
untrue with `forward`; found by the review of the content rules.)

**X69. `compare` reports, for each `executor.rules` fingerprint the
records name, how many receipts and denials name it and whether a slip in
the book states it (`contentRules`), and lists as `withoutRules` the
executor's receipts and denials under a slip that states rules on content
which name no `executor.rules` (X72); neither changes whether the copy and
the book agree.** A statement, not proof: it shows which rules the
executor held and which the person approved, not what the rules did. A
record in `withoutRules` shows an executor that ran without the rules the
person approved, which the start now refuses (X72), so it points to an
executor of another version or a record written by other means. The other
way: let `withoutRules` make `agree` false; not taken, because `agree`
answers whether the copy and the book hold the same calls, and this is a
question of the book against its slip, reported apart (`summary.withoutRules`).

**X70. The words to the model name the rule and what it asked for
("the value at "/scan" in the content at "/content" must equal false, or
be absent"), never the value found.** The value found is from the
arguments, which do not go into the executor's log or copy; the rule's
own values are the person's, from the rules file, and are shown cut to
120 characters. The copy and the log carry the rule's name
(`rule`) beside the reason; `_meta` of the tool error carries
`red.prova/rule`.

*Choices made after the independent review of the content rules
(1 November 2026).*

**X71. With `unlisted: "forward"`, a content rule that names a tool no
rule in `tools` names stops the start** (the review's M1). The words say
which rule and which tool, and the two ways out. The other way: test the
content rules before forwarding an unlisted call; not taken, because a
forwarded call has no receipt and no denial, so a refusal by a rule
would be the only record of it, and a rule for a tool the executor does
not otherwise know is more likely a slip of the person's than a design.

**X72. A permission that states rules on content, with no rules file in
the settings, stops the start** (the review's M2). "States rules on
content" means an `agent.software` entry whose name begins `Content rules
of `, the form `keys` prints, whatever executor name follows. The other
way: only the entry for this executor's own name; not taken, because an
executor renamed in its settings would then start silently with no rules.
The cost: a permission for two executors, one with rules and one without,
cannot be used; the settings already warn against naming other services
in `with`, so one permission serves one executor.

**X73. A `/` or a `\` in a pattern matches either separator in the text**
(the review's M3): X60 said both separators count, but a literal `/`
matched only `/`, so `**/settings.json` missed `C:\proj\settings.json`.
The other way: a literal matches only itself and the person writes both
forms; not taken, since X60's promise is the one people read.

**X74. A rules file holds at most 20,000 pattern tokens in all** (a
character, a `?` or a run of stars each; the review's L1). The work of one
call grows with the tokens times the length of the text (at most 4,096
characters); as first built, 985 rules of 1,000-character patterns took
9.6 seconds for one call. Measured on this computer on 1 November 2026, at
the bound, over a text of 4,096 characters: about 0.2 seconds for patterns
of `*a` or `**a`, about 0.01 seconds for patterns of plain characters or
`?`. A file over the bound stops the start, with the count. The other way:
a bound per call in time; not taken, since a time limit makes the answer
depend on the computer's load.

**X75. The rules file is decoded as strict UTF-8** (`TextDecoder` with
`fatal: true`; the review's L2). As first built, it was read as text with
Node's lenient decoder, which turns a bad byte into U+FFFD, so the file
X66 called UTF-8 could hold names no editor shows the same way. A
byte-order mark at the start is still dropped.

**X76. A JSON Pointer with a `~` not followed by `0` or `1` is not a
pointer** (RFC 6901, section 3; the review's L3), so a rule that holds one
stops the start, with its place named. The other way: accept it and let
the call be refused as unreadable; not taken, because a mistake in the
rules is better found when the executor starts than on the first call.
The same reading serves the amount's pointer in `tools`. `~1` is read
before `~0`, as section 4 says, so `~01` is `~1`; a test holds the order.

**X77. Four more limits are stated, not closed** (the review's L4): a
`when` with `matches` is met only by text, so a path given as a list does
not match and the rule does not apply; names inside the content are
compared exactly, so a lone `SCAN` passes an `absent` or `orAbsent` test
on `/scan`; a path with a trailing full stop is another text; and `as:
"json"` reads one layer, so JSON text inside a JSON string is a string to
the rule. Each could be closed by a new kind of condition or reading,
which is later work; meanwhile a rule with no `test` closes a tool
outright.

**X36. The tests use a made-up MCP server written for them
(`test/fake-server.mjs`), started as a real process, with tools that
answer, fail, err, stall, ask the client something, or end the process.**
Nothing is sent over the network; nothing of anyone else's is run. A test
that starts the executor as a process ends it, and so the server, on
every path (success, failure, time limit), and the test script gives each
test 60 seconds: a child left alive would keep the test process alive.

*Choices made for version 0.2.0 and the demonstration (1 November 2026).*

**X78. `package.json` names the server for the official MCP Registry:
`"mcpName": "io.github.provared/mcp-executor"`.** The registry takes an npm
package only where this field equals the name in `server.json`, which is
how it knows that the publisher holds the package. The name is under the
GitHub organisation `provared`, so whoever publishes must sign in to the
registry as a member of that organisation. The other way: a name under
the domain `red.prova`, proved by a DNS record; not taken, since GitHub
sign-in needs nothing new on the domain.

**X79. `server.json` lives in `mcp-executor/`, beside `package.json`, and
is not in the npm package.** The registry's publishing tool reads it from
the folder it is run in and sends it to the registry; nothing reads it
from npm. `package.json` lists the files it ships, so `server.json` and
`demo/` stay out of the package without a rule of their own. The other
way: ship it too; not taken, since a copy in the package could differ from
the one published and would say nothing new.

**X80. In `server.json` the command line is given as three positional
arguments, `stdio`, `--config` and the settings file's path, not as a
named argument `--config`.** The registry's schema describes a named
argument as `--flag={value}`, written as one word; the executor reads
`--config` and its value as two words and does not read
`--config=<path>`. Positional arguments are inserted as they are, so a
client builds exactly `provared-mcp-executor stdio --config <path>`. The
other way: teach the executor `--config=<path>` as well and use a named
argument; not taken, because how a client writes a named argument is not
settled between clients, and the positional form leaves no doubt.

**X81. `server.json` names no environment variable and no secret.**
The executor takes everything from its settings file, and the server's
credentials are best read from files the settings name, not from the
client's environment (the README's "The settings": an `env` source is
warned against). So the one thing a client must supply is the settings file's
path, marked `isRequired` and of format `filepath`.

**X82. A demonstration in `demo/`, apart from the package**: a made-up
tool server with two harmless tools (`echo`, `add`), one content rule,
and a start that sets everything up on its first run and then runs the
executor in front of the server. It exists so that a directory of MCP
servers, which starts a server and asks it what it offers, can start the
executor with no settings and no secret. It is not in the npm package and
is never the way to use the executor for real work.

**X83. The demonstration's permission is signed by the library's
development stand-in for a passkey (`provared/dev`), made for one set-up
and then forgotten.** The issuer's name ends with "(development)", which
the checker prints, and the purpose and the README say that its records
prove nothing about anyone. The stand-in is forgotten, so the demonstration
cannot sign a second permission or a cancellation with it: when the
permission comes within an hour of its end, the folder is renamed aside
(nothing is thrown away) and a new set-up is made. The other way: a
permission kept in the repository, signed once; not taken, because it
would end, and because its agent's keys would have to be in the
repository too.

**X84. The demonstration sets itself up through the executor's own
commands.** `keys` makes the key files and prints what goes into the
permission; `check` reads the settings before the first call; then
`stdio` runs. So it follows the README's "Set it up" step for step, with
the stand-in in place of the person, and uses no file of the package that
the package does not export. The stand-in is made first, because `keys`
refuses settings that trust no passkey.

**X85. The demonstration's permission is valid for 30 days, allows
`demo.echo` and `demo.add`, holds at most 1,000 `add` calls in any 24
hours, needs the executor's countersignature on every action, and states
the content rules' fingerprint in `agent.software`.** So it shows each
part of a permission the executor uses, and the executor starts without
a warning.

**X86. The made-up server will not start without `DEMO_TOKEN`, a made-up
credential that the start writes into the demonstration's folder and the
settings name as a file.** It shows, in miniature, what the executor is
for: only the executor holds what the server needs.

**X87. The demonstration installs `provared` 0.7.0 and
`provared-mcp-executor` 0.2.0 from npm at exact versions, named in
`demo/package.json`, with no install scripts run.** Neither has any other
dependency, so two exact versions fix everything installed. There is no
lock file: one can be made only once 0.2.0 is published. The `Dockerfile`
takes a build argument, `EXECUTOR`, that replaces the executor's version,
so that a packed file can be tried before it is published.

**X88. The `Dockerfile` starts from the official `node` image, version
24.22.2 on Debian 12 (bookworm), slim, pinned by its version and by the
digest of its multi-platform index, read from Docker Hub on 1 November
2026; it is built from the top of the repository, and runs as the image's
own unprivileged user `node`.** Built from the top, because a directory
that builds from the repository clones it whole and works from its top
folder; the README gives the same steps for a service that takes a build
step and a command rather than a `Dockerfile`. A newer Node.js 24 means a
new digest, read again by hand.

**X89. A test (`test/demo.test.mjs`) starts the demonstration as a real
process against this folder's own files** (`test/local-executor.mjs`
maps the name `provared-mcp-executor` to this folder, as
`test/local-library.mjs` maps `provared` to the repository's library). It
holds the set-up, `initialize`, `tools/list`, a call with a countersigned
receipt, a call refused by the content rule with a denial, and a second
start that uses what the first made. So a change to the executor that
breaks the demonstration fails the tests, not a directory's listing.

*Choices made after an independent review of version 0.2.0 and the
demonstration (1 November 2026).*

**X90. Who may publish to the registry, and in what order (corrects
X78).** X78 said that a member of the organisation may publish. The
registry's own page on signing in (read on 1 November 2026) says that only
an **Owner** of the organisation may publish under `io.github.<org>/`,
and that `mcp-publisher login github` without a token cannot publish to an
organisation's names today: it grants only the person's own names. The
ways that work are a personal access token that can read the
organisation's members (a classic token with `read:org`, or a fine-grained
one with Organization permissions, Members, Read-only), given with
`mcp-publisher login github --token`, or GitHub Actions. The order is
fixed: the npm version first, since the registry reads
`registry.npmjs.org/provared-mcp-executor/0.2.0` and compares its
`mcpName` with the name in `server.json`. The README says both.

**X91. The demonstration uses its folder only if the folder is empty or
holds the demonstration's own mark, `provared-demo.json`; each set-up is a
folder of its own inside it, and the mark names the one in use (replaces
the renaming of the whole folder in X83).** As first built, a start renamed
aside any folder that `PROVARED_DEMO_DIR` named and that held something,
whoever made it. Now a folder with anything in it and no mark is refused,
with a message, and nothing in it is touched. A set-up that cannot be used
is kept where it is and a new one is made beside it, so nothing is thrown
away and the folder itself is never renamed (it may be a volume mounted in
a container, which cannot be renamed). The start says the true reason: the
permission has ended, ends within the hour, cannot be read, or the
settings no longer pass the executor's check. The other way: rename aside
only a folder that holds the mark; not taken, because a mounted folder
cannot be renamed.

**X92. On every start the paths to Node.js, to `server.mjs` and to the
rules file are written into the set-up's settings afresh, and the settings
are checked again with the executor's `check` (adds to X84).** As first
built, the settings kept the paths of the first start, so a demonstration
moved to another folder, a second copy of the repository, or a new
Node.js stopped it ("The rules file … is missing or empty"). None of these
paths is signed, and the rules file's fingerprint is taken over its parsed
content, not its path, so the permission's `agent.software` still matches;
where the rules file itself has changed, `check` fails and a new set-up is
made, with that reason. The check costs about half a second: a start that
reuses a set-up answered `initialize` in about 0.7 seconds on this
computer, a fresh set-up in about 1 second. The other way: keep a set-up
for each copy of the demonstration; not taken, since one copy moved would
still break.

**X93. Two starts at once on an empty folder each make a set-up of their
own (the review's L1).** The mark is first written with exclusive creation,
so of two starts on an empty folder one writes it and both accept it; each
then sets up in a folder of its own with a random part in its name, and
replaces the mark in one step (a temporary file renamed over it). The last
to finish is named in the mark; neither touches the other's folder. Two
starts at once on a folder already set up share its book, and once the
first has written to it the second takes no more calls (the executor's own
"the book file is not as the executor left it"); the README says to run one
start at a time on one folder. The other way: a lock file held while an
executor runs; not taken, because a lock left by a process that ended
without removing it cannot be told reliably from a live one inside a
container, where process numbers repeat.

**X94. A folder that cannot be written stops the start, with a message
that says how to give it one; there is no fallback to the system's
temporary folder (the review's L2).** In a container started with
`--read-only`, the temporary folder is read-only as well, and a silent move
elsewhere would hide where the records went. The message and the README
name `PROVARED_DEMO_DIR`, `--tmpfs /home/node/provared-demo`, or a volume
there.

**X95. The made-up server compares `DEMO_TOKEN` with the credential in the
file `demo-token` of the folder it is started in, in constant time
(replaces X86's check of presence only).** The executor starts the server
in the set-up's folder (the settings file's folder, as `server.cwd` is not
given), so the server finds the file there. The words now say what this
shows: where a credential lives, and that the agent's client is never
handed it; not that only the executor can reach the server, since anything
that can read the set-up's folder can read the file.

**X96. The content rule refuses only the lower-case word `password`, and
says so in its name.** A `matches` pattern compares characters exactly
(X77), and the rules have no way to ignore capitals; `PASSWORD` passes, and
the README says so. The other way: three rules, for `password`,
`Password` and `PASSWORD`; not taken, as it would still miss other
mixtures and suggest more than it does.

**X97. The start runs the executor's command by the path of `bin.mjs` in
the installed package (corrects X84).** X84 said the start uses no file
that the package does not export. `bin.mjs` is the file that npm's `bin`
names, and it is not in `exports`; the start finds the package's folder
through `provared-mcp-executor/package.json`, which is exported, and runs
`bin.mjs` there. Running the command by name would go through npm's
`.cmd` shim on Windows, which cannot be started without a shell.

**X98. The container is built from exactly four files, and a packed
executor is handed to the builder as a context of its own and never
copied into the image (replaces the build argument's form in X87 and the
`COPY` of X88).** `Dockerfile.dockerignore`, beside the `Dockerfile`, lets
only `package.json`, `start.mjs`, `server.mjs` and `content-rules.json` of
the demonstration reach the builder, so nothing else of the repository (a
`.env`, a Python environment, a `node_modules` or a packed file left in
`demo/`) is sent to it or copied; it needs BuildKit, the builder of every
current Docker. The `COPY` names the four files. For a test before
publishing, `--build-context executor-file=<folder>` hands over the folder
that holds the `.tgz`, which the install step reads through a mount that
is not kept in the image, and `EXECUTOR=file:/tmp/executor/<name>.tgz`
names it. Without them the stage `executor-file` is empty. The README says
that installing from `demo/package.json`, the `Dockerfile` without
`EXECUTOR`, and the build step for a directory all fail until 0.2.0 is on
npm.

**X99. The demonstration's tests hold the changes above** (adds to X89):
a folder holding a file of someone else's is refused and left as it was;
settings whose paths point elsewhere are rewritten and the same set-up is
used; a permission that cannot be read leaves its set-up in place and a
new one is made, with that reason; two starts at once on an empty folder
both answer and leave two set-ups; the made-up server refuses a
credential other than the one in its folder.

**X100. Four small points of a second, narrow review.** (1) The mark is
made, then written, so a start stopped in between left an empty mark, and
the folder was refused for good as not the demonstration's; an empty mark
alone in the folder (with at most a mark being written beside it) is now
taken as the demonstration's own and written again, whole. Two starts at
once can both do this; both write the same text. (2) A set-up that is not
used was said to be "kept as it is", but its paths may already have been
written afresh before the executor's check; the words now say it is left
where it is, with at most its paths written afresh. (3) A file error
inside the folder after it was opened (a set-up mounted read-only, a full
disk) now gives the words of X94, not the system's own message. (4) The
message of X94 named the system's code as the cause, though Node.js reports
`ENOENT` for a folder it cannot make on a read-only disk; it now says the
folder "cannot be made or written" and gives the code as what the system
reported, and a name that is a file gets words of its own. Two more tests.

**X101. The HTTP transport is a second way to run the same executor, in
`http.mjs` of the same package, and the handling of a call is one piece of
code for both.** `executor.mjs` opens each agent (`prepareAgent`,
`openAgent`: keys, slip, book, copy, writer, one call at a time, the late
receipts at a start) and handles a `tools/call` (`callCore`) through a
link the transport gives: an id for the server, how to send the call, how
to answer the agent, how to cancel, and whether the server can take a call.
On stdio the link writes lines; over HTTP it makes one exchange with the
upstream. Why: the check, the documents, the countersignature and the copy
cannot differ between transports, and a second copy of two hundred lines in
a security-critical place would. The stdio tests pass unchanged. The other
way: a separate package, or a transport that speaks to a stdio executor
over a socket.

**X102. Agents sign in as the gateway's do.** Exactly one `Authorization`
header, `Bearer <secret>`, the secret 1 to 512 visible ASCII characters;
the settings hold SHA-256 of the secret in base64url (`secretHash`), never
the secret; the hash of what was given is held against each agent's with
`timingSafeEqual`; `provared-mcp-executor secret` makes a secret and prints
its hash, and stores neither. Two `Authorization` headers, a `Basic` one,
or the hash itself sign in as nobody (401, `WWW-Authenticate: Bearer`). The
secret is not logged, and a test holds every log line, book, copy and
answer against it. Why: the gateway settled this already, and the brief
says security-critical detail follows it. The other way: tokens the
executor issues at a sign-in (the authorization specification's OAuth
flow), which the gateway does not have either.

**X103. Each agent has its own copy and copy key, by default
`copies/<name>.jsonl` and `copies/<name>.jsonl.key` beside the settings,
and no two agents may share a secret hash, a slip, a book, a key file, a
copy or a copy key.** `compare` takes `--agent <name>` on HTTP settings;
`check` reports each agent; `keys` makes one key file for each and prints
the entries for each permission, with the executor's one entry for `with`.
Why: a line of one agent's copy must not be able to stand in another's,
and the gateway keeps a journal and a key for each agent. The other way:
one copy for the executor with the agent's name in each line, which would
need the comparison to filter and the key to bind the name.

**X104. Headers go to the upstream by allow-list, not by deny-list.**
`Accept`, `Accept-Language`, `Content-Type`, `Mcp-Session-Id` and
`Last-Event-ID` pass; `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`
and `Mcp-Param-*` as X110 says; `Authorization` is the executor's; `Content-Length` is of the body
as sent (the executor's id is longer than the agent's); every other header
(`Cookie`, `X-Api-Key`, anything named in `Connection`, `X-Forwarded-*`,
`Origin`, a header of a name nobody foresaw) is dropped, and the names of
the dropped ones are logged, the usual ones of a browser or a library
aside. Back from the upstream only `Content-Type`, `Mcp-Session-Id`,
`MCP-Protocol-Version` and `Cache-Control`. Why: the authorization
specification says a server "MUST NOT accept or transit any other
tokens", and a token can ride in a header of any name; the gateway's
deny-list fits web calls whose headers mean something to the upstream,
and here they do not. The other way: the gateway's deny-list with its
lists of credential, address and override headers.

**X105. The upstream's credential is a bearer token from a file alone
(`upstream.credential.file`), and the executor sees to it that the token
reaches no agent.** No `env` and no `value` form: the brief names a file,
and the gateway warns against the others. Without a credential the upstream
is called with none and the start says so. Every byte to an agent (a JSON
body, each event of a stream, an error of the executor's own) has the
token's text replaced with "[a credential was removed by the Provared
executor]"; a 401 or 403 from the upstream is answered as the executor's
own error ("The upstream refused the executor's credential") with none of
its headers or body; a 3xx is never followed and never relayed, since a
redirection would carry the token elsewhere; a non-2xx answer to a call is
relayed, scrubbed, only where its body is a JSON-RPC error under the call's
id (X116), and is otherwise an outcome of its own, body not relayed. A
token shorter than 16 characters
gets a warning, since text that happens to hold it would be replaced too.
Why: the brief says the credential must reach the agent in no header,
body, error or log, and an upstream that echoes its bearer token in a
result is not far-fetched. The limit: a token the upstream encodes or
splits before echoing is not seen. The other way: trust the upstream.

**X106. Framing.** Each request goes under an id of the executor's own
(`serverIds`, one maker per executor; on stdio one per session, so that
the first id of a session is still `provared-1-…`), and the answer comes
back under the agent's id, spliced into the upstream's text as on stdio.
For a call, the response under the executor's id is the outcome: in a JSON
body, or in the event of a stream that carries it, after which the stream
to the upstream is closed (nothing more is wanted, and an unending stream
after the answer would otherwise hold the call open). Every other event
passes to the agent as it was, including a response under another id
(X5); a JSON body under another id, or that is not a message, ends the
call at once with "not its response", since no further answer can come on
that exchange, where stdio waits for the timeout. A stream that ends
without the response, a dropped connection and a non-2xx status without a
JSON-RPC error under the call's id (X116) are outcomes of "no answer"
(1002) with a receipt naming `provared.error`. A
response that cannot be read strictly but whose top-level id is the call's
is handed to the agent as it was, with the receipt of `UNREADABLE_ANSWER`,
as on stdio. The event that carried the outcome keeps its other lines
(`id:`, `event:`, comments) in the final event the agent gets; the
executor's own answer, where the stream had begun, is the final event.
Notifications and the agent's responses are relayed as they are, with the
upstream's status (202). A `tools/list` answer is filtered in a JSON body
and in a stream alike (`filteredList`, shared with stdio).

**X107. Limits.** The agent's POST body up to `bodyLimit`, 10 MiB by
default as the gateway's, refused with 413 whether declared or not; an
upstream JSON body, or one event, up to 16 MiB (`ANSWER_LIMIT`, the stdio
line limit), past which the exchange is cut and a call gets "no answer";
the executor's `timeout` on every POST exchange (a GET stream of server
messages is open-ended by nature, bounded by the event limit and by X113,
which cuts off an agent that reads nothing for `timeout` ms); 256
requests of one agent in flight at once (`MAX_OPEN`), beside `maxWaiting`
for its calls, which `callCore` counts for each agent; 1,000 sessions
remembered for each agent, that agent's oldest forgotten first (X114). Why:
each bounds something an upstream or an agent could otherwise grow without
end. The other way: no bound on the GET stream's events, or a bound on its
length in time.

**X108. A session belongs to the agent that opened it.** An
`Mcp-Session-Id` the upstream gives in a 2xx answer is remembered for the
agent whose request it answered; a request, GET or DELETE carrying a
session id is served only where the executor remembers it for this agent,
else 404, which the specification makes the client's cue to begin a new
session; a DELETE by the owner forgets it; a restart forgets all, so every
client begins anew. A header given twice, or an id outside 1 to 512
visible ASCII characters, is refused (400). Why: a session id is a
capability the upstream handed to one agent, and passing an unknown one
on would let an agent use another's after a restart. The other way: pass
unknown ids on and let the upstream decide, which it cannot.

**X109. An `Origin` is refused (403) unless `allowedOrigins` lists it, and
the executor listens on 127.0.0.1:8796 at `/mcp` unless the settings say
otherwise; another address is warned about; the `Origin` itself never goes
on.** The transport's rule on `Origin` (against DNS rebinding) was not
among the texts of section 3, so this takes the safest reading: nothing
from a web page unless the operator says so. To be checked against the
specification's security warning of the Streamable HTTP transport
(validating `Origin`; binding to localhost). The other way: allow any
`Origin`, as a server for browsers would.

**X110. Mirrored metadata.** `MCP-Protocol-Version`: where the header and
the body's `_meta."io.modelcontextprotocol/protocolVersion"` are both
given and differ, 400; the body's value goes on; a header alone (a legacy
client, no version in the body) goes on; a header given twice, or a body
value that is not text, 400. The mirrored headers of the 2026-07-28
revision, as its text says (read 7 November 2026): a property of a tool's
`inputSchema` annotated `x-mcp-header: <name>` is mirrored as
`Mcp-Param-<name>`, whose value is "the instance value at the exact
property path of the annotated property" in the call's `arguments`; a
value may be wrapped as `=?base64?…?=`, which "servers MUST decode …
before comparing"; a mismatch is "400 Bad Request and JSON-RPC error code
-32020 (HeaderMismatch)"; `Mcp-Method` and `Mcp-Name` mirror the method
and the name. So the executor learns the annotations from every
`tools/list` answer that passes through it (before any filtering; up to
1,000 tools, 64 headers each, properties nested up to 8 deep), and an
`Mcp-Param-<name>` goes on only where the message is a `tools/call`, the
tool's annotations name `<name>` (case not counted), and the argument at
the annotated path is text equal to the decoded header, or a number or
boolean whose text is; `Mcp-Method` only where it is the body's `method`;
`Mcp-Name` only where it is the body's `params.name` as text. Anything
else (no annotation seen, a disagreement, a GET or DELETE, a response, a
Base64 form that does not decode, a header given twice) is refused with
400 and -32020 before anything reaches the upstream, as is a
`MCP-Protocol-Version` mismatch, so that a client reading the body does
not take the executor for a legacy server. Their absence is never
refused, on either era, and the executor adds none of its own (X117). Why:
a header must never reach the upstream disagreeing with the body the rules
checked, and the body is what the rules read. The earlier rule (a
`_meta` member of the same name) was wrong; this one follows the text.
To be checked: what `Mcp-Name` mirrors for a request that is not a
`tools/call` (the executor takes `params.name`; a `resources/read` may
mirror its `uri`), where the passage was not among those read. The other
way: forward the headers as given, or generate them from the body.

**X111. Cancellation over HTTP is closing the stream to the upstream, and
nothing more is sent to it.** The agent closing its response before the
answer, the executor's timeout, and the agent's `notifications/cancelled`
(as a POST of its own, naming a call of this agent in progress, answered
202 and not forwarded) each close the upstream exchange and settle the
outcome as not known, with a receipt naming `provared.error`; a call still
waiting its turn is withdrawn and never sent, and the copy says so. The
agent's response is then the executor's error, as a JSON body or as the
final event. Why: section 10 says the transport's cancellation is the
closed stream; the upstream knows the call by the executor's id, and a
notification under it after the stream is closed would be a second
message about a call that is already over. The other way: also POST
`notifications/cancelled` to the upstream, as stdio sends it on the one
stream it has.

**X112. The executor's own answers over HTTP.** A request that was read
and refused by the executor (a call the permission does not allow, no
rule, the limits of X107 on calls, a duplicate id in progress, 1001, 1002)
is answered 200 with the JSON-RPC result or error under the agent's id,
as on stdio, so the agent's MCP library reads it as a response; a body
that cannot be read as one message is 400 with a JSON-RPC error (the id
where one was read, else null); the transport's own refusals are 401 (not
signed in), 403 (`Origin`), 404 (the path, a session), 405 (a method other
than POST, GET or DELETE), 413 (the body), 415 (not `application/json`),
503 (too many in flight), each with a JSON-RPC error body and id null;
an upstream failure on a request that is not a call is 502 or 504 with the
same. A duplicate id is counted for each agent (on stdio, for the one
session), so two concurrent calls of one agent under one id are refused
and two agents may use the same ids. The tests' client speaks to the
executor over `node:http` on one connection for each request: the
built-in `fetch` keeps connections alive, which kept the test process
from ending and tripped an assertion in Node.js on Windows at exit.

**X113. An agent that does not read.** `res.write`'s return value is
honoured: where the agent's connection takes no more, the upstream's
response is paused until the agent drains it; an agent that drains nothing
within `timeout` ms is cut off (the exchange with the upstream closed, the
agent's connection destroyed, a call's outcome "not known"), and so is one
for which more than 16 MiB is waiting (`BACKLOG_LIMIT`), which the pause
makes reachable only where one event is itself over the limit in bytes. Why:
a review showed an agent that reads nothing making the executor hold an
upstream stream without bound (954 MiB in four seconds); a GET stream has no
time limit (X107), so a stalled one must end by this rule or hold memory and
a slot for ever. `timeout` is reused rather than a knob of its own: one
limit on how long the executor waits for the far side, whichever side that
is. The other way: a bound on memory alone, which would cut a slow but
honest agent rather than wait for it.

**X114. Sessions are capped for each agent, not for the executor.** Each
agent may have 1,000 sessions remembered (`MAX_SESSIONS`); past that its own
oldest is forgotten and it begins a new one; the total is at most 1,000 times
the number of agents, which the settings fix at the start. Why: a review
showed one agent evicting every other agent's session by opening ten
thousand of its own under one executor-wide cap; a cap for each agent lets
an agent harm only itself, and the total still has a bound. The other way:
one cap with a fair share for each agent, which would have to be recomputed
as agents come and go.

**X115. A stop on request settles the calls in flight as the executor's
stop, and says so in their receipts.** `close()` (which SIGINT and SIGTERM
reach in `bin http`) first marks the executor as stopping: no new request is
taken (503), a call waiting its turn is not sent (the link's `unavailable`)
and is answered so, and every call that is with the upstream has its
exchange closed and is settled with `EXECUTOR_STOPPED` ("The executor
stopped while this call was with the tool server, so its outcome is not
known."), code 1002; the receipts are written and the agents answered, which
the stop waits for up to `STOP_WAIT` (5 s); only then are the connections
closed. Why: before this the stop closed every connection first, and the
receipts blamed the agent ("The agent closed the connection…"), which was
false. The text is the first sentence of `OUTCOME_UNKNOWN` and not the
whole of it: the second sentence ("The receipt was written when the
executor next started, from its own copy") is true of a stop without
warning and false of this one, where the receipt is written before the stop
completes; a receipt must not say what did not happen. `OUTCOME_UNKNOWN` is
now built from `EXECUTOR_STOPPED` and its text is unchanged. The signal path
is tested as a separate process; on Windows, which delivers no signal to a
child, a wrapper (`test/signal-wrapper.mjs`) raises the signal named over
an IPC channel, and the command's own handlers run. The other way: settle
with `OUTCOME_UNKNOWN` as the review suggested, for one text to recognise.

**X116. A non-2xx answer to a call is an outcome where its body is a
JSON-RPC error under the call's id.** The specification makes 400 with
`UnsupportedProtocolVersionError` or `HeaderMismatch`, and 404 with -32601,
the normal way a server refuses, and tells the client to "inspect the
response body before falling back". So such a body is read whole, and where
it is a response under the executor's id with an `error` member, that error
is the outcome (`server-error`, the receipt naming it) and goes to the agent
scrubbed, under its id, with the upstream's status, as a 200 body does. A
non-2xx whose body is not that (no body, another id, unreadable, or a
`result` under a refusing status) stays "outcome not known" with the body
not relayed; 401 and 403 stay the executor's own problem, nothing relayed;
a 3xx is never followed. Why: before this every 4xx was "outcome not
known", which hid the server's own reason from the record and the agent.
The other way: take a `result` under a 4xx as an answer, which the
specification gives no meaning.

**X117. The executor generates no mirrored header, and refuses none for
being absent.** On the 2026-07-28 revision `Mcp-Method` and `Mcp-Name`
"are REQUIRED for compliance", and a validating server "MUST reject requests
where … a required standard header is missing"; the legacy revision has no
such headers. A request that carries only the body goes on as it is, on
either era: the executor adds neither `Mcp-Method`, `Mcp-Name` nor any
`Mcp-Param-*`, and refuses nothing for their absence. Why: a header the
executor made up would be a claim it makes on the agent's behalf, and
whether it is required is the upstream's rule to apply, not the executor's
to guess for a legacy upstream that has never heard of it; a validating
upstream's refusal (400, -32020 or a missing-header error, with a JSON-RPC
body) now reaches the agent and the record as the call's outcome (X116),
so a client that sends only the body learns why. The other way: generate
the three headers from the body the rules checked, which would make the
executor a conforming modern client on the agent's behalf but could not
know which `Mcp-Param-*` the upstream wants before its `tools/list` is
seen.
