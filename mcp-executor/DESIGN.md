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
| `executor.written-late` | a fixed text; only in a receipt written later than its call, from the copy: one text in a receipt written at a restart, another in one written when the administrator acknowledged the call (X140) | no, a label |
| `executor.acknowledged` | a fixed text; only in a receipt written when the administrator acknowledged the call (X140) | no, a label |

`executor.call`, `executor.written-late` and `executor.acknowledged` are labels. The tool's name
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
stub, so that the call stays unfinished; the kind of outcome only where
there are such documents, X165), `refused` (with the reason, the
codes and the denial's fingerprint), `withdrawn` (cancelled before it
was sent) and `set-aside` (a call that was sent and has no receipt, which
the administrator set aside; X130). Each line carries its number from 0 and HMAC-SHA-256 (RFC 2104)
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
| unfinished | the executor sent the call and stopped before the receipt; the next start writes it, or, where the permission has changed since, the administrator acknowledges it |
| set aside | the executor sent the call, and the administrator set it aside: it has no receipt, and the copy and the book do not agree (X130) |
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
  known. Such a receipt names `executor.written-late`, so that the book
  itself says so: its `when` is the time the call was sent, and its
  countersignature is dated at the restart, so a reader sees both times.
  The founder has kept this automatic late receipt (F-158).
- **The same, where the permission has changed since.** The executor
  writes no receipt by itself under a permission that is no longer the
  one in force: the call waits for the administrator, who acknowledges it
  or sets it aside (`acknowledge`; section 12, X127 to X131, X140, X141).
  Over stdio the executor does not start while a call waits; over HTTP it
  starts, and that agent's calls to tools that have a rule are refused
  until none waits (a call to a tool no rule names is answered as
  always: a denial, or, with `unlisted: forward`, sent on unrecorded).
- **Two programs on one book.** A program that opens a book and its copy
  to write takes a lock first, which the operating system releases when
  the program ends; a second is refused before it reads anything (X139).
  A command with `--offline` writes no late receipt by itself (X143).
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
- The clocks: times in receipts are the executor's; a countersignature
  and a seal are by the same clock. No outside time-stamp is put beside a
  seal (X135).
- The recorder's sealing keys are in a file on the executor, beside the
  agent's keys and the executor's own. Whoever can read the executor's
  files can seal a book of their own making; a central sealer, seals held
  elsewhere and witnesses are later steps (X134).
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
   come back by allow-list and scrubbed, a refusal of the token (401, 403)
   and a redirection are not relayed, and every byte sent to an agent is
   checked for the token's text (X105).
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
3. **Cancellation** follows the era. On 2026-07-28 it is the agent closing
   the response stream: the executor then closes its stream to the
   upstream, and the outcome is settled as not known, as on stdio; the
   receipt names `provared.error`; the agent's own `notifications/cancelled`
   does the same. On a legacy session the notification is sent on under the
   upstream's id for the call and then the stream is closed, and a
   disconnection alone is not a cancellation: the call runs on and its
   outcome is recorded (X111).
4. **Mirrored headers.** The `MCP-Protocol-Version` header must agree with
   the body's `_meta` value where both are given; the body's value is what
   goes on. `Mcp-Method` goes on only where it is the body's `method`;
   `Mcp-Name` only where it is the body's `params.uri` on a
   `resources/read` or its `params.name` on a `tools/call` or
   `prompts/get`, and on any other method it is refused. An
   `Mcp-Param-<name>` header goes on
   only where the upstream's `tools/list` annotated a property of the
   tool's `inputSchema` with `x-mcp-header: <name>` and the call's
   argument at that property's path is the header's value, the Base64
   form decoded first. A header that disagrees, or that the executor
   cannot check, is refused with 400 and -32020 (the specification's
   HeaderMismatch) and nothing reaches the upstream; their absence is not
   refused, and the executor never generates `Mcp-Method`, `Mcp-Name` or
   `Mcp-Param-*` (X110, X117). The specification's
   text on the `Origin` rule was not among the sources of section 3, so
   X109 takes the safest reading and names what is to be checked.

Limits (X107): the agent's body up to `bodyLimit` (10 MiB); an upstream
JSON body or one event up to 16 MiB, as a line on stdio; the executor's
`timeout` on every POST exchange; 256 requests of one agent in flight at
once, beside `maxWaiting` for its calls; an `Origin` refused unless the
settings allow it, and the local address listened on unless they say
otherwise (X109). A JSON answer nobody reads is held after its place among
the 256 is freed, up to 16 MiB for each connection (`ANSWER_LIMIT`), until
that connection closes: the exchange has ended, so neither `timeout` nor
X113 reaches it, and the number of connections is not limited. A stop on request with a call in flight settles the call
as the executor's stop, writes its receipt and answers the agent before the
connections close (X115); a stop without warning, followed by a start,
writes the receipt from the agent's copy before the executor listens
(section 8).

What it does not do: it speaks plain HTTP, so the agents' secrets and the
upstream's token are only as safe as the connection (encryption is
something else's); it binds a session to its agent only while it runs; a
token the upstream encodes before echoing is not seen by the check of
X105, and JSON's escaping of a `/`, `"` or `\` in the token counts as
encoding; and the credential is kept from an agent only for what passes
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
- That a member is named as the program reads it, beyond the way to the
  pointers a rule reads: on that way a name in other capitals is refused
  as unreadable (X249, from 0.4.2; before, a lone `SCAN` passed an
  `absent` or `orAbsent` test on `/scan`, X77); elsewhere the rule does
  not see it.
- That content nested in content is read: `as: "json"` reads one layer.
  JSON text where the rule's pointer walks on is refused as unreadable
  (X249, from 0.4.2); JSON text in a member the rule does not walk
  through is a string to the rule (X77).
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
11); the HTTP transport with several agents on one executor (section
10); and, in 0.5.0, sealing a book by command and on a timer,
acknowledging a call sent under a permission no longer in force, and the
status (below; X120 to X146); and a book sealed by a central sealer,
which holds the recorder's keys away from the executor (below; X147 to
X159). Two reviews of these changed parts of them: X160 to X166, and
X167 to X171.

**Sealing.** The settings name a recorder (`recorder`: its key file, a
name, and `sealEvery`). A seal is the library's (format description,
section 21.1), signed with the recorder's three keys, and goes into the
book through the stub writer's `add`, in the agent's turn, so that it
covers the book as it is and is added only if the whole book still passes
its check with it. By command: `seal` asks the running HTTP executor
(`POST /provared/seal`, the administrator's secret), or opens the files
with `--offline`. On a timer, on both transports: at a start, and then
every `sealEvery` milliseconds, a book that holds an entry after its last
seal is sealed (at a start, only where that seal is at least `sealEvery`
old, or there is none), each agent's book in a round of its own. Every
use of the recorder's key file goes through `sealing.mjs`.

**A central sealer.** In place of the key file, the settings may name a
central sealer (`recorder.sealer`): the program in `sealer/`, which
holds the recorder's three keys (format description, section 21.7). The
executor then holds the recorder's token and no key of the recorder's.
From `save()` in `openAgent`, the one place where a line reaches a book
file, the leaf fingerprint of each new line is sent to the sealer, in
order, each at its place (the sealer's `extend`; the book's first line
itself with the first of them). The questions, their HMAC proofs and the
check of each answer are the sealer's own client, copied
(`sealer-client.mjs`, X151); the leaf fingerprint is the library's. A
seal is asked of the sealer, only once it has answered for every line,
and its entry is added through the stub writer's `add`. At a start the
sealer must answer, and what it holds is compared with the book file
(the sealer's `held` and `latest`). While it does not answer, the lines
wait in the book file, the status says how many and since when, and past
a limit the agent's calls are refused with a denial. Everything of this
is in `sealing.mjs`; `executor.mjs` calls it from `save()`, from `seal`,
at the start of an agent, and before a call is sent.

**Acknowledging.** A call the copy shows as sent, with no receipt in the
book, under another permission than the one in force, waits for the
administrator. `acknowledge` writes its receipt from the copy's line,
through a stub writer opened for the permission it was sent under, or
sets it aside (a `set-aside` line in the copy; no receipt). The receipt
names `executor.acknowledged` and `executor.written-late` (X140), and is
countersigned with the executor's keys, or with those of a key file it
held before where the permission names them (X141).

**Status.** `GET /provared/status` of a running HTTP executor, or the
files read without writing: the last seal, whether the book as it stands
passes its check, and the calls waiting to be acknowledged.

**One program at a time.** A book and its copy are locked for the program
that opens them to write, by a lock the operating system releases when
the program ends (`lock.mjs`, X139). A command with `--offline` is not a
start, and writes no receipt by itself (X143).

**Who is asked.** Before a command sends the administrator's secret to a
running executor, the executor signs the command's challenge and the
address it was asked at with its own keys (`identity.mjs`, X138). The
command checks that with the executor's public keys alone (X166).

Still to build:

- An outside time-stamp beside a seal; seals held elsewhere and witnesses
  (library 0.6.0).
- With a central sealer (X158): bringing a sealer up to date after its
  record was lost or put back; a second book under one permission; a
  sealer on another computer, which the sealer's program does not yet
  allow.
- The copy shipped line by line to a place the executor's operator cannot
  change (a sealer, a witness, an append-only store).
- Content read in other forms than JSON (YAML, TOML, `key = value`
  lines), as further values of a rule's `content.as` (section 11).
- Keys held in a key service, through the library's signer interface.
- Listing in the MCP registry, once a published version exists.

## 13. The choices, numbered for review

Each is what, why, and the other way. None changes a record or a rule of
the format: the executor writes ordinary stubs, countersignatures,
denials and, from 0.5.0, seals.

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
act on the other value. The other way: trust the exact names. (From
0.4.2 such arguments are refused in every call, before any rule is read:
X241.)

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
body, each event of a stream, an error of the executor's own, each of the
four headers that come back) has the token's text replaced with "[a
credential was removed by the Provared executor]"; a 401 or 403 from the
upstream is answered as the executor's
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
splits before echoing is not seen, and JSON's own escaping of a `/`, `"`
or `\` in the token counts as encoding (the check is on the text as sent,
not on the decoded value). The other way: trust the upstream.

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
the executor's `timeout` on every POST exchange, and on the reading of a
POST body (X119) (a GET stream of server messages is open-ended by nature,
bounded by the event limit and by X113, which cuts off an agent whose
connection does not take what is waiting within `timeout` ms); 256
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
-32020 (HeaderMismatch)"; `Mcp-Method` mirrors the method; and its table
of standard request headers gives "| Mcp-Name | params.name or params.uri |
tools/call, resources/read, prompts/get requests |", with
`Mcp-Method: resources/read` and
`Mcp-Name: file:///projects/myapp/config.json` as its example, beside
`"uri"` in params. So the executor learns the annotations from every
`tools/list` answer that passes through it (before any filtering; up to
1,000 tools, 64 headers each, properties nested up to 8 deep), and an
`Mcp-Param-<name>` goes on only where the message is a `tools/call`, the
tool's annotations name `<name>` (case not counted), and the argument at
the annotated path is text equal to the decoded header, a boolean whose
text is, or a number equal to it as a number, since "servers SHOULD compare
the header value and the body value numerically rather than as strings
(e.g., 42.0 and 42 are considered equal)". A header can equal a number only
in the form JSON writes one (RFC 8259): not `0x2A`, an empty value,
`Infinity` or anything with a space, all of which `Number()` would take or
make something of, and not `042` or `+42`. An exponent is allowed, since
that is how a large number's text reads (`1e+21`, which passed as text
before). The comparison is of the exact decimal value, not of doubles, so
that `42.00000000000000000001`, which rounds to 42, is refused; the body's
number is compared as `JSON.parse` read it, so a body number with more
digits than a double holds is compared after that rounding. `Mcp-Method` only where it is the body's `method`;
`Mcp-Name` only where it is, as text, the body's `params.uri` on a
`resources/read`, or its `params.name` on a `tools/call` or `prompts/get`.
Anything else (no annotation seen, a disagreement, a GET or DELETE, a
response, an `Mcp-Name` on any other method, whatever its params hold, a
Base64 form that does not decode, a header given twice) is refused with
400 and -32020 before anything reaches the upstream, as is a
`MCP-Protocol-Version` mismatch, so that a client reading the body does
not take the executor for a legacy server. The absence of any of these
headers is never refused, on either era; the body's protocol version goes
on as its header, and `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` are never
generated (X117). Why:
a header must never reach the upstream disagreeing with the body the rules
checked, and the body is what the rules read. The earlier rule (a
`_meta` member of the same name) was wrong; this one follows the text.
On a method the table does not list, the header mirrors nothing, so it is
treated as a message with no such field has always been: refused. The other
way: forward the headers as given, or generate them from the body.

**X111. Cancellation over HTTP follows the era of the session.** On the
2026-07-28 revision, "closing the SSE response stream is itself the
cancellation signal and no `notifications/cancelled` message is expected":
the agent closing its response before the answer, the executor's timeout,
and the agent's `notifications/cancelled` (as a POST of its own, naming a
call of this agent in progress, answered 202 and not forwarded) each close
the upstream exchange and settle the outcome as not known, with a receipt
naming `provared.error`. On a legacy session (an `Mcp-Session-Id`, or a
protocol version before 2026-07-28), the 2025-11-25 text says
"Disconnection SHOULD NOT be interpreted as the client cancelling its
request. To cancel, the client SHOULD explicitly send an MCP
`CancelledNotification`": so the agent's `notifications/cancelled` is sent
on to the upstream with `requestId` replaced by the upstream's id for the
call, the upstream's answer is the agent's, and then the exchange is closed
and the outcome settled as not known; and the agent merely disconnecting
is not a cancellation: a call that was sent runs on, bounded by `timeout`,
and its real outcome is recorded, with the answer written to nobody. On
either era a call still waiting its turn is withdrawn and never sent, and
the copy says so. Why: before this, nothing reached a legacy upstream,
which by its own text would have kept working; and a disconnection on a
legacy session was recorded as "not known" where the upstream's answer was
still to come. The other way: one rule for both eras, which would be wrong
for one of them.

**X112. The executor's own answers over HTTP.** A request that was read
and refused by the executor (a call the permission does not allow, no
rule, the limits of X107 on calls, a duplicate id in progress, 1001, 1002)
is answered 200 with the JSON-RPC result or error under the agent's id,
as on stdio, so the agent's MCP library reads it as a response; a body
that cannot be read as one message is 400 with a JSON-RPC error (the id
where one was read, else null); the transport's own refusals are 401 (not
signed in), 403 (`Origin`), 404 (the path, a session), 405 (a method other
than POST, GET or DELETE), 408 (a body not whole within `timeout`), 413
(the body), 415 (not `application/json`), 503 (too many in flight, or the
executor stopping), each with a JSON-RPC error body and id null; a
mirrored header that disagrees with the body or cannot be checked is 400
with -32020 (X110);
an upstream failure on a request that is not a call is 502 or 504 with the
same. A duplicate id is counted for each agent (on stdio, for the one
session), so two concurrent calls of one agent under one id are refused
and two agents may use the same ids. The tests' client speaks to the
executor over `node:http` on one connection for each request: the
built-in `fetch` keeps connections alive, which kept the test process
from ending and tripped an assertion in Node.js on Windows at exit.

**X113. An agent that does not take what it is sent.** `res.write`'s return
value is honoured: where the agent's connection takes no more, the
upstream's response is paused until the connection has taken all that is
waiting. An agent whose connection does not take what the executor has
waiting within `timeout` ms is cut off (the exchange with the upstream
closed, the agent's connection destroyed, a call's outcome "not known").
The clock stops only when all of it has gone, not at each part read, so a
very slow reader can be cut too, though it is reading. So is an agent
for which more than 16 MiB is waiting (`BACKLOG_LIMIT`), a second defence
left as it is, which the pause keeps almost out of reach: the reader's limit
(X107) stops an event over 16 MiB first, so the backlog passes 16 MiB only
where one event of nearly that size is waiting and more events came in the
same read of the upstream, which are written before the pause takes effect.
A trial on 7 November 2026 reached it so, with 16,777,709 waiting; no test
does. Why:
a review showed an agent that reads nothing making the executor hold an
upstream stream without bound (954 MiB in four seconds); a GET stream has no
time limit (X107), so a stalled one must end by this rule or hold memory and
a slot for ever. `timeout` is reused rather than a knob of its own: one
limit on how long the executor waits for the far side, whichever side that
is. The other way: a bound on memory alone, or a clock that begins again at
each part read, either of which would spare a slow but honest agent, and
leave one that reads a byte at a time holding a slot.

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

**X117. The executor generates no `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*`
header, and refuses none for being absent.** On the 2026-07-28 revision `Mcp-Method` and `Mcp-Name`
"are REQUIRED for compliance", and a validating server "MUST reject requests
where … a required standard header is missing"; the legacy revision has no
such headers. A request that carries only the body goes on, on either era,
with one header it did not send where the body states a protocol version:
that version, as `MCP-Protocol-Version` (X110), copied from the body the
rules checked. `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` are never
generated, and nothing is refused for their absence. Why: a header the
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

**X118. The four headers that come back from the upstream are scrubbed
too.** `Content-Type`, `Mcp-Session-Id`, `MCP-Protocol-Version` and
`Cache-Control` go to the agent with the token's text replaced, as a body
or an event does. Why: a header is a way to carry a token, and the claim
that every byte to an agent is checked was wider than the code before this.
A session id that held the token would come back changed and so be
unknown to the upstream; the agent then begins a new session, which is the
right outcome for an upstream that puts its own credential in a session
id. The other way: narrow the claim.

**X119. The reading of a POST body has a time limit of `timeout` ms.**
The server's own request timeout stays off, since it would cut a long GET
stream or a long answer; instead `readBody` fails after `timeout` with 408
and closes the connection, and a connection that closes mid-body ends the
reading too, so a half-sent body counts in the agent's requests in flight
only until then. Why: a review showed an authenticated POST that stopped
sending staying open for ever and holding a slot. `timeout` again rather
than a knob of its own (as X113). The other way: Node's `requestTimeout`,
which does not tell a body from a stream.

**X120. The recorder is named in the settings as the gateway names it:
`recorder.keys`, a file of three keys (Ed25519, ML-DSA-87,
SLH-DSA-SHA2-256s), and `recorder.name`.** The name is a label on each
seal and is the executor's `name` unless given. There is no `signers`
module here, as there is none for the executor's other keys: keys held in
a key service are a later step for all of them (section 12). Why: one
shape for the same thing in both programs. The other way: a fixed default
name, as the gateway's "Provared gateway", which would give every
executor's seals the same label.

**X121. `keys` makes the recorder's key file with the others, and prints
the fingerprint of its key set on the standard error, not in the JSON.**
The gateway has `keys --recorder`; here one run of `keys` makes every key
file the settings name. What `keys` prints on its standard output is what
goes into a permission, and the recorder's keys go into none; over HTTP
the members of that JSON are the agents' names, so a member `recorder`
could be read as an agent. The fingerprint is what a reader names as the
recorder they expect; `check` and `status` give it too. The recorder's
file may not be the executor's or an agent's. The other way: a
`--recorder` flag, and a second run.

**X122. Where the settings name a recorder, every check the executor
makes of a book names that recorder as the one expected (`sealKeys`), as
the gateway does.** A seal signed with other keys is then a problem
(`sealer-not-expected`), and the executor does not start on such a book.
Where the settings name none, a seal in the book is checked and its keys
are compared with nothing, as the format description allows. `compare`
does the same where the recorder's key file is there to be read. The
other way: never name the recorder, which would let anyone who can write
the book file add a seal of their own that the executor then builds on.

**X123. A seal is added in the agent's turn, through the stub writer's
`add`, and by no check of the executor's own.** The library's `add` takes
an entry only if the whole book still passes its check with it; a second
check here could not be shown to matter by any test. Before a seal is
asked for, the agent must not be stopped (no seal while a call waits to
be acknowledged, as the gateway) and the book file must be as the
executor left it, which is the check made before a call is sent (section
8). A seal waits behind a call in progress and holds up that agent's
next: about two seconds, most of it the SLH-DSA signature, which is made
outside the program's own thread so that other agents are served
meanwhile (X145), one at a time (X161).

**X124. Over stdio there is no administrator's address: `seal` and
`acknowledge` take `--offline` only, and `status` reads the files.** The
stdio executor is started by the agent's client and speaks on its
standard streams alone. An address to ask it at would be a listener and a
secret that stage 1 does not have, on a computer the agent's client
controls. So the gateway's `--offline` is the only way by command, the
timer (X125) is the way while it runs, and the executor does not start
with a call waiting (X127). A command with `--offline` is refused while
an executor runs on the files (X139). `status` writes nothing and may be
run at any time. The other
way: a local socket or named pipe for the administrator.

**X125. The timer: `recorder.sealEvery`, in milliseconds as the other
times in the settings, from 1,000 to 604,800,000 (seven days); off unless
given.** Two rules. At a start, a book that holds an entry after its last
seal is sealed where that seal is at least `sealEvery` old, or there is
none. Then, every `sealEvery` milliseconds after the round before has
ended, a book that holds an entry after its last seal is sealed. Why the
first rule: over stdio the executor lives only as long as the client's
session, and a session shorter than `sealEvery` would never be sealed by
a clock that starts again with each session. Why never a seal over a
seal: a seal is about 52 KB, and an idle executor would otherwise grow
its books for nothing. The gateway has no timer and leaves it to the
system's scheduler; a stdio executor cannot be sealed from outside while
it runs (X124), so the timer is in the program. Each agent's book has its
round to itself, so that one agent's long call holds back its own seal
and no other's; over HTTP the timer starts once the executor is
listening; a seal that cannot be written is logged once for as long as
the reason stays the same; and a `sealEvery` under a minute is warned
about. The timer does not keep the program running. When the executor
ends no further seal is asked for; one already waiting its turn is
written. The other
way: a fixed time of day.

**X126. The executor's own addresses over HTTP are the gateway's, with
four rules added.** `GET /provared/status`, `POST /provared/seal` and
`POST /provared/acknowledge`, under the administrator's secret, kept as
its SHA-256 in `admin.secretHash` and compared in constant time; without
`admin` they answer 404; answers are JSON in the gateway's form
(`{"taken": false, "code", "message"}` for a refusal; 401, 400, 409 as
there). Added, because this executor listens for agents on the same
port: a request that names an `Origin` is refused whatever
`allowedOrigins` says (the administrator is never a web page); a body is
read up to 64 KiB and no further, whatever `bodyLimit` is; `path` may
not be `/provared` or under it; an executor that is stopping answers 503;
a fourth address, `POST /provared/hello`, lets a command see that it has
reached the executor before it sends the secret (X138); and
`admin.secretHash` may not be an agent's, so that no agent is the
administrator. The commands read the secret from
`PROVARED_MCP_EXECUTOR_ADMIN_SECRET`, named after the program as the
gateway's variable is. The other way: a second port for the
administrator.

**X127. A call sent under a permission no longer in force waits for the
administrator; the automatic late receipt stays for a call sent under the
permission in force (F-158).** Until 0.5.0 the executor did not start and
asked for the old permission to be put back for one start. Now: over
HTTP it starts and that agent's calls are refused (1001) until none
waits, as the gateway stops one agent; over stdio it does not start
(X124) and names `acknowledge --offline`. Why not write the receipt
automatically under the old permission: a new permission in place means
a person decided something between the two starts, and a receipt under
the permission they replaced is theirs to allow.

**X128. The acknowledged receipt.** As the gateway's: a stub writer for
the permission the call was sent under is opened on the book as it stands
and writes the stub, dated when the call was sent; the agent's own writer
takes the line only if the book still passes its check with it. As this
executor's late receipt: `with` is the executor, it is countersigned with
the executor's keys (dated at the acknowledgement), and it names the
outcome the copy holds, or `provared.error` with a fixed text. Which
labels and texts it names was changed after the review of 0.5.0, before
any version wrote one: X140 gives them.

**X129. Which lines can have a receipt.** The gateway's rules, read for
the copy: the line holds only the members and documents the executor
writes before a call is sent, none twice, with the tool's and the call's
fingerprints matching; it names a permission the book holds; its time is
not after this start; its amount fits its rule's unit, or, where the rule
has gone, is of the right form, with a warning. Three differences. (1) A
line whose tag does not check never reaches the list: the executor does
not start on a copy with such a line (section 8), where the gateway
starts and names the line `line-<16 characters>` to be set aside. (2) The
permission must name the agent's keys and, in `with`, the executor's keys
as the executor holds them now, checked before anything is signed: under
other executor keys the countersignature would not check, and the
receipt would read as one the executor never saw. Since X141 the
executor's keys may also be those of a key file it held before, named in
the settings, which then countersigns. The other way: write it one-sided,
as a call that was sent always gets its receipt (section 5). (3) The library's own checks of a request's fields are left to the
moment the receipt is written: the checks above are at least as strict,
so no test could show a second check mattering; a receipt the library
refuses (one dated before the receipt ahead of it) is not written, and
the call stays waiting.

**X130. A call set aside is a line in the copy (`set-aside`), not a file
apart, and `compare` does not agree from then on.** The gateway keeps a
file beside its journal because a clean start empties the journal; the
copy is never emptied, and its numbered, tagged lines already hold. A
later `sending` line for the same call is not taken up again. `compare`
lists the call under `setAside` and ends with code 1: the executor sent a
call the book does not show, which is what `compare` is for, whoever
decided it. The other way: count a call set aside as settled, which
would make setting aside a way to quiet `compare`. X142 makes this known
state possible to tell from a new disagreement.

**X131. Never two receipts for one call.** At a start, a call whose
receipt the book holds is finished, whatever the copy says (as before).
On acknowledgement, the book is looked at again before each receipt is
written, so a receipt that reached the book while its line did not reach
the copy is found, not written twice.

**X132. One program writes a copy at a time.** Before each line, the
copy file must be the size this program left it; else nothing more is
written. Why: `acknowledge --offline` is the first thing that writes a
copy from a second program, and a running executor that wrote on after
it would give a line a number already used, after which no start takes
the copy. Since X139 a lock keeps a second program off the files before
it reads them; this check stays behind it, for a program that got past
the lock.

**X133. What the status holds is the gateway's, by name**: `slip`,
`entries`, `bytes`, `lastSeal`, `sound`, `withinSlips`, `checkedAt`,
`checkedNow`, `stopped`, `receiptsMissing`, `waiting`, `fileHoldsBook`,
with the seal's time added to `lastSeal`. Read from the files it is
marked `"from": "files"`, has `slipInBook` and `receiptsAtNextStart`, and
leaves out what only a running executor knows. In a program the method is
`report()` on both transports, since the stdio executor already had a
`status()` that counts its requests.

**X134. Where a central sealer fits.** `sealing.mjs` gives the executor a
sealer: an object with `fingerprint`, `name` and `seal(book, {previous,
when})`, which hands back the seal record. Every use the executor makes
of the recorder's key file goes through `sealing.mjs`: making it (`keys`),
reading it to see that it is whole (`check`, `compare`) and reading it to
seal; the file itself is read and written by `files.mjs`, as every key
file is, and the sealer handed to the rest of the program holds a
fingerprint, a name and `seal`, never a key. A later step puts in its
place an object with the same `seal` that asks the central sealer in
`sealer/`, which holds the keys elsewhere. The one place where every new
line reaches a book file is `save()` in `openAgent` (`executor.mjs`), for
the permission's own line, a call, a late or acknowledged receipt, a
denial and a seal alike (the permission's line went to the file from
`prepareAgent` until the review of 0.5.0): that is where each new line's
leaf fingerprint would be sent as it is written. A book looks
the same either way: the format description (section 21.7) says a seal
made from fingerprints is the same record. This was written before it
was built; X147 to X159 are what was built, in those two places.

**X135. No outside time-stamp is written.** A seal's time is the
recorder's own word. The README says so under its limits, as the
gateway's does.

**X136. The example settings name no recorder and no administrator.**
`init`, `keys` and `check` on the examples do what they did in 0.4.1;
`check` warns that the executor cannot seal, and over HTTP that its own
addresses answer nothing, and says what to add. The other way: name both
in the examples, which adds a key file and a secret to the first five
minutes.

**X137. `--offline` did not look for a running executor**, as the
gateway's does not, and the README said never to use it beside one. The
review of 0.5.0 showed what that cost (a false receipt for a call in
flight), and X139 replaces this choice: a command with `--offline` is
refused while an executor runs on the files.

The choices from X138 on were made after an independent review of 0.5.0,
before it was published. X138, X140, X141 and X142 are for the founder's
review.

**X138. A command sends the administrator's secret only once the executor
has shown that it is the executor (for the founder's review).** The
commands ask over plain HTTP at the address the settings name, and
whatever listens there would be handed the secret: a program on the same
computer that takes the port while the executor is down, say. So a
command first sends 32 fresh random bytes, in base64url, with no secret,
to `POST /provared/hello`. The executor answers with two signatures, by
the two keys of its own key file (Ed25519 and ML-DSA-87, the keys it
countersigns with), each over the bytes of this text:

```
provared-mcp-executor hello v1\n<challenge>\n<address>\n<port>\n
```

where `<challenge>` is the 43 characters it was sent, and `<address>` and
`<port>` are where it received the request (an IPv4 address reached over
IPv6 written as the IPv4 address; the port in decimal). The command checks
both signatures against the public keys in `executor.keys`, which it
reads itself, over its own challenge and the address and port it
connected to, and sends the secret only then, on the same connection.
What is fixed, and why:
- *Both keys sign, and both must check*, as for every record of the
  executor's: breaking one method is not enough.
- *The address and port are signed.* Without them a listener in the
  middle could fetch the executor's answer to the command's challenge and
  hand it back; with them that answer names the executor's address, not
  the listener's.
- *The same connection.* The secret is written to the connection the
  answer came on. Where that connection has closed, the command stops and
  says to try again.
- *The text cannot be a record's.* Every record is signed over two runs
  of base64url joined by a full stop; this text holds spaces and line
  feeds, and a challenge that is not 43 characters of base64url is
  refused. So the address, which signs for anyone, cannot be used to have
  the executor countersign something.
- *No new primitive.* The signatures are made by the library's signers
  for the key file and checked with the Web Crypto methods the library
  itself uses. The library has no public function that checks a signature
  over bytes that are not a record, so the check calls Web Crypto
  directly (`identity.mjs`).
- *No secret at `hello`, and none without `admin`.* It answers 404 where
  the settings name no administrator, as the other addresses do.
What it does not do: it does not encrypt. Whoever can read the connection
reads the secret; the README says so. As first built, the command had to
be able to read `executor.keys`, which holds the private keys too, and so
to run as the executor's user; since X166 it needs the public keys alone.
The other ways: never send the secret and answer the
executor's challenge with an HMAC of it, which needs the executor to keep
the secret and not its hash; or take the executor's public keys from the
agents' permissions, which a command could read as another user, but
which whoever can write those files could replace.

**X139. One program writes a book and its copy at a time, by a lock the
operating system releases (replaces X137).** Before `stdio`, `http` or a
command with `--offline` reads an agent's files, it takes a lock named
after the book file; a second program is refused at once, having read
and written nothing. Why: the review showed that a command with
`--offline` beside a running executor took a call in flight for a call
cut off by a stop, wrote it a receipt saying the outcome was not known,
countersigned it and sealed over it, and that the comparison then agreed.
The lock is a listener, so that it goes when the program goes, however
it ends, and none is left behind by a stopped program: on Windows a named
pipe, on Linux a socket in the abstract namespace, elsewhere a socket
file in `/tmp`, told from one left behind by trying to connect to it. Its
name is the SHA-256 of the book file's path as the file system resolves
it. Over HTTP a command takes every agent's lock, since it opens every
agent's files. Commands that only read (`status`, `check`, `compare`)
take none. What it does not reach is in `lock.mjs` and the README: two
paths to one file that the file system does not resolve; a shared folder
seen from two computers, or from two containers that do not share a
network; two programs racing for a socket file left behind (not on
Windows or Linux); and a program that takes the name first, which keeps
the executor from starting and gains nothing else. The checks of X123
and X132 stay behind it. Node.js offers no file lock, and no way to open
a file without sharing, so a listener it is. The other way: a lock file
holding a process number, which a stopped program leaves behind and
another program can be given the number of.

**X140. An acknowledged receipt has a label of its own, and three short
texts (for the founder's review; replaces what X128 said of labels).**
It names `executor.acknowledged` as well as `executor.written-late`. The
first says who decided (a person, under a permission that had been
replaced); the second says when the receipt was written (later than the
call, from the copy). A reader can so count a person's interventions in
a book by the label alone, and whoever looks for late receipts still
finds both kinds. The texts, each named by its SHA-256 in base64url:

| Document | Text | Fingerprint |
|---|---|---|
| `executor.acknowledged` | The administrator acknowledged this call. The permission it was made under was not the one in force when this receipt was written. | `poJcnPoQB6EyH2Pvp2ZPgD6_2XrDua1XAOpPHBaUezI` |
| `executor.written-late` | This receipt was written later than its call, from the executor's own copy. Its date is the time the copy gives for the call. | `L_sk-qfojehaePxOm8pV-04nhqDY78T5E040ZwBKtho` |
| `provared.error` (no outcome in the copy) | The executor recorded that it was sending this call, and has no record of its outcome. | `pOqSHPh3dRwENnfo2e8cGdYHpsYRvvGW2CUyBeGaGiU` |

They claim only what the executor knows. The copy's line is written
before the call goes to the server, so the executor knows that it was
sending the call, not that the server received it. It cannot tell a stop
from any other reason for the receipt not being in the book, so no text
says "stopped". No text says that there is a countersignature, since a
receipt can stand without one. The texts of a receipt written at a
restart (`WRITTEN_LATE`, `OUTCOME_UNKNOWN`) say more than that, and are
left as they are: receipts of 0.4.1 carry their fingerprints. A test
holds all five texts and fingerprints, letter for letter. A text is not
changed once a version that writes it is published.

**X141. The settings may name the key files the executor held before
(for the founder's review).** `executor.formerKeys`, a list of up to 16
paths. A former key file is used for one thing: to countersign the
receipt of a call the administrator acknowledges, where the permission
the call was sent under names that file's keys for the executor. Why: new
executor keys always mean a new permission, and keys are changed after
trouble, which is when a call is left unfinished; without this, such a
call could only be set aside, and then the book never shows it. The
receipt checks as any other of that permission, and its line in the copy
and the answer of `acknowledge` say that former keys were used. Where no
former key file fits, setting aside stays the only way; the executor
writes no one-sided receipt, by itself or on request. The other way: a
receipt without a countersignature, asked for by call, which is true but
reads as the mark of a call that went round the executor.

**X142. `compare` tells calls set aside from a new disagreement (for the
founder's review).** It still does not agree while a call set aside has
no receipt (X130). Its answer now says `onlySetAside: true` where the
calls set aside are the only disagreement, and the command then ends
with code 3, where it ends with 1 for anything else and 0 where the two
agree. Why: a check that fails for ever stops being read; with one code
for both, a receipt left out later changed nothing a scheduler could see.
The other way: let the operator name the calls they know of, and end
with 0 for those; that hides a set-aside once named.

**X143. A command with `--offline` is not a start.** It writes no receipt
by itself for a call the copy shows as sent and unfinished; `status`
counts such calls, and `seal --offline` does not seal that book while
there is one. Why: to a second program a call in flight looks the same as
a call cut off by a stop; the lock of X139 keeps the second program out,
and this holds where the lock does not reach.

**X144. `acknowledge` gives back what it did.** `{written, setAside,
failed, remaining}`: a call that was to get a receipt or be set aside and
did not is named in `failed` with why, and the calls after it are tried
all the same, unless the book file or the copy can no longer be written.
Why: a call set aside cannot be taken back, and the review showed the
command saying only an error where it had set one aside. Over HTTP the
answer is 200 with the same members.

**X145. The third seal key signs outside the program's own thread.**
`sealing.mjs` wraps the SLH-DSA key as a signer that uses Node.js's
`crypto.sign` in its form with a callback, where the library's signer for
a key in memory uses the form that does not give way and held up every
agent for about a second and a half. The signature is the same.

**X146. Smaller rules of the commands.** `seal`, `acknowledge`, `status`
and `compare` refuse an option they do not know, as `demo` and `init` do:
a mistyped `--set-aside` had been taken for none, and the call given a
receipt. `status` ends with 1 where a book does not pass its check, a
call waits or an agent has stopped. `compare --sealer` names the recorder
by the fingerprint of its key set, as the checker does, for whoever
compares without the recorder's key file, and the answer says which
recorder was expected, or that none was. `secret` says that the secret it
makes may be an agent's or the administrator's.

The choices from X147 on are for a book sealed by a central sealer
(section 12). X152, X153 and X156 are for the founder's review.

**X147. The settings name a central sealer in place of the recorder's
key file, never beside it.** `recorder.sealer`: `address`, `name`,
`token`, `keySet` and, where wanted, `timeout` and `maxUnsent`;
`recorder.sealEvery` as before. `recorder.keys` or `recorder.name` beside
`recorder.sealer` is a problem with the settings. Why: the point of a
central sealer is that whoever runs the executor holds no key that makes
a seal; a key file kept as a second way, for when the sealer does not
answer, would give that back, and a book would then hold seals of two
key sets, of which a reader expects one. The seals give the sealer's own
name, so a name here would say nothing. Without `recorder.sealer`
nothing changes: the key file is read as in X120. The other way: both,
with the key file used while the sealer is away.

**X148. The settings name the key set the sealer signs with
(`recorder.sealer.keySet`), and the executor does not ask for it.** It
is the fingerprint `provared-sealer init` prints, the one a reader
names. Every check the executor makes of a book expects it (X122), so
`check`, `compare` and the reading of the files need no answer from the
sealer; at the sealer's first answer its own word for its key set
(`about`) is held against it, and another stops the start. Why: what a
reader is told to expect is then written down by the person who set the
executor up, and not taken from whoever answers at the address. The
other way: take the key set from the sealer at each start.

**X149. The recorder's token is read from a file or from the
environment, and is never in the settings.** `recorder.sealer.token` is
`{"file": <path>}` or `{"env": <name>}`, one of the two; a value
written there is a problem, and is not repeated in the message. What is
read must have the form of a token (32 bytes in base64url) and is never
logged or printed. The same two ways as the tool server's credentials
(`server.env`), without the third, a value in the settings.

**X150. Each line is sent from `save()`, once it is in the book file, at
its place.** The link to the sealer (`sealing.mjs`) is told the text the
file now holds; it works out the leaf fingerprint of each new line with
the library's `leafFingerprint` and sends them with the sealer's
`extend`, naming the place of the first. The place moves on only by the
sealer's own answer, which must be the place plus the number sent. The
book's first line goes itself with the first question, as the sealer
asks. One question is asked at a time, for every book of one executor,
so that several agents do not fill the sealer's sixteen places. Nothing
is kept but the count of lines the sealer has answered for: the lines
that wait are the book file's own. The answer to a call is not held back
until the sealer has its receipt: the tool has done its work by then,
and holding the answer would protect nothing.

**X151. The sealer's client is a copy, `sealer-client.mjs`, held to the
sealer's by a test, declaration by declaration.** The executor depends
on the library alone, as before. The copy holds the labels, the proofs,
the members a question may hold and `connectSealer`; a test
(`test/same-files.test.mjs`) takes each of the ten declarations from the
copy and from `sealer/sealer.mjs` and holds them the same byte for
byte, and holds that the copy has no other code. Why not the package:
`provared-sealer` is not published, and it is the program that keeps the
keys and signs, which the executor should not carry. Why not the whole
file, as X1 does for `files.mjs`: the client is one part of a file that
also holds the server and the key files. The other way: the sealer's
client in a file of its own in `sealer/`, copied whole; that changes the
sealer's package, which this step does not.

**X152. At a start the sealer must answer, and what it holds is compared
with the book file before anything is written (for the founder's
review).** Compared: the key set (X148); that the sealer holds no more
lines than the file; that its latest seal is the book's last seal; that
no later book follows this one. Where they do not agree, the executor
does not start. Where the sealer's latest seal covers exactly the lines
of the file and is not in it, the sealer signed and the book never took
the seal (X156): it is asked for (`latest`) and added, then. Not
compared, because it cannot be: the lines after the sealer's latest
seal, of which the sealer holds fingerprints and gives none back; a
change among them shows when the next seal is added (X155). After the
permission's line is written, the sealer must also take every line of
the file before the agent takes a call, so that a sealer that was not
told this agent stops the start. A command with `--offline` opens the
files the same way. Why the sealer must answer: an executor that
started without it could write a line where a seal the sealer had
signed must stand, and nothing could then put the two right. The other
way: start, and queue; it needs the executor to remember across a stop
that a seal was asked for.

**X153. While the sealer does not answer, lines wait, in order, and past
a limit calls are refused (for the founder's review).** No question
waits longer than `recorder.sealer.timeout` (5,000 ms unless given; 100
to 60,000). After a question that failed, the lines are sent again
every two seconds. A sealer that answers that the place is not the one
it holds (`out-of-step`: it was started again, and stands at its latest
seal) is asked what it holds, compared as at a start, and sent the
lines from there; after three such rounds in a row it is given up on
until the next try. `recorder.sealer.maxUnsent` (100 unless given; 0 to
10,000) is how many lines of one book may be unsent: past it, a call
waits for one try to send them, at most `timeout`, and none where a try
failed within the last second; it is then refused as a rule of the
executor's refuses, with a denial, a line in the copy and the code
`sealer-behind`. The denial is a line, and so unsent too;
`denialsPerHour` bounds them. Receipts written late at a start and
acknowledged receipts are not held to the limit: their calls were sent
already. A sealer's refusal to take lines (the recorder past its number
of books, say) leaves them unsent in the same way, with the sealer's
words in the status. Why a limit in lines: it bounds what whoever runs
the executor could still change unseen. The other ways: a limit in
time; no call at all while a line is unsent (`maxUnsent` 0 gives that).

**X154. A seal is asked of the sealer only after it has said what it
holds.** In the agent's turn: the sealer is asked (`held`), compared as
at a start, and sent what it lacks; only where it then answers for every
line, and its latest seal is the book's last, is `seal` asked, with
`previous` and with `when`, the executor's clock, as with a key file
(the sealer takes a time within 300 seconds of its own). The question
may take 30 seconds. The entry is added whole through the stub writer's
`add`; the seal's place and fingerprint, as the executor reports and
keeps them, come from the book's own check, not from the sealer's
answer. A refusal by the sealer leaves the book without a seal and the
agent at work. Why ask first: a sealer started again stands at its
latest seal, or at the first line; asked for a seal as it stood, it
would sign over fewer lines than the book holds.

**X155. A seal the book refuses stops the agent, and the executor does
not start on that book again.** The sealer signed over other lines than
the book holds: the book file was changed after the lines were sent, or
other lines were sent. The sealer's latest seal is then one the book can
never hold, and the sealer signs no other history. Nothing the executor
could do would make the two agree, so it stops (`sealer-disagrees`) and
keeps both as they are.

**X156. Where a seal may have been signed and the answer did not come,
no line is written until the sealer has said (for the founder's
review).** A seal sits after exactly the entries it covers, so a line
written before a seal that was signed would shut that seal out for
good. Until the sealer has said, the agent takes no call, answering as
it does when stopped, and writes no denial. The sealer is asked again
every two seconds, and at the next seal or start; a seal it signed is
added in the agent's turn, before any other line. At a start with a
permission new to the book, the seal cannot be added, since the
permission's line would come first: the executor says so, and is
started once with the permission the book last held. The other way:
write on, and lose the book's seals.

**X157. What the status says, and `keys`.** Each agent has `sealer`:
from a running executor `address`, `recorder`, `unsent`, `since`,
`answeredAt` and `problem`; from the files, where the sealer is asked
once (`held`), `reached`, `holds`, `unsent`, `latestSeal` and `problem`.
`since` is in a running executor's memory only. Unsent lines do not
change the code `status` ends with: they are ordinary while a sealer is
away. `recorder` shows the sealer's key set, its address, the
recorder's name and `maxUnsent`. Where the settings name a sealer,
`keys` says the fingerprint of each agent's key set, which the sealer
is told when the recorder is added, and makes no recorder's key file;
it runs before `recorder.sealer` is complete.

**X158. Not built.** Bringing a sealer up to date after its record was
lost or put back (the sealer's `update`): the executor stops, and says
that it is to be done with the sealer's own client. A second book under
one permission (format description, section 21.6): the executor seals
first books only, and a new book file under a permission whose first
book the sealer holds is not started on. Going on, under a central
sealer, with a book already sealed with a key file (X122 refuses it).
Witnesses for the seals, and seals held elsewhere. A time-stamp that a
sealer puts beside its seal is added with the entry, and was not tried.

**X159. A limit that is the sealer's protocol's.** The question for a
seal names the seal before, and not the number of lines the seal should
cover. A sealer that is started again between its answer about what it
holds and the question for a seal signs over the lines it then holds.
For a book that has a seal, that is none new, and it refuses. For a
book with no seal yet, it signs over the first line alone; the book
refuses that seal, and X155 applies. The executor cannot close this from
its side; a question for a seal that named the number of lines would.

The choices from X160 on come from a second review of the fixes to
`seal`, `acknowledge` and `status`.

**X160. `POST /provared/hello` reads little, for a short time, from few
callers at once.** It needs no secret, so anyone who can reach the
executor may ask. A challenge is some 60 bytes of JSON, so a body of
more than 256 bytes is refused with 400 and nothing is signed; a body
that has not arrived whole within 5 seconds is refused with 400, where
the agents' own `timeout` may be minutes; and where 8 such questions are
already in hand a ninth is answered 503 (`busy`) at once, with nothing
read and nothing signed. These are fixed numbers, not settings: a
command sends one question and waits for one answer. A caller can still
ask again and again, one after another; each answer costs two
signatures. X168 changes the 5 seconds to 1, and what the 8 count.

**X161. One SLH-DSA signature at a time.** Node.js's thread pool has
four threads unless `UV_THREADPOOL_SIZE` says otherwise, and a call needs
it too: its receipt is signed there and the upstream's name is looked up
there. Each agent's round of the timer starts at the same moment, so four
books with something new filled the pool for the two seconds or so of
their third signatures, and every agent's call waited. `sealing.mjs` now
makes these signatures one after another, for every recorder in the
program, so that sealing takes one thread of the pool at most. The
fourth of four seals asked for at once is then done some four signatures
later, where it had been one, and that agent's next call, which waits
for its own seal, waits that much longer. Other agents' calls do not
wait. The rounds were not set apart in time instead: the
queue holds however the seals are asked for, by the timer or by
`seal --agent`.

**X162. The lock's name, on Windows, writes the folder out in full.**
`lockName` resolves the book's folder with `realpathSync.native`, which
writes a short name (`C:\Users\LONGNA~1`) out in full, and falls back to
`realpathSync` where that fails. A guard started with a short name and a
command run with the long one had taken two locks. The book file's own
name is still taken as written, since the file may not be there yet.

**X163. A socket file left behind is cleared by one program at a time
(not Windows or Linux).** The program that makes the folder
`<socket file>.clearing` looks again, clears the file away, listens and
takes the folder away; a program that cannot make the folder is refused
(or asks again, X164). Two programs that started together after a third
was stopped had both cleared the file and both listened. A socket file
that gives no answer within 2 seconds counts as live: the start had
waited for ever. A folder left by a program stopped in that moment is
not taken away by itself, since that would let two programs in again;
the refusal names it, to be taken away by hand. Not run on a Mac: the
tests of this branch run on Linux, where a socket file works the same
way when it is asked for.

**X164. A start asks again for a lock that is held.** For 10 seconds
over HTTP; over stdio, for `shutdownWait` and 5 seconds more where that
is longer, since the guard before keeps the lock while its server is
given that time to end. A command (`seal`, `acknowledge` with
`--offline`) asks once, as before: it is run by hand, and a person can run
it again. A client that started the executor again at once had been
refused where 0.4.1 started.

**X165. A `done` line names the kind of outcome only beside its
documents.** The third fixed text of an acknowledged receipt, "The
executor recorded that it was sending this call, and has no record of
its outcome.", was approved word for word and does not change. It is
written where the copy holds no document of the outcome. A `done` line
with no stub and no documents (the documents could not be made, and the
book could not be written) had still named the kind, `"outcome":
"answer"` or another, so the copy held something of the outcome after
all. Such a line now names no kind, so the text is true wherever it is
written. Nothing reads the kind back: it was for whoever reads the copy.
A line with documents names its kind as before.

**X166. A command checks a running executor with its public keys alone
(for the founder's review).** Under X138 the command read `executor.keys`
with the reader that loads the private keys. So the administrator, who
until then needed only a secret, had to be able to read the keys that
countersign every receipt, and a file of the public keys alone was
refused ("Unsupported key usage for Ed25519 key"). The command now takes
the public parts of the two keys and loads no private key
(`readPublicKeys` in `identity.mjs`). What is fixed, and why:
- *Where the keys are read.* From `executor.keys`, as before; or from the
  file that `--public-keys <file>` names to `status`, `seal` and
  `acknowledge`, in place of it. The option is refused where the command
  asks no running executor (`--offline`, and the stdio executor's
  settings), so that it is not taken for something it does not do.
- *The file of public keys.* The form of a key file with nothing private
  in it: `{"about": <a sentence>, "keys": [<Ed25519>, <ML-DSA-87>]}`,
  each key the public JSON Web Key that `keys` prints in the `with`
  entry. `keys --public-keys <file>` writes it, for the HTTP executor's
  settings, to a new file: it overwrites nothing and refuses a key file
  of the settings. The plainest form there is: no new format, no new
  label, no signed byte.
- *The check is the same.* Both signatures, over the same text, the
  address and port the command connected to, and the same connection
  (X138). The file must hold exactly the two keys, Ed25519 and then
  ML-DSA-87, each one that Web Crypto takes as a key to check a signature
  with. Anything else is said to hold no usable keys, and nothing is
  sent, not even a challenge.
- *What the file is trusted for.* Whoever can change the file the command
  reads can make it trust another listener, as with `executor.keys` and
  with the settings themselves. The file is no secret; it is kept where
  only the administrator can change it.
- *The executor still needs its private keys.* A start, `check`, `keys`
  or a command with `--offline` that is given a file of public keys says
  that it holds public keys only (`loadSigningKeys` in `executor.mjs`;
  `files.mjs` is the gateway's file byte for byte, and is left as it is).

Through a forwarder (an SSH tunnel, a published container port, a
reverse proxy) the address the executor signs is not the one the command
connected to, and the command refuses. That is X138 as designed, and the
README now says it. The other way to the public keys, not built: from
the agents' permissions, checked against `issuerKeys` as a start checks
them. `issuerKeys` is in the settings the command already trusts, so it
would be as strong; but the command would read and check every agent's
permission where a file of two keys is plainer.

The choices from X167 on come from a third review, of the book sealed by
a central sealer and of the fixes above.

**X167. A seal that comes a second time, by another way, is not added
again and stops nothing.** After an answer that was lost (X156) the
executor asks the sealer every two seconds, and a seal it finds is
handed to the agent's turn. A seal asked for in that moment (the timer's
next round, or `seal`) is handed the same seal and adds it. The one
handed over first then came to a book that held it already; the book
refused it, and the agent was stopped as under X155, with a sound book
and a message that was not true. Now `addCentralSeal` adds nothing where
all three of these hold:
- the book's last line is the entry byte for byte, the entry written
  out with the library's `entryLine`, as `add` writes it;
- the book's own check takes that line as a seal with nothing wrong;
- its fingerprint by that check is the one the sealer named for its
  latest seal.

Anything else goes to `add` as before, and a refusal there stops the
agent (X155): an entry that differs in one byte, the book's last line
where it is no seal, or the book's last seal under another fingerprint.
A seal newly signed, the answer to `seal`, comes with no fingerprint
named and always goes to `add`. Why the line and the fingerprint both:
the fingerprint is the sealer's word until the book's check has made it,
and the line alone would let any last line pass as "the seal". The link
also hands one seal to the agent's turn at a time (`sealing.mjs`): while
one waits there, a later question that finds the same seal hands nothing
over, so that a turn that is long in coming does not gather the same
seal many times, each with a check of the whole book. The other way:
tell the two cases apart by the book's refusal; `add` gives one refusal
for every entry it does not take.

**X168. A `hello` takes a place only once its body is whole, and a
command that is told `busy` asks again.** Under X160 a question took one
of the 8 places from the moment it arrived, for up to 5 seconds. A
caller with no secret who kept 8 questions open, each with a body begun
and never ended, and began each again when it was given up on, filled
every place: `status`, `seal` and `acknowledge` were then answered 503
and ended with code 2. What is fixed now, as numbers and not settings:
- *The body has 1 second* (it had 5). A command sends its 60 bytes at
  once.
- *A place is taken once the body has arrived whole and holds a
  challenge*, and is kept for the two signatures alone. So the places
  bound the signing, and a caller who sends a body slowly, or never
  ends it, holds none. A caller cannot keep a place either: it is given
  up when the answer is written, whether or not the caller reads it.
- *Of the 8 places, callers at one address hold 4 at most.* A fifth
  from that address is answered 503 (`busy`) while others still find a
  place. The address is the one the connection comes from. Callers at
  one address count as one caller: a program on the administrator's own
  computer shares the administrator's four places.
- *The command asks again.* Told `busy`, a command waits half a second
  and asks again, five times in all, then says that what answers is
  busy and that the secret was not sent. It had said that what answers
  "did not show that it is the executor", which was not the reason.
  `busy` is taken on the listener's word: the command sends it nothing
  but the challenge, each time.

What stays: questions whose bodies are not whole are not counted, so
their number is not bounded here. Each holds a connection for a second
and 256 bytes at most; the number of connections to the executor is not
bounded either. And a caller can still ask whole questions as fast as the
executor signs, which costs two signatures each (X160). The other ways:
a count of unfinished questions for each address, which a program at
the administrator's own address fills as before; the oldest unfinished
question giving way to a new one, which bounds them and is more to get
right.

**X169. An answer at the sealer's address is read up to 8 MiB and no
further.** The client read the whole answer into memory and looked at
its size afterwards, before its proof. Whatever listens at
`recorder.sealer.address` could so send as much as it liked for as long
as a question may take: while the sealer is stopped, any program on the
computer can take its port, and the executor asks every two seconds.
With 200 MB offered, the executor's side read all of it and its memory
rose from 54 MB to 679 MB; it now takes 16 MB off the listener and
stays at 80 MB. A length declared over the limit is refused before any
of the body is read; a body is read piece by piece with a count, and
the reading stops, and the connection is given up, once the count
passes the limit. The words of the refusal are as they were. The change
is made in `sealer/sealer.mjs`, the sealer's own client, and copied
(X151): the test that holds the copy holds this too.

**X170. What the test of the copy takes for a comment.** X151's test
holds that `sealer-client.mjs` has no code but the ten declarations and
two import lines. It had let through any line that began `//`, `/**` or
` *`, and so a line of code after a comment mark (`/** */ run();`). It
now takes for a comment only: a line that begins `//`; a line that
begins `/**` and ends with the first `*/` in it; or a block that opens
with `/**` alone on a line and closes with ` */` alone on a line, every
line between beginning ` * ` (or being ` *`) and holding no `*/`. A
line that holds a carriage return, U+2028 or U+2029 counts as code,
since each ends a `//` comment. These are the forms the copy's comments
have. The other way: read the file with a JavaScript parser; the
package has none, and takes no dependency for a test.

**X171. A socket file of another user's is named in the refusal (not
Windows or Linux); and what a re-check of the lock found here.** A
re-check of the lock on another branch, whose `lock.mjs` is older than
X162 to X164, found two faults. Both were looked for in this one.
- *Two programs taking over one socket file left behind.* Not here:
  X163 closes it. On Linux, with Node.js told it runs on another system
  so that `lock.mjs` takes the socket file's way: a file left behind by
  a program ended by force, then 8 starts at one moment, 60 rounds; 2
  starts one straight after the other, 150 rounds; and 8 starts that ask
  again for 10 seconds, 30 rounds. Never two holders at once, never a
  folder left. With the folder of X163 taken out of a copy, the same
  probe found two holders at once in 28 of 30 rounds and in 15 of 60.
  The re-check's own fix (every program that takes the lock looks a
  moment later whether the name still leads to its own listener) is
  therefore not added.
- *A file left by another user.* Here too. A socket file left in `/tmp`
  by a program of another user (an executor once run as root) may not
  be connected to, so it cannot be told from a live one; and `/tmp`
  lets only its owner take it away. The start was refused with "An
  executor is running on the book …", which need not be so. The lock is
  still refused, since nothing else is safe, and the refusal now names
  the file and says who can take it away. `alive` gives the code of the
  refusal (`EACCES`, `EPERM`) in place of `true`; `lockAt` puts the file
  and the code on its `LOCKED` error (`notAsked`, `why`); `lockFiles`
  writes the sentence. No function's arguments or result change.
- *On Windows, a folder's short name, or `\\?\` in front.* Not here:
  X162 resolves the folder with `realpathSync.native`, which gives one
  name for all of them. A test now holds `\\?\` beside the short name.
  Still another lock, and said in the README: a share of the computer's
  own drive (`\\localhost\D$\…`, `\\127.0.0.1\D$\…`) and `::$DATA`
  after the file's name.

**X241. A message is refused where a name in it differs only in capitals
from one the executor reads (0.4.2).** The number is the one this choice
has in the later design, so that one number names one choice. Three
rules, in `readMessage` (`jsonrpc.mjs`), the same on stdio and over HTTP:

- At its top level a message has the members `jsonrpc`, `id`, `method`,
  `params`, `result` and `error`, written exactly so, and no other. A
  message with any other member is refused. This holds for the agent's
  messages and for the server's.
- The agent's `params` hold, in one object at any depth (so in
  `arguments` and in `_meta` too), no two names that are one once folded,
  as X8 folds them: capitals, the long s and `s`, the Kelvin sign and `k`.
- In the `params` of a `tools/call` the names `name`, `arguments` and
  `_meta`, and in those of a `notifications/cancelled` the name
  `requestId`, are written exactly: a name that is one of them once
  folded, and is not written so, is refused (`Arguments` with no
  `arguments`). In the `_meta` of a `tools/call` the same holds for
  `red.prova/call-id` and `traceparent` (`handleCall` in `executor.mjs`).

The agent is answered with the error -32600, as for a member name given
twice, which the executor has refused from the start, and nothing is sent
to the server. A message of the server's that the first rule refuses is
treated as any line the executor cannot read: a call's receipt says the
answer could not be read and names no result, and the line goes to the
agent as it was. In a `tools/list` answer that the executor filters, a
tool with a second name in other capitals is not shown, and a member that
is `tools` once folded, and is not `tools`, is left out.

Why: a review ran a tool that no rule names through a made-up server
whose JSON reader takes member names without regard to capitals, the
later one winning, as the standard JSON reader of the Go language does
for the fields it knows. `{"method":"ping","Method":"tools/call", ...}`
was a ping to the executor, passed on with no check and no receipt, and a
tool call to that server. `{"name":"echo","Name":"order", ...}` was
checked and receipted as `echo`, and run as `order`. Every version up to
0.4.1 has this weakness where it stands in front of such a server. A
server that reads names exactly, as the JSON readers of Node.js and
Python do, is not affected. Servers built on the official Go SDK before
1.3.1 ignore capitals (GHSA-wvj2-96wp-fq3f); other servers have not been
checked.

No denial is written for such a message: it has two readings, and a
denial would name a tool and an amount that may not be the ones meant.
X8's refusal of such arguments, and the content rules' own, stay in the
code for a caller of `amountOf` and `testCall`; through the executor they
are no longer reached, since the message is refused before any rule is
read.

What this does not cover. The folding is that of capitals and a little
wider: besides the two letters above it makes one of the sharp s and
`ss`, of the dotless i, the dotted capital I and `i`, and of the
ligatures and their letters, so `Masse` and `Maße` in one object are
refused too; it errs on the side of refusing, and the refusal says
"differ only in capitals, or in letters that some readers take as the
same". A reader that takes two names for one in another way (by leaving
out `_` or `-`, or by a Unicode normal form) is not covered. Nothing is
checked in the `result` or `error` of the agent's own answers to a
server's requests, where the executor reads nothing. A lone name in the
arguments in other capitals (`Total` where a rule reads `/total`) is not
refused here: the amount is then not found and the call is refused (X8),
and a rule on content refuses a call where such a name stands on the way
to a pointer the rule reads (X249). The cost:
arguments that rightly hold two names that differ only in capitals in one
object (`path` and `PATH`) can no longer be sent.

The other ways. Refuse only at the top level and one level deep in a
tool call's `params`, the review's smallest fix: not taken, since a
server that folds names folds them at every depth of the arguments it
reads into its own types. Or fold names in the executor and read as such
a server would: not taken, since the executor would then differ from the
servers that read names exactly. `test/names.test.mjs` sends each such
message on stdio and over HTTP, in front of a made-up server that reads
names without regard to capitals, and reads that server's own record of
what it ran.

**X248. One message, one line, for a reader of UTF-8 (0.4.2).** The
number is the one this choice has in the later design, as for X241. A
message the executor writes to the tool server's standard input is first
made one line (`oneLine` in `jsonrpc.mjs`, used by `toServer` in
`executor.mjs`), and is still the same JSON: a line feed or a carriage
return between its values, where alone JSON allows them outside a text,
becomes a space; and U+0085, U+2028 and U+2029, which JSON allows only
inside a text, are written as their JSON escapes. The agent's own text is
changed in nothing else. This makes the message one line for a reader
that takes the bytes as UTF-8 and ends a line at any of those. A reader
that takes the bytes as another encoding may still cut a line inside a
character beyond ASCII (one that reads Latin-1 and ends a line at the
byte 0x85 does); such a cut falls inside a text, where quotation marks
are escaped, so it can spoil a message and cannot hide a call. The other
way, to write every character beyond ASCII as an escape, was not taken
for 0.4.2: it would change the bytes of every message with such a
character, for a reader that no server is known to be.

Why: the executor ends a line at a line feed alone, as the specification
frames stdio, and some readers end one at more. `node:readline` ends a
line at a bare carriage return, U+2028 and U+2029; a text reader with
universal newlines, which Python's `io.TextIOWrapper` gives unless told
otherwise, as the official Python SDK's stdio server uses, and how Python
opens its standard input on Windows, ends one at a bare carriage return.
A message of the agent's with a whole
`tools/call` between two carriage returns, inside a list in the `params`
of a `ping`, was one `ping` to the executor, passed on with no check, and
three lines to such a server, the second a call that the executor never
saw: it ran with no receipt and no denial, and its answer came back to
the agent (run, in front of a made-up server reading each way). A text
argument with U+2028 in it reached a server that reads with
`node:readline` as two lines: no call was hidden, since the quotation
marks of a text within a text are escaped, but the call was not answered
and was recorded as "outcome not known". Every version from 0.1.0 to
0.4.1 wrote the agent's text to the server as it came. A server that ends
a line at a line feed alone is not affected. Servers built on the
official Python SDK read standard input through `io.TextIOWrapper`, so
they end a line at a bare carriage return; other servers have not been
checked. U+0085 is escaped as well because some line readers end a line
there.

Over HTTP the executor sends the upstream a body, not lines, and nothing
changes. The demonstration's made-up server (`demo/server.mjs`) still
reads with `node:readline`; behind the executor it is now sent one line
for each message.

The other way: refuse a message with a carriage return between its
values. Not taken: it is valid JSON, and the same message on one line is
plainer than a refusal. `test/lines.test.mjs` sends such messages in
front of the made-up server reading each of the two ways, and reads its
own record of what it read.

**X249. A rule on content does not take for absent what it cannot read
exactly (0.4.2).** The number follows X248, so that it names the same
choice in the later design. Where a rule reads a pointer, in a `when` or
a `test`, two things on the way to it are now `content-unreadable`, and
the call is refused with a denial (`unreadableAt` and `holds` in
`rules.mjs`):

- An object on the way holds a member that is the pointer's name once
  folded (as X241 folds) and is not written as the rule reads it: `Path`
  where the rule reads `/path`, `SCAN` in the content where it reads
  `/scan`.
- The way stops, with names still to follow, at a value that is neither
  an object nor a list: a text, a number, true, false or null.

Why: an independent review of 0.4.2 ran the README's own example rules
in front of the made-up server that ignores capitals. `write_file` with
`Path` in place of `path` was let through and receipted as an allowed
change, since the rule's `when` found no `path` and the rule did not
apply, and the server wrote the file with the scan on; an `edit_file`
under `Path`, and a lone `SCAN` inside the content, passed too. Every
version with rules on content, from 0.2.0 to 0.4.1, does the same. X241
could not catch it: the message has one reading of its tool and one
spelling of each name, and only a rule knows which names matter. The
second came from the same review: a rule that tests `/debug` in `options`
refused `{"options":{"debug":true}}` and let through the same object
given as a text that holds JSON, which a server may read as the object
(as the reviewer recalls of one SDK; not run).

A denial is written here, unlike X241: the tool and the rule are known,
and only the content could not be read. What stays as it was: a member
that is simply not there is absent, and `orAbsent` and `absent` hold for
it; a list that is asked for a member by name has none; and a rule sees
a name in other capitals only on the way to a pointer it reads. The cost:
a call whose arguments rightly hold a name that differs only in capitals
from one a rule reads, in the object the rule reads it from, is refused.

The other way: fold names in the rule's own reading, so that `/path`
finds `Path`. Not taken: a server that reads names exactly would then
act on what the rule did not test. `test/content-rules.test.mjs` runs
both, the first in front of the made-up server that ignores capitals.

**X250. Reading a message never ends the executor, and a refusal names
its request where it can (0.4.2).** The check of X241 for two names that
are one once folded walks the message's text as it came
(`foldedInParams` in `jsonrpc.mjs`), as `repeatedName` does, and calls
nothing that calls itself. `readMessage` also catches whatever its
reading throws and refuses the line; no line is known to reach that. The
refusals for a member name given twice, and for a whole number beyond
2^53 - 1, are answered under the request's id where the text has one
top-level `id` that is text or a whole number every reader holds exactly
(`topLevelId`); before, under no id.

A message nested more than 256 levels deep, objects and lists together
and the message itself the first, is not read at all (`MAX_DEPTH` and
`deeperThan` in `jsonrpc.mjs`, which walks the text and calls nothing
that calls itself). The agent's is refused with -32600 under its id, and
nothing is sent to the server. The server's is a line the executor
cannot read, as X241 treats a member it does not know: where it answers
a call, the receipt says the answer could not be read and names no
result, and the line goes to the agent as it was; where it answers
another request, it is handed on as it was; a notification or a request
of the server's is handed on as it was.

One answer is not handed on: the server's answer to a `tools/list` that
the executor is to filter (`hideUnlisted`) and cannot read, whether it
is nested too deeply, names a member twice, holds no `tools` list in its
result or, over HTTP, comes under another id or is no message. Handed on
as it was, it would show the agent the tools the executor is to hide. The
agent's request is answered with the error -32603 under its id, with the
words of `LIST_NOT_READ`, and the log says `tools-list-not-read`
(`executor.mjs` on stdio; `http.mjs` for a JSON body and for an event).
The server's own error to `tools/list` goes on as it is (over HTTP, as
X260 has it). Before, in
every version, such a list was handed on unfiltered. What stays: a line
of the server's that the executor cannot match to any request (an id
given twice, no id or a null one, a list of messages, a byte order mark
before the message), and an event with no id, under another id or
holding a list of messages, are handed on as they were, and may hold
anything the server chooses to write: a list of tools too, with the
request not answered.
`test/list.test.mjs` runs each on stdio and over HTTP.

Why: the same review found that the first build of 0.4.2, never
released, wrote the `params` out afresh to look for such names, which
calls itself once for each level of nesting: one line of 10 KB, 5,000
levels deep, overflowed the stack where the lines are read and ended the
executor on stdio (over HTTP it answered 500 and went on). The walk
closed that one place, and others were left, on both sides: an agent's
cancellation of a call in flight is written afresh for the server; a
server's error is written out for the receipt, and its list of tools is
written afresh once filtered. Each calls itself in the same way: one
deep answer of the server's ended the executor (run), and so did the
agent's deep cancellation of a call in flight (run in the review's
re-check: 0.4.1 ends at `executor.mjs:1214`). A limit where the message
is read closes them together, and whatever is written later. 256 is the
builder's number: it is far below the depth at which any of these
overflows (some thousands), and above what the library fingerprints: the
fingerprint of a call's arguments, and of its result, takes 64 levels.
Between the two, as before, a call whose arguments nest too deeply is
answered with error 1001 and not sent, and a result that nests too
deeply is receipted as a result that could not be fingerprinted. The
receipt's text for an answer that could not be read names three reasons
(not JSON, a name given twice, not a response) and not this one; the
text is left as it is, since its fingerprint is what receipts name. And
a client on stdio that is answered under no id cannot match the answer
to its request, and waits out its own timeout.

The other way: catch the error at each place that writes a value out.
Not taken: each new place would need its own, and the stack's depth
where one is reached is not the same from one run to the next.
`test/deep.test.mjs` sends 200,000 levels each way on stdio and over
HTTP: the agent's requests, a call and a cancellation, and the server's
result, error, list of tools and notification.

**X260. Over HTTP, the upstream's own error answer to `tools/list` goes
on as it is, and the executor's own error in its place is sent as JSON
(0.4.2).** The number is out of order: X251 to X253 name other choices
in the later design. X250 answers for a list the executor is to filter
and cannot read, and let one answer through: the upstream's error under
the request's id. Two things follow from the review's re-check.

An upstream may refuse a request it could not read, or a session it does
not know, with a 4xx and a JSON-RPC error under a null id. As X250 was
first built, the agent was given -32603 in place of the upstream's
words. Now a JSON body that is an error answer and nothing more is
handed on as it was, with its status and content type, under whatever
id it has (`errorAnswer` in `jsonrpc.mjs`): one object whose members are
`jsonrpc` (`"2.0"`), `id` (text, a whole number or null) and `error` (an
object with a whole number `code` and a text `message`), each once and
written exactly so, nested no deeper than 256 levels, with no member
name given twice at any depth. Such a body has no `result`, under any
spelling, for any reader, so it holds no list of tools as a client
reads one. What its `message` and `data` say is the upstream's to
choose, as in its error under the request's id. Everything else is
answered as X250 has it: a result beside the error, a member the
executor does not know, a list of messages, a byte order mark, an error
that is not such an object.

Where the executor writes its own error in place of the upstream's
answer, the body is the executor's, so it is sent as
`application/json; charset=utf-8` with its own length and
`cache-control: no-store`, as the executor's other refusals are, and
not under the upstream's content type (`text/html` for a page) or its
word on caching. The status stays the upstream's, so that a client that
acts on the status is not misled. The upstream's `content-length` and
`content-encoding` were never handed on: of the upstream's headers only
the content type, the session, the protocol version and the word on
caching come back.

The other way for the first: hand on every error under a null id as the
text came. Not taken: a body with a `result` beside the error, or with
`Result`, is a list to some reader. The other way for the second: keep
the upstream's word on caching. Not taken: it was said of a body the
agent is not given. `test/list.test.mjs` runs both, and fourteen bodies
that are not such an error answer.
