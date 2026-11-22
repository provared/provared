# provared-mcp-executor

A guard, called the executor below, in front of an MCP tool server. It
holds the server's credential in place of the agent, checks each tool call against a permission a
person signed with a passkey, refuses calls outside it with a signed
denial, and writes a receipt, countersigned with its own keys, for each
call it lets through. The credential is kept from the agent only where
the agent cannot read the guard's files or reach the server another way
([What it is](#what-it-is) says when). Evidence, not a verdict.

## Quick start

With Node.js 24.7 or later:

```
npm install -g provared-mcp-executor
provared-mcp-executor demo
```

`demo` needs no passkey and no settings. In a new temporary folder, which
it names and leaves in place, it puts the executor in front of a made-up
tool server, under a permission signed by a development stand-in for a
passkey, sends it one tool call that is let through and one that a rule
refuses, and checks the book with the Provared checker. The stand-in is not
a person: its name ends with "(development)", and nothing the
demonstration writes proves anything about anyone. It writes nothing
outside that folder.

`provared-mcp-executor demo --stdio` is for trying the executor from an MCP
client or a directory's inspector. Each start makes a new temporary
folder, as `demo` does, and leaves it in place; in it go the settings and
a stand-in permission valid for one hour, after which every call is
refused until it is started again. It then runs the executor over stdio
in front of the made-up server, with its two tools `echo` and `add`, until
its input closes. Its standard output carries MCP messages only; on its
standard error it says, in one line, that this is a demonstration whose
records prove nothing about anyone, when the permission ends, and where
the book is.

For real use, in a folder of your own:

```
provared-mcp-executor init
provared-mcp-executor keys --config executor.json
provared-mcp-executor check --config executor.json
```

`init` copies the example settings and rules into the folder, as
`executor.json` and `content-rules.json`. Put in each value written
`<like this>` but the passkey's thumbprint, then make the keys; a person
signs the permission with a passkey, and its thumbprint goes in last;
`check` lists every problem left. "Set it up" below gives each step.
The executor holds the tool server's credential in place of the agent,
and keeps it from the agent only if the agent cannot read the
executor's files: see "What it is".

## What it is

**This is the executor's record of what an agent asked for through it, and
what the executor did with each call. It proves nothing about calls that do
not go through it.** It counts only if the agent has no other way to the
tool server behind it: take the server's credential away from the agent,
so that the executor alone holds it.

An **executor**, in the words of the Internet-Draft
[draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/),
is software other than the agent that takes actions for it or holds what
they need, and refuses an action the permission does not allow. This one
stands between an agent and a tool server that speaks the Model Context
Protocol (MCP). It runs in two ways: over the stdio transport, where the
agent's MCP client starts the executor as if it were the tool server and the
executor starts the real server, with its credential; or over HTTP, where
the executor is itself a Streamable HTTP MCP server in front of one upstream
HTTP MCP server, or of a local program it starts for each session, and
several agents call it, each signing in with a secret
of its own (see "Over HTTP, for several agents"). Either way, for every
`tools/call`:

1. works out which action the call is, and its amount, from a rules file
   the person writes, by the tool's name, not from anything the agent says;
2. asks the agent's stub writer whether the person's signed permission (the
   slip) allows it: the check before acting of the Provared library;
3. if it does, writes its own copy of the call to the disk, sends the call
   on, and writes a signed receipt (a stub) that names the executor and
   binds the arguments and the server's answer by their fingerprints, and
   **countersigns it with keys of its own**;
4. if it does not, sends nothing, tells the model why in a tool error, and
   writes a signed denial.

Every other message (`server/discover`, `initialize`, `ping`, resources,
prompts, notifications, a legacy server's own requests to the client) passes
through unchanged. `tools/list` comes back without the tools that have no
rule.

The executor holds the agent's keys and the server's credential. The agent
holds neither, so it cannot write, change or skip a receipt, as long as it
cannot read the executor's files: an agent with a shell or file tools that
runs as the same computer user can read them, and then the copy, the keys
and the credential are all in its reach. Run the executor under a separate user account that the agent cannot use,
or give the agent no shell or file tools. Over HTTP it can also run apart from
the agent, where the agent cannot read the executor's files:
[an example](recipes/agent-with-a-shell/README.md) (in the repository, not
in the npm package) puts them in separate
Docker containers on one computer, and its seven checks passed with
Docker Desktop on Windows; on separate computers it has not been tried. The executor
also keeps its own copy of every call, apart from the agent's log, which can
be held against the log to find a receipt that was left out
(`compare`). Where the settings name a recorder, the executor can seal the
book with the recorder's keys, by command or on a timer (`seal`; see
"Sealing, acknowledging, and what the executor says about itself"). The
recorder's keys are in a file of the executor's, or with a central
sealer, a program of its own that is sent the fingerprint of each line
as it is written and signs the seals.

Evidence, not a verdict. The whole design, with every choice numbered for
review, is in `DESIGN.md`. The format is described in the Provared format
description (`spec/provared-format.md` in the repository); the library is
the npm package `provared`.

## Install

```
npm install -g provared-mcp-executor
```

Or from a copy of the repository: in `mcp-executor`, `npm pack`, then
`npm install -g ./provared-mcp-executor-0.5.1.tgz`.

Use version 0.4.2 or later. Every version from 0.1.0 to 0.4.1 has two
weaknesses: in front of a tool server whose JSON reader ignores capitals
in names, or, over stdio, one that ends a line at a bare carriage return,
an agent could have a tool run that the executor never checked, with no
receipt or with a receipt that names a different tool, or get a call past
a rule on its content. npm marks those versions as deprecated. The security advisory,
https://github.com/provared/provared/security/advisories/GHSA-q53c-6wvv-gfj8,
says which servers are affected and what to check; `CHANGELOG.md` in the
repository has the details.

It needs Node.js 24.7 or later. It depends only on the `provared` library,
at exactly version 0.9.0: its receipts name
`provared.tool-name` and `provared.tool-result`, which the format reserved
in 0.7.0 and which a checker of 0.5.0 or 0.6.0 refuses (0.4.0 and
earlier read them as labels); and its owner's check uses two functions
of that version that the library does not yet name among its exports, so
it does not take a later one unasked. A library without them stops the
start, with a message that says so. `provared-mcp-executor --version` prints the
version installed.

The example files (`executor.example.json`, `executor-http.example.json`
and `content-rules.example.json`) are in the installed package's folder,
`provared-mcp-executor` inside the folder that `npm root -g` prints;
`provared-mcp-executor init` copies them into the current folder.

Node.js says that its ML-DSA-87 signing is experimental each time it is
first used in a program. The executor signs every receipt with ML-DSA-87
beside Ed25519, so the notice is expected; the command does not print that
one notice, and prints every other warning. A program of your own that
uses the executor's or the library's code sees the notice: it is not an
error. When the executor seals a book it signs with SLH-DSA-SHA2-256s too,
and Node.js then says once that SLH-DSA is experimental; the command
prints that notice.

## Set it up

1. Write the settings. `provared-mcp-executor init` copies the example
   settings and rules into the current folder as `executor.json` and
   `content-rules.json` (`init --http` copies the HTTP executor's as
   `executor-http.json`), and overwrites nothing. Then put in each value
   written `<like this>`: the server to start, the folder it runs in and
   the file its credential is read from. Set `tools` to the server's tools
   and the action each is, and change `content-rules.json` to rules of
   your own, or take `contentRules` out. The paths of the agent's keys,
   slip and book and of the executor's keys and copy can stay as they are.
   Paths are read from the settings file's folder. Leave the passkey's
   thumbprint (`agent.issuerKeys`) for step 3.

2. Make the keys. This makes the two key files if there are none, and
   prints what goes into the permission:

   ```
   provared-mcp-executor keys --config executor.json
   ```

   It does not need the passkey's thumbprint yet. It reads and checks
   everything before it writes: the settings, the rules file, any key file
   already there, and that the folder of each file it would write can be
   made. With `--out <file>` it writes what it prints to a new file
   instead (not one of the key files), making its folder where needed. The printed `agent.keys` go into the permission as the
   agent's keys; the printed `with` entry (the executor's id, name and
   keys) goes into the permission's `with`; and `requires` should hold
   `{"need": "countersignature"}`, so that a receipt without the executor's
   countersignature is a finding. Where the settings name a recorder
   (`recorder`, see "Sealing, acknowledging, and what the executor says
   about itself"), `keys` also makes the recorder's key file, with the
   three keys a seal is signed with, and says on its standard error the
   fingerprint of that key set; those keys go into no permission.

3. The person signs the permission with their passkey (on the signing page
   at https://sign.prova.red, or from a web page of your own with the
   library's browser part, `provared/passkey-browser`) and saves it where
   the settings say (`agent.slip`). The thumbprint of the passkey goes into
   `agent.issuerKeys`.

4. Check the settings. This reads every rule, the keys, the slip and the
   credentials, and says what is wrong. It prints no credential.

   ```
   provared-mcp-executor check --config executor.json
   ```

   It writes nothing: no line to the book, no copy key. It lists in one run
   every problem it can find on its own: each value still written
   `<like this>`, the server's program and folder, each credential, the
   rules file, each key file and the slip. Once none is left, it holds the
   slip against the keys and the rules, as a start does, and stops at the
   first difference there.

5. Point the agent's MCP client at the executor where it named the server.
   For a client whose settings are JSON:

   ```json
   {
     "mcpServers": {
       "files": {
         "command": "provared-mcp-executor",
         "args": ["stdio", "--config", "/etc/provared-mcp/files/executor.json"]
       }
     }
   }
   ```

   The client starts the executor; the executor starts the server named in
   `server.command` with `server.args`, in `server.cwd`, with the
   credentials in `server.env`.

## Over HTTP, for several agents

```
provared-mcp-executor http --config executor-http.json
```

The executor listens as a Streamable HTTP MCP server (one endpoint, `/mcp`
unless the settings say otherwise, on `127.0.0.1:8796` unless they say
otherwise) in front of one upstream HTTP MCP server named in
`upstream.url`, or of a local program it starts for each session (see "A
local program in place of the upstream", below). Each agent signs in with a secret of its own, in one header,
`Authorization: Bearer <secret>`, and has its own slip, keys, book and copy
under `agents.<name>`. `provared-mcp-executor secret` makes a secret and
prints its hash; the hash goes into the settings as the agent's
`secretHash`, the secret goes to the agent and is stored nowhere else.
`init --http` copies the example settings (`executor-http.json`) and rules
into the current folder. `keys` makes the executor's key file and one for
each agent (and the recorder's, where the settings name one), and prints the entries for each agent's permission (it needs
no secret hash and no passkey's thumbprint yet); `check` reads every
agent's slip;
`compare --agent <name>` holds one agent's copy against its book.

What the executor does with each request:

- A `tools/call` goes through the same rules, check, receipt,
  countersignature and copy as on stdio, under the slip and into the book
  of the agent that sent it. The check happens before anything reaches the
  upstream. One call at a time goes through each agent's writer; agents do
  not wait for each other. `maxWaiting` holds for each agent on its own.
- The agent's `Authorization` header is removed. The upstream is sent the
  executor's own credential, a bearer token read from the file
  `upstream.credential.file`. Of the agent's headers only `Accept`,
  `Accept-Language`, `Content-Type`, `Mcp-Session-Id` and `Last-Event-ID`
  go on (`Last-Event-ID`, which asks the upstream to replay a stream, only
  where it names an event the executor gave that agent, among the last
  1,000), with the `MCP-Protocol-Version` the body states, and the mirrored
  headers of the 2026-07-28 revision where each agrees with the body:
  `Mcp-Method` with the body's `method`, `Mcp-Name` with its
  `params.uri` on a `resources/read` or its `params.name` on a
  `tools/call` or `prompts/get`, and `Mcp-Param-<name>` with the call's
  argument at the
  property of the tool's `inputSchema` that the upstream's `tools/list`
  annotated `x-mcp-header: <name>` (a value wrapped as `=?base64?…?=` is
  decoded before comparing, and a number in the body is compared as a
  number with a header in JSON's form of one, so `42.0` agrees with 42 and
  `0x2A` does not). Every other header is dropped, and the names
  of the dropped ones are logged. A mirrored header that does not agree
  with the body, or that the executor cannot check (no `tools/list` seen
  yet, no such annotation, a GET or a response, an `Mcp-Name` on any other
  method), is refused with 400 and
  JSON-RPC error -32020 (the specification's HeaderMismatch), and nothing
  reaches the upstream; a request with none of these headers is not
  refused, and the executor never generates `Mcp-Method`, `Mcp-Name` or
  `Mcp-Param-*` itself, though the protocol version the body states goes on
  as its header. Of the upstream's
  headers only `Content-Type`, `Mcp-Session-Id`, `MCP-Protocol-Version`
  and `Cache-Control` come back.
- One message per POST, read as strictly as a line on stdio: a batch, a
  repeated member name, an id that is not text or a whole number, a number
  beyond 2^53 - 1, or a shape that is not a message is refused (400) and
  goes no further. So is a message with a member at its top level other
  than the six of JSON-RPC, or whose `params` hold two names that differ
  only in capitals (see `tools` under "The settings"). A request's method
  sent with no id, such as a `tools/call` sent as a notification, is not
  sent on and is refused (400).
- The upstream's answer comes back as it came: a JSON body, or a stream of
  events forwarded one by one as they arrive. The response under the call's
  id is the outcome and ends the call; a response under another id is never
  taken as the outcome. The stream to the upstream is closed once the
  outcome is in. An upstream that refuses a call with a 4xx status and a
  JSON-RPC error under the call's id (the specification's way: 400 for a
  header mismatch or an unsupported protocol version, 404 for a method it
  does not have) has that error recorded as the outcome and relayed, with
  its status, under the agent's id; a non-2xx with no such body is
  recorded as "outcome not known", and its body is not relayed.
- Legacy sessions pass through: the `Mcp-Session-Id` the upstream gives
  comes back as it is, the GET stream of server messages and `initialize`
  pass through, and a session belongs to the agent that opened it and, for
  an agent that connects through OAuth, to the connection it was begun
  under. Another agent's request under it, a request under it from another
  connection (the session is then forgotten), or an unknown id (after a
  restart, the executor knows none), is answered 404, and the client
  begins a new session. Where a request names a session, a call in flight
  is held by that session and its id, so two sessions of one agent may use
  the same ids, and a `notifications/cancelled` names a call of its own
  session only.
- To the upstream all agents are one caller: each request reaches it with
  the executor's one credential, and only a session, which belongs to the
  agent that opened it, tells one agent's requests from another's there.
  So what the upstream keeps for its caller rather than for a session is
  shared by every agent. What it sends on a GET stream opened without a
  session would go to whichever agent opened one, so where the settings
  name more than one agent, such a GET is answered 405 (the
  specification's "no stream offered here") and does not reach the
  upstream; under a session, or with one agent, it passes. A response an
  agent sends goes on only where it answers a request of the upstream's
  own that the executor handed on to that agent, under the same session,
  and only once (the last 1,000 unanswered for each agent); any other is
  refused with 400 and does not reach the upstream. A task it keeps for its
  caller could be read or cancelled by any agent. Tasks are therefore
  refused unless the settings allow them (`allowTasks`). Then every
  `tasks/` request is answered with JSON-RPC error -32601, and a request
  that asks for a task (`params.task`, 2025-11-25) or a subscription that
  names tasks (`params.notifications.taskIds` of `subscriptions/listen`,
  2026-07-28) with -32602, each under the request's id with 200, as the
  executor's other refusals of a request it has read; none of these
  reaches the upstream. In the 2026-07-28 revision tasks are an extension
  (`io.modelcontextprotocol/tasks`) that a client declares in the client
  capabilities of its request's `_meta`, and the server decides whether
  to make a task: the executor takes the extension out of every request
  it sends on, so the upstream answers at once, with the result. A call
  that the upstream answers with a task all the same is recorded with its
  outcome not known, and the agent is told so. With `allowTasks`, the
  extension goes on, and a call that becomes a task is checked and
  receipted as any call (its receipt's result is the task's handle; a
  later `tasks/result` or `tasks/get` passes with no receipt). The task an
  answer names (`result.task.taskId` where the request asked for one;
  `result.taskId` where `result.resultType` is `"task"`, in any answer) is
  held to the agent the answer went to (the last 1,000 for each agent),
  and a task named in answers to two agents is neither's. `tasks/get`,
  `tasks/result`, `tasks/cancel` and `tasks/update` that name another
  agent's task, or one the executor did not see made, are refused (-32602)
  and not sent, and so is a subscription that names one in
  `notifications.taskIds`; `tasks/list` comes back with that agent's tasks
  alone; any other `tasks/` method is refused; and an event of the
  upstream's that names another agent's task (`notifications/tasks/status`,
  `notifications/tasks`, or a message whose `_meta` ties it to that task)
  is dropped from this agent's streams. After a restart the executor knows
  no task, so the tasks made before it are refused. The methods and fields
  covered are those of the 2025-11-25 revision and, for 2026-07-28, those
  named here.
- Cancellation follows the era. On the 2026-07-28 revision, closing the
  response stream is the cancellation: the executor then closes its stream
  to the upstream, the outcome is recorded as not known, as on stdio, and
  the agent's own `notifications/cancelled` for a call in progress does the
  same and is answered 202, with nothing sent on. On a legacy session (a
  session id, or a protocol version before 2026-07-28), where the
  specification says a disconnection is not a cancellation, the agent's
  `notifications/cancelled` is sent on to the upstream under the
  upstream's id for the call, answered as the upstream answers it, and
  then the stream is closed; the agent merely disconnecting leaves the
  call running, bounded by `timeout`, and its real outcome is recorded.
- A request that names an `Origin` is refused (403) unless
  `allowedOrigins` lists it; a body over `bodyLimit` (4 MiB) is refused
  (413), and one that does not arrive whole within `timeout` is refused
  (408); a body that would take the bodies of one agent's requests in
  flight past `waitingBytes` (32 MiB) is refused (503); a message of more
  than 100,000 elements (list items and member names together) is
  refused (400) before it is read, on stdio as over HTTP (the number is
  fixed: no setting changes it, so a call whose arguments hold more, such
  as 34,000 rows of three fields, is refused wherever it is sent); a message of the
  tool server's of more than 100,000 elements is not read either: a call's
  answer is handed on as it came and its receipt says the answer could not
  be read (no fingerprint of the result), another answer is handed on as
  it came, and a `tools/list` that is to be filtered is answered with an
  error; an answer or an event of the upstream over 16 MiB is cut off; a
  call the upstream does not answer within `timeout` is cancelled and gets
  a receipt that says its outcome is not known; an agent whose connection
  does not take what the executor has waiting within `timeout` has that
  exchange cut, the upstream's stream having been paused meanwhile rather
  than buffered, and a very slow reader can be cut too, since the clock
  stops only when all that is waiting has gone; each agent may have 256 requests in flight and 1,000 sessions
  remembered, its own oldest forgotten first. A JSON answer the agent does
  not read is still held after its place among the 256 is freed, up to
  16 MiB for each connection, until that connection closes; the executor
  does not limit the number of connections.
- A stop on request (SIGINT, SIGTERM) with a call in flight settles the
  call as the executor's stop ("The executor stopped while this call was
  with the tool server, so its outcome is not known."), writes its receipt,
  answers the agent with that error, and then closes; a call still waiting
  its turn is not sent and is answered so. A stop without warning, followed
  by a start, writes the receipt from the agent's copy before the executor
  listens, as on stdio.

**When the credential is kept from the agent, and when it is not.** The
upstream's token never goes to an agent in a header, a body, an error or a
log: the executor forwards none of the upstream's headers but the four
named, and those with the token's text replaced too; relays nothing of an
upstream answer that refuses the token (401 or 403; the agent is told the
executor's credential was refused, and no more); never follows a
redirection; and replaces the token's text wherever it occurs in anything
it sends an agent (a tool result that echoes it, an error text, an event, a
header) with the words "[a credential was removed by the Provared
executor]". That holds for the token as it is in the file; a token the
upstream encodes or splits before echoing it is not seen, and JSON's own
escaping of a `/`, `"` or `\` in the token counts as encoding. It holds only
for what passes through the executor: an agent that can reach the upstream
by another way, or read the executor's files, has the token. And the
agents' secrets are only as safe as the connection they travel on: the
executor listens on the local address by default and speaks plain HTTP, so
an agent on another computer should reach it through an encrypted
connection that something else provides.

The settings (`executor-http.example.json` is a start): `name`, `service`,
`tools`, `contentRules`, `unlisted`, `hideUnlisted`, `timeout`,
`denialsPerHour`, `callIdInMeta`, `maxWaiting` and `recorder` as below; and

- `listen`: `host` (default `127.0.0.1`; another address is warned about;
  name one address rather than every address, see "Through a forwarder
  the command refuses") and `port` (default 8796). `path`: the endpoint
  (default `/mcp`).
- `upstream`: `url` (http or https; plain http off this computer is warned
  about) and `credential`: `{"file": <path>}`, the file that holds the
  bearer token, readable by the executor alone. Without `credential` the
  upstream is called with none, and the start says so.
- `allowTasks`, in front of an upstream only: `true` lets agents use the
  upstream's tasks, each held to the agent whose call made it; default
  `false`, every task request refused (see "To the upstream all agents are
  one caller", above). With `false`, the upstream's offer of tasks is not
  handed on either, so that a client is not asked to use what is refused:
  the answer to `initialize` or `server/discover` loses
  `capabilities.tasks`, and each tool in a `tools/list` loses
  `execution.taskSupport`. A tool the upstream marks as one that must be
  called as a task may then fail when called.
- `server`, in place of `upstream` and never beside it: a local program,
  with `shutdownWait` and `sessions` (below).
- `agents`: one member for each agent, by name (1 to 64 lower-case letters,
  digits, full stops, hyphens or underscores): `secretHash` (or
  `"oauth": true`, for a connection made through OAuth), `slip`,
  `book`, `keys`, `issuerKeys`, and `copy` and `copyKey` (defaults
  `copies/<name>.jsonl` and `copies/<name>.jsonl.key`). No two agents may
  share a secret or a file.
- `executor`: `keys`, the executor's own key file; and, where its keys
  were changed, `formerKeys`, the key files it held before (see "Where
  the executor's keys were changed").
- `admin`: `{"secretHash": <hash>}`, the hash of the administrator's
  secret, for the executor's own addresses (status, seal, acknowledge; see
  "Sealing, acknowledging, and what the executor says about itself").
  Without it those addresses answer nothing. It may not be an agent's.
- `bodyLimit`: the most a POST body may be, in bytes (default 4,194,304,
  the MCP TypeScript SDK's own limit).
- `waitingBytes`: the most bytes of bodies one agent's requests may hold
  at once, in bytes (default 33,554,432, as the gateway's). A body counts
  from its declared length, or from its first byte, until its request has
  been answered; a request that would take the agent past it is refused
  with 503, and other agents are not touched. In front of an upstream,
  what the executor holds of the upstream's answers to one agent (read
  and not yet handed on, or waiting for the agent's connection to take
  it) is held to the same number, counted apart: past it a JSON answer is
  refused with 503 (a call's outcome is then not known) and a stream is
  closed. What is counted is bytes as they came: one agent's bodies and
  answers together count at most about twice `waitingBytes`. The memory
  they take is more, since a message read takes several times its bytes
  (measured in the review of this release, with the default 32 MiB and
  bodies of 1 MiB: the whole 32 MiB of bodies held took about 470 MiB
  more of the executor's memory, 542 MiB at its peak). Lower
  `waitingBytes` and `bodyLimit` where memory is short, as the claude.ai
  recipe does with `bodyLimit`.
- `allowedOrigins`: the origins (scheme, host and port) whose pages may
  call the executor. Default none.
- `oauth`: where agents connect through OAuth (below): `issuer`,
  `clients` and `state`.

### A local program in place of the upstream

The tool server behind the HTTP executor may be a program on the same
computer that speaks MCP over its standard input and output, as the stdio
executor's does. Leave `upstream` out and give `server`:

```json
"server": {
  "command": "/usr/bin/node",
  "args": ["/srv/tools/server.mjs"],
  "cwd": "/srv/tools",
  "env": { "TOOLS_TOKEN": { "file": "secrets/tools-token" } }
},
"sessions": { "max": 8, "idle": 1800000 },
"shutdownWait": 5000
```

`server` and `shutdownWait` are the stdio executor's settings, read by the
same code, with the same rules for the program, its folder and its
credentials (see "The settings"). Settings with both `upstream` and
`server`, or with neither, are refused. The program is found and its
credentials are read once, when the executor starts; `check` names a
program that is not there and a credential that cannot be read.

What is different from an upstream HTTP server:

- **One program for each session.** A program is started when an agent
  sends `initialize` with no `Mcp-Session-Id`, and the answer carries a
  new session id. Every later message must name its session. A session is
  the agent's that began it: another agent that names it is answered 404,
  as for a session that does not exist, and nothing reaches the program.
  So no agent's messages or answers pass through a program that serves
  another. A message with no session, other than that `initialize`, is
  refused with 400.
- **Which revisions of MCP.** In front of a local program the executor
  serves clients and programs that speak revision 2025-11-25 of the
  specification (and 2025-06-18 and 2025-03-26, which have the same
  transport). Revision 2026-07-28, which has no sessions, is not yet
  supported in this mode: a client that speaks it alone cannot use a
  local program, and a program that speaks it alone, and so answers
  `initialize` with an error, cannot be served. A request whose
  `MCP-Protocol-Version` header names a version other than those three is
  refused with 400, unless it is the version the session's program
  answered `initialize` with; a request with no such header is taken.
  The `initialize` that begins a session, sent with no `Mcp-Session-Id`,
  is taken whatever the header names: the version is agreed inside
  `initialize`, and the one the program answers with is the session's.
  The log line of such a refusal (`"code":"protocol-version"`) has
  `"version"`, the version named where it is written as a date and
  `"other"` where it is not, and `"session"`, whether a session id came
  with the request.
- **The same check and the same records.** A `tools/call` goes through the
  same rules, check, receipt, countersignature and copy, under the slip
  and into the book of the agent that sent it. The program is sent the
  call under an id of the executor's own.
- **Answers.** A request is answered with one JSON body. A notification,
  or the agent's response to a request of the program's, is answered 202
  once it is written to the program; one that is not written is answered
  with an error: 400 for a request's method sent with no id, which is
  never sent on, 503 where the program is not reading, 502 where it has
  ended. The program's own requests and notifications, the progress of a
  call and a question a tool asks during it among them, go on the
  session's GET stream; a session has one, a later GET taking the place
  of the earlier, and where none is open they are dropped and the log
  says so, at most once a second with a count. So a client must keep the
  stream open to be asked anything by a tool. Nothing is replayed.
- **When a session ends**, its program is ended: its input is closed;
  where it has not ended `shutdownWait` milliseconds later it is sent
  SIGTERM, which a program may ignore; and where it is still running
  after a second wait (`shutdownWait` again, and at most 5 seconds) it is
  sent SIGKILL, which it cannot. On Linux and macOS both signals go to
  the program's whole process group, so to whatever the program started,
  a server behind a launcher among them; and what a program leaves in
  its group when it has gone is ended too, and counts as the program
  until then. On Windows the first of the two is already final, and it
  ends the one process the executor started: what that process started
  is ended only where Windows ties it to its parent, as it does for a
  launcher written in Node.js. So on Windows name the server itself in
  `server.command`, not a launcher that starts it. A session ends when
  the agent sends DELETE under it
  (204); when its program ends by itself; when it has been idle; when it
  makes room for a new one; when the connection made through OAuth it was
  begun under ends (a refreshed token goes on with the same session);
  when its program is not reading or writes without pause (below); and
  when the executor stops. Once the stop has begun no program is started:
  an `initialize` that arrives then is answered 503. The stop waits for
  the programs for the two waits and 2 seconds more, and then finishes
  whether or not each has gone, saying in the log how many have not. A
  request under an ended session is answered 404, and the client begins a
  new one.
- **A program that misbehaves.** Where more than 16 MiB already wait to
  be written to a program that is not reading, the next message for it is
  refused with 503 and not held, and the session is ended. Its program is
  given `shutdownWait`, as at every end of a session, so a call it was
  busy with may still be answered; then it is ended by force. A program
  that does one thing at a time reads nothing while it works, so the
  bound counts what an agent sends meanwhile: 16 MiB in all, however
  large `bodyLimit` is. A program that is to take large messages during
  long calls must go on reading while it works. A program that
  writes more than 1,000 messages that answer nothing in flight in each
  of 5 seconds running has its session ended: seconds by the clock,
  counted from the session's start, so that one second with 1,000 or
  fewer breaks the run. One read of a program's output is handled at a
  time, so that one agent's program does not hold up another agent's
  requests; and the calls that were with a program are settled once its
  output has been read to the end, so that an answer written just before
  the program ended is not lost.
- **A list of tools the executor cannot read** (nested more than 256
  levels deep, a member named twice, no `tools` in the result) is not
  handed to the agent where the executor is to filter it (`hideUnlisted`):
  the request is answered with the error -32603. The same in front of an
  upstream and on stdio.
- **A program that ends with a call in flight** gives the receipt it gives
  on stdio: the agent is answered with the error "The tool server ended
  before it answered this call, so its outcome is not known." and the
  receipt names that text.
- **A program that cannot be run**, or that ends or says nothing before it
  answers `initialize`, begins no session: the agent is answered 502 (504
  where it gave no answer within `timeout`) and told why.
- **The limits.** `sessions.max` (default 8, from 1 to 256) is the most
  sessions one agent may have at once, and the most programs the executor
  runs for it: the program of a session that has ended counts until it
  has gone. An agent at its most that begins another has its own session
  that has been quiet longest ended to make room, and the new one is
  begun once that program has gone; where each of its sessions has a
  message in hand, or no program goes in time, the new one is refused
  with 503. `sessions.idle` (default 1,800,000 ms, half an hour;
  from a second to a day) is how long a session is kept after the agent's
  last message under it; the time does not run while a call is with the
  program, and an open GET stream does not keep a session. A request
  other than a call that the program does not answer within `timeout` is
  answered 504, and the program is told that it is cancelled.
- **Cancelling** is as on stdio: the agent's `notifications/cancelled` is
  written to the program under the executor's id for the call. Closing
  the connection does not cancel a call.

What each program writes to its standard error goes to the executor's,
among the executor's own log lines, in whole lines (a line of more than
64 KiB is dropped). At most 256 KiB of each program's is written on in
each second of the clock, and nothing while more than 1 MiB already
waits to be written there; lines past either are dropped, and the log's
`server-stderr-dropped` says how many, once a second. So a program that
writes to it without pause neither fills the executor's memory nor holds
up the other agents.

What it does not do: the program's credentials are not looked for in what
it answers (as on stdio; the replacing described above is for the
upstream's token); every session's program is given the same environment
and folder, and the executor does not keep the programs from each other
on the disk; no session outlives the executor; and a call that asks for a
task (`params.task`) is checked and receipted as any call, with the
task's handle as its result, while the later requests for the task's
result pass with no receipt (the same on every transport).

`provared-mcp-executor init --http --demo` writes settings of this kind
for the demonstration's made-up server (the tools `echo` and `add`, which
reach no network), with the OAuth sign-in below: `executor-http.json`,
`content-rules.json` and `demo-token`, a made-up credential that server
asks for. It overwrites nothing. The public address, the client and the
passkey's thumbprint are left to put in, and the keys, the permission and
the owner are set up as for any agent; nothing is signed by a stand-in.

### Signing in through OAuth

A client that cannot be handed a secret can connect through OAuth instead.
The executor is then its own authorisation server, for itself alone,
following the MCP authorization specification (2025-11-25). Add to the
settings:

```json
"oauth": {
  "issuer": "https://guard.example.com",
  "clients": ["https://client.example/oauth/client-metadata.json"],
  "state": "oauth-state.json"
},
"agents": {
  "connection-1": { "oauth": true, "slip": "slips/connection-1.json", "book": "books/connection-1.jsonl", "keys": "keys/connection-1.jwk", "issuerKeys": ["<thumbprint>"] }
}
```

- `issuer` is the executor's public address, as clients reach it: an
  https origin with no path. The executor itself still speaks plain HTTP;
  a reverse proxy in front of it gives it HTTPS at that address, and must
  pass the path and the `Origin` header on unchanged. Only
  `http://127.0.0.1:<port>` and `http://localhost:<port>` are taken
  without HTTPS, for tests (a browser makes a passkey at `localhost`, and
  none at an IP address).
- `clients` lists the clients that may connect, each by the https URL of
  its client metadata document. With none, no client can connect. There is
  no other way to register a client. The list admits a client as a whole,
  not one account at it: anyone with an account at a listed client can
  begin a connection, and only the owner's approval makes it one.
- `state` is the file that holds the connections and the owner (default
  `oauth-state.json`). It holds only hashes of tokens, and of the owner
  only a public key and ciphertext. The executor writes
  it whole, through a new file that only its owner may read (on Windows,
  keep others out of the folder), made sure to be on the disk before it
  takes the old file's place. Where it cannot be written, nothing is
  changed and the client is answered 500: it keeps the tokens it had.
  One program holds a state file at a time: two executors need a state
  file each. A second executor whose settings name the same file, with
  whatever agents, does not start ("An executor is running on the state
  file …"); two settings files in one folder that both leave `state` at
  its default name the same file.
- The end of a connection is the one change that does not wait for the
  file. A connection that is ended (a refresh token or a code used twice;
  at a start, a client off the list or an agent no longer marked) is
  ended in memory at once, and is not used again while the executor runs.
  Where the file could not be written at that moment, it still holds the
  connection, and a start from it would bring the connection back. So the
  executor tries the write again every second (the log says
  `oauth-state-not-written` when the write fails, and
  `oauth-state-written` when it is made), and once more when it is
  stopped. **If the end is still unwritten then, the executor says so on
  its error output, names the agent and the client, and ends with code 1,
  not 0.** Before starting it again, see that the file can be written and
  take that agent's entry out of the file's `grants`, or run `owner
  --reset`, which removes the owner and ends every connection. An executor
  that is killed, or loses power, while an end is unwritten cannot say so:
  the next start brings that connection back.
- Each connection is one agent marked `"oauth": true`, with its own slip,
  keys, book and copy, as an agent with a secret. Agents with secrets work
  as before, beside it.

What happens:

- A request with no token gets 401, with a `WWW-Authenticate` header that
  names the resource's metadata, at
  `/.well-known/oauth-protected-resource/mcp`. The server's metadata is at
  `/.well-known/oauth-authorization-server`.
- The client sends the person to `/oauth/authorize`. The executor fetches
  the client's document (over HTTPS, at most 5 KiB, within 5 seconds, no
  redirection followed), keeps it for its `Cache-Control` age (5 minutes
  to 24 hours; 1 hour by default; 5 minutes for `no-store`), and keeps a
  copy. Where a later fetch gets no answer, or a 5xx, the copy is used
  while it is no more than 7 days old. Any other failure, a 404 among
  them, refuses the client. One fetch is made at a time for each client,
  and none for a minute after one that failed. The redirect address must
  be one the document names, exactly (only an address written
  `http://127.0.0.1` or `http://[::1]` may differ in its port). PKCE is
  required, with S256 only. The `resource` must be the executor's
  endpoint; its scheme and host may be in capitals.
- The page shows the owner which client asks, named by the host of its
  document's address ("Approve client.example connecting to your guard",
  for a client whose document is at client.example), and which agent it would
  become, and asks for the owner's passkey (below). It cannot tell whose
  request it is, so **approve only a connection you began yourself, just
  now**: a page that came as a link from someone else is to be refused.
  With the owner's approval the browser goes back to the client with a
  code, which lasts 60 seconds and works once. A code used twice by its
  client revokes what it gave; a used code shown without its PKCE verifier
  is refused and ends nothing.
- At `/oauth/token` the code becomes an access token (1 hour) and a refresh
  token (30 days). Both are random and kept only as hashes. The access
  token works only at this endpoint, for this client and this agent. Each
  refresh gives a new refresh token; an old one used again ends the
  connection. Approving a new connection for the same agent ends the old
  one. Taking a client off the list, or the `oauth` mark off an agent,
  ends its connections for good at the next start: putting it back does
  not bring them back.
- A GET stream opened with an access token is ended when that token is no
  longer one the executor takes: it expires, its connection ends, or later
  refreshes push it out (a connection keeps its 16 newest access tokens).
  A call already taken is finished, within the `timeout`, and receipted.
- Failed attempts are not counted, and shut nothing: a wrong answer, code
  or token is refused, and the right one passes straight after. What is
  guarded is 160 or 256 random bits, or a signature. A request waiting at
  the page is kept in the page's form, under a key the executor makes at
  each start and never writes down, so nothing anyone sends can push the
  owner's page out, and a start ends the pages that wait.
- With `oauth`, the `timeout` default is 230,000 ms, under the 240 seconds
  a client gives a tool call; a longer one is warned about. The token
  endpoint and the metadata make no request to anyone, and answer at once.
- An approval leaves no mark in the agent's book: approvals, new
  connections and their ends are in the executor's log only. The receipts
  say which agent acted, not which connection or client.

The owner's check is by the owner's passkey (DESIGN.md, section 14.1): a
plain passkey, with nothing more asked of it than that it verifies its
user (a fingerprint, a face or a PIN). The executor checks its signature
with the `provared` library's own check, and needs no other package.

- **Set up the owner, once.** With the executor stopped, run
  `provared-mcp-executor owner --config executor-http.json`. It prints a
  link, `<issuer>/oauth/owner#<code>`, which works once, within 15
  minutes. Start the executor and open the link in the browser you will
  approve connections in. Then do one of two things.
  - Add the executor in your client, in the same browser. The client sends
    you to the executor's page, which shows who asks to connect. **Approve**
    there asks for one passkey prompt: it makes the owner's passkey and
    approves that connection. The page then shows a recovery code, once:
    write it down, then press **Continue**.
  - Or press **Make the passkey** on the setup page. It makes the passkey,
    shows the recovery code, and approves nothing; you add the executor in
    your client afterwards.

  If the client's page is opened first, it says that the executor has no
  owner yet. Press **Keep this connection for the setup link** on it, then
  open the setup link in the same browser within 10 minutes: it offers to
  show that connection again, and Approve there is the same one prompt.
  Opening the link approves nothing by itself, and a page that is merely
  opened keeps nothing: only the connection you pressed the button for is
  offered.

  If the page says that the executor's answer did not arrive, press
  again. Where it then says that an owner is already set up, the setup
  finished: the passkey you just made is the owner's, and approves
  connections. Only the recovery code was not shown. To get one, run
  `owner --reset` and set up again; at that moment no connection exists
  to be ended.
- **What the executor keeps.** The passkey's identifier, its public key,
  and a hash of the recovery code. Nothing that could stand in for the
  passkey or the code.
- **Where the passkey is kept.** The browser asks: on this device, on a
  phone, or on a security key. The page names none of them.
- **Approve a later connection.** On the page, Approve asks for the
  passkey: one prompt. The passkey signs a challenge the executor made for
  that one request, and the executor checks the signature against the
  public key it keeps, for its own address, with the user verified.
- **The recovery code.** 32 letters and digits, shown once at the setup.
  Typed into its box on the page in place of the passkey, it approves that
  one connection, once: it is then spent, and no new code takes its
  place. The executor says so on a page of its own, before the browser
  goes back to the client: press **Continue** there, once. That page
  gives you 5 minutes for it, however late on the first page the code
  was typed, and says so. Once Approve or Continue has been sent, the
  page's buttons send nothing more, Refuse included: a Refuse behind an
  approval would not undo it. Every
  authorisation page after that says that the code is spent. If it says
  so and you did not use the code, someone else did: reset the owner. To
  have a recovery code again, stop the executor and run
  `provared-mcp-executor owner --config <settings> --reset` on the
  server: it removes the owner and ends every connection, and the new
  setup shows a new code. Until then the passkey approves as before. A
  code that is typed and whose page is then closed or lost, or whose
  Continue is not pressed in its time, is spent all the same, and
  approved nothing. The code does not make a new passkey:
  for that, reset the owner too.
- **The log says how each connection was approved.** The line
  `"event":"oauth-approved"` carries `"by"`: `"passkey"`, `"recovery"` or
  `"setup"` (the first approval, made with the owner).
- **The passkey belongs to the issuer's address.** If the public address
  changes, the passkey no longer works there. The recovery code still
  approves a connection; `owner --reset` makes a new owner at the new
  address.
- **One owner.** `owner` is refused while an owner exists. `owner --reset`
  removes the owner and ends every connection, with its tokens, then
  prints a new link.
- The pages run only the executor's own scripts, from its own address:
  the page's script and the library's own files. Nothing is loaded from
  anywhere else. The setup link's code, and a request the owner chose to
  keep where there is no owner, are kept in the browser's storage for the
  executor's address until they are used, or until one of the executor's
  pages next finds them ended: a code may lie there after its 15 minutes,
  of no use to anyone. That is true of what the
  executor sends: a program on the owner's own computer that changes the
  pages a browser shows, or reads the browser's storage, can still do
  what the owner can.

The program's interface takes another check, or none
(`openHttpExecutor(settings, {ownerCheck})`); the executor counts no
failed attempts, so what such a check asks for must not be guessable. Such
a check approves by answering `true`, or the name of the proof that
passed (`passkey`, `recovery` or `setup`); any other answer refuses. The
tests run the page's script on a stand-in page, with a software passkey.
In a real browser the pages have been run outside the tests, in headless
Chromium 153 with a virtual authenticator that verifies its user, against
the executor's own commands at `http://localhost` (an issuer the settings
take for tests, since a browser makes no passkey at an IP address): the
setup and the first approval in one prompt, in both orders; a later
approval in one prompt; an approval by the recovery code, as it then was,
with a new code shown; each through to a token and a tool call. The
recovery code as it now is, spent and not replaced, was run in a headless
Chromium browser, version 157, with no authenticator: two presses of
Approve, and of Continue, sent one form each, and the connection was
approved once; Approve and then Refuse, before the answer came, sent one
form. A virtual authenticator is not a device: the
pages have not been tried here with a computer's own authenticator, a
phone or a security key.
There is no
revocation endpoint, no dynamic
client registration, and no OAuth towards the upstream: the upstream still
gets the executor's fixed token. The folder `recipes/` in the repository
holds the settings for particular clients.

## The settings

```json
{
  "name": "Provared MCP executor for the files server",
  "service": "executor",
  "server": {
    "command": "node",
    "args": ["files-server.mjs"],
    "cwd": "servers/files",
    "path": ["/usr/local/bin"],
    "env": { "FILES_API_TOKEN": { "file": "secrets/files-token" } },
    "passEnv": ["PATH", "HOME"]
  },
  "agent": {
    "slip": "slip.json",
    "book": "book.jsonl",
    "keys": "keys/agent.jwk",
    "issuerKeys": ["<thumbprint of the person's passkey>"]
  },
  "executor": {
    "keys": "keys/executor.jwk",
    "copy": "copy.jsonl",
    "copyKey": "copy.jsonl.key"
  },
  "recorder": {
    "keys": "keys/recorder.jwk",
    "sealEvery": 3600000
  },
  "tools": {
    "read_file": { "action": "provared.data.read" },
    "order_supplies": { "action": "supplies.order", "amount": { "unit": "GBP", "pointer": "/total" } },
    "send_messages": { "action": "provared.message.send", "amount": { "unit": "messages", "count": "/recipients" } }
  },
  "unlisted": "refuse",
  "hideUnlisted": true,
  "timeout": 300000,
  "denialsPerHour": 600,
  "callIdInMeta": true,
  "shutdownWait": 5000,
  "maxWaiting": 16
}
```

- `name`: the executor's name; part of the tag on each line of its copy.
- `service`: the id the permission gives the executor in `with`; written
  into each stub's `with`. Default `executor`.
- `server.command`: the program to start, best named by its path. A bare
  name (`node`) is looked for in the folders of `server.path`, or, where
  that is not given, in the folders of the executor's own `PATH`, with a
  warning: that environment is set by the agent's client, which could then
  choose which program is given the credential. On Windows a bare name is
  tried with `.exe` and `.com` only; the server is started without a
  shell, which cannot run a `.cmd` or `.bat` shim (name the program the
  shim starts, such as `node.exe` with the script as an argument). A
  program that is not found stops the start.
- `server.env`: each variable the server needs, and where its value is read
  from: a file (`file`; one line ending at its end is dropped), the
  executor's own environment (`env`, warned against: that environment is
  only as safe as the agent's client that set it), or the settings
  themselves (`value`, warned against). The server's environment holds these and the variables
  in `passEnv` (by default `PATH`, `PATHEXT`, `SYSTEMROOT`, `COMSPEC`,
  `WINDIR`, `TEMP`, `TMP`, `HOME`, `USERPROFILE`, `LANG`, `LC_ALL`, `TZ`),
  and nothing else of the executor's environment: the agent's client, which
  starts the executor, passes the agent's environment to it, and the server
  must not inherit that.
- `agent.issuerKeys`: the thumbprints of the passkeys the executor trusts.
  With a slip signed by any other passkey the executor does not start.
- `executor.copy`, `executor.copyKey`: the executor's own copy of every
  call, and the key its lines are tagged under (32 random bytes, made the
  first time). Put them, and the executor itself, under a user the agent's
  side cannot write as; the copy shows a receipt left out of the book only
  if the agent's side cannot change the copy.
- `executor.formerKeys`: optional; a list of key files the executor held
  before its present one, used only to countersign the receipt of a call
  the administrator acknowledges (see "Where the executor's keys were
  changed").
- `recorder`: optional; the recorder that seals the book: `keys`, its key
  file; `name`, a label on each seal (the executor's `name` unless
  given); and `sealEvery`, how often the book is sealed while the executor
  runs, in milliseconds (no timer unless given); and `stamp`, a
  time-stamp service each seal is sent to (none unless given). Or, in
  place of `keys`, `name` and `stamp`, `sealer`: a central sealer that holds the recorder's keys
  (`address`, `name`, `token`, `keySet`, and, where wanted, `timeout`
  and `maxUnsent`). The example settings name none. See "Sealing,
  acknowledging, and what the executor says about itself".
- `tools`: each tool the agent may call, by its exact name, with the action
  name the slip uses for it and, where it applies, its amount: a fixed
  `value`, the whole number at a JSON Pointer (RFC 6901) in the call's
  arguments (`pointer`), or the length of the list there (`count`). A call
  whose amount cannot be read is refused, and so is one whose arguments
  name one member twice in one object, or two that differ only in capitals
  (`total` and `TOTAL`): a server may read the other one. A member name
  given twice exactly is refused in every message. So is every message of
  the agent's whose `params` hold, in one object at any depth, two names
  that differ only in capitals; a `tools/call` that writes `name`,
  `arguments` or `_meta` in other capitals; and a message with a member
  at its top level other than `jsonrpc`, `id`, `method`, `params`,
  `result` and `error`. The agent is answered with the error -32600 and
  nothing is sent to the server. Why: a tool server whose JSON reader
  ignores capitals takes `Method` for `method` and `Name` for `name`, so
  such a message was one thing to the executor and another to that server
  (DESIGN.md, X241). Versions up to 0.4.1 did not refuse them. Refused in
  the same way: a method that is `tools/call`, `tools/list`, `initialize`
  or `notifications/cancelled` in other capitals (`Tools/Call`); with
  `"unlisted": "forward"`, a call whose tool name is a ruled tool's in
  other capitals; and a message nested more than 256 levels deep, which
  from the server is treated as any line the executor cannot read
  (DESIGN.md, X250 and X253). The folding is a little wider than
  capitals: it also makes one of the long s and `s`, the Kelvin sign and
  `k`, the sharp s and `ss`, the dotless i, the dotted capital I and `i`,
  and the ligatures and their letters.
- `contentRules`: optional; the path of a file of rules on the content of
  a change, tested before a call is let through (see "Rules on the content
  of a change" below). Its fingerprint is named in every receipt and
  denial.
- `unlisted`: `refuse` (default) refuses a call to a tool no rule names and
  writes a denial named `executor.unlisted`; `forward` sends it on with no
  receipt and no denial, and the record then leaves those calls out. With
  `forward`, a content rule that names a tool no rule in `tools` names
  stops the start.
- `hideUnlisted`: whether `tools/list` comes back without such tools.
  Default true. Where the executor cannot read the server's answer to
  `tools/list` so as to leave them out, it does not hand the answer on:
  the request is answered with the error -32603 under its id. The
  server's own error goes on as it is, over HTTP with its status. An
  answer the executor cannot match to the request (on stdio a line with
  an id given twice, no id, a list of messages or a byte order mark; over
  HTTP an event with no id or another's) is handed on as it was.
- `timeout`: how long the server is given to answer a call, in
  milliseconds (default 300,000; from 1,000 to 86,400,000). After it the
  executor cancels the call and writes the receipt with an error.
- `callIdInMeta`: whether the executor's own identifier for the call is sent
  to the server in `params._meta["red.prova/call-id"]`, so that a server
  that logs `_meta` can be matched line for line with the record. Default
  true. Off, the stub names the identifier under `executor.call` alone.
- `denialsPerHour`: the most denials written in any hour (default 600).
- `shutdownWait`: how long the server is given to exit after its input is
  closed before it is ended (default 5,000 milliseconds). It is then sent
  SIGTERM and, where it is still running after a second wait (the same
  again, and at most 5 seconds), SIGKILL.
- Each message is written to the server as one line: a carriage return
  between its values becomes a space, and U+0085, U+2028 and U+2029 in a
  text are written as their JSON escapes, so that a server that ends a
  line at one of them reads one message and not several, of which one
  could be a call the executor never checked (DESIGN.md, X248).
  `node:readline` ends a line at a bare carriage return, and so does a
  text reader with universal newlines, which Python's `io.TextIOWrapper`
  gives unless told otherwise, as the official Python SDK's stdio server
  uses, and how Python opens its standard input on Windows. This holds
  for a server that reads its input as UTF-8; one that reads it as
  another encoding may still cut a line inside a character beyond ASCII,
  which can spoil a message and cannot hide a call. Versions up to 0.4.1
  wrote the agent's message as it came.
- `maxWaiting`: the most tool calls in progress or waiting their turn at
  once (default 16; 1 to 1,000). A call past it is answered with error 1001
  and nothing is written. At most 256 `tools/list` requests may wait for
  the server's answer.

## Rules on the content of a change

A permission allows kinds of action. Being allowed to change a file is not
being allowed to change everything the file controls: a call that changes
a label in a settings file and, with the same edit, switches on a `scan`
setting is one call of one kind, and the permission accepts both. The
executor can hold rules on content, in a JSON file of its own named by
`contentRules`, and test each proposed change against them before it is
let through. `content-rules.example.json` is a start:

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

A rule has:

- `name`: text of 1 to 200 characters, different for each rule. It is
  shown to the model when the rule refuses, and written into the
  executor's log and copy.
- `tool`: the tool's exact name, or a list of 1 to 64 names.
- `when` (optional): one condition, or a list of up to 16, on the call's
  arguments; all must hold for the rule to apply. With no `when` the rule
  applies to every call to the tool.
- `content` (optional): where the proposed content is in the arguments
  (`pointer`, a JSON Pointer, RFC 6901) and how to read it (`as`: `json`,
  the argument is text holding JSON; `value`, the argument is the content
  itself, as plain data). With no `content` the tests read the arguments
  themselves. Point it only at an argument the server writes as the whole
  new content.
- `test` (optional): one condition, or a list of up to 64, on the content;
  all must hold. **A rule with no `test` refuses every call it applies
  to.** That is how to close a route the executor cannot judge: a tool
  whose arguments carry only a partial edit (an old text and a new text),
  a template, or a reference to content elsewhere, whose resulting file
  the executor cannot know.

A condition is `pointer` and exactly one of `equals` (the same JSON value,
compared in full), `oneOf` (a list of 1 to 64 values), `absent` (`true`:
nothing may be at the pointer) or `matches` (a pattern over text: `*`
matches any run of characters other than `/` and `\`, `**` any run of any
characters, `?` one character other than `/` and `\`, and a `/` or a `\`
in the pattern matches either separator, so `**/settings.json` matches
`C:\proj\settings.json`; nothing else is special). A missing value fails `equals`, `oneOf` and `matches`, because
the executor cannot know what the program defaults to; `orAbsent: true`
lets it pass. "May not change" cannot be tested without reading the file:
write "stays equal to" the approved value instead.

The executor tests a call against every rule that names its tool, in the
file's order, after the amount is read and before the check before acting.
The first rule that refuses stops the call: the model is told
`Not taken by the Provared executor: Content rule "…": the value at "/scan"
in the content at "/content" must equal false, or be absent.`, with
`red.prova/refused` `content-rule` and `red.prova/rule` in `_meta`, and a
denial is written. **Content the rule cannot read exactly also refuses
the call** (`content-unreadable`): not JSON, a member named twice in one
object or twice once folded (`scan` and `SCAN`), a whole number beyond
9,007,199,254,740,991, nothing at the content pointer, something other
than text where JSON text is expected, a text over 4,096 characters where
a pattern would match it, or arguments with such folded names. A rule that
let through what it could not read would be a rule any comment in a file
evades. The executor reads no file and keeps no content: it tests only
what the call carries. No value from the arguments is written into the
model's error, the log or the copy.

**The rules file in the record.** Every receipt and every denial names
`executor.rules`, the SHA-256 of the rules file's parsed content in the
one form of RFC 8785 (so spacing does not change it; any rule does), and
a denial by a rule also names `executor.rule`, the fingerprint of the
rule's name; both are labels. So that a reader can see that the rules in
force were the ones the person approved, put the same fingerprint into
the permission's `agent.software` (format description, section 4.1):
`provared-mcp-executor keys --config executor.json` prints the entry,
`{"name": "Content rules of <the executor's name>", "sha256": "<the
fingerprint>"}`, beside the agent's keys. **The executor does not start
where the permission states software (`agent.software`) and the rules
file in force is not among it**: the person approved other rules than
these. **Nor does it start where the permission states rules on content
(an `agent.software` entry whose name begins `Content rules of `) and the
settings name no rules file**: it would run without the rules the person
approved. Where the permission states nothing, it starts and warns.
`check` reports the rules read and whether the permission states them;
`compare` reports, for each rules fingerprint the records name, how many
receipts and denials name it and whether a slip in the book states it,
and lists as `withoutRules` the executor's receipts and denials under a
slip that states rules on content which name no rules file.

The rules file is read strictly: UTF-8 (a byte that is not part of a
character stops the start), JSON, no member named twice, no whole number
beyond 9,007,199,254,740,991, `"version": 1`, no member that is not part
of a rules file, a rule or a condition, JSON Pointers as RFC 6901 writes
them (a `~` only as `~0` or `~1`), up to 1,000 rules, at most 1 MiB, and
at most 20,000 pattern parts in all (each character, `?` or run of stars
in a `matches` counts as one), so that testing one call takes at most
about a quarter of a second on an ordinary computer; anything else stops
the start and names its place. A rule that names a tool no rule in `tools`
names gets a warning where `unlisted` is `refuse`: such a call is refused
as unlisted before any content rule is reached. **Where `unlisted` is
`forward`, such a rule stops the start**: a call to that tool would be
sent on with no content rule tested.

**What the rules can never promise.**

- That the setting stays as the rule says by every path. A rule on
  `write_file` does not see a shell tool that edits the same file, a
  second tool with another name, the same file given under another
  argument name the rule's `when` does not read, a path written another
  way than the pattern expects, a change split over two calls each of
  which passes, or a file written under another name and moved. An edit
  by any route that does not go through the executor is not seen at all.
- That the content was read as the server reads it. The executor refuses
  what it cannot read exactly, but a server that reads the same text more
  loosely, or in another encoding, may act on something the executor did
  not see. A file type the executor cannot read (YAML, TOML, a line-based
  form; later work) cannot be tested: only a rule with no `test` can
  refuse such a write.
- That a tool's arguments show the resulting file. A partial edit, a
  template, a reference to content kept elsewhere, or a command gives the
  executor nothing to test; only a refusal outright closes it.
- That a pattern catches a meaning. `*` and `**` match characters, not
  files: `**settings.json` also matches `my-settings.json`; a path with
  other capitals, a trailing space, a trailing full stop
  (`settings.json.`, which Windows opens as `settings.json`) or a symbolic
  link is another text. A `/` or `\` in a pattern matches either
  separator, so that one pattern covers paths written either way; on a
  server on Linux or macOS, where `\` is an ordinary character in a
  file name, a `test` used as an allow-list (`matches: "safe/**"`)
  also accepts `safe\x`, a file in the current folder.
- That a `when` reads a value of another kind. A `when` with `matches` is
  met only by text: a path given as a list (`["settings.json"]`) or any
  other value that is not text does not match, so the rule does not apply
  and the call goes on to the next rule. Where a server could take a path
  of another kind, close the tool with a rule with no `test`.
- That a member is named as the program reads it, beyond the way to the
  pointers a rule reads. Where a rule reads a pointer and an object on
  the way to it holds a member that is the pointer's name in other
  capitals, the call is refused as unreadable: `Path` where the rule
  reads `/path`, and `"SCAN": true` in the content where it tests `/scan`
  (versions up to 0.4.1 took both for absent, so that in front of a
  program that reads names without regard to capitals the rule was
  skipped). A rule still does not see such a name in an object it does
  not walk through. And it takes two names for one only where they
  differ in capitals, or in a few letters that some programs take as the
  same (the long s and `s`, the Kelvin sign and `k`, the sharp s and
  `ss`, the dotless i, the dotted capital I and `i`, the ligatures and
  their letters): a program that takes two names for one in some other
  way acts on what the rule did not see.
- That a value of another kind is read as the program reads it. Where
  the way to a pointer stops, with names still to follow, at a value that
  is neither an object nor a list (a text, a number, true, false or
  null), the call is refused as unreadable: a program may read a text
  that holds JSON as the object. So a JSON text inside a JSON string
  (`"{\"scan\": true}"` as the content's text) is refused where a rule
  tests `/scan`. What stays: a list that is asked for a member by name is
  taken as having none, and `as: "json"` reads one layer, so JSON held as
  text in a member the rule does not walk through is a string to the
  rule.
- That the rules were right, or were applied. The record holds the
  fingerprint of the rules file and, in a denial, of the rule that
  refused; it does not hold the rules, and a receipt shows only that the
  executor that wrote it was running those rules. The fingerprint of a
  short rule name can be guessed from a list of likely names.

The rule writer has to know the tool: which argument carries the whole new
content, under which name the path is given, and which other tools reach
the same file.

## What the executor does with each call

1. **The line.** Read strictly: UTF-8, one JSON object with
   `"jsonrpc": "2.0"`, no batch, no member name given twice anywhere in it,
   no whole number beyond 9,007,199,254,740,991 anywhere in it (two readers
   would hold it differently), an id that is text or a whole number.
   Anything else is answered with a JSON-RPC error and goes no further: the
   method the executor reads must be the one the server acts on. (The rule
   on whole numbers is stricter than the gateway's: it holds for the whole
   line, the arguments included, not only where an amount is read.) A line
   over 16 MiB is refused. A notification whose method is not one of the
   protocol's own (`notifications/…`), such as a `tools/call` sent without
   an id, is dropped and logged: it would reach the server unchecked; so is
   a vendor's own extension notification under another prefix. Every
   request, not only `tools/call`, goes to the server under an id of the
   executor's own (`provared-<number>-<random text>`, unique for the
   session and not guessable), and the answer comes back to the client
   under the client's id; so nothing the client sends can collide with a
   call in flight, and an answer that arrives late, after a timeout or a
   cancellation, can never be taken for the answer to a later request that
   reuses an id. A call past `maxWaiting` is answered with error 1001.
2. **The rule**, by the tool's name (1 to 128 letters, digits, `_`, `-` and
   `.`; any other name is refused with -32602).
3. **The amount**, as the rule says. Then **the rules on content**, where
   the settings name a rules file: a call a rule refuses, or whose content
   a rule cannot read exactly, is not sent, the model is told which rule,
   and a denial is written that names the rules file and the rule.
4. **The check before acting**, through the agent's stub writer. A call it
   refuses is not sent: the client gets a tool result with
   `isError: true` whose text begins "Not taken by the Provared executor"
   and says why, and whose `_meta` carries `red.prova/refused`,
   `red.prova/codes` and `red.prova/denial`; the stub writer writes a
   denial with the codes.
5. **The copy.** A line saying the call is being sent goes into the
   executor's copy and is made sure to be on the disk before anything goes
   to the server. If it cannot be written, the call is not sent (error
   1001), and the executor takes no more calls until it is started again.
6. **Sending.** The call goes to the server as the client wrote it, with
   the executor's identifier added to `params._meta`. The stub names
   `provared.arguments` (the arguments in the one form of RFC 8785; `{}`
   where there are none), `provared.tool-name` (the tool's name), `executor.call`
   and `provared.request-id` (the executor's identifier), and
   `provared.trace-id` where the call's `_meta` carried a well-formed
   `traceparent`, and `executor.rules` (the fingerprint of the rules file
   on content) where the settings name one. After the answer it names `provared.tool-result` (the server's
   whole `result`, in the one form of RFC 8785) or, where there was no
   result, `provared.error` (the text of the error the client is given, or
   the server's JSON-RPC error as JSON). A result that cannot be written in
   that form (text that is not well-formed Unicode, a number JSON cannot
   write, a whole number beyond 9,007,199,254,740,991) gets
   `provared.error` with a fixed text saying so; so does an answer the
   executor could not read as a message at all (not JSON, a member name
   given twice), which still reaches the client as it was. The
   `inputResponses` and `requestState` of a retried multi round-trip call
   are not bound: only `arguments` are.
7. **A call that was sent always gets its stub**, whatever happened: the
   server's result (an `isError` result included), its error, no answer
   within `timeout`, the agent's cancellation, or the server ending. The
   executor countersigns the stub with its own keys once the outcome is
   known, so the countersignature covers the result's fingerprint. Then a
   line saying the receipt is in the book goes into the copy, naming the
   stub. Where the book file cannot be written after the call (something
   changed it, or it is not writable), the line names no stub and holds
   what the executor knew of the outcome instead; the call stays
   unfinished, the executor takes no more calls, and the next start writes
   the receipt from the copy with that outcome.
8. **The answer to the client** is the server's own bytes, with the
   client's id spliced in place of the executor's and nothing else
   changed: numbers keep their digits and spellings, however large. (The
   one answer the executor rebuilds is a filtered `tools/list`, in which
   each number is still written as the server wrote it.) Where there is
   none,
   the client gets a JSON-RPC error of the executor's own: code 1002 (no
   answer: the time ran out, the agent cancelled, or the server ended) with
   the stub's fingerprint in `data`. A line from the server that is not one
   JSON object (a batch, a bare value), or that names `id` twice at its
   top level, is not a message: it is handed on to the client as it is,
   matched with no call, and the call ends by the timeout with a "no
   answer" receipt. Code 1001 means the call was not taken: the executor
   could not record it, is stopped, or has too many calls waiting. The
   same holds for a line the executor cannot read as a message for another
   reason (not UTF-8, not JSON) whose top-level `id` it cannot find; a
   server line over 16 MiB is dropped. A request other than a tool call that the server never
   answers is forgotten after 1,000 such requests have piled up, the
   oldest first; its answer, if it ever comes, is handed on under the
   executor's id, which the client does not know and ignores.

One tool call goes through the stub writer at a time; other messages pass
through at once. A long tool call delays the next tool call.

**Cancellation.** A `notifications/cancelled` from the client for a call
that is with the server is passed on; the outcome is then taken as not
known (the specification says the server sends nothing more for it), the
receipt names `provared.error`, and a late answer is dropped. For a call
still waiting its turn nothing is sent and nothing is written; the copy
notes it as withdrawn.

**The server ends.** The call with it gets its receipt with
`provared.error`; calls still waiting get error 1002 and no record; the
executor exits with the server's code, and the client restarts it, as the
specification says it should.

**A call the executor was sending when it stopped.** Its line in the copy
has no line naming its receipt. At the next start the receipt is written
from that line, under the permission in force: with the result's or the
error's fingerprint where the copy holds it (the receipt was made and the
book could not be written), or else naming `provared.error` with the
words "The executor stopped while this call was with the tool server, so
its outcome is not known…". Such a receipt also names a document
`executor.written-late` (the fingerprint of a fixed text), so that the
book itself says the executor wrote it at a restart: its date is the time
the call was sent, and its countersignature is dated at the restart, so a
reader sees the two times apart. Where the call was sent under another
permission than the one now in force, the executor writes no receipt by
itself: the call waits for the administrator (see "A call sent under a
permission no longer in force").

Where the book already holds a receipt for such a call (the executor
stopped after the book took it and before the copy said so), that receipt
settles the call only where it is the only receipt naming the call, it is
the call the copy's `sending` line shows (the same permission, action,
amount and service; the line's documents first, then only the result, the
error or the fixed texts of a receipt written later), and, where the
permission names the executor with keys, it carries a valid countersignature.
The copy then notes it `found-in-book`, with its countersignature's
fingerprint. Any other such receipt is not taken as the executor's: the log
says `receipt-not-matching`, the executor does not start over stdio (over
HTTP, that agent's calls are refused), and the call waits for the
administrator, who can only set it aside (`acknowledge --set-aside`).

**The copy cannot be read** (its key is missing while it holds lines; no
line checks under the key; a last line was cut by a stop; a line was taken
out, put twice or moved, which the number each line carries shows): the
executor does not start, and says why. A copy cut at its end is not seen:
nothing in a line says it is the last.

## The copy, and comparing it with the book

```
provared-mcp-executor compare --config executor.json [--book <another copy of the book>]
provared-mcp-executor compare --config executor-http.json --agent <name> [--book <another copy of the book>]
```

For every call the copy shows as sent, the book is searched for the stub
that names the executor and the same `executor.call`. The answer lists the
calls that match, those whose receipt in the book is not the one the
executor wrote, or is not the call the copy's `sending` line shows (its
permission, action, amount, service, or documents differ: `differs`, with
`why`), those whose receipt lacks the countersignature the copy says the
executor gave it, or carries another (`countersignatures`; for a receipt
written at a later start, whose `done` line names no stub, one missing or
not checking), those with more than one receipt in the book
(`moreThanOne`), those with no receipt in the book (`missing`:
whoever keeps the book left it out, or the book is older than the copy),
those whose receipt the executor itself could not write to the book
(`notWritten`: its own stop, told apart from an omission), those the
executor sent and never gave a receipt, receipts in the book that name the
executor and that the copy does not know, and denials the book lacks.
Beside these, `withoutRules` lists the executor's receipts and denials
under a slip that states rules on content and that name no rules file;
it does not change the code. It ends with code 0 only where everything agrees, every line of the copy
checks under the key and runs in sequence, and the book itself has no
problem, was fully checked and is within its slips (the summary's
`bookProblem`, `bookFullyChecked` and `bookWithinSlips`). A book outside
its slips, for whatever reason, is no agreement, even where every call of
the copy matches; nor is a book this computer could not fully check (a
signature method it lacks). The copy key must exist (`compare` makes none), and a book named
with `--book` must exist.

It cannot find a call that never went through the executor, whether a tool
did what its result says, or a copy changed by whoever holds the copy key.

A call the administrator set aside (below) is listed under `setAside`: the
executor sent it and wrote no receipt for it, so the copy and the book do
not agree (`agree: false`) from then on. So that this known state can be
told from a new disagreement, the answer says `onlySetAside: true` where
the calls set aside are all that is wrong, and `compare` then ends with
code 3; it ends with 0 where the two agree, and with 1 for anything else.

`compare` expects every seal in the book to be signed by one recorder:
the one `--sealer <fingerprint>` names by the fingerprint of its key set
(as the checker's `--sealer`; several with commas between them), or else
the recorder of the settings, where its key file is there to be read. The
answer says which was expected, in `book.sealersExpected`; `null` there
means that no recorder was named and a seal's keys were compared with
nothing.

## Sealing, acknowledging, and what the executor says about itself

Over stdio:

```
provared-mcp-executor seal        --config executor.json --offline
provared-mcp-executor acknowledge --config executor.json --offline [--set-aside <call,…>]
provared-mcp-executor status      --config executor.json
```

Over HTTP, to a running executor:

```
PROVARED_MCP_EXECUTOR_ADMIN_SECRET=<secret> provared-mcp-executor seal        --config executor-http.json --agent research
PROVARED_MCP_EXECUTOR_ADMIN_SECRET=<secret> provared-mcp-executor acknowledge --config executor-http.json --agent research [--set-aside <call,…>]
PROVARED_MCP_EXECUTOR_ADMIN_SECRET=<secret> provared-mcp-executor status      --config executor-http.json
```

and, on the files of an HTTP executor that is not running, the same three
with `--offline` and no secret.

**The recorder's keys.** A seal (format description, section 21) is signed
by whoever keeps the book, the recorder, with three keys: Ed25519,
ML-DSA-87 and SLH-DSA-SHA2-256s. It fixes everything in the book before
it. The settings name the recorder:

```json
"recorder": { "keys": "keys/recorder.jwk", "name": "The recorder of the files executor", "sealEvery": 3600000 }
```

- `keys`: the recorder's key file. `provared-mcp-executor keys` makes it
  where there is none, as it makes the other key files, and says on its
  standard error the fingerprint of the key set. A person who checks a
  book names that fingerprint as the recorder they expect (the checker's
  `--sealer`); `check` and `status` show it too. The file may not be the
  executor's key file or an agent's.
- `name`: a label on each seal; the executor's `name` unless given.
- `sealEvery`: see "On a timer". Left out, there is no timer.
- `stamp`: see "An outside time-stamp on each seal". Left out, no
  time-stamp is asked for.

**An outside time-stamp on each seal.** With `"stamp": {"address": ...,
"timeout": ...}`, each seal the executor signs is sent, as its
fingerprint, to that time-stamp service (RFC 3161), and the time-stamp it
gives goes beside the seal in the book, in `stamps`. `address` begins
`http://` or `https://` and holds no user name, password, query or
fragment; `timeout` is from 100 to 20,000 milliseconds, 5,000 if left
out. No service is named by this package: the address is yours to
choose. The request and the check are the library's
(`provared/net/timestamp`, in `provared` 0.9.0 or later; with an earlier
release `check` says so and the executor does not start): the answer is
read up to 12,544 bytes and within the time limit, a redirect is not
followed, and the time-stamp is kept only if the library's `checkStamp`
passes it for this fingerprint, it carries the number used once that was
sent, and the time it states is within 300 seconds of this computer's
clock, no more than 300 seconds before the seal's own `when`, and no more
than 300 seconds before the latest time a service's time-stamp gave a
seal before it in the book. Anything else costs no seal: the seal goes into the
book without a time-stamp, `seal` answers `stampProblem` (its code and
why) and the command prints it, and the log has a `stamp-not-given` event
with the code and the reason. A seal that carries one answers `stamped:
true` and `stampedBy`, the fingerprint of the certificate that signed the
time-stamp; its `sealed` event says the same, the command prints it, and
`status` shows it with the last seal. The service sees the
seal's fingerprint, this computer's address and when it asked; nothing of
the book. While it is asked, the agent's calls wait, as for the seal's own
signatures, and the book's files stay held: an executor started on them
in that time waits for them (10 seconds, or `shutdownWait` and 5 seconds
more where that is longer) and is refused after it. So the signing and
`timeout` together are best kept below that, which the default of 5
seconds does; `check` warns where `timeout` is more than 8 seconds.
`stamp` is not taken beside `sealer`: a central sealer asks
for its seals' time-stamps under its own settings (its `stamp`), and
where it was not given one, the executor logs `stamp-not-given` with the
reason the sealer gave, also for a seal it takes back after the answer
was lost, while the sealer has not stopped since. A seal from a central
sealer answers `stamped: true` with `stampedBy` where it carries a
time-stamp, and `stamped: false` where it carries none.

**Which service signed: `authority`.** The check of the answer shows that
the time-stamp was made for this seal, not who made it. Over plain
`http:`, anyone between this computer and the service can answer in its
place with a key of their own, and without `authority` such a time-stamp
is kept and reported as one, while a person who checks the book and names
the real service does not count it. `"authority"` names the certificate
the service signs with: its fingerprint, or a list of up to 16, in the
form a checker names a trusted service (`stampServices`, or the
checker's `--stamp-service`): the SHA-256 of the certificate in base64url,
43 characters. A time-stamp signed by any other is not kept
(`stamp-not-given`, naming the fingerprint that signed it). To learn the
fingerprint, seal once and read `stampedBy`, then compare it with what
the service publishes. `check` warns where the address begins `http:`
and no `authority` is named. Left out, any signer is taken, as before.

Without `recorder` the executor seals nothing, and `check` says so. Where
the settings name a recorder, the executor expects every seal in a book to
be that recorder's: on a book sealed with other keys it does not start,
because the book does not pass its check.

**A central sealer.** The recorder's keys need not be among the
executor's files. In place of `keys`, the settings may name a central
sealer: the program `provared-sealer` (`sealer/` in the repository),
run by someone other than whoever runs the executor. It holds the
recorder's three keys, and the executor holds none of them. The executor
sends it the leaf fingerprint of each line of a book as the line is
written, never the line, except the book's first line, the permission
(format description, section 21.7), and asks it for the seals. The
sealer signs only over what it was sent.

```json
"recorder": {
  "sealer": {
    "address": "http://127.0.0.1:8797",
    "name": "files-executor",
    "token": { "file": "keys/sealer-token" },
    "keySet": "<the fingerprint of the sealer's key set>"
  },
  "sealEvery": 3600000
}
```

- `address`: where the sealer listens: `http://127.0.0.1:<port>`. The
  sealer listens on 127.0.0.1 only, so the two programs run on one
  computer.
- `name`: the name the sealer knows this recorder by: 1 to 63 small
  letters, digits and hyphens.
- `token`: where the recorder's token is read from: `{"file": <path>}`
  or `{"env": <the name of a variable>}`. The token is never written in
  the settings, and no command prints it. Keep the file for the
  executor's user alone.
- `keySet`: the fingerprint of the key set the sealer signs with, as
  `provared-sealer init` prints it. It is what a person who checks a book
  names as the recorder they expect. The executor expects every seal in a
  book to be signed with it, and does not start where the sealer says it
  signs with another.
- `timeout`: how long one question to the sealer may take, in
  milliseconds: 5,000 unless given, from 100 to 60,000. The question for
  a seal is given 30 seconds.
- `maxUnsent`: how many lines of a book may be unsent before that
  agent's calls are refused: 100 unless given, from 0 to 10,000.

`keys` and `name` may not be named beside `sealer`: the recorder's keys
are in one place, and a central sealer's seals give its own name.

To set it up:

```
provared-sealer init --folder /srv/sealer --name "Example Ltd central sealer"
provared-mcp-executor keys --config executor.json
provared-sealer add-recorder --folder /srv/sealer --agent <fingerprint> files-executor
provared-sealer start --folder /srv/sealer
```

`init` prints the fingerprint of the sealer's key set, for `keySet`.
Where the settings name a sealer, `keys` says on its standard error the
fingerprint of each agent's key set, which `add-recorder` takes with
`--agent`: the sealer starts a recorder's books only from permissions
for the agents it was told. `add-recorder` prints the token, once; put
it in the token file. Then start the sealer, and then the executor.

*What is sent.* Every line reaches a book file in one place of the
program, and from there its leaf fingerprint goes to the sealer: the
permission's line, each receipt, each denial and each seal. A line is
sent only once it is in the file. Each question names the place of its
first line, and the place moves on only by the sealer's answer, so no
line is left out or sent out of order.

*Where the sealer does not answer.* No question waits longer than
`timeout`. The lines not yet sent stay in the book file, and are sent in
order when the sealer answers again; it is tried every two seconds. A
sealer that was started again holds each book only up to its latest
seal, so it is sent the lines since. While no more than `maxUnsent`
lines are unsent, calls are taken. Past that, a call waits for one more
try, at most `timeout`, and is then refused as a rule of the executor's
refuses: a denial in the book, and a tool error with the code
`sealer-behind`, until the sealer has caught up. A denial is a line too;
`denialsPerHour` bounds how many are written. The answer to a call is
not held back until the sealer has its receipt. No seal is asked for
until the sealer holds every line.

*At a start.* The sealer must answer, or the executor does not start;
nor does a command that opens the files to write (`--offline`). Before
anything is written, what the sealer holds is compared with the book
file: that it signs with the key set of the settings; that it holds no
more lines than the file; that its latest seal is the book's last; and
that no later book follows this one. Where they do not agree, the
executor does not start, and says why. A sealer whose record is behind
the book's seals (lost, or put back to an older one) must be brought up
to date with the sealer's own `update`; this program does not do that.
A seal the sealer signed over the book as it stands, which the book
never took (the executor stopped between the two), is added then. The
lines after the latest seal cannot be compared: the sealer holds
fingerprints, and gives none back. A change among them is found when the
next seal is added: the book refuses the seal, the agent is stopped,
and the executor does not start on that book again.

*A seal.* The executor first asks the sealer what it holds, and sends
what it lacks; then it asks for a seal, naming the book's last seal and
the time by its own clock. The seal's entry is added through the stub
writer as the sealer gave it. Where the sealer refuses, there is no
seal, and the agent goes on. Where no answer comes, the sealer may have
signed: a seal sits after exactly the entries it covers, so no line is
written, and no call is taken, until the sealer has said. The executor
asks again every two seconds, and adds the seal before any other line
if there is one. A seal asked for in that moment (the timer's next
round, or `seal`) may be handed the same seal: it is added once, and the
agent goes on, also where a line (a denial) was written between the two.
Only a seal that is none of the book's sound seals, byte for byte, is put
to the book, which refuses one signed over other lines.

*What such a seal shows, and what it does not.* It shows that the
sealer's keys signed the number of entries and the top fingerprint of
the tree the sealer built from the fingerprints it was sent. Whoever
runs the executor holds no key that makes a seal, so they cannot change
or leave out a line that a seal covers and seal again. While the sealer
keeps its record, it signs one history of a book: a line it was sent is
in its next seal, changed or not in the file, unless the sealer is
started again before that seal. It does not show that the lines are
true, nor that every call has a line. The executor still holds the
agent's keys and its own, and a line is in its operator's hands until it
is sent: an executor that its operator has changed can leave a call out
before anything reaches the sealer (`compare`, and a copy kept where the
operator cannot change it, are the checks for that). The sealer sees no
line but the first. Whoever holds the recorder's token and the agent's
keys can have another book sealed, from another permission for the same
agent; the sealer's own README says what it can and cannot tell apart.
The sealer listens on 127.0.0.1 with no TLS, so the two programs are
kept apart by two user accounts on one computer: whoever can read both
accounts' files holds everything. A checker cannot tell a seal made by a
central sealer from one made beside the agent.

**`seal`** seals one book now. The executor asks the library for a seal
over the book as it stands, naming the seal before it where there is one,
and adds it to the book through the stub writer, which takes it only if
the whole book still passes its check with it. Nothing is sealed while a
call of that agent waits to be acknowledged, or where the book file is no
longer as the executor left it. A seal waits its turn behind a tool call
of the same agent that is in progress, and that agent's next call waits
for the seal: on the computer this was built on, a seal took just under
two seconds to sign and added about 52 KB to the book. The slowest of the
three signatures is made outside the program's own thread, so other
agents' calls are served meanwhile. Such signatures are made one at a
time: where several books are sealed at once, each seal after the first
waits its turn (and so does the next call of that seal's agent), and
other agents' calls do not.

Over HTTP, `seal --agent <name>` asks the running executor
(`POST /provared/seal`, with the body `{"agent": "<name>"}`). Over stdio
there is no address at which a running executor could be asked, so `seal`
and `acknowledge` take `--offline` only. `--offline`, with either kind of
settings, opens the files itself, for an executor that is not running, and
needs no secret: whoever can write those files can do as much.

**One program at a time.** A book and its copy are written by one program
at a time. Before `stdio`, `http` or a command with `--offline` reads
them, it takes a lock named after the book file, which the operating
system takes away when the program ends, however it ends. A second program
is refused ("An executor is running on the book …"), having read and
written nothing. A command asks once. A start (`stdio`, `http`) asks
again for 10 seconds (over stdio, for `shutdownWait` and 5 seconds more
where that is longer) before it is refused, so that a client that starts
the executor again while the one before is still ending is not turned
away. So `seal --offline` or `acknowledge --offline` beside
a running executor does nothing, and a second `http` on the same settings
does not start; nor does a second `stdio`, where a client starts the
executor twice on one settings file. Over HTTP a command with `--offline` takes every agent's
lock, not only that of the agent it names. `status`, `check` and `compare`
only read, take no lock, and may be run at any time. The state file of an
HTTP executor that takes connections (`oauth.state`) has a lock of the
same kind, named after the state file: `http` takes it first and holds it
while it runs, and `owner` holds it while it works, so a second `http`
whose settings name the same state file does not start, whatever its
agents ("An executor is running on the state file …"). As for a book,
`http` asks again for it for 10 seconds before it is refused, and `owner`
asks once. "What it does not do"
says where the lock does not reach.

Where the lock is a socket file (not Windows or Linux), a program ended
by force in the first milliseconds of its try for the lock can leave the
folder `<socket file>.clearing` beside it, and every later start and
command on that book is then refused until someone takes the folder away.
The refusal names the folder, and says it was left only where it is more
than 5 seconds old; a younger one is another program's, at work for a
moment, and a program that finds it looks again for 100 milliseconds
first.

A command with `--offline` is not a start. It writes no receipt by itself
for a call the copy shows as sent and unfinished (a start does, as above);
`status` counts such calls in `receiptsAtNextStart`, and `seal --offline`
does not seal that book while there is one: start the executor first.

`seal`, `acknowledge`, `status` and `compare` refuse an option they do not
know, and then do nothing.

**On a timer.** With `recorder.sealEvery`, a whole number of milliseconds
from 1,000 to 604,800,000 (seven days), the executor seals while it runs,
over stdio and over HTTP. When it starts (over stdio, when the client
starts it; over HTTP, when it begins to listen), a book that holds an
entry after its last seal is sealed if that seal is at least `sealEvery`
old by the executor's clock, or if the book holds no seal. After that,
every `sealEvery` milliseconds, a book that holds an entry after its last
seal is sealed. A book whose last entry is its last seal is left as it is,
so an idle executor writes no seal over a seal. Each agent's book has its
round to itself: a seal waits its turn behind that agent's own calls in
progress or waiting, and holds back no other agent's seal. An agent can
so put off the seal of its own book for as long as its calls last. A seal
that could not be written is noted in the log (`not-sealed`), once for as
long as the reason stays the same, and tried again `sealEvery`
milliseconds later. Over HTTP the timer starts once the executor is
listening: a start that cannot listen seals nothing. When the executor
stops, no further seal is asked for; one that was already waiting its
turn is still written. Over stdio the executor runs only while the client
keeps it running: where a session is shorter than `sealEvery`, the entries
written since the last seal have no seal until a later start writes one.
A `sealEvery` of less than a minute is allowed, and warned about.

**The executor's own addresses, over HTTP.** `GET /provared/status`,
`POST /provared/seal` and `POST /provared/acknowledge` are for the
administrator, who signs in with a secret of their own in one header,
`Authorization: Bearer <secret>`. The settings hold its hash, as
`"admin": {"secretHash": "<hash>"}`; `provared-mcp-executor secret` makes
a secret and its hash (the same command makes an agent's; the
administrator's must be kept from every agent). Without `admin` these
addresses answer nothing (404), and `check` says so. An agent's secret is
refused there (401); the administrator's secret is refused at the MCP
endpoint; and settings in which an agent's hash is the administrator's are
refused. A request that names an `Origin` (a web page's) is refused (403)
whatever `allowedOrigins` says; a body is read up to 64 KiB and refused
past that (413), whatever `bodyLimit` is; and the MCP endpoint (`path`)
may not be `/provared` or under it. An executor that is stopping answers
503 there.

**Who the commands send the secret to.** The commands read the secret
from the environment variable `PROVARED_MCP_EXECUTOR_ADMIN_SECRET` and ask
at `listen.host` and `listen.port`, over plain HTTP. So that the secret
does not go to whatever happens to listen there, a command first sends a
challenge, 32 random bytes it has just made, with no secret, to a fourth
address, `POST /provared/hello`. The executor answers with two signatures,
by the two keys of its own key file (the keys it countersigns with), over
the challenge and the address and port at which it received the request.
The command checks them against the executor's public keys, and against
the address and port it connected
to; only then does it send the secret, on that same connection. Where the
check fails it says "… did not show that it is the executor of these
settings … The administrator's secret was not sent." and ends with code
2. `POST /provared/hello` needs no secret, signs for anyone who asks, and
signs nothing but that text, which cannot be taken for a record: a
challenge must be 43 characters of base64url. Since anyone may ask, it
reads a body of 256 bytes at most and waits 1 second at most for it. It
signs for 8 such questions at once, and for 4 from one address; a
further one is answered 503 (`busy`) and nothing is signed for it. A
question counts only once its body has arrived whole, so a caller who
never ends a body takes no place. A command that is told `busy` asks
again after half a second, five times in all; if the answer is still
`busy` it says "… says that it is busy … The administrator's secret was
not sent. Run the command again." and ends with code 2. Programs at one
address count as one caller, so a program on the administrator's own
computer that asks without pause can still make a command wait or fail
in this way. This shows the command that
it reached the executor; it does not hide the secret from whoever can read
the connection, which is plain HTTP.

**The keys a command checks with.** A command needs the executor's two
public keys and no private key. It takes them from `executor.keys`, of
which it reads the public parts alone. Where the administrator may not
read that file, write the public keys alone to a new file, as the
executor's user:

```
provared-mcp-executor keys --config executor-http.json --public-keys executor-public.json
```

and name that file to `status`, `seal` or `acknowledge` with
`--public-keys executor-public.json`; the command then reads it in place
of `executor.keys`. The file has the form of a key file with nothing
private in it and is no secret, but whoever can change it can make the
command trust another listener: keep it where only the administrator can
change it. A file that holds no usable keys (not the two keys, Ed25519 and
then ML-DSA-87) is said to hold none, and nothing is sent. The executor
itself signs, and does not start on a file of public keys.

**Through a forwarder the command refuses.** Through an SSH tunnel, a
published container port or a reverse proxy, the address the executor
signs is not the one the command connected to, so the command refuses and
sends no secret: that is the defence working, since the command cannot
tell such a forwarder from a listener in the middle. Run the command where
it reaches the executor directly: on the executor's computer, or inside
its container. Name one address in `listen.host` rather than every address
(`0.0.0.0` or `::`): on Windows, another program of the same user can
listen on `127.0.0.1` at the executor's port while the executor listens
on every address. The check keeps the administrator's secret from such a
program; an agent that connects to `127.0.0.1` would still hand it the
agent's own secret.

**`status`**, asked of a running HTTP executor, gives the recorder's name,
the fingerprint of its key set and the timer, and for each agent: the
fingerprint of the permission in force, the number of entries and bytes in
the book, the last seal (its entry, its fingerprint and its time), whether
the book as it stands passes its check (`sound`) and is within its
permissions (`withinSlips`), why the agent takes no call (`stopped`, or
null), the calls waiting to be acknowledged (`receiptsMissing`) and the
number of tool calls in progress or waiting their turn (`waiting`). While
one of the agent's calls is with the upstream, the stub writer gives no
check, so the check shown is the last one, with `checkedNow: false` and
its time in `checkedAt`.

Over stdio, and over HTTP with `--offline`, `status` reads the files
instead, and writes nothing (`"from": "files"`). It gives the book file's
entries and bytes, its last seal, whether it passes its check, the calls
waiting to be acknowledged, and the number of calls that the next start
will give a late receipt (`receiptsAtNextStart`). It cannot show what a
running executor holds only in memory: whether it has stopped, or the
calls in progress. Where the files cannot be opened as a start would open
them, it gives the reason in `problem`.

Where the settings name a central sealer, the recorder is shown by the
fingerprint of the sealer's key set, the sealer's address, the name it
knows the recorder by and `maxUnsent`, and each agent has a member
`sealer`. From a running executor: how many lines of the book the sealer
has not answered for (`unsent`), when the oldest of them was written
(`since`), when the sealer last answered (`answeredAt`) and what is
wrong (`problem`, or null). From the files, the sealer is asked, once,
how many lines of the book it holds: `reached`, `holds`, `unsent` and
its latest seal (`latestSeal`), with `problem` where it could not be
asked or holds more lines than the file; `since` is known only to a
running executor, whose log names it too (`sealer-behind`). Lines that
are unsent do not change the code `status` ends with.

`status` ends with code 0 where every book it shows passes its check (or
is not there yet), no call waits to be acknowledged and no agent has
stopped; with 1 otherwise; and with 2 where it could not ask or read.

### A call sent under a permission no longer in force

A call the executor was sending when it stopped is given its receipt at
the next start, as "What the executor does with each call" says, where the
permission in force is still the one the call was sent under. Where a new
permission has been put in place since, the executor does not write that
receipt by itself. The call waits for the administrator:

- Over stdio the executor does not start while a call waits, and names
  the command to run.
- Over HTTP it starts. That agent's calls to tools that have a rule are
  refused (error 1001, with the reason) until no call waits; the other
  agents' calls are taken; the log says `receipt-missing`. A call to a
  tool no rule names is answered as it always is: refused, with a denial
  written into the book, or, where `unlisted` is `forward`, sent on with
  no record.

`status` lists each waiting call under `receiptsMissing`: its `call`
identifier, when it was sent, the permission it was sent under, its tool
and its action, whether the copy holds its outcome (`outcomeKnown`),
whether a key file the executor held before would countersign it
(`formerKeys`), and, where no receipt can be written from its line, why
(`usable: false`, with `problem`).

`acknowledge` writes a receipt for each waiting call that can have one,
from the call's line in the copy. A stub writer for the permission the
call was sent under is opened on the book as it stands and writes the
receipt, dated with the time the copy gives for the call; the executor
countersigns it, dated at the acknowledgement; and the agent's own writer
takes the line into the book only if the book still passes its check with
it. So the receipt names the permission the call was sent under, not the
new one. Beside what every receipt names, it names three documents, each
the fingerprint (SHA-256, in base64url) of a fixed text:

| Document | The text | Its fingerprint |
|---|---|---|
| `executor.acknowledged` | "The administrator acknowledged this call. The permission it was made under was not the one in force when this receipt was written." | `poJcnPoQB6EyH2Pvp2ZPgD6_2XrDua1XAOpPHBaUezI` |
| `executor.written-late` | "This receipt was written later than its call, from the executor's own copy. Its date is the time the copy gives for the call." | `L_sk-qfojehaePxOm8pV-04nhqDY78T5E040ZwBKtho` |
| `provared.error`, where the copy does not hold the outcome | "The executor recorded that it was sending this call, and has no record of its outcome." | `pOqSHPh3dRwENnfo2e8cGdYHpsYRvvGW2CUyBeGaGiU` |

Where the copy holds the outcome (the receipt had been made and the book
could not be written), the receipt names that in place of
`provared.error`: the result's or the error's fingerprint.
`executor.acknowledged` is on these receipts alone, so a reader can count
them in a book. `executor.written-late` is also on a receipt written at a
restart, there with the fingerprint of another text, as in 0.4.1:
`DIPtu-Cf-GQqigMV51m5ehHX2zdFIQJyKn2gRgsOFVU`, of "This receipt was
written when the executor next started, from its own copy of what it had
sent: the executor stopped before the receipt could be written. Its date
is the time the call was sent; the countersignature is dated at the
restart." The three texts above say only what
the executor knows: its copy's line is written before a call goes to the
server, so it knows that it was sending the call, not that the server
received it, nor why the receipt was not written at the time.

`acknowledge` always says what it did: the calls set aside, the receipts
written, each call that was to have a receipt or be set aside and did not
(`failed`, with why), and the calls still waiting. A call that fails does
not stop the others from being tried, unless the book file or the copy
can no longer be written. It ends with code 0 only where no call is left
waiting.

**Where the executor's keys were changed.** A permission names the
executor's keys, so new executor keys mean a new permission, and a call
left unfinished under the old one would have a countersignature that does
not check. The settings may name the key files the executor held before:

```json
"executor": { "keys": "keys/executor.jwk", "formerKeys": ["keys/executor-2026-10.jwk"] }
```

A former key file is used for one thing: to countersign the receipt of a
call the administrator acknowledges, where the permission the call was
sent under names that file's keys for the executor. The receipt then
checks as any other of that permission. Keep such a file as a key file is
kept, and take it out of the settings once no call under the old
permission waits. Where no former key file fits, the call can only be set
aside. Where the agent's keys were changed there is nothing to sign with,
and setting aside is all that is left.

A receipt can be written from a line only if all of this holds; otherwise
the call can only be set aside:

- the line holds only what the executor writes before a call is sent, and
  its documents are the ones the executor names, none twice, with the
  tool's and the call's fingerprints matching the tool and the call the
  line names;
- the book holds the permission the call was sent under, and that
  permission names the agent's keys as the executor holds them now and,
  in `with`, the executor's keys as it holds them now or as a key file
  named in `executor.formerKeys` holds them;
- its time is not after this start of the executor (where the clock is
  behind, put it right and start again);
- its service id is the one the settings give the executor now;
- its amount is a unit and a whole number from 0 up, in the unit its rule
  gives. Where no rule names the tool with that action any more, the line
  can still be acknowledged, and the status shows a warning.

A line of the copy whose tag does not check is never acted on: the
executor does not start on a copy with such a line. The library makes its
own checks when the receipt is written: a receipt with which the book
would not pass its check (one dated before the receipt ahead of it, say)
is not written, the command says why, and the call stays waiting. A call
leaves the list once the line saying so is in the copy, and before each
receipt is written the book is looked at again for a receipt that names
the call, so trying again after a failure writes no receipt twice.

**A call set aside gets no receipt** (`--set-aside`, with the `call`
identifiers the status gives, separated by commas; over HTTP,
`"setAside": [...]` in the body). The copy and the log say so. **Setting
aside a call that was sent leaves it with no receipt**: the book then does
not show it, and `compare` reports it from then on (with code 3 where
that is all it finds). It cannot be taken back. It stays set aside: a
later line for the same call is not taken up again. The agent takes calls
again once no call waits.

## What it does not do, and what it does not prove

- **Calls that do not go through it.** It proves nothing about them. Take
  the credentials away from the agent.
- **What a tool does.** The action is the rule's reading of the tool's
  name; the arguments and the result are fingerprinted, not understood. A
  tool that does more than its name says is recorded under the rule's
  action.
- **Retries.** Each `tools/call` is one receipt, including each retry of a
  call that asked for more input (`resultType: "input_required"`), and
  each counts against totals and counts.
- **Time.** Times are the executor's clock: a receipt's, a
  countersignature's and a seal's. Without `recorder.stamp` (or a central
  sealer's `stamp`), no outside time-stamp is put beside a seal, so a
  seal's time is the recorder's own word, and nothing outside the
  executor shows when a book was sealed. With one, a seal that carries
  a time-stamp shows, to a reader who trusts that service by the
  fingerprint of its certificate, that the seal's content, and so every
  entry before it, existed by the time the service states. It does not
  show that any entry is true, that the times the entries state are
  right, when an entry after the last time-stamped seal was written, or
  that the book was not cut back to an earlier seal; and it rests on the
  service's own clock and key. A seal the service gave no time-stamp for
  has none, and is shown so.
- **What a seal shows.** That the recorder's keys signed the book as it
  stood, so a later change to an entry before the seal no longer passes
  the check. Where the recorder's sealing keys are in a file on the
  executor, beside the agent's keys and the executor's own, whoever can
  read the executor's files can write a book of their own and seal it.
  With a central sealer they hold no key that makes a seal; what such a
  seal shows and does not is set out under "A central sealer". Seals held elsewhere and
  witnesses are not built here. A book cut back to an earlier seal still
  passes its check by itself; an executor with a central sealer does not
  start on one, while the sealer keeps its record.
- **With a central sealer, not built.** Bringing a sealer up to date
  after its record was lost or put back (the sealer's `update`): the
  executor stops and says so. A second book under one permission (the
  book numbers of the format description, section 21.6): a new book file
  under a permission whose first book the sealer holds is not started
  on. Going on, under a central sealer, with a book already sealed with
  a key file. A sealer on another computer: the sealer listens on
  127.0.0.1 only. A time-stamp beside the sealer's seal is the sealer's
  to ask for (its settings' `stamp`): the sealer's tests cover a
  time-stamp given and one not given; the executor's, one not given.
  Between the sealer's answer about what it holds and the question for a
  seal, a sealer that is started again signs over the lines it then
  holds: for a book with no seal yet, that is a seal the book refuses,
  and the agent is stopped.
- **Sealing is off unless the settings name a recorder**, and there is no
  timer unless they give `sealEvery`. Over stdio a book is sealed only
  while the client runs the executor, or by `seal --offline` while it
  does not.
- **Where the lock does not reach.** The lock that keeps two programs off
  one book is named after the book file's path as the file system
  resolves it, the folder written out in full (a short name on Windows
  included, and `\\?\` in front of a path there changes nothing) and the
  file's own name as written. Two paths that reach one
  file through a link the file system does not resolve, a short name for
  the book file itself, `::$DATA` after the book file's name on Windows,
  a share of the computer's own drive (`\\localhost\D$\…`), or two
  computers' views of a shared folder, are
  two locks. On Windows it is a named pipe; on Linux a socket in the
  abstract namespace, which belongs to a network namespace, so two
  containers that share a folder and not a network do not see each
  other's lock; on other systems a socket file in `/tmp`, which a
  program stopped leaves behind: the next start clears it away. Only the
  program that first makes the folder `<socket file>.clearing` beside
  it may listen there or clear it away. A program stopped in the moment
  it holds that folder leaves it,
  and the lock is then refused, with the folder named, until someone
  takes it away. A socket file left by another user's program (an
  executor once run as root, say) cannot be asked or cleared away by
  this user: the lock is refused, and the refusal names the file, for
  that user or an administrator to take away. So it is where such a file
  may be asked and nothing answers, and where a link of another user's
  that leads nowhere is in its place. A program that takes the lock's name first keeps the
  executor from starting on those files, and gains nothing else. The lock
  has been tried on Windows and on Linux, not on a Mac; the tests of the
  socket file run on Linux and not on Windows, where Node.js has no
  socket files, and the socket file's way was tried on Linux with
  Node.js told it runs on another system. Behind it, the book file and the copy
  are still checked before each write: a program that got past the lock
  and wrote to them stops the executor at its next call. The state
  file's lock has the same limits, and nothing behind it: two executors
  that got past it would each write their own memory over the file, and
  lose each other's connections and the mark of a spent recovery code.
- **The administrator's secret travels in the clear**, like the agents'.
  The commands check that they have reached the executor before they send
  it; they do not hide it from whoever can read the connection. To make
  the check they need the executor's public keys, from `executor.keys` or
  from a file of the public keys alone (`--public-keys`), and they refuse
  through a tunnel, a published container port or a reverse proxy.
- **A call set aside has no receipt**, and the book does not show it;
  only the executor's copy and its log do, and `compare` from then on.
- **An acknowledged receipt says what the copy says.** Its date is the
  time the copy's line was written, just before the call was to go to the
  tool server. The executor does not know whether the server received
  the call unless the copy also holds the outcome.
- **An agent can put off the seal of its own book** by the timer for as
  long as it keeps calls in progress or waiting: a seal takes its turn
  behind them.
- **One server.** One executor stands in front of one tool server: on
  stdio for one agent, over HTTP for several, each with its own slip and
  book. Shipping the copy elsewhere and keys held in a key service are
  designed in `DESIGN.md` and not built.
- **Over HTTP, the agents' secrets** travel in the clear unless something
  else encrypts the connection; the executor listens on the local address
  by default. A session id the upstream gives is bound to the agent that
  opened it only for as long as the executor runs.
- **Tried with.** Over HTTP the executor has been tried with the official
  MCP software on protocol version 2025-11-25 only, with every program on
  one computer; on 2026-07-28 it has met only a test server of its own
  (`test/fake-http-server.mjs`, in the repository).
- **The rules on content** test only what a call carries, and prove
  nothing about calls that do not go through the executor; see "What the
  rules can never promise" above.
- **The copy** is only as safe as the folder it is in, and whoever holds
  the copy key can write lines that check.

## Working from a copy of the repository

This part is for a copy of the repository
(https://github.com/provared/provared): the tests, the `demo/` folder
but for the two files `demo` uses, and `server.json` are not in the npm
package.

```
cd mcp-executor
npm test
```

The tests start a made-up MCP server (`test/fake-server.mjs`) as a real
process and speak to the executor over its streams, and a made-up HTTP MCP
server (`test/fake-http-server.mjs`) on the local address, in front of
which the HTTP executor is tested; nothing leaves the computer. The name
`provared` is taken to mean the repository's own
library (`test/local-library.mjs`), so the tests run against the library
as it is in the same commit.

`demo/` holds a second demonstration, `start.mjs`, which is not the `demo`
command: the executor in front of the same made-up tool server, run as an
MCP server that a client or a directory of MCP servers can start, set up
on its first start with a permission signed by the library's development
stand-in for a passkey, so that it can be started with no settings and no
secret. Its records prove nothing about anyone; see `demo/README.md`. Of
that folder, only `server.mjs` (the made-up server) and
`content-rules.json` (its one rule) are in the npm package, for the `demo`
command. `server.json` describes the package for the official MCP
Registry, where the guard is listed. It is published there by the workflow
`.github/workflows/mcp-registry.yml`, started by hand, which signs in
with GitHub's identity token for the run. A version can be published to
the registry only after the same version is on npm, because the registry
reads that version's `package.json` from npm and compares its `mcpName`
with the name in `server.json`.

## Licences

Apache License 2.0 for the code (`LICENSE`); Creative Commons Attribution
4.0 for the documents (`LICENSE-CC-BY-4.0.txt`). Copyright 2026 Pavel
Izmaylov.
