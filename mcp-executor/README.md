# provared-mcp-executor

**This is the executor's record of what an agent asked for through it, and
what the executor did with each call. It proves nothing about calls that do
not go through it.** It counts only if the agent has no other way to the
tool servers behind it: take the servers' credentials away from the agent,
so that the executor alone holds them.

An **executor**, in the words of the Internet-Draft
[draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/),
is software other than the agent that takes actions for it or holds what
they need, and refuses an action the permission does not allow. This one
stands between an agent and a tool server that speaks the Model Context
Protocol (MCP) over the stdio transport. The agent's MCP client starts the
executor as if it were the tool server; the executor starts the real server,
with its credential, and for every `tools/call`:

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
holds neither, so it cannot write, change or skip a receipt. The executor
also keeps its own copy of every call, apart from the agent's log, which can
be held against the log to find a receipt that was left out
(`compare`).

Evidence, not a verdict. The whole design, with every choice numbered for
review, is in `DESIGN.md`. The format is described in the Provared format
description (`spec/provared-format.md` in the repository); the library is
the npm package `provared`.

## Install

It is not yet published. From a copy of the repository:

```
cd mcp-executor
npm pack
npm install -g ./provared-mcp-executor-0.1.0.tgz
```

It needs Node.js 24.7 or later, and depends only on the `provared` library.

## Set it up

1. Write the settings (`executor.example.json` is a start): the server to
   start and where its credential is read from; the paths of the agent's
   keys, slip and book; the executor's keys and copy; the tools and the
   action each is. Paths are read from the settings file's folder.

2. Make the keys. This makes the two key files if there are none, and
   prints what goes into the permission:

   ```
   provared-mcp-executor keys --config executor.json
   ```

   The printed `agent.keys` go into the permission as the agent's keys; the
   printed `with` entry (the executor's id, name and keys) goes into the
   permission's `with`; and `requires` should hold
   `{"need": "countersignature"}`, so that a receipt without the executor's
   countersignature is a finding.

3. The person signs the permission with their passkey (on the signing page
   at https://sign.prova.red, or with the library) and saves it where the
   settings say (`agent.slip`). The thumbprint of the passkey goes into
   `agent.issuerKeys`.

4. Check the settings. This reads every rule, the keys, the slip and the
   credentials, and says what is wrong. It prints no credential.

   ```
   provared-mcp-executor check --config executor.json
   ```

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

## The settings

```json
{
  "name": "Provared MCP executor for the files server",
  "service": "executor",
  "server": {
    "command": "node",
    "args": ["files-server.mjs"],
    "cwd": "servers/files",
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
  "shutdownWait": 5000
}
```

- `name`: the executor's name; part of the tag on each line of its copy.
- `service`: the id the permission gives the executor in `with`; written
  into each stub's `with`. Default `executor`.
- `server.env`: each variable the server needs, and where its value is read
  from: a file (`file`; one line ending at its end is dropped), the
  executor's own environment (`env`), or the settings themselves (`value`,
  warned against). The server's environment holds these and the variables
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
- `tools`: each tool the agent may call, by its exact name, with the action
  name the slip uses for it and, where it applies, its amount: a fixed
  `value`, the whole number at a JSON Pointer (RFC 6901) in the call's
  arguments (`pointer`), or the length of the list there (`count`). A call
  whose amount cannot be read is refused, and so is one whose arguments
  name one member twice in one object, or two that differ only in capitals
  (`total` and `TOTAL`): a server may read the other one.
- `unlisted`: `refuse` (default) refuses a call to a tool no rule names and
  writes a denial named `executor.unlisted`; `forward` sends it on with no
  receipt and no denial, and the record then leaves those calls out.
- `hideUnlisted`: whether `tools/list` comes back without such tools.
  Default true.
- `timeout`: how long the server is given to answer a call, in
  milliseconds (default 300,000; from 1,000 to 86,400,000). After it the
  executor cancels the call and writes the receipt with an error.
- `callIdInMeta`: whether the executor's own identifier for the call is sent
  to the server in `params._meta["red.prova/call-id"]`, so that a server
  that logs `_meta` can be matched line for line with the record. Default
  true. Off, the stub names the identifier under `executor.call` alone.
- `denialsPerHour`: the most denials written in any hour (default 600).
- `shutdownWait`: how long the server is given to exit after its input is
  closed before it is ended (default 5,000 milliseconds).

## What the executor does with each call

1. **The line.** Read strictly: UTF-8, one JSON object with
   `"jsonrpc": "2.0"`, no batch, no member name given twice anywhere in it,
   an id that is text or a whole number. Anything else is answered with a
   JSON-RPC error and goes no further: the method the executor reads must
   be the one the server acts on. A line over 16 MiB is refused.
2. **The rule**, by the tool's name (1 to 128 letters, digits, `_`, `-` and
   `.`; any other name is refused with -32602).
3. **The amount**, as the rule says.
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
   where there are none), `mcp.tool` (the tool's name), `executor.call`
   and `provared.request-id` (the executor's identifier), and
   `provared.trace-id` where the call's `_meta` carried a well-formed
   `traceparent`. After the answer it names `mcp.result` (the server's
   whole `result`, in the one form of RFC 8785) or, where there was no
   result, `provared.error` (the text of the error the client is given, or
   the server's JSON-RPC error as JSON).
7. **A call that was sent always gets its stub**, whatever happened: the
   server's result (an `isError` result included), its error, no answer
   within `timeout`, the agent's cancellation, or the server ending. The
   executor countersigns the stub with its own keys once the outcome is
   known, so the countersignature covers the result's fingerprint. Then a
   line saying the receipt is in the book goes into the copy.
8. **The answer to the client** is the server's, exactly as the server
   wrote it. Where there is none, the client gets a JSON-RPC error of the
   executor's own: code 1002 (no answer: the time ran out, the agent
   cancelled, or the server ended) with the stub's fingerprint in `data`.
   Code 1001 means the call was not taken because the executor could not
   record it.

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
has no line saying the receipt was written. At the next start the receipt
is written from that line, naming `provared.error` with the words "The
executor stopped while this call was with the tool server, so its outcome
is not known…", under the permission in force. Where the call was sent
under another permission, the executor does not start, and says to put
that permission back for one start.

**The copy cannot be read** (its key is missing while it holds lines; no
line checks under the key; a last line was cut by a stop): the executor
does not start, and says why.

## The copy, and comparing it with the book

```
provared-mcp-executor compare --config executor.json [--book <another copy of the book>]
```

For every call the copy shows as sent, the book is searched for the stub
that names the executor and the same `executor.call`. The answer lists the
calls that match, those whose receipt in the book is not the one the
executor wrote, those with no receipt in the book, those the executor sent
and never gave a receipt, receipts in the book that name the executor and
that the copy does not know, and denials the book lacks. It ends with code
0 only where everything agrees and every line of the copy checks under the
key.

It cannot find a call that never went through the executor, whether a tool
did what its result says, or a copy changed by whoever holds the copy key.

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
- **Time.** Times are the executor's clock. No seal and no outside
  time-stamp is written yet.
- **One agent, one server.** One executor serves one agent (one slip, one
  book) and one server. The HTTP transport, several agents, sealing, keys
  held in a key service and content rules are designed in `DESIGN.md` and
  not built.
- **The copy** is only as safe as the folder it is in, and whoever holds
  the copy key can write lines that check.

## Working from a copy of the repository

```
cd mcp-executor
npm test
```

The tests start a made-up MCP server (`test/fake-server.mjs`) as a real
process and speak to the executor over its streams; nothing is sent over
the network. The name `provared` is taken to mean the repository's own
library (`test/local-library.mjs`), so the tests run against the library
as it is in the same commit.

## Licences

Apache License 2.0 for the code (`LICENSE`); Creative Commons Attribution
4.0 for the documents (`LICENSE-CC-BY-4.0.txt`). Copyright 2026 Pavel
Izmaylov.
