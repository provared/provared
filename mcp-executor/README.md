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

```
npm install -g provared-mcp-executor
```

Or from a copy of the repository: in `mcp-executor`, `npm pack`, then
`npm install -g ./provared-mcp-executor-0.2.0.tgz`.

It needs Node.js 24.7 or later, and depends only on the `provared` library,
at version 0.7.0 or a later 0.7 version (`^0.7.0`): its receipts name
`provared.tool-name` and `provared.tool-result`, which the format reserved
in 0.7.0 and which a checker of 0.5.0 or 0.6.0 refuses (0.4.0 and
earlier read them as labels).

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

   It writes nothing: no line to the book, no copy key.

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
- `tools`: each tool the agent may call, by its exact name, with the action
  name the slip uses for it and, where it applies, its amount: a fixed
  `value`, the whole number at a JSON Pointer (RFC 6901) in the call's
  arguments (`pointer`), or the length of the list there (`count`). A call
  whose amount cannot be read is refused, and so is one whose arguments
  name one member twice in one object, or two that differ only in capitals
  (`total` and `TOTAL`): a server may read the other one. (A member
  name given twice exactly is refused in every message; names that differ
  only in capitals are refused only where a rule reads the amount from the
  arguments.)
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
- That a member is named as the program reads it. Names inside the
  content are compared exactly: `"SCAN": true` is not `scan`, so it passes
  an `absent` test, or an `orAbsent` one, on `/scan` (two members that
  differ only in capitals in one object are refused as unreadable, but a
  lone `SCAN` is not). A program that reads names without regard to
  capitals acts on what the rule did not see.
- That content nested in content is read. `as: "json"` reads one layer: a
  JSON text inside a JSON string (`"{\"scan\": true}"` as the content's
  text) is a string to the rule, and its tests on `/scan` find nothing.
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
permission, the executor does not start, and says to put that permission
back for one start.

**The copy cannot be read** (its key is missing while it holds lines; no
line checks under the key; a last line was cut by a stop; a line was taken
out, put twice or moved, which the number each line carries shows): the
executor does not start, and says why. A copy cut at its end is not seen:
nothing in a line says it is the last.

## The copy, and comparing it with the book

```
provared-mcp-executor compare --config executor.json [--book <another copy of the book>]
```

For every call the copy shows as sent, the book is searched for the stub
that names the executor and the same `executor.call`. The answer lists the
calls that match, those whose receipt in the book is not the one the
executor wrote (`differs`), those with no receipt in the book (`missing`:
whoever keeps the book left it out, or the book is older than the copy),
those whose receipt the executor itself could not write to the book
(`notWritten`: its own stop, told apart from an omission), those the
executor sent and never gave a receipt, receipts in the book that name the
executor and that the copy does not know, and denials the book lacks.
Beside these, `withoutRules` lists the executor's receipts and denials
under a slip that states rules on content and that name no rules file;
it does not change the code. It ends with code 0 only where everything agrees, every line of the copy
checks under the key and runs in sequence, and the book itself has no
problem. The copy key must exist (`compare` makes none), and a book named
with `--book` must exist.

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
  book) and one server. The HTTP transport, several agents, sealing and
  keys held in a key service are designed in `DESIGN.md` and not built.
- **The rules on content** test only what a call carries, and prove
  nothing about calls that do not go through the executor; see "What the
  rules can never promise" above.
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

`demo/` holds a demonstration: the executor in front of a made-up tool
server, set up on its first start with a permission signed by the
library's development stand-in for a passkey, so that it can be started
with no settings and no secret. Its records prove nothing about anyone;
see `demo/README.md`. `server.json` describes the package for the
official MCP Registry; it is not in the npm package. A version can be
published to the registry only after the same version is on npm, because
the registry reads that version's `package.json` from npm and compares its
`mcpName` with the name in `server.json`. Publishing under
`io.github.provared/` needs an Owner of the GitHub organisation
`provared`, signed in with a personal access token that can read the
organisation's members (a classic token with `read:org`, or a
fine-grained one with Organization permissions, Members, Read-only) or
from GitHub Actions; `mcp-publisher login github` without a token cannot
publish to an organisation's names today.

## Licences

Apache License 2.0 for the code (`LICENSE`); Creative Commons Attribution
4.0 for the documents (`LICENSE-CC-BY-4.0.txt`). Copyright 2026 Pavel
Izmaylov.
