# <img src="https://prova.red/favicon.svg" alt="" width="36"> Provared

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/provared/provared/badge)](https://scorecard.dev/viewer/?uri=github.com/provared/provared)

A guard for an AI agent's tools: it holds the tools' credentials in
place of the agent, and stops any tool call that the person did not
allow in a permission they signed with a passkey.

The guard, [provared-mcp-executor](mcp-executor/README.md), stands
between the agent and a tool server that speaks the Model Context
Protocol (MCP), the common way for AI agents to reach tools. It holds
the tool server's credential in place of the agent, and refuses a call
the permission does not allow before the call reaches the tool. It can
also test what a call would change, for example which paths a file tool
may touch. It starts a tool server itself on the same computer, for one
agent (MCP's "stdio" transport), or, from version 0.3.0, stands in front
of one reached over the network (MCP over HTTP, the protocol of the web),
for several agents, each with its own secret, permission and record.

The record follows from it. For each call it lets through, the guard
writes a signed receipt and countersigns it with keys of its own; for a
call the permission does not allow, a signed note of the refusal (a
denial). Anyone can check these records later, on their own computer,
with the free checker.

**What it does not do yet.** One guard stands in front of one tool
server. Over the network it has been tried with the official MCP software
on protocol version 2025-11-25 only; on the newer 2026-07-28 it has met
only a test server of its own. The agents' secrets travel in the clear
unless something else encrypts the connection to the guard. Sealing the
record and keys held in a key service are designed but not built. And it
proves nothing about a tool the agent can reach without
it: the tool's credential must be taken away from the agent. It keeps
the credential, and its own keys, from the agent only where the agent
cannot read the guard's files: an agent with a shell or file tools that
runs as the same computer user can read them. So run the guard under a
separate user account that the agent cannot use, or give the agent no
shell or file tools; a tested recipe for this is not written yet.

*Evidence, not a verdict.* A record shows what was signed and by which
keys. People decide what it means.

```
npm install -g provared-mcp-executor   # Node.js 24.7 or later
```

[Its README](mcp-executor/README.md) sets it up in five steps: write its
settings, make its keys, sign the permission with a passkey at
https://sign.prova.red, check the settings, and name the guard in the
agent's MCP client where the tool server was named. For a client whose
settings are JSON:

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

To see it work first, [mcp-executor/demo/](mcp-executor/demo/) runs the
guard in front of a made-up tool server, with no settings and no secret;
its records prove nothing about anyone. The guard is listed in the
official MCP Registry as `io.github.provared/mcp-executor`. "Executor"
is the Internet-Draft's word for software, other than the agent, that
acts for it and refuses what the permission does not allow.

## Other ways to record an agent

The guard is one way to put an agent's actions behind a signed
permission. The others write the same kind of record, read by the same
checker:

- **The library**, in JavaScript or Python, for an agent you write
  yourself: each action is checked against the permission first and
  receipted after (see "A first record of your own", below).
- **[The recorder beside Claude Code](integrations/claude-code/README.md)**
  (`provared-claude-code`, also a Claude Code plugin), which checks and
  receipts every tool call Claude Code makes.
- **Packages for two Python agent frameworks**, LangChain and Pydantic
  AI, and [an example](examples/frameworks/) for the Vercel AI SDK.
- **[The gateway](gateway/README.md)**, for agents that act through web
  interfaces: it stands in front of each system an agent uses, holds
  that system's credential and receipts each call. In the repository,
  not yet on npm.

## The checker, and the sample record

```
npm install provared          # Node.js 24.7 or later, no dependencies
pip install provared          # Python 3.11 or later, one dependency
npx provared-check --sample   # the checker's answer for the sample record
```

The sample is an invented office agent that goes over its limit at its
fifth order. The checker's answer ends:

```
Summary
  Is the record intact?                 yes
  Was every signature checked?          yes
  Did the agent stay within its slip?   NO: first at entry 5
  Time-stamped in a way you trust?      yes: the first 9 entries existed by 2026-10-05T10:16:00Z
  Checked against keys you named?       yes: the passkey you trust, and the recorder you expect
```

## A first record of your own

Three commands. The permission is signed with a **development stand-in
for a passkey**: a key made in memory, which no person confirmed. Every
permission it signs says so in its issuer's name, and the checker prints
that name. A real permission is signed by a person, in a browser, with a
real passkey (`provared/passkey-browser`, and the checking page).

```
npm install provared
node first-record.mjs
npx provared-check book.jsonl --issuer <the thumbprint it prints>
```

`first-record.mjs` ([examples/first-record.mjs](examples/first-record.mjs)):

```js
import { writeFileSync } from 'node:fs';
import { developmentRecorder } from 'provared/dev';

const SEND = 'provared.message.send';

// A permission: the agent may send messages, at most two.
const { recorder, issuerKeys } = await developmentRecorder({
  actions: [SEND],
  limits: [{ action: SEND, count: 2 }],
  purpose: 'Send a few messages, to make a first record.',
});

// Each action is asked for first, taken only if the permission allows it,
// and receipted after. The third message is outside it, so it is not sent.
for (let i = 1; i <= 3; i++) {
  const outcome = await recorder.act({ action: SEND }, async () => console.log(`message ${i} sent`));
  if (!outcome.done) console.log(`message ${i} not sent: ${outcome.answer.breaches[0].message}`);
}

writeFileSync('book.jsonl', recorder.book());
console.log(`npx provared-check book.jsonl --issuer ${issuerKeys[0]}`);
```

The same in Python is
[python/examples/first_record.py](python/examples/first_record.py), with
`from provared.dev import development_recorder`. For a LangChain agent,
`pip install provared-langchain` puts every tool call behind the same
check with no change to the tools
([python/integrations/provared-langchain](python/integrations/provared-langchain)):

```py
from langchain.agents import create_agent
from provared_langchain import ProvaredMiddleware

agent = create_agent(model, tools=[order_supplies, send_message],
                     middleware=[..., ProvaredMiddleware(writer, {
                         'order_supplies': {'action': 'supplies.order', 'with': 'supplier',
                                            'amount': lambda a: {'unit': 'GBP', 'value': a['total_gbp']}},
                         'send_message': 'provared.message.send',
                     })])   # last among the middleware that wrap tool calls
```

The package is listed among the middleware in
[LangChain's own documentation](https://docs.langchain.com/oss/python/integrations/middleware).
For JavaScript agents, [examples/frameworks/](examples/frameworks/) shows the
same with the Vercel AI SDK, through `recordTools`.

## The four parts

| Part | What it is |
|---|---|
| **The permission (a Slip)** | A person signs it with a passkey: which agent, which actions, what limits and conditions, with whom, from when until when, and why |
| **The receipt (a Stub)** | The agent signs one for each action, pointing back to its slip; the other side countersigns it where it can, and the person approves it where the slip asks |
| **The sealed book (a Seal)** | The receipts chained, gathered under one fingerprint, signed by whoever keeps the book and time-stamped by an outside service |
| **One page with proof (a Show)** | One entry handed to a checker with proof that it is in the book, and when the book was sealed, with the names it does not need kept covered |

The checker answers two questions and keeps them apart: **is the record
intact**, and **did the agent stay within its slip**. Going over a limit
is not a fault in the record. It is what a sound record shows.

## What the author found nowhere else

Signed, chained and time-stamped receipts for an agent's actions exist
in other open projects too, some with quantum-safe signatures. As far as
the author knows, in October 2026, three things are only here: **limits
a machine can check** in a permission the person signs, with the
checker's answer "did the agent stay within it"; **passing a permission
on** to a helper agent so that it can narrow and never widen; and
**cancelling** with the agent's signed acknowledgement, so that a record
shows when the agent's side was told. If you know of another project
that does any of these, open an issue: the list is kept honest.

## What a record does not prove

It shows what was recorded, not what was left out: an agent that acts
and writes no stub leaves no trace. A one-sided stub shows what the
agent's side said. It does not show that an action was wise, lawful or
wanted, nor who was holding the device when the passkey signed. A name
in a record is a label; only keys are checked. The full list, with what
each part protects against, is in
[docs/threat-model.md](docs/threat-model.md).

## Where everything else is

- **[The guide](docs/guide.md)**: the whole library, in one document.
  Installing and importing; the command-line checker; what a slip can
  say; seals, time-stamps, witnesses and the chain of block headers; cancelling;
  who stands behind a name; covered fields; passing a slip on; the check
  before acting; the stub writer beside an agent and the connector for
  its tools; what the checker returns; what it never does; what is not
  built yet.
- **[The format, described exactly](spec/provared-format.md)**, and
  the shared test files in [test-vectors/](test-vectors/) that any
  implementation can be held to.
- **[The Python version](python/README.md)**, which gives the same
  answers, with examples for three agent frameworks and packages for
  two of them.
- **Two programs beside an agent, each on npm with its own README:**
  [the recorder beside Claude Code](integrations/claude-code/README.md)
  (`npm install -g provared-claude-code`, also installable as a Claude
  Code plugin), which checks and receipts every tool call Claude Code
  makes; and [the executor for MCP tool servers](mcp-executor/README.md)
  (`npm install -g provared-mcp-executor`), which stands between an
  agent and its tool servers, holds their credentials, and countersigns
  each receipt with keys of its own.
- **[The pages at prova.red](https://prova.red/)**: the checker's answer
  for the sample record, a worked example for developers, and the same
  in plain words for a reader who does not write code.
- **[The checking page](https://prova.red/check/)**, which checks a
  record in a browser and loads nothing from anywhere; also built as
  one file, attached to each release. It uses only the signing methods
  the browser has built in. Tried on the author's computer on
  13 October 2026: Chrome 155, Edge 155 and Brave 155 each check the
  quantum-safe signatures on receipts (ML-DSA). None of the three has the
  third method a seal is signed with (SLH-DSA), so in a browser a book
  with a seal is never a pass. The command-line checker checks all three.
- **The core of the format as an individual Internet-Draft** at the
  IETF:
  [draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/).
  An Internet-Draft is a working document, not a standard.
- **[CHANGELOG.md](CHANGELOG.md)**, [SECURITY.md](SECURITY.md) and
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

**Version 0.8.0, a draft.** Published as it is, by one author in their
own time, built with AI tools since 3 October 2026; fixes as time
allows. The code has been through more than 80 rounds of review by AI
reviewers, each a fresh session given the code, the documents and a
brief of what to look at. Until 7 November 2026 each reviewer likely
also had the author's private planning notes loaded, so could see the
author's reasoning; since then reviewers start without them. Every
fault was fixed, or stated as a limit, and kept as a test. No person
other than the author has reviewed it yet.
That is an invitation. The format may still change.
Every published version stays on npm and the Python Package Index, so a
record made with one version can always be checked by that version.

Questions, faults and suggestions: hello@prova.red, or
[issues on GitHub](https://github.com/provared/provared/issues).

## Licences

Copyright 2026 Pavel Izmaylov.

The code, the pages and the sample files: Apache License 2.0
(`LICENSE`). The format description and the other documents: Creative
Commons Attribution 4.0 International (`LICENSE-CC-BY-4.0.txt`).
