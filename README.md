# Provared

Proof of what an AI agent was allowed to do, and what it then did.

A person signs the permission with a passkey. The agent signs a receipt
for each action. A free checker says whether the agent stayed within the
permission, and where it did not.

*Evidence, not a verdict.* A record shows what was signed and by which
keys. People decide what it means.

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
  say; seals, time-stamps and the chain of block headers; cancelling;
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
- **[The pages at prova.red](https://prova.red/)**: the checker's answer
  for the sample record, a worked example for developers, and the same
  in plain words for a reader who does not write code.
- **[The checking page](https://prova.red/check/)**, which checks a
  record in a browser and loads nothing from anywhere; also built as
  one file, attached to each release.
- **The core of the format as an individual Internet-Draft** at the
  IETF:
  [draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/).
  An Internet-Draft is a working document, not a standard.
- **[CHANGELOG.md](CHANGELOG.md)**, [SECURITY.md](SECURITY.md) and
  [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

**Version 0.3.0, a draft.** Published as it is, by one author in their
own time, built with AI tools since 3 October 2026; fixes as time
allows. The code has been through 25 rounds of review by AI reviewers,
each a fresh session given only the code and the documents; every fault
was fixed and kept as a test. No person other than the author has
reviewed it yet. That is an invitation. The format may still change.
Every published version stays on npm and the Python Package Index, so a
record made with one version can always be checked by that version.

Questions, faults and suggestions: hello@prova.red, or
[issues on GitHub](https://github.com/provared/provared/issues).

## Licences

Copyright 2026 Pavel Izmaylov.

The code, the pages and the sample files: Apache License 2.0
(`LICENSE`). The format description and the other documents: Creative
Commons Attribution 4.0 International (`LICENSE-CC-BY-4.0.txt`).
