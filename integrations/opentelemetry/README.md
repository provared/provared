# provared-opentelemetry

**A span is the agent's side's own word, as a receipt is. The receipt and
the checker are the evidence; the span is a pointer to it.** Whoever runs
the agent writes both, so a span that says "taken, within the permission"
proves nothing by itself. To know what the agent was allowed to do and
what it did, check the book of receipts with the Provared checker,
naming the passkey you trust.

This package links the two records that already exist for a tool call:

- the trace span that observability tools show (OpenTelemetry, an open
  standard for traces, metrics and logs);
- the Provared receipt (a "stub"): a signed record of the call, written
  under a permission (a "slip") that a person signed with a passkey.

It links them both ways, in one call:

- **the span names the receipt.** The span of the tool call gets the
  receipt's fingerprint, the fingerprint of the permission, the action, and
  what the check before acting said (taken, or not taken and why, as
  finding codes);
- **the receipt names the span's trace.** The receipt names, among its
  documents, `provared.trace-id`: the fingerprint of the span's trace id
  (format description, section 27).

So from a span in a tracing tool you can find its receipt in the book, and
from a receipt you can find its trace.

Status: version 0.1.0, a draft, not yet published. Evidence, not a verdict.

## Use

```js
import { openRecorder } from 'provared';
import { traceTools } from 'provared-opentelemetry';

const recorder = await openRecorder({ book, slip, privateKeys, issuerKeys });

// As recordTools, with each call traced.
const tools = traceTools(recorder, {
  order: { action: 'shop.order', run: placeOrder, amount: (a) => ({ unit: 'GBP', value: a.total }) },
});

await tools.order({ item: 'paper', total: 30 });
```

Each tool is described as for the library's `recordTools` (see the guide,
"The agent's tools"). By default the bridge starts one span for each call,
named `execute_tool <tool name>`, as OpenTelemetry's conventions for
generative AI ask, and makes it the active span while the tool runs, so
that what the tool does (a web call, say) is traced beneath it.

Where an agent framework already makes a span for each tool call, use
`span: 'active'`: the bridge then adds its attributes to that span and
starts none, since the conventions ask for one span for one call. It then
leaves that span's name, kind and status to the framework.

```js
const tools = traceTools(recorder, described, { span: 'active' });
```

A tool may also give `callId`: a function of the second argument it is
called with (the options a framework hands a tool) that gives the
identifier the model gave the call. It goes on the span as
`gen_ai.tool.call.id`, and into the receipt as the fingerprint
`provared.event-id`.

```js
order: { action: 'shop.order', run: placeOrder, callId: (options) => options?.toolCallId }
```

`traceAct(recorder, request, perform, more, options)` does the same for one
call of the stub writer's `act`. As with `act`, a call that is not taken
is given back, not thrown; `more.detailsAfter` is passed on.

The options:

| Option | What it does | Default |
|---|---|---|
| `span` | `'new'`: a span for each call; `'active'`: add to the active span | `'new'` |
| `tracer` | the tracer for new spans | `trace.getTracer('provared-opentelemetry')` |
| `agentName` | `gen_ai.agent.name` on each new span | none |
| `bindTrace` | put the trace's fingerprint into the receipt | `true` |
| `bindCallId` | put the fingerprint of the model's call identifier into the receipt | `true` |
| `event` | add a span event `provared.not_taken` where a call is not taken | `false` |
| `onStub` | as for `recordTools` | none |

With no OpenTelemetry software set up to record traces, OpenTelemetry's
interface makes no real span: the tools still run and are receipted, and
the receipt names no trace.

## What goes on the span

From OpenTelemetry's conventions for generative AI, on a span the bridge
starts:

| Attribute | Value |
|---|---|
| `gen_ai.operation.name` | `execute_tool` |
| `gen_ai.tool.name` | the tool's name, as given to `traceTools` |
| `gen_ai.tool.call.id` | the model's identifier for the call, where `callId` gives one |
| `gen_ai.agent.name` | the `agentName` option, where given |
| `error.type` | where the call ended in an error: `NotTaken`, or the class name of the tool's error (such as `TypeError`), or `_OTHER` |

Provared's own, under its own name, on every span the bridge works on:

| Attribute | Value |
|---|---|
| `provared.outcome` | `taken` (the tool ran, and its receipt is written), `not_taken` (the check before acting said no; the tool did not run) or `error` (the call ended in an error, and no receipt was written) |
| `provared.action` | the action name, as the permission names it |
| `provared.check.codes` | where not taken: the finding codes, a list of text, such as `over-count-limit` |
| `provared.stub.fingerprint` | the receipt's fingerprint |
| `provared.stub.seq` | the receipt's place in its chain, from 0 |
| `provared.stub.countersigned` | `true` where the other side's countersignature was checked and kept |
| `provared.stub.trace_bound` | `true` where the receipt names this span's trace |
| `provared.slip.fingerprint` | the fingerprint of the permission the receipt, or the denial, relies on |
| `provared.denial.fingerprint` | where not taken and the stub writer wrote a denial: its fingerprint |

The span's status is "error" where the call was not taken or failed. For
a call not taken its description gives the finding codes.

**What never goes on the span:** a call's arguments, its amount, a
document's content, a key, a passkey value, the words of a finding, and an
error's message. Each of these may hold what the tool was given. The
conventions' own `gen_ai.tool.call.arguments` and
`gen_ai.tool.call.result` are not set. A tracing setup of your own may
still record them, or the error, through other software: this package
cannot stop that.

`attributes.mjs` (`provared-opentelemetry/attributes`) does the same work
on any object with `setAttribute`, and does not import OpenTelemetry:
`annotate(span, facts)` and `attributesFor(facts)`.

## Finding one from the other

- **From a span to its receipt:** look in the book for the stub whose
  fingerprint is `provared.stub.fingerprint`. The checker's answer gives
  each entry's fingerprint (`entries[].fingerprint`).
- **From a receipt to its trace:** the receipt holds the fingerprint of the
  trace id, not the trace id. Work out `identifierFingerprint(traceId)`
  for the traces you hold, and compare.

## What it does not do, and what it does not prove

- A span is not signed. Whoever runs the agent, or the tracing system,
  can change it, drop it or make one up. Only the receipt is signed, and
  only the checker says whether the book is intact and within its
  permission.
- A span exists only for calls that go through `traceTools` or
  `traceAct`. A call the agent made another way has neither a span from
  this package nor a receipt.
- A trace id is the agent's side's choice. A matching trace id shows that
  two records speak of the same trace, not that the call did what either
  says.
- A trace id is not secret: anyone who sees the trace can work out its
  fingerprint and find the receipt that names it.
- For a call not taken with no denial written, the span does not name the
  permission: the check before acting does not give it.
- OpenTelemetry's conventions for generative AI are marked "development":
  their names may change. Span events are being replaced by log records in
  OpenTelemetry, which is why the event is off by default.

## Versions

Tested with Node.js 24, `@opentelemetry/api` 1.9.1, and, for the tests
only, `@opentelemetry/sdk-trace` 2.12.0 and
`@opentelemetry/context-async-hooks` 2.12.0 (all under the Apache License
2.0). `@opentelemetry/api` is a peer dependency, as OpenTelemetry asks of
libraries: the application chooses the one copy. The bridge uses no part of
the SDK.

## Tests

```
cd integrations/opentelemetry
npm ci --ignore-scripts
npm test
```

The tests use this repository's own library, OpenTelemetry's SDK with its
in-memory exporter, and permissions signed with the library's development
stand-in for a passkey. They run inside a guard that refuses any
connection, and check that none was tried.

## Licences

The code is under the Apache License 2.0; this file is under the Creative
Commons Attribution 4.0 International licence. Copyright 2026 Pavel
Izmaylov.
