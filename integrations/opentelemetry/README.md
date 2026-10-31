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
- **the receipt names the span's trace, for a tool that sends it out.**
  Where you say that a tool sends the trace out with its call, in a W3C
  Trace Context `traceparent` header (a web call made with OpenTelemetry's
  own instrumentation, say), its receipt names, among its documents,
  `provared.trace-id`: the fingerprint of the trace id that header
  carries, which is the span's. That is what the format description,
  section 27, says the name stands for. For any other tool the receipt
  names no trace, and `provared.stub.trace_bound` on the span says so.

So from a span in a tracing tool you can always find its receipt in the
book, and from the receipt of a tool that sends the trace out you can find
its trace.

**The bridge cannot see whether a tool really sends the trace.** Your
`sendsTrace: true` is the agent's side's word, as the receipt is: a
matching trace id in the other system's log is what shows it was sent.

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
that what the tool does (a web call, say) is traced beneath it. The tool
name is the name the tool has in the object you give, as you gave it: keep
it to a plain name, because it goes on the span.

Where an agent framework already makes a span for each tool call, use
`span: 'active'`: the bridge then adds its attributes to that span and
starts none, since the conventions ask for one span for one call. It then
leaves that span's name, kind and status to the framework. Several calls
made at once under one active span (an agent's turn, say) share that span,
and each call's attributes replace the one before: the span then names
only the call that ended last. Give each call its own span.

```js
const tools = traceTools(recorder, described, { span: 'active' });
```

A tool may also give `callId`: a function of the second argument it is
called with (the options a framework hands a tool) that gives the
identifier the model gave the call. It goes on the span as
`gen_ai.tool.call.id`, and never into the receipt: it is the model's
identifier, not the platform's, and `provared.event-id` stands for the
platform's (section 27). What it gives is used only where it is text of 1
to 256 characters; anything else is set aside.

A tool says that it sends the trace out with `sendsTrace: true`:

```js
order: {
  action: 'shop.order',
  run: placeOrder,            // calls the shop's interface, with a traceparent header
  sendsTrace: true,
  callId: (options) => options?.toolCallId,
}
```

`traceAct(recorder, request, perform, more, options)` does the same for one
call of the stub writer's `act`. As with `act`, a call that is not taken
is given back, not thrown, and `more.detailsAfter` is passed on. Its span
is named after `options.toolName`, or else the action where it is 1 to 64
visible characters with no spaces, or else `action`. The receipt names the
trace only where `options.sendsTrace` is true, and even then two cases add
nothing to the request:

- where `more.approval` is given: the person approved the request as it
  stands, and an approval covers exactly the documents the person saw, so
  a document added afterwards would no longer match it. The span still
  names the receipt; the receipt does not name the trace. (`traceTools`
  asks for the approval after the trace is added, so the person approves
  the request with it.)
- where `request.details` is given and is not a list: the request is
  passed on as it is, and `act` refuses it.

The options:

| Option | What it does | Default |
|---|---|---|
| `span` | `'new'`: a span for each call; `'active'`: add to the active span | `'new'` |
| `tracer` | the tracer for new spans | `trace.getTracer('provared-opentelemetry')` |
| `agentName` | `gen_ai.agent.name` on each new span, 1 to 256 characters | none |
| `event` | add a span event `provared.not_taken` where a call is not taken | `false` |
| `onStub` | as for `recordTools` | none |
| `toolName` | `traceAct` only: the span's tool name | the action |
| `callId` | `traceAct` only: the model's identifier for the call, 1 to 256 characters, for the span | none |
| `sendsTrace` | `traceAct` only: `perform` sends the trace out with the call; the receipt then names it | `false` |

For `traceTools`, `sendsTrace` and `callId` are members of each tool's
description, not options.

An option that is not in this list, or that is not of the form given, is
refused with an error that names it.

With no OpenTelemetry software set up to record traces, OpenTelemetry's
interface records no span, and the tools still run and are receipted. The
receipt of a tool that sends the trace out then names a trace only where
the call was made inside one passed on from elsewhere (from a
`traceparent` header that came in, say). A trace that is not sampled, so
that no span is kept, is still named in such a receipt: its trace id is
still passed on to what the tool calls.

## What goes on the span

From OpenTelemetry's conventions for generative AI, on a span the bridge
starts:

| Attribute | Value |
|---|---|
| `gen_ai.operation.name` | `execute_tool` |
| `gen_ai.tool.name` | the tool's name, as given to `traceTools`; for `traceAct`, as above |
| `gen_ai.tool.call.id` | the model's identifier for the call, where one is given |
| `gen_ai.agent.name` | the `agentName` option, where given |
| `error.type` | where the call ended in an error: `NotTaken`, or the class name of the tool's error (such as `TypeError`), or `_OTHER` |

The class name is put on the span as the code named it, where it is a
plain name of at most 64 characters, and `_OTHER` where it is not or cannot
be read. A tool that makes up names of error classes from what it was
given would put that on the span.

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

`not_taken` means this call's own check said no. An error that the tool,
or one of its own functions (`amount`, `with`, `details`, `approve`,
`countersign`), throws is the tool's error, `error`, even where it is a
`NotTaken` from another stub writer.

On a span the bridge starts, the status is "error" where the call was not
taken or failed. For a call not taken its description gives the finding
codes. For a tool's error there is no description, and no record of the
exception: OpenTelemetry's rules ask for the error's message as the
description and for the exception to be recorded, and both are left out
here because the message may quote what the tool was given.

**What never goes on the span:** a call's arguments, its amount, a
document's content, a key, a passkey value, the words of a finding, and an
error's message. Each of these may hold what the tool was given. The
conventions' own `gen_ai.tool.call.arguments` and
`gen_ai.tool.call.result` are not set.

A tracing setup of your own may still record these through other
software: this package cannot stop that. An agent framework that records
the exceptions its tools throw will record a `NotTaken`'s message, which is
the checker's own words and may give amounts ("With this action the total
would be 280 GBP").

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
- A trace id is the agent's side's choice, and so is `sendsTrace`. A
  matching trace id shows that two records speak of the same trace, not
  that the call did what either says, and a trace may hold many calls.
- A trace id is not secret: anyone who sees the trace can work out its
  fingerprint and find the receipt that names it.
- For a call not taken with no denial written, the span does not name the
  permission: the check before acting does not give it.
- A stub may name at most 32 documents (28 where `detailsAfter` is given),
  and the trace takes one of them. A tool that sends the trace and names
  32 documents of its own leaves no room: the check before acting then
  refuses the call (`not_taken`).
- The meaning of `provared.trace-id` and `provared.event-id` is a draft
  of the format, to be settled. This package writes only the first, and
  only in the case section 27 describes.
- OpenTelemetry's conventions for generative AI are marked "development":
  their names may change. Span events are being replaced by log records in
  OpenTelemetry, which is why the event is off by default.

## Versions

`@opentelemetry/api` (`^1.9.0`) and `provared` (`^0.6.0`, that is, 0.6 only, until a later version is tested) are peer
dependencies: the application chooses the one copy of each. OpenTelemetry
asks this of libraries, so that every part of an application uses the one
tracer provider; and the bridge must use the same copy of `provared` as
the stub writer handed to it, or it would not know a `NotTaken` from it.
The bridge uses no part of OpenTelemetry's SDK.

Tested with Node.js 24 and, for the tests, at the versions locked in
`package-lock.json`: `@opentelemetry/api` 1.9.1, `@opentelemetry/sdk-trace`
2.12.0 and `@opentelemetry/context-async-hooks` 2.12.0. Also tried on
25 October 2026 with `@opentelemetry/api` 1.9.0 (with the same SDK), and
with `@opentelemetry/api` 1.10.0, `@opentelemetry/sdk-trace` 3.0.0 and
`@opentelemetry/context-async-hooks` 3.0.0. All are under the Apache
License 2.0. The repository's test workflow runs the tests at the locked
versions and again at the newest releases.

## Tests

```
cd integrations/opentelemetry
npm ci --ignore-scripts
npm test
```

The tests use this repository's own library, OpenTelemetry's SDK with its
in-memory exporter, and permissions signed with the library's development
stand-in for a passkey. One file runs with no SDK at all. They run inside a
guard that refuses any connection, and check that none was tried.

## Licences

The code is under the Apache License 2.0; this file is under the Creative
Commons Attribution 4.0 International licence. Copyright 2026 Pavel
Izmaylov.
