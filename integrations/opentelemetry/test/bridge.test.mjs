// The OpenTelemetry bridge, with OpenTelemetry's own SDK and its in-memory
// exporter. Nothing leaves the process: the guard refuses every connection,
// and the last test checks that none was tried.

import './local-library.mjs';
import { refused } from './no-network.mjs';
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

const { INVALID_SPAN_CONTEXT, SpanStatusCode, context, trace } = await import('@opentelemetry/api');
const { InMemorySpanExporter, SimpleSpanProcessor, TracerProvider } = await import('@opentelemetry/sdk-trace');
const { AsyncLocalStorageContextManager } = await import('@opentelemetry/context-async-hooks');
const { NotTaken, argumentsFingerprint, fromBase64url, identifierFingerprint } = await import('provared');
const { developmentRecorder } = await import('provared/dev');
const bridge = await import('../index.mjs');
const { ATTRIBUTES, NOT_TAKEN_EVENT, annotate, traceAct, traceTools } = bridge;

const exporter = new InMemorySpanExporter();
const provider = new TracerProvider({ spanProcessors: [new SimpleSpanProcessor({ exporter })] });
const contextManager = new AsyncLocalStorageContextManager().enable();
context.setGlobalContextManager(contextManager);
trace.setGlobalTracerProvider(provider);
after(async () => {
  await provider.shutdown();
  contextManager.disable();
});
beforeEach(() => exporter.reset());

// Text that must never reach a span: it is in every call's arguments, and in the error a tool throws.
const CANARY = 'CANARY-do-not-trace-7f3a';
const CANARY_NUMBER = 987654321;
const ORDER = 'shop.order';
const LOOKUP = 'shop.lookup';

const contentOf = (record) => JSON.parse(new TextDecoder().decode(fromBase64url(record.payload)));
const documentsOf = (stub) => contentOf(stub.record).details ?? [];
// The SDK hands a span to its exporter a moment after it ends: wait for it.
const finished = async () => {
  await provider.forceFlush();
  return exporter.getFinishedSpans();
};
const spanNamed = async (name) => {
  const spans = (await finished()).filter((s) => s.name === name);
  assert.equal(spans.length, 1, `one span named ${name}`);
  return spans[0];
};

// Everything a span holds, written out, for the search for the canary.
function everything(span) {
  return JSON.stringify({ name: span.name, attributes: span.attributes, events: span.events.map((e) => ({ name: e.name, attributes: e.attributes })), status: span.status });
}

async function shop({ count = 2, denials = false } = {}) {
  return developmentRecorder(
    { actions: [ORDER, LOOKUP], limits: [{ action: ORDER, count }], purpose: 'Testing the OpenTelemetry bridge.' },
    { denials },
  );
}

const orderTool = (ran) => ({
  action: ORDER,
  run: async (args) => {
    ran.push(args);
    return { ordered: args.item };
  },
});

test('a call within the permission: the span names the receipt, and the receipt names the span\'s trace', async () => {
  const { recorder, slipFingerprint, issuerKeys } = await shop();
  const ran = [];
  const written = [];
  const tools = traceTools(recorder, { order: orderTool(ran) }, { agentName: 'Test agent', onStub: (stub) => written.push(stub) });
  const args = { item: CANARY, quantity: CANARY_NUMBER };
  assert.deepEqual(await tools.order(args), { ordered: CANARY });
  assert.equal(ran.length, 1);
  assert.equal(written.length, 1);

  const span = await spanNamed('execute_tool order');
  const a = span.attributes;
  assert.equal(span.kind, 0); // INTERNAL
  assert.equal(a['gen_ai.operation.name'], 'execute_tool');
  assert.equal(a['gen_ai.tool.name'], 'order');
  assert.equal(a['gen_ai.agent.name'], 'Test agent');
  assert.equal(a[ATTRIBUTES.outcome], 'taken');
  assert.equal(a[ATTRIBUTES.action], ORDER);
  assert.equal(a[ATTRIBUTES.stubFingerprint], written[0].fingerprint);
  assert.equal(a[ATTRIBUTES.stubSeq], 0);
  assert.equal(a[ATTRIBUTES.slipFingerprint], slipFingerprint);
  assert.equal(a[ATTRIBUTES.countersigned], false);
  assert.equal(a[ATTRIBUTES.traceBound], true);
  assert.equal(a['error.type'], undefined);
  assert.equal(span.status.code, SpanStatusCode.UNSET);

  // The receipt names the span's own trace, and the arguments as recordTools would.
  const documents = documentsOf(written[0]);
  assert.deepEqual(documents, [
    { name: 'provared.arguments', sha256: await argumentsFingerprint(args) },
    { name: 'provared.trace-id', sha256: await identifierFingerprint(span.spanContext().traceId) },
  ]);

  // The record still checks, naming the passkey.
  const answer = await recorder.check();
  assert.equal(answer.summary.problemFound, false);
  assert.equal(answer.summary.withinSlips, true);
  // The checker's own answer gives the same fingerprints the span names.
  const entries = answer.entries.filter((e) => e.kind === 'stub');
  assert.equal(entries.length, 1);
  assert.equal(entries[0].fingerprint, a[ATTRIBUTES.stubFingerprint]);
  assert.equal(answer.entries.find((e) => e.kind === 'slip').fingerprint, a[ATTRIBUTES.slipFingerprint]);
  assert.ok(issuerKeys.length === 1);
  assert.ok(!everything(span).includes(CANARY) && !everything(span).includes(String(CANARY_NUMBER)));
});

test('a call not taken: no tool run, the span says why in codes, and the error goes to the caller', async () => {
  const { recorder, slipFingerprint } = await shop({ count: 1, denials: true });
  const ran = [];
  const tools = traceTools(recorder, { order: orderTool(ran) }, { event: true });
  await tools.order({ item: CANARY });
  exporter.reset();
  await assert.rejects(tools.order({ item: CANARY, note: `${CANARY} again` }), (e) => e instanceof NotTaken);
  assert.equal(ran.length, 1, 'the second call did not run the tool');

  const span = await spanNamed('execute_tool order');
  const a = span.attributes;
  assert.equal(a[ATTRIBUTES.outcome], 'not_taken');
  assert.equal(a[ATTRIBUTES.action], ORDER);
  assert.deepEqual(a[ATTRIBUTES.codes], ['over-count-limit']);
  assert.match(a[ATTRIBUTES.denialFingerprint], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(a[ATTRIBUTES.slipFingerprint], slipFingerprint);
  assert.equal(a[ATTRIBUTES.stubFingerprint], undefined);
  assert.equal(a['error.type'], 'NotTaken');
  assert.equal(span.status.code, SpanStatusCode.ERROR);
  assert.equal(span.status.message, 'over-count-limit');
  assert.equal(span.events.length, 1);
  assert.equal(span.events[0].name, NOT_TAKEN_EVENT);
  assert.deepEqual(span.events[0].attributes, {
    [ATTRIBUTES.action]: ORDER,
    [ATTRIBUTES.codes]: ['over-count-limit'],
    [ATTRIBUTES.denialFingerprint]: a[ATTRIBUTES.denialFingerprint],
  });
  // The denial in the book is the one the span names.
  const lines = recorder.book().trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(lines.filter((l) => l.denial).length, 1);
  assert.ok(!everything(span).includes(CANARY));
});

test('a call not taken, with no denial and no event asked for', async () => {
  const { recorder } = await shop({ count: 1 });
  const tools = traceTools(recorder, { order: orderTool([]) });
  await tools.order({ item: 'first' });
  exporter.reset();
  await assert.rejects(tools.order({ item: CANARY }), NotTaken);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'not_taken');
  assert.equal(span.attributes[ATTRIBUTES.denialFingerprint], undefined);
  assert.equal(span.attributes[ATTRIBUTES.slipFingerprint], undefined, 'without a denial, the slip is not known from the answer');
  assert.equal(span.events.length, 0);
});

test('a tool that throws: no receipt, the error goes to the caller, and its message stays off the span', async () => {
  const { recorder } = await shop();
  const tools = traceTools(recorder, {
    order: {
      action: ORDER,
      run: async (args) => {
        throw new TypeError(`could not order ${args.item} x ${args.quantity}`);
      },
    },
  });
  await assert.rejects(tools.order({ item: CANARY, quantity: CANARY_NUMBER }), (e) => e instanceof TypeError && e.message.includes(CANARY));
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'error');
  assert.equal(span.attributes[ATTRIBUTES.action], ORDER);
  assert.equal(span.attributes[ATTRIBUTES.stubFingerprint], undefined);
  assert.equal(span.attributes['error.type'], 'TypeError');
  assert.equal(span.status.code, SpanStatusCode.ERROR);
  assert.equal(span.status.message, undefined);
  assert.equal(span.events.length, 0, 'no exception event: its message would quote the arguments');
  assert.ok(!everything(span).includes(CANARY) && !everything(span).includes(String(CANARY_NUMBER)));
  // Nothing was written but the slip.
  assert.equal(recorder.book().trim().split('\n').length, 1);
});

test('an error whose class has no plain name is "_OTHER"', async () => {
  const { recorder } = await shop();
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => { throw Object.create(null); } } });
  await assert.rejects(tools.order({ item: 'x' }));
  assert.equal((await spanNamed('execute_tool order')).attributes['error.type'], '_OTHER');
});

test('calls in parallel: each under its own span, each span naming its own receipt and each receipt its own trace', async () => {
  const { recorder } = await shop({ count: 10 });
  const tracer = trace.getTracer('test');
  const written = [];
  const tools = traceTools(
    recorder,
    {
      order: {
        action: ORDER,
        // What the tool does is traced beneath the bridge's span.
        run: (args) => tracer.startActiveSpan(`inner ${args.n}`, async (inner) => {
          await new Promise((resolve) => setTimeout(resolve, 5 * (5 - args.n)));
          inner.end();
          return args.n;
        }),
      },
    },
    { onStub: (stub) => written.push(stub) },
  );
  const results = await Promise.all([1, 2, 3, 4].map((n) => tools.order({ n, secret: CANARY })));
  assert.deepEqual(results, [1, 2, 3, 4]);

  const spans = (await finished()).filter((s) => s.name === 'execute_tool order');
  assert.equal(spans.length, 4);
  assert.equal(new Set(spans.map((s) => s.spanContext().spanId)).size, 4);
  const byStub = new Map(written.map((s) => [s.fingerprint, s]));
  assert.equal(byStub.size, 4);
  for (const span of spans) {
    const stub = byStub.get(span.attributes[ATTRIBUTES.stubFingerprint]);
    assert.ok(stub, 'the span names one of the receipts');
    const traceDocument = documentsOf(stub).find((d) => d.name === 'provared.trace-id');
    assert.equal(traceDocument.sha256, await identifierFingerprint(span.spanContext().traceId));
    assert.ok(!everything(span).includes(CANARY));
  }
  // Each span names a different receipt.
  assert.equal(new Set(spans.map((s) => s.attributes[ATTRIBUTES.stubFingerprint])).size, 4);
  // Each inner span is a child of the bridge's span for the same call.
  for (const n of [1, 2, 3, 4]) {
    const inner = await spanNamed(`inner ${n}`);
    const outer = spans.find((s) => s.spanContext().spanId === inner.parentSpanContext?.spanId);
    assert.ok(outer, `inner ${n} has the bridge's span as its parent`);
    assert.equal(outer.spanContext().traceId, inner.spanContext().traceId);
  }
});

test('"active": the bridge adds to the caller\'s own span, and leaves its name, its kind and its status alone', async () => {
  const { recorder } = await shop({ count: 1 });
  const tracer = trace.getTracer('framework');
  const written = [];
  const tools = traceTools(recorder, { order: orderTool([]) }, { span: 'active', onStub: (s) => written.push(s) });
  await tracer.startActiveSpan('framework tool span', async (span) => {
    await tools.order({ item: CANARY });
    span.end();
  });
  let span = await spanNamed('framework tool span');
  assert.equal((await finished()).length, 1, 'no second span for one call');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'taken');
  assert.equal(span.attributes[ATTRIBUTES.stubFingerprint], written[0].fingerprint);
  assert.equal(span.attributes['gen_ai.operation.name'], undefined);
  const traceDocument = documentsOf(written[0]).find((d) => d.name === 'provared.trace-id');
  assert.equal(traceDocument.sha256, await identifierFingerprint(span.spanContext().traceId));

  exporter.reset();
  await tracer.startActiveSpan('framework tool span', async (s) => {
    await assert.rejects(tools.order({ item: CANARY }), NotTaken);
    s.end();
  });
  span = await spanNamed('framework tool span');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'not_taken');
  assert.equal(span.attributes['error.type'], undefined);
  assert.equal(span.status.code, SpanStatusCode.UNSET, 'the caller sets its own span\'s status');
});

test('"active" with no span active: the tool runs and is receipted, with no trace in the receipt', async () => {
  const { recorder } = await shop();
  const written = [];
  const tools = traceTools(recorder, { order: orderTool([]) }, { span: 'active', onStub: (s) => written.push(s) });
  await context.with(trace.deleteSpan(context.active()), () => tools.order({ item: 'x' }));
  assert.equal((await finished()).length, 0);
  assert.deepEqual(documentsOf(written[0]).map((d) => d.name), ['provared.arguments']);
});

test('with no tracing set up, the tools work as without the bridge', async () => {
  const { recorder } = await shop();
  const written = [];
  const noTracer = { startActiveSpan: (name, options, fn) => fn(trace.wrapSpanContext(INVALID_SPAN_CONTEXT)) };
  const tools = traceTools(recorder, { order: orderTool([]) }, { tracer: noTracer, onStub: (s) => written.push(s) });
  assert.deepEqual(await tools.order({ item: 'x' }), { ordered: 'x' });
  assert.deepEqual(documentsOf(written[0]).map((d) => d.name), ['provared.arguments']);
});

test('the identifier the model gave the call: on the span, and in the receipt as its fingerprint', async () => {
  const { recorder } = await shop();
  const written = [];
  const tools = traceTools(
    recorder,
    { order: { ...orderTool([]), callId: (extra) => extra?.toolCallId } },
    { onStub: (s) => written.push(s) },
  );
  await tools.order({ item: 'x' }, { toolCallId: 'call_abc123' });
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes['gen_ai.tool.call.id'], 'call_abc123');
  const eventDocument = documentsOf(written[0]).find((d) => d.name === 'provared.event-id');
  assert.equal(eventDocument.sha256, await identifierFingerprint('call_abc123'));
});

test('a tool\'s own documents are kept, and "details: false" leaves only the bindings', async () => {
  const { recorder } = await shop({ count: 5 });
  const written = [];
  const own = { name: 'invoice', sha256: await identifierFingerprint('invoice-1') };
  const tools = traceTools(
    recorder,
    {
      a: { action: ORDER, run: async () => 1, details: async () => [own] },
      b: { action: ORDER, run: async () => 2, details: false },
      c: { action: ORDER, run: async () => 3, details: false },
    },
    { onStub: (s) => written.push(s) },
  );
  await tools.a({});
  await tools.b({});
  assert.deepEqual(documentsOf(written[0]).map((d) => d.name), ['invoice', 'provared.trace-id']);
  assert.deepEqual(documentsOf(written[1]).map((d) => d.name), ['provared.trace-id']);
  const unbound = traceTools(recorder, { c: { action: ORDER, run: async () => 3, details: false } }, { bindTrace: false, onStub: (s) => written.push(s) });
  await unbound.c({});
  assert.deepEqual(documentsOf(written[2]), []);
  assert.equal((await spanNamed('execute_tool c')).attributes[ATTRIBUTES.traceBound], false);
});

test('a mistake in a tool\'s description is found when the tools are put together', async () => {
  const { recorder } = await shop();
  assert.throws(() => traceTools(recorder, { order: { action: ORDER } }), /run/);
  assert.throws(() => traceTools(recorder, { order: { ...orderTool([]), callId: 'x' } }), /callId/);
  assert.throws(() => traceTools(recorder, { order: orderTool([]) }, { span: 'both' }), /span/);
});

test('traceAct: "act" traced, a call not taken given back, not thrown, and "detailsAfter" passed on', async () => {
  const { recorder, slipFingerprint } = await shop({ count: 1 });
  const first = await traceAct(
    recorder,
    { action: ORDER },
    async () => ({ id: 'evt-42' }),
    { detailsAfter: async (r) => [{ name: 'provared.event-id', sha256: await identifierFingerprint(r.id) }] },
    { toolName: 'place_order' },
  );
  assert.equal(first.done, true);
  assert.equal(first.detailsAfter.added, 1);
  let span = await spanNamed('execute_tool place_order');
  assert.equal(span.attributes[ATTRIBUTES.stubFingerprint], first.stub.fingerprint);
  assert.equal(span.attributes[ATTRIBUTES.slipFingerprint], slipFingerprint);
  assert.deepEqual(documentsOf(first.stub).map((d) => d.name), ['provared.trace-id', 'provared.event-id']);
  assert.equal(documentsOf(first.stub)[0].sha256, await identifierFingerprint(span.spanContext().traceId));

  exporter.reset();
  const second = await traceAct(recorder, { action: ORDER }, async () => assert.fail('not taken'));
  assert.equal(second.done, false);
  span = await spanNamed(`execute_tool ${ORDER}`);
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'not_taken');
  assert.deepEqual(span.attributes[ATTRIBUTES.codes], ['over-count-limit']);
  assert.equal(span.status.code, SpanStatusCode.ERROR);
});

test('annotate works on any object with setAttribute, and sets only fingerprints, names and codes', async () => {
  const { recorder } = await shop();
  const outcome = await recorder.act({ action: ORDER, details: [{ name: 'provared.arguments', sha256: await argumentsFingerprint({ item: CANARY }) }] }, async () => CANARY);
  const set = {};
  const span = { setAttribute: (k, v) => { set[k] = v; } };
  const returned = annotate(span, { outcome: 'taken', action: ORDER, stub: outcome.stub, traceBound: false });
  assert.deepEqual(set, returned);
  assert.deepEqual(Object.keys(set).sort(), Object.values(ATTRIBUTES).filter((n) => !['provared.check.codes', 'provared.denial.fingerprint'].includes(n)).sort());
  assert.ok(!JSON.stringify(set).includes(CANARY));
  // Something that is not a written stub sets only the outcome.
  assert.deepEqual(annotate(null, { outcome: 'nonsense' }), {});
  assert.deepEqual(bridge.attributesFor({ outcome: 'taken', action: 'not an action name with spaces', stub: { fingerprint: 'short', seq: -1 } }), {
    [ATTRIBUTES.outcome]: 'taken',
    [ATTRIBUTES.countersigned]: false,
    [ATTRIBUTES.traceBound]: false,
  });
});

test('the guard refuses a connection, so that the test below means something', async () => {
  const net = await import('node:net');
  assert.throws(() => net.connect(9, '127.0.0.1'), /guard refused/);
  await assert.rejects(async () => fetch('https://example.invalid/'), /guard refused/);
  assert.deepEqual(refused.splice(0), ['net.connect', 'fetch']);
});

test('nothing in these tests tried to connect anywhere', () => {
  assert.deepEqual(refused, []);
});
