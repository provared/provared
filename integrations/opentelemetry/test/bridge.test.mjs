// The OpenTelemetry bridge, with OpenTelemetry's own SDK and its in-memory
// exporter. Nothing leaves the process: the guard refuses every connection,
// and the last test checks that none was tried.

import './local-library.mjs';
import { refused } from './no-network.mjs';
import { after, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';

const { INVALID_SPAN_CONTEXT, SpanStatusCode, context, trace } = await import('@opentelemetry/api');
const { AlwaysOffSampler, InMemorySpanExporter, SimpleSpanProcessor, TracerProvider } = await import('@opentelemetry/sdk-trace');
const { AsyncLocalStorageContextManager } = await import('@opentelemetry/context-async-hooks');
const { NotTaken, argumentsFingerprint, assembleApproval, checkBook, countersign, fromBase64url, generateKeySet, identifierFingerprint, prepareApproval, recordTools } = await import('provared');
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

// --- After the first independent check (M1 to M4, L1 to L10) ---

const namesOf = (stub) => documentsOf(stub).map((d) => d.name);

test('a NotTaken from another stub writer, thrown inside the tool, is the tool\'s error, not this call\'s check', async () => {
  const outer = await shop({ count: 5 });
  const inner = await shop({ count: 1, denials: true });
  const innerTools = traceTools(inner.recorder, { sub: { action: ORDER, run: async () => 1 } });
  await innerTools.sub({});
  exporter.reset();
  let ran = false;
  const tools = traceTools(outer.recorder, { order: { action: ORDER, run: async () => { ran = true; return innerTools.sub({}); } } });
  await assert.rejects(tools.order({ item: CANARY }), NotTaken);
  assert.equal(ran, true);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'error');
  assert.equal(span.attributes['error.type'], 'NotTaken');
  for (const name of [ATTRIBUTES.codes, ATTRIBUTES.denialFingerprint, ATTRIBUTES.slipFingerprint, ATTRIBUTES.stubFingerprint]) assert.equal(span.attributes[name], undefined, name);
  // The inner call's own span says what its own check said.
  const sub = await spanNamed('execute_tool sub');
  assert.equal(sub.attributes[ATTRIBUTES.outcome], 'not_taken');
  assert.equal(sub.attributes[ATTRIBUTES.slipFingerprint], inner.slipFingerprint);
});

test('something that only looks like a NotTaken, thrown by the tool, is the tool\'s error', async () => {
  const { recorder } = await shop();
  const fake = { name: 'NotTaken', answer: { problems: [{ code: 'over-total-limit', message: `${CANARY} 230 GBP` }], breaches: [] }, denial: { written: true, fingerprint: 'Q0FOQVJZLXNlY3JldC12YWx1ZS1oaWRkZW4taGVyZQ', line: '{}' } };
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => { throw fake; } } });
  await assert.rejects(tools.order({}), (e) => e === fake);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'error');
  assert.equal(span.attributes[ATTRIBUTES.codes], undefined);
  assert.equal(span.attributes[ATTRIBUTES.denialFingerprint], undefined);
  assert.ok(!everything(span).includes(CANARY));
});

test('a NotTaken thrown by a tool\'s own "amount", before the tool runs, is the caller\'s error too', async () => {
  const { recorder } = await shop();
  const elsewhere = new NotTaken('order', { allowed: false, problems: [], breaches: [{ code: 'over-count-limit', message: 'x' }], needs: [] });
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => 1, amount: () => { throw elsewhere; } } });
  await assert.rejects(tools.order({}), (e) => e === elsewhere);
  assert.equal((await spanNamed('execute_tool order')).attributes[ATTRIBUTES.outcome], 'error');
});

test('an error whose class cannot even be read is "_OTHER", and reaches the caller as it was', async () => {
  const { recorder } = await shop();
  const bad = { get constructor() { throw new Error(`getter ${CANARY}`); } };
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => { throw bad; } } });
  await assert.rejects(tools.order({}), (e) => e === bad);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes['error.type'], '_OTHER');
  assert.ok(!everything(span).includes(CANARY));
});

// A slip under which an order above 40 GBP needs the person's own approval.
async function approving() {
  return developmentRecorder(
    { actions: [ORDER], limits: [{ action: ORDER, max: 1000, unit: 'GBP' }], requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }], purpose: 'Testing the OpenTelemetry bridge.' },
    { denials: true },
  );
}
async function approve(made, request) {
  const prepared = await prepareApproval({ slip: made.slipFingerprint, ...request, when: Date.now() - 1000 });
  return { record: assembleApproval(prepared, await made.passkey.sign(prepared.challenge)) };
}

test('traceAct with an approval made beforehand adds no binding, so the approval still fits the request', async () => {
  const made = await approving();
  const request = { action: ORDER, amount: { unit: 'GBP', value: 60 } };
  const outcome = await traceAct(made.recorder, request, async () => 'ok', { approval: await approve(made, request) }, { callId: 'call_1' });
  assert.equal(outcome.done, true, JSON.stringify(outcome.answer));
  assert.equal(outcome.denial, undefined);
  assert.deepEqual(namesOf(outcome.stub), []);
  const span = await spanNamed(`execute_tool ${ORDER}`);
  assert.equal(span.attributes[ATTRIBUTES.stubFingerprint], outcome.stub.fingerprint);
  assert.equal(span.attributes[ATTRIBUTES.traceBound], false);
  assert.equal(span.attributes['gen_ai.tool.call.id'], 'call_1');
  const answer = await made.recorder.check();
  assert.equal(answer.summary.withinSlips, true);
  assert.equal(answer.entries.filter((e) => e.kind === 'denial').length, 0);
});

test('traceTools with "approve": the person approves the request with its bindings', async () => {
  const made = await approving();
  const tools = traceTools(made.recorder, { order: { action: ORDER, run: async () => 'ok', amount: (a) => ({ unit: 'GBP', value: a.total }), approve: async (request) => approve(made, request) } });
  assert.equal(await tools.order({ total: 60 }), 'ok');
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'taken');
  assert.equal(span.attributes[ATTRIBUTES.traceBound], true);
  const answer = await made.recorder.check();
  assert.equal(answer.summary.withinSlips, true);
  const stub = answer.entries.find((e) => e.kind === 'stub');
  assert.equal(stub.fingerprint, span.attributes[ATTRIBUTES.stubFingerprint]);
  assert.ok(stub.content.approval, 'the stub names the approval');
});

test('traceAct passes a "details" that is not a list on as it is, for "act" to refuse', async () => {
  const { recorder } = await shop();
  const request = { action: ORDER, details: { name: 'x' } };
  const said = (p) => p.then((o) => ({ done: o.done, codes: o.answer.problems.map((x) => x.code) }), (e) => ({ threw: e.code ?? e.name }));
  const alone = await said(recorder.act(request, async () => assert.fail('not taken')));
  const traced = await said(traceAct(recorder, request, async () => assert.fail('not taken')));
  assert.deepEqual(traced, alone);
  assert.notEqual(alone.done, true);
});

test('one receipt never holds two "provared.event-id" from different sources', async () => {
  const { recorder } = await shop({ count: 5 });
  const outcome = await traceAct(
    recorder,
    { action: ORDER },
    async () => ({ id: 'platform-1' }),
    { detailsAfter: async (r) => [{ name: 'provared.event-id', sha256: await identifierFingerprint(r.id) }] },
    { callId: 'call_model_1' },
  );
  assert.deepEqual(namesOf(outcome.stub), ['provared.trace-id', 'provared.event-id']);
  assert.equal(documentsOf(outcome.stub)[1].sha256, await identifierFingerprint('platform-1'));
  assert.equal((await spanNamed(`execute_tool ${ORDER}`)).attributes['gen_ai.tool.call.id'], 'call_model_1');

  const own = { name: 'provared.event-id', sha256: await identifierFingerprint('platform-2') };
  const written = [];
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => 1, details: async () => [own], callId: () => 'call_model_2' } }, { onStub: (s) => written.push(s) });
  await tools.order({});
  assert.deepEqual(namesOf(written[0]), ['provared.event-id', 'provared.trace-id']);
  assert.deepEqual(documentsOf(written[0])[0], own);
});

test('traceAct names its span after the action only where the action has the form of one', async () => {
  const { recorder } = await shop();
  await traceAct(recorder, { action: `order 30 GBP for ${CANARY}` }, async () => 1).catch(() => {});
  const span = (await finished())[0];
  assert.equal(span.name, 'execute_tool action');
  assert.equal(span.attributes['gen_ai.tool.name'], 'action');
  assert.ok(!everything(span).includes(CANARY));
  await assert.rejects(traceAct(recorder, { action: ORDER }, async () => 1, {}, { toolName: 'two words' }), /toolName/);
});

test('a tool that names 32 documents of its own has no room for the binding, and the call is not taken', async () => {
  const { recorder } = await shop();
  const docs = await Promise.all(Array.from({ length: 32 }, async (_, i) => ({ name: `d${i}`, sha256: await identifierFingerprint(`d${i}`) })));
  const plain = recordTools(recorder, { order: { action: ORDER, run: async () => 1, details: async () => docs } });
  assert.equal(await plain.order({}), 1);
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => assert.fail('not run'), details: async () => docs } });
  // The check before acting refuses a request with more documents than a stub may name.
  await assert.rejects(tools.order({}), NotTaken);
  assert.equal((await spanNamed('execute_tool order')).attributes[ATTRIBUTES.outcome], 'not_taken');
  const unbound = traceTools(recorder, { order: { action: ORDER, run: async () => 2, details: async () => docs } }, { bindTrace: false });
  assert.equal(await unbound.order({}), 2);
});

test('traceAct: an action that throws leaves no receipt, and its error reaches the caller', async () => {
  const { recorder } = await shop();
  await assert.rejects(traceAct(recorder, { action: ORDER }, async () => { throw new RangeError(`boom ${CANARY}`); }), RangeError);
  const span = await spanNamed(`execute_tool ${ORDER}`);
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'error');
  assert.equal(span.attributes['error.type'], 'RangeError');
  assert.equal(span.status.message, undefined);
  assert.ok(!everything(span).includes(CANARY));
  assert.equal(recorder.book().trim().split('\n').length, 1);
});

test('"onStub" that fails: the receipt stands and the span names it, the status is an error, and the error reaches the caller', async () => {
  const { recorder } = await shop();
  const failing = new Error(`could not keep ${CANARY}`);
  const tools = traceTools(recorder, { order: orderTool([]) }, { onStub: () => { throw failing; } });
  await assert.rejects(tools.order({ item: 'x' }), (e) => e === failing);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'taken');
  assert.match(span.attributes[ATTRIBUTES.stubFingerprint], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(span.attributes['error.type'], 'Error');
  assert.equal(span.status.code, SpanStatusCode.ERROR);
  assert.ok(!everything(span).includes(CANARY));
  assert.equal(recorder.book().trim().split('\n').length, 2);
});

test('a countersignature checked and kept: provared.stub.countersigned is true', async () => {
  const service = await generateKeySet();
  const { recorder, issuerKeys } = await developmentRecorder({
    actions: [ORDER],
    with: [{ id: 'shop', name: 'Invented shop', keys: service.keys }],
    purpose: 'Testing the OpenTelemetry bridge.',
  });
  const tools = traceTools(recorder, { order: { action: ORDER, with: 'shop', run: async () => 1, countersign: (stub) => countersign(stub, service.privateKeys, Date.now()) } });
  assert.equal(await tools.order({}), 1);
  const span = await spanNamed('execute_tool order');
  assert.equal(span.attributes[ATTRIBUTES.countersigned], true);
  const answer = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(answer.entries.find((e) => e.kind === 'stub').countersignature.state, 'valid');
});

test('"active" with a tool that throws, and with a denial: the bridge sets only its own attributes', async () => {
  const { recorder } = await shop({ count: 1, denials: true });
  const tracer = trace.getTracer('framework');
  const tools = traceTools(recorder, { order: orderTool([]), broken: { action: ORDER, run: async () => { throw new TypeError(CANARY); } } }, { span: 'active' });
  await tracer.startActiveSpan('framework broken', async (s) => {
    await assert.rejects(tools.broken({}), TypeError);
    s.end();
  });
  let span = await spanNamed('framework broken');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'error');
  assert.equal(span.attributes['error.type'], undefined);
  assert.equal(span.status.code, SpanStatusCode.UNSET);
  await tools.order({});
  exporter.reset();
  await tracer.startActiveSpan('framework order', async (s) => {
    await assert.rejects(tools.order({}), NotTaken);
    s.end();
  });
  span = await spanNamed('framework order');
  assert.equal(span.attributes[ATTRIBUTES.outcome], 'not_taken');
  assert.match(span.attributes[ATTRIBUTES.denialFingerprint], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(span.status.code, SpanStatusCode.UNSET);
});

test('the denial and the slip the span names are those an independent check of the book finds', async () => {
  const { recorder, issuerKeys } = await shop({ count: 1, denials: true });
  const tools = traceTools(recorder, { order: orderTool([]) });
  await tools.order({});
  exporter.reset();
  await assert.rejects(tools.order({}), NotTaken);
  const span = await spanNamed('execute_tool order');
  const answer = await checkBook(recorder.book(), { issuerKeys });
  assert.deepEqual(answer.entries.map((e) => e.kind), ['slip', 'stub', 'denial']);
  assert.equal(answer.entries[2].fingerprint, span.attributes[ATTRIBUTES.denialFingerprint]);
  assert.equal(answer.entries[0].fingerprint, span.attributes[ATTRIBUTES.slipFingerprint]);
});

test('a trace that is not sampled is still named in the receipt, though no span is kept', async () => {
  // An exporter of its own: shutting a provider down shuts its exporter down too.
  const kept = new InMemorySpanExporter();
  const unsampled = new TracerProvider({ sampler: new AlwaysOffSampler(), spanProcessors: [new SimpleSpanProcessor({ exporter: kept })] });
  const { recorder } = await shop();
  const written = [];
  let traceId;
  const tools = traceTools(recorder, { order: { action: ORDER, run: async () => { traceId = trace.getActiveSpan().spanContext().traceId; return 1; } } }, { tracer: unsampled.getTracer('off'), onStub: (s) => written.push(s) });
  await tools.order({});
  await unsampled.forceFlush();
  assert.equal(kept.getFinishedSpans().length, 0);
  assert.equal(documentsOf(written[0]).find((d) => d.name === 'provared.trace-id').sha256, await identifierFingerprint(traceId));
  await unsampled.shutdown();
});

test('options are checked: an unknown option, and agentName, callId and toolName in traceAct', async () => {
  const { recorder } = await shop();
  assert.throws(() => traceTools(recorder, { order: orderTool([]) }, { spans: 'new' }), /spans: is not an option/);
  assert.throws(() => traceTools(recorder, { order: orderTool([]) }, { callId: 'x' }), /callId: is not an option/);
  await assert.rejects(traceAct(recorder, { action: ORDER }, async () => 1, {}, { agentName: '' }), /agentName/);
  await assert.rejects(traceAct(recorder, { action: ORDER }, async () => 1, {}, { callId: 12 }), /callId/);
  await assert.rejects(traceAct(recorder, { action: ORDER }, async () => 1, {}, { callid: 'x' }), /callid: is not an option/);
  const outcome = await traceAct(recorder, { action: ORDER }, async () => 1, {}, { agentName: 'Agent A', callId: 'call_9', toolName: 'place_order' });
  const span = await spanNamed('execute_tool place_order');
  assert.equal(span.attributes['gen_ai.agent.name'], 'Agent A');
  assert.equal(span.attributes['gen_ai.tool.call.id'], 'call_9');
  assert.deepEqual(namesOf(outcome.stub), ['provared.trace-id', 'provared.event-id']);
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
