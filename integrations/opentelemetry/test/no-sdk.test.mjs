// The bridge with OpenTelemetry's API and no SDK: no tracer provider is
// registered in this process, so the API records no span. A file of its
// own, so that the provider registered in the other tests is not here.

import './local-library.mjs';
import { refused } from './no-network.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { TraceFlags, context, trace } = await import('@opentelemetry/api');
const { AsyncLocalStorageContextManager } = await import('@opentelemetry/context-async-hooks');
const { NotTaken, fromBase64url, identifierFingerprint } = await import('provared');
const { developmentRecorder } = await import('provared/dev');
const { traceAct, traceTools } = await import('../index.mjs');

const ORDER = 'shop.order';
const namesOf = (stub) => (JSON.parse(new TextDecoder().decode(fromBase64url(stub.record.payload))).details ?? []).map((d) => d.name);
const shop = () => developmentRecorder({ actions: [ORDER], limits: [{ action: ORDER, count: 2 }], purpose: 'Testing the OpenTelemetry bridge.' });

test('with no SDK, the tools run and are receipted, and the receipt names no trace', async () => {
  const { recorder } = await shop();
  const written = [];
  const tools = traceTools(recorder, { order: { action: ORDER, run: async (a) => a.n } }, { onStub: (s) => written.push(s) });
  assert.equal(await tools.order({ n: 1 }), 1);
  assert.deepEqual(namesOf(written[0]), ['provared.arguments']);
  const outcome = await traceAct(recorder, { action: ORDER }, async () => 2);
  assert.equal(outcome.done, true);
  assert.deepEqual(namesOf(outcome.stub), []);
  await assert.rejects(tools.order({ n: 3 }), NotTaken);
});

test('with no SDK, but inside a trace passed on from elsewhere, the receipt names that trace', async () => {
  const manager = new AsyncLocalStorageContextManager().enable();
  context.setGlobalContextManager(manager);
  try {
    const { recorder } = await shop();
    const written = [];
    const tools = traceTools(recorder, { order: { action: ORDER, run: async () => 1 } }, { onStub: (s) => written.push(s) });
    // As a propagator gives it, from a "traceparent" header that came in.
    const parent = { traceId: '0af7651916cd43dd8448eb211c80319c', spanId: 'b7ad6b7169203331', traceFlags: TraceFlags.SAMPLED, isRemote: true };
    await context.with(trace.setSpanContext(context.active(), parent), () => tools.order({}));
    assert.deepEqual(namesOf(written[0]), ['provared.arguments', 'provared.trace-id']);
    const sha256 = JSON.parse(new TextDecoder().decode(fromBase64url(written[0].record.payload))).details[1].sha256;
    assert.equal(sha256, await identifierFingerprint(parent.traceId));
  } finally {
    context.disable();
    manager.disable();
  }
});

test('nothing in these tests tried to connect anywhere', () => {
  assert.deepEqual(refused, []);
});
