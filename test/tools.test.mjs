// The connector between an agent's tools and the stub writer: each call
// asks first, runs the tool only if the slip allows it, and leaves a stub.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NotTaken, argumentsFingerprint, checkBook, countersign, fingerprint, openRecorder, recordTools, thumbprint, utf8 } from '../src/index.js';
import { START, makeWorld } from './helpers/world.mjs';

const MINUTE = 60 * 1000;
const ORDER = 'supplies.order';
const LOOK = 'provared.data.read';

async function opened(fields = {}) {
  const w = await makeWorld({ fields: { actions: [ORDER, LOOK], ...fields } });
  const clock = START + MINUTE;
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const recorder = await openRecorder({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys, now: () => clock });
  return { w, clock, issuerKeys, recorder };
}

test('a recorded tool runs only if the slip allows the action, and leaves a stub that fixes what was asked for', async () => {
  const { w, clock, issuerKeys, recorder } = await opened();
  const ran = [];
  const written = [];
  const tools = recordTools(
    recorder,
    {
      placeOrder: {
        action: ORDER,
        with: 'supplier',
        amount: (order) => ({ unit: 'GBP', value: order.total }),
        run: async (order) => {
          ran.push(order);
          return { accepted: order.item };
        },
        countersign: (stub) => countersign(stub, w.service.privateKeys, clock + 1000),
      },
      readStock: { action: LOOK, run: (query) => `stock of ${query.item}: 3` },
    },
    { onStub: (stub, tool) => written.push([tool, stub.seq]) },
  );
  assert.deepEqual(Object.keys(tools), ['placeOrder', 'readStock']);

  const order = { item: 'paper', boxes: 5, total: 45 };
  assert.deepEqual(await tools.placeOrder(order), { accepted: 'paper' });
  assert.equal(await tools.readStock({ item: 'toner' }), 'stock of toner: 3');
  assert.deepEqual(written, [['placeOrder', 0], ['readStock', 1]]);

  const r = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  const [first, second] = r.entries.slice(1).map((e) => e.content);
  assert.equal(first.action, ORDER);
  assert.deepEqual(first.amount, { unit: 'GBP', value: 45 });
  assert.equal(first.with, 'supplier');
  // The stub names the arguments by their fingerprint, which anyone who holds them can work out again.
  assert.deepEqual(first.details, [{ name: 'arguments', sha256: await argumentsFingerprint({ total: 45, boxes: 5, item: 'paper' }) }]);
  assert.equal(r.entries[1].countersignature.state, 'valid');
  assert.equal(second.action, LOOK);
  assert.equal(second.amount, undefined);

  // Over the limit: the tool is not run, nothing is written, and the error says why.
  const before = recorder.book();
  const refused = await tools.placeOrder({ item: 'desks', total: 500 }).catch((e) => e);
  assert.ok(refused instanceof NotTaken);
  assert.equal(refused.tool, 'placeOrder');
  assert.deepEqual(refused.answer.breaches.map((b) => b.code), ['over-limit']);
  assert.match(refused.message, /The tool "placeOrder" was not run\. With this stub the total is 545 GBP/);
  assert.equal(ran.length, 1);
  assert.equal(recorder.book(), before);
});

test('the arguments are copied when the call is made: the copy is what is fingerprinted, and what the tool is run with', async () => {
  const { issuerKeys, recorder } = await opened();
  let seen;
  const tools = recordTools(recorder, {
    look: {
      action: LOOK,
      run: async (query) => {
        seen = query;
        query.changedByTheTool = 1;
        return 'done';
      },
    },
  });
  const query = { item: 'paper', where: ['shelf', 2] };
  const pending = tools.look(query);
  query.item = 'something else';
  assert.equal(await pending, 'done');
  assert.notEqual(seen, query);
  assert.equal(query.changedByTheTool, undefined);
  const r = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(r.entries[1].content.details[0].sha256, await argumentsFingerprint({ item: 'paper', where: ['shelf', 2] }));
});

test('the fingerprint of the arguments: one form, whatever the order of the members, and only for JSON', async () => {
  const a = await argumentsFingerprint({ b: [1, 2.5, -0, true, null, 'x'], a: { d: 'é', c: 1e21 } });
  const b = await argumentsFingerprint({ a: { c: 1e21, d: 'é' }, b: [1, 2.5, 0, true, null, 'x'] });
  assert.equal(a, b);
  // It is SHA-256 of the text RFC 8785 gives.
  assert.equal(a, await fingerprint(utf8('{"a":{"c":1e+21,"d":"é"},"b":[1,2.5,0,true,null,"x"]}')));
  assert.notEqual(a, await argumentsFingerprint({ a: { c: 1e21, d: 'é' }, b: [1, 2.5, 0, true, null, 'y'] }));
  assert.equal(await argumentsFingerprint('paper'), await fingerprint(utf8('"paper"')));
  assert.equal(await argumentsFingerprint(null), await fingerprint(utf8('null')));
  let deep = 'x';
  for (let i = 0; i < 70; i++) deep = [deep];
  for (const bad of [undefined, { a: undefined }, NaN, Infinity, 10n, () => 1, new Date(0), new Map(), { a: [new Uint8Array(2)] }, '\ud800', deep]) {
    await assert.rejects(async () => argumentsFingerprint(bad), (e) => e.code === 'bad-field');
  }
});

test('a tool may name other documents, or none; a call with no arguments names none', async () => {
  const { issuerKeys, recorder } = await opened();
  const document = { name: 'Order form', sha256: await fingerprint(utf8('the order form')) };
  const tools = recordTools(recorder, {
    bare: { action: LOOK, details: false, run: () => 1 },
    own: { action: LOOK, details: () => [document], run: () => 2 },
    plain: { action: LOOK, run: () => 3 },
  });
  assert.equal(await tools.bare({ secret: 'not fingerprinted' }), 1);
  assert.equal(await tools.own({ anything: true }), 2);
  assert.equal(await tools.plain(), 3);
  const r = await checkBook(recorder.book(), { issuerKeys });
  assert.deepEqual(r.entries.slice(1).map((e) => e.content.details), [undefined, [document], undefined]);
  assert.equal(r.summary.intact, true);
});

test('where the slip asks for the person\'s approval, the tool\'s "approve" is asked for it once', async () => {
  const { w, clock, issuerKeys, recorder } = await opened({ requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }] });
  const asked = [];
  let answer = 'yes';
  const tools = recordTools(recorder, {
    placeOrder: {
      action: ORDER,
      with: 'supplier',
      amount: (order) => ({ unit: 'GBP', value: order.total }),
      run: (order) => `ordered ${order.item}`,
      approve: async (request) => {
        asked.push(request);
        if (answer === 'no') return null;
        if (answer === 'for something else') return w.approve({ slip: w.slipFingerprint, ...request, amount: { unit: 'GBP', value: 1 }, when: clock });
        return w.approve({ slip: w.slipFingerprint, ...request, when: clock });
      },
    },
  });
  // Below the amount: nobody is asked.
  assert.equal(await tools.placeOrder({ item: 'pens', total: 10 }), 'ordered pens');
  assert.equal(asked.length, 0);
  // Above it: the person is asked, with exactly what the stub will say, and the action is taken with the approval.
  assert.equal(await tools.placeOrder({ item: 'toner', total: 60 }), 'ordered toner');
  assert.equal(asked.length, 1);
  assert.deepEqual(Object.keys(asked[0]).sort(), ['action', 'amount', 'details', 'with']);
  const r = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(r.summary.intact, true);
  assert.equal(r.summary.withinSlips, true);
  assert.equal(r.summary.counts.approved, 1);
  // The person says no, or approves something else: the tool is not run.
  for (answer of ['no', 'for something else']) {
    const refused = await tools.placeOrder({ item: 'chairs', total: 70 }).catch((e) => e);
    assert.ok(refused instanceof NotTaken, answer);
  }
  assert.equal(asked.length, 3);
  assert.equal((await checkBook(recorder.book(), { issuerKeys })).summary.counts.stubs, 2);
});

test('a tool that fails passes its error on, and leaves no stub; a tool that is not allowed is never asked to approve', async () => {
  const { recorder } = await opened();
  let approvals = 0;
  const tools = recordTools(recorder, {
    broken: {
      action: LOOK,
      run: async () => {
        throw new Error('the shelf fell over');
      },
    },
    forbidden: { action: 'provared.data.delete', run: () => 'deleted', approve: async () => void approvals++ },
  });
  const before = recorder.book();
  await assert.rejects(tools.broken({}), /the shelf fell over/);
  const refused = await tools.forbidden({}).catch((e) => e);
  assert.ok(refused instanceof NotTaken);
  assert.deepEqual(refused.answer.breaches.map((b) => b.code), ['action-not-allowed']);
  assert.equal(approvals, 0);
  assert.equal(recorder.book(), before);
  // Arguments that are not plain data are refused before anything is asked.
  await assert.rejects(tools.broken({ callback: () => 1 }), (e) => e.code === 'bad-field');
});

test('a tool that is not described as it must be is refused when the tools are put behind the writer', async () => {
  const { recorder } = await opened();
  const run = () => 1;
  for (const [tools, where] of [
    [{ a: { run } }, 'action'],
    [{ a: { action: 'Not A Name', run } }, 'action'],
    [{ a: { action: 'provared.not.on.the.list', run } }, 'action'],
    [{ a: { action: LOOK } }, 'run'],
    [{ a: { action: LOOK, run, countersign: 'yes' } }, 'countersign'],
    [{ a: { action: LOOK, run, approve: true } }, 'approve'],
    [{ a: { action: LOOK, run, details: 'none' } }, 'details'],
    [{ a: null }, 'a'],
    [[], 'tools'],
    [null, 'tools'],
  ]) {
    assert.throws(() => recordTools(recorder, tools), (e) => e.code === 'bad-field' && e.message.includes(where), where);
  }
  assert.throws(() => recordTools({}, { a: { action: LOOK, run } }), (e) => e.code === 'bad-field');
  // What a tool is, is fixed when it is put behind the writer.
  const spec = { action: LOOK, run: () => 'first' };
  const tools = recordTools(recorder, { a: spec });
  spec.run = () => 'changed';
  spec.action = 'provared.data.delete';
  assert.equal(await tools.a(), 'first');
});
