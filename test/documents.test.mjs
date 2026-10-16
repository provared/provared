// The reserved document names, the fingerprints they stand for, and
// "detailsAfter": a receipt bound to the platform's own identifier for the
// call (format description, section 27).

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  DOCUMENT_NAMES,
  RESERVED_DOCUMENT_PREFIX,
  checkBefore,
  checkBook,
  countersign,
  httpRequestFingerprint,
  httpResponseFingerprint,
  identifierFingerprint,
  prepareApproval,
  recordTools,
  thumbprint,
  writeStub,
} from '../src/index.js';
import { httpRequestBase, httpResponseBase } from '../src/documents.js';
import { MAX_LINE_BYTES } from '../src/book.js';
import { lineBound } from '../src/guard.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const ORDER = 'supplies.order';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const FP = 'A'.repeat(43);
const sha = (text) => createHash('sha256').update(text).digest('base64url');
const content = (record) => JSON.parse(Buffer.from(record.payload, 'base64url').toString());

async function opened(w, more = {}) {
  return openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], ...more });
}

test('seven document names are reserved, each beginning "provared.", and the list cannot be changed', () => {
  assert.equal(RESERVED_DOCUMENT_PREFIX, 'provared.');
  assert.deepEqual(Object.keys(DOCUMENT_NAMES).sort(), [
    'provared.arguments',
    'provared.error',
    'provared.event-id',
    'provared.http-request',
    'provared.http-response',
    'provared.request-id',
    'provared.trace-id',
  ]);
  assert.ok(Object.isFrozen(DOCUMENT_NAMES));
});

test('an HTTP request is written as the signature base of RFC 9421, with the Content-Digest of RFC 9530', async () => {
  const body = new TextEncoder().encode('{"hello": "world"}');
  const r = { method: 'POST', url: 'https://example.com/foo?param=Value&Pet=dog', body };
  const base = await httpRequestBase(r);
  // The digest RFC 9530 gives for this body.
  assert.equal(
    base,
    '"@method": POST\n"@target-uri": https://example.com/foo?param=Value&Pet=dog\n"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n"@signature-params": ("@method" "@target-uri" "content-digest")',
  );
  assert.equal(await httpRequestFingerprint(r), sha(base));
  // No body, and an empty body, are two different things.
  const none = await httpRequestFingerprint({ method: 'POST', url: 'https://example.com/foo' });
  const empty = await httpRequestFingerprint({ method: 'POST', url: 'https://example.com/foo', body: new Uint8Array() });
  assert.notEqual(none, empty);
  assert.equal(await httpRequestBase({ method: 'GET', url: 'https://example.com/' }), '"@method": GET\n"@target-uri": https://example.com/\n"@signature-params": ("@method" "@target-uri")');
});

test('an address is taken exactly as it was sent: two spellings of one address give two fingerprints', async () => {
  const a = await httpRequestFingerprint({ method: 'GET', url: 'https://example.com/a%2Fb' });
  const b = await httpRequestFingerprint({ method: 'GET', url: 'https://example.com/a%2fb' });
  const c = await httpRequestFingerprint({ method: 'GET', url: 'https://EXAMPLE.com/a%2Fb' });
  assert.equal(new Set([a, b, c]).size, 3);
  for (const url of ['https://example.com/a#b', 'https://example.com/a b', 'https://example.com/café', '/a', 'HTTPS://example.com/', 'ftp://example.com/', 'https://']) {
    await assert.rejects(httpRequestFingerprint({ method: 'GET', url }), (e) => e.code === 'bad-field', url);
  }
  for (const method of ['', 'GET X', 'GÉT', 5]) await assert.rejects(httpRequestFingerprint({ method, url: 'https://example.com/' }), (e) => e.code === 'bad-field');
  await assert.rejects(httpRequestFingerprint({ method: 'POST', url: 'https://example.com/', body: 'text' }), (e) => e.code === 'bad-field');
  // A body of null is no body, as in Python, where None is no body.
  assert.equal(await httpRequestFingerprint({ method: 'POST', url: 'https://example.com/', body: null }), await httpRequestFingerprint({ method: 'POST', url: 'https://example.com/' }));
  assert.equal(await httpResponseFingerprint({ status: 404, body: null }), await httpResponseFingerprint({ status: 404 }));
  await assert.rejects(httpRequestFingerprint(null), (e) => e.code === 'bad-field');
});

test('an HTTP answer is written by its status and, where it has one, its body', async () => {
  assert.equal(await httpResponseBase({ status: 204 }), '"@status": 204\n"@signature-params": ("@status")');
  const body = new TextEncoder().encode('{"hello": "world"}');
  assert.equal(await httpResponseFingerprint({ status: 200, body }), sha('"@status": 200\n"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n"@signature-params": ("@status" "content-digest")'));
  for (const status of [99, 600, '200', 200.5, undefined]) await assert.rejects(httpResponseFingerprint({ status }), (e) => e.code === 'bad-field');
});

test('an identifier or an error text is fingerprinted exactly as given', async () => {
  assert.equal(await identifierFingerprint('toolu_01AbC'), sha('toolu_01AbC'));
  assert.equal(await identifierFingerprint('Erreur\n\u{1F600}'), sha('Erreur\n\u{1F600}'));
  assert.notEqual(await identifierFingerprint('evt-1'), await identifierFingerprint('evt-1 '));
  for (const id of ['', 'a\ud800', 42, null]) await assert.rejects(identifierFingerprint(id), (e) => e.code === 'bad-field');
});

test('a stub may name every reserved document, and the same one twice; a reserved name not on the list is refused everywhere', async () => {
  const w = await makeWorld();
  for (const name of Object.keys(DOCUMENT_NAMES)) await w.add({ details: [{ name, sha256: FP }] });
  await w.add({ details: [{ name: 'provared.event-id', sha256: FP }, { name: 'provared.event-id', sha256: FP }] });
  // A name that was written before the list: still a label like any other.
  await w.add({ details: [{ name: 'arguments', sha256: FP }] });
  const sound = await checkBook(w.book(), { issuerKeys: [await thumbprint(w.passkey.key)] });
  assert.equal(sound.summary.intact, true);

  const unknown = [{ name: 'provared.invoice', sha256: FP }];
  await assert.rejects(writeStub({ slip: w.slipFingerprint, after: null, action: ORDER, details: unknown }, w.agent.privateKeys), (e) => e.code === 'bad-field' && /reserved/.test(e.message));
  await assert.rejects(prepareApproval({ slip: w.slipFingerprint, action: ORDER, details: unknown }), (e) => e.code === 'bad-field');
  const answer = await checkBefore(w.book(), { slip: w.slipFingerprint, ...order(1), details: unknown }, { issuerKeys: [await thumbprint(w.passkey.key)] });
  assert.equal(answer.allowed, false);
  assert.deepEqual(answer.problems.map((p) => p.code), ['bad-field']);
  // Names that only look like it are labels.
  for (const name of ['Provared.invoice', 'my provared.invoice']) {
    await writeStub({ slip: w.slipFingerprint, after: null, action: ORDER, details: [{ name, sha256: FP }] }, w.agent.privateKeys);
  }
});

test('a book that holds a stub with a reserved name not on the list has a problem', async () => {
  const w = await makeWorld();
  const { signWithKeySet } = await import('../src/stub.js');
  const { entryLine } = await import('../src/index.js');
  const stub = (name) => ({ type: 'provared.stub.v0', id: 'AgICAgICAgICAgICAgICAg', slip: w.slipFingerprint, seq: 0, action: ORDER, when: '2026-10-05T09:00:00Z', details: [{ name, sha256: FP }] });
  const trust = { issuerKeys: [await thumbprint(w.passkey.key)] };
  // Signed properly by the agent's keys: only the name differs.
  const fine = (await signWithKeySet('stub', stub('provared.event-id'), w.agent.privateKeys)).record;
  const unknown = (await signWithKeySet('stub', stub('provared.invoice'), w.agent.privateKeys)).record;
  assert.equal((await checkBook(w.book() + entryLine({ stub: fine }) + '\n', trust)).summary.problemFound, false);
  const r = await checkBook(w.book() + entryLine({ stub: unknown }) + '\n', trust);
  assert.equal(r.summary.problemFound, true);
  assert.match(JSON.stringify(r.entries.at(-1)), /reserved, and this one is not on the list of document names/);
});

test('detailsAfter: the identifier the action gave is signed into the stub after the action, which keeps its starting time', async () => {
  const w = await makeWorld();
  let clock = START;
  const recorder = await opened(w, { now: () => clock });
  const event = await identifierFingerprint('evt-42');
  let handed;
  const asked = [];
  const r = await recorder.act(
    { ...order(10), details: [{ name: 'order.pdf', sha256: FP }] },
    async () => {
      clock += 90 * 1000; // the action takes a minute and a half
      return { id: 'evt-42' };
    },
    {
      detailsAfter: (result) => {
        handed = result;
        return [{ name: 'provared.event-id', sha256: event }];
      },
      countersign: (stub) => {
        asked.push(content(stub).details.length);
        return countersign(stub, w.service.privateKeys, clock);
      },
    },
  );
  assert.equal(r.done, true);
  assert.deepEqual(handed, { id: 'evt-42' });
  assert.deepEqual(r.detailsAfter, { added: 1, problem: null });
  const c = content(r.stub.record);
  assert.deepEqual(c.details, [
    { name: 'order.pdf', sha256: FP },
    { name: 'provared.event-id', sha256: event },
  ]);
  assert.equal(c.when, '2026-10-05T09:00:00Z');
  // The other side countersigned the stub with the identifier in it.
  assert.deepEqual(asked, [2]);
  assert.equal(r.stub.countersignature.accepted, true);
  const checked = await recorder.check();
  assert.equal(checked.summary.intact, true);
  assert.equal(checked.entries.at(-1).countersignature.state, 'valid');
  // Without detailsAfter the answer has the shape it always had.
  const plain = await recorder.act(order(1), async () => 'x');
  assert.equal(Object.hasOwn(plain, 'detailsAfter'), false);
});

test('detailsAfter: when it fails, takes too long, or gives what cannot go in, the stub is written without further documents', async () => {
  const w = await makeWorld();
  // Long enough that a busy computer never runs it out except where nothing answers.
  const recorder = await opened(w, { countersignWithin: 300 });
  const cases = [
    [() => { throw new Error('no identifier'); }, 'details-not-added'],
    [() => new Promise(() => {}), 'details-not-added'],
    [() => Array(5).fill({ name: 'a', sha256: FP }), 'bad-field'],
    [() => [{ name: 'provared.invoice', sha256: FP }], 'bad-field'],
    [() => [{ name: 'a', sha256: 'short' }], 'bad-field'],
    [() => ({ name: 'a', sha256: FP }), 'bad-field'],
    [() => [() => 'not data'], 'bad-field'],
  ];
  let value = 0;
  for (const [later, code] of cases) {
    const r = await recorder.act(order(1), async () => ++value, { detailsAfter: later });
    assert.equal(r.done, true);
    assert.equal(r.result, value);
    assert.equal(r.detailsAfter.added, 0);
    assert.equal(r.detailsAfter.problem.code, code);
    assert.equal(Object.hasOwn(content(r.stub.record), 'details'), false);
  }
  assert.equal((await recorder.check()).summary.counts.stubs, cases.length);
  assert.equal((await recorder.check()).summary.intact, true);
});

test('only the three identifiers may be named more than once; any other reserved name twice is refused, in a stub, an approval, the check before acting and detailsAfter', async () => {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  for (const name of ['provared.trace-id', 'provared.request-id', 'provared.event-id']) {
    await writeStub({ slip: w.slipFingerprint, after: null, action: ORDER, details: [{ name, sha256: FP }, { name, sha256: FP }] }, w.agent.privateKeys);
  }
  for (const name of ['provared.arguments', 'provared.http-request', 'provared.http-response', 'provared.error']) {
    const twice = [{ name, sha256: FP }, { name, sha256: FP }];
    await assert.rejects(writeStub({ slip: w.slipFingerprint, after: null, action: ORDER, details: twice }, w.agent.privateKeys), (e) => e.code === 'bad-field' && /named twice/.test(e.message));
    await assert.rejects(prepareApproval({ slip: w.slipFingerprint, action: ORDER, details: twice }), (e) => e.code === 'bad-field');
    const answer = await checkBefore(w.book(), { slip: w.slipFingerprint, ...order(1), details: twice }, { issuerKeys });
    assert.deepEqual(answer.problems.map((p) => p.code), ['bad-field']);
  }
  const recorder = await opened(w);
  const r = await recorder.act({ ...order(1), details: [{ name: 'provared.arguments', sha256: FP }] }, async () => 'done', { detailsAfter: () => [{ name: 'provared.arguments', sha256: FP }] });
  assert.equal(r.detailsAfter.problem.code, 'bad-field');
  assert.deepEqual(content(r.stub.record).details, [{ name: 'provared.arguments', sha256: FP }]);
});

test('detailsAfter: where the second signing fails, the stub made before the action is written, and the answer says so in true words', async () => {
  const w = await makeWorld();
  const { signerFromKey } = await import('../src/index.js');
  let asked = 0;
  let failing = false;
  const signers = w.agent.privateKeys.map((key, i) => {
    const inner = signerFromKey(['Ed25519', 'ML-DSA-87'][i], key, w.agent.keys[i]);
    return {
      key: inner.key,
      sign: async (data) => {
        asked++;
        if (failing && asked > 2) throw new Error('the key service is down');
        return inner.sign(data);
      },
    };
  });
  const recorder = await opened(w, { privateKeys: signers });
  failing = true;
  const r = await recorder.act(order(1), async () => 'done', { detailsAfter: () => [{ name: 'provared.event-id', sha256: FP }] });
  assert.equal(r.done, true);
  assert.deepEqual(r.detailsAfter, {
    added: 0,
    problem: { code: 'details-not-added', message: 'The stub with the further documents could not be made or signed, so the stub made before the action was written, without them.' },
  });
  assert.equal(Object.hasOwn(content(r.stub.record), 'details'), false);
  assert.equal((await recorder.check()).summary.intact, true);
});

test('detailsAfter: null is the same as not given', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const r = await recorder.act(order(1), async () => 'done', { detailsAfter: null });
  assert.equal(r.done, true);
  assert.equal(Object.hasOwn(r, 'detailsAfter'), false);
});

test('detailsAfter: what it gave is copied when it is read, so a change made to it while the stub is signed changes nothing', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const given = [{ name: 'provared.event-id', sha256: FP }];
  const r = await recorder.act(order(1), async () => 'done', {
    detailsAfter: () => {
      // Changed again and again while the writer reads, checks and signs it.
      const timer = setInterval(() => {
        given[0].sha256 = given[0].sha256 === FP ? 'E'.repeat(43) : FP;
        given.push({ name: 'provared.error', sha256: FP });
      }, 0);
      setTimeout(() => clearInterval(timer), 200);
      return given;
    },
  });
  assert.equal(r.detailsAfter.added, 1);
  assert.deepEqual(content(r.stub.record).details, [{ name: 'provared.event-id', sha256: FP }]);
});

test('detailsAfter: a call to the writer from inside it is refused at once, and the documents it then gives are added', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  let inner;
  const r = await recorder.act(order(1), async () => 'done', {
    detailsAfter: async () => {
      inner = await recorder.act(order(1), async () => 'again').then(
        () => 'ran',
        (e) => e.message,
      );
      return [{ name: 'provared.event-id', sha256: FP }];
    },
  });
  assert.match(inner, /inside an action/);
  assert.equal(r.detailsAfter.added, 1);
});

test('detailsAfter: refused before the action is taken, with an approval, with too many documents named, or if it is not a function', async () => {
  const w = await makeWorld({ fields: { requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }] } });
  const recorder = await opened(w);
  const approval = await w.approve({ slip: w.slipFingerprint, ...order(60), when: START - 60000 });
  let taken = 0;
  const perform = async () => ++taken;
  const tries = [
    [order(60), { approval: { record: approval.record }, detailsAfter: () => [] }],
    [{ ...order(1), details: Array(29).fill({ name: 'a', sha256: FP }) }, { detailsAfter: () => [] }],
    [order(1), { detailsAfter: 'provared.event-id' }],
  ];
  for (const [request, more] of tries) {
    const r = await recorder.act(request, perform, more);
    assert.equal(r.done, false);
    assert.deepEqual(r.answer.problems.map((p) => p.code), ['bad-field']);
  }
  assert.equal(taken, 0);
  // Twenty-eight named beforehand leave room for four more.
  const r = await recorder.act({ ...order(1), details: Array(28).fill({ name: 'a', sha256: FP }) }, perform, { detailsAfter: () => Array(4).fill({ name: 'provared.event-id', sha256: FP }) });
  assert.equal(r.detailsAfter.added, 4);
  assert.equal(content(r.stub.record).details.length, 32);
});

test('the largest stub detailsAfter can make still fits a line, with its countersignature, so the room kept for it is always there', () => {
  const big = { name: '\u0001'.repeat(200), sha256: FP };
  const c = { action: 'a'.repeat(64), when: '2026-10-05T09:00:00Z', amount: { unit: 'U'.repeat(16), value: Number.MAX_SAFE_INTEGER }, with: 'w'.repeat(64), details: Array(32).fill(big) };
  assert.ok(lineBound(c, undefined) <= MAX_LINE_BYTES);
});

test('recordTools still names the arguments "arguments" by default, and a tool may name them "provared.arguments"', async () => {
  const w = await makeWorld();
  const recorder = await opened(w);
  const { argumentsFingerprint } = await import('../src/index.js');
  const tools = recordTools(recorder, {
    old: { action: ORDER, run: () => 1, with: 'supplier', amount: { unit: 'GBP', value: 1 } },
    reserved: { action: ORDER, run: () => 2, with: 'supplier', amount: { unit: 'GBP', value: 1 }, details: async (args) => [{ name: 'provared.arguments', sha256: await argumentsFingerprint(args) }] },
  });
  await tools.old({ item: 'paper' });
  const lines = recorder.book().trim().split('\n');
  assert.deepEqual(content(JSON.parse(lines.at(-1)).stub).details, [{ name: 'arguments', sha256: await argumentsFingerprint({ item: 'paper' }) }]);
  await tools.reserved({ item: 'paper' });
  assert.deepEqual(content(JSON.parse(recorder.book().trim().split('\n').at(-1)).stub).details, [{ name: 'provared.arguments', sha256: await argumentsFingerprint({ item: 'paper' }) }]);
});
