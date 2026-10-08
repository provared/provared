// Shared test cases for the stub writer (openRecorder) and the connector
// for an agent's tools (recordTools): scenarios, each a world of records
// made beforehand and a list of steps, with the transcript this library
// gives (scenarios.mjs). Any other implementation must give the same
// transcript for each. Each scenario follows one or more of the tests in
// test/, as its name says.
//
// The seal's third signing method is treated as not built in wherever a
// seal is used ("withoutMethods"), so that an implementation without
// SLH-DSA can be held to every answer.

import { argumentsFingerprint, countersign, fromBase64url, toBase64url, writeAcknowledgement, writeBook, writeStub, writeVouching, writeWithdrawal } from '../../src/index.js';
import { thumbprint } from '../../src/keys.js';
import { playScenario, seededKeySet } from './scenarios.mjs';
import { makeStampService } from './stamp.mjs';
import { finish } from './vector-tools.mjs';
import { START, makeWorld } from './world.mjs';

const HOUR = 3600 * 1000;
const MINUTE = 60 * 1000;
const DAY = 24 * HOUR;
const ORDER = 'supplies.order';
const LOOK = 'provared.data.read';
const SLH = 'SLH-DSA-SHA2-256s';
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const SIGN = { sign: 'service', at: 1000 };

/** How each kind of case is answered. */
export const ANSWER = {
  recorderScenario: async (c) => ({ ok: await playScenario(c) }),
};

// --- the steps ---

const act = (w, request, more, perform = { gives: 'done' }) => (more === undefined ? { op: 'act', w, request, perform } : { op: 'act', w, request, perform, more });
const record = (w, request, more) => (more === undefined ? { op: 'record', w, request } : { op: 'record', w, request, more });
const before = (w, request, more) => (more === undefined ? { op: 'before', w, request } : { op: 'before', w, request, more });
const add = (w, entry, label) => (label === undefined ? { op: 'add', w, entry } : { op: 'add', w, entry, label });
const check = (w) => ({ op: 'check', w });
const held = (w) => ({ op: 'held', w });
const book = (w) => ({ op: 'book', w });
const clock = (change) => ({ op: 'clock', ...change });

// --- building a scenario ---

class Scenario {
  constructor(name, w) {
    this.name = name;
    this.w = w;
    this.start = START + HOUR;
    this.keys = {};
    this.records = {};
    this.steps = [];
    this.count = 0;
  }

  /** Keep a key set's seeds in the scenario, under a name. */
  key(name, set) {
    this.keys[name] = set.seeds;
    return set;
  }

  /** A record of the world, and the expression that names it. A record without a name of its own is kept once. */
  ref(name, value) {
    if (name === null) {
      const text = JSON.stringify(value);
      this.seen ??= new Map();
      if (this.seen.has(text)) return { $ref: this.seen.get(text) };
      name = `r${++this.count}`;
      this.seen.set(text, name);
    }
    this.records[name] = value;
    return { $ref: name };
  }

  /** The book as the world holds it now. */
  book() {
    return this.ref(null, this.w.book());
  }

  step(...steps) {
    this.steps.push(...steps);
    return this;
  }

  open(as, o = {}) {
    const step = { op: 'open', as, book: Object.hasOwn(o, 'book') ? o.book : this.book(), slip: o.slip ?? this.slip, keys: o.keys ?? 'agent', issuerKeys: o.issuerKeys ?? this.issuer };
    for (const name of ['pass', 'options', 'countersignWithin']) if (Object.hasOwn(o, name)) step[name] = o[name];
    return this.step(step);
  }

  /** The person cancels: the cancellation, kept out of the world's book, with its entry as a record. */
  async cancel(when, more = {}) {
    const c = await this.w.cancel({ when, ...more });
    this.w.entries.pop();
    return { ...c, ref: this.ref(null, c.entry), recordRef: this.ref(null, c.record) };
  }

  /** An acknowledgement signed beforehand, as a record. */
  async acknowledgement(c, when, signer = this.w.agent.privateKeys, pass) {
    return this.ref(null, (await writeAcknowledgement({ slip: this.w.slipFingerprint, cancellation: c.fingerprint, pass, when }, signer)).record);
  }

  done() {
    return { name: this.name, world: { start: this.start, keys: this.keys, records: this.records }, steps: this.steps };
  }
}

async function setUp(name, o = {}) {
  const agent = seededKeySet();
  const service = seededKeySet();
  const w = await makeWorld({ fields: o.fields, agent, service });
  const s = new Scenario(name, w);
  s.key('agent', agent);
  s.key('service', service);
  s.stranger = s.key('stranger', seededKeySet());
  s.slip = s.ref('slip', w.slipFingerprint);
  s.issuer = s.ref('issuerKeys', [await thumbprint(w.passkey.key)]);
  return s;
}

// A second world, whose slip goes into the same book: the writer trusts both passkeys.
async function second(s) {
  const other = await makeWorld();
  const issuerKeys = s.ref('bothIssuers', [await thumbprint(s.w.passkey.key), await thumbprint(other.passkey.key)]);
  const cancel = async (when, more = {}) => {
    const c = await other.cancel({ when, ...more });
    other.entries.pop();
    return { ...c, ref: s.ref(null, c.entry), recordRef: s.ref(null, c.record) };
  };
  return { other, issuerKeys, cancel };
}

async function stampService(s, name = 'trust') {
  const service = await makeStampService();
  const trust = s.ref(name, [service.fingerprint]);
  const stamp = async (c, at) => toBase64url(await service.stamp(fromBase64url(c.fingerprint), at));
  return { service, trust, stamp };
}

// --- the stub writer: actions ---

async function actions() {
  // recorder.test.mjs
  const s = await setUp('allowed actions, countersigned and one-sided, one outside the slip, one that fails, and one recorded');
  s.open('a');
  s.step(
    act('a', order(150), { countersign: SIGN }, { gives: 'first' }),
    clock({ add: HOUR }),
    act('a', order(50), undefined, { gives: { taken: 2 } }),
    act('a', order(51)),
    act('a', order(5), undefined, { throws: 'the supplier did not answer' }),
    before('a', order(0)),
    record('a', order(500)),
    record('a', order(1), { when: START }),
    check('a'),
    book('a'),
    held('a'),
    { op: 'open', as: 'b', book: { $book: 'a' }, slip: s.slip, keys: 'agent', issuerKeys: s.issuer },
    record('b', { action: ORDER }),
    { op: 'checkBook', text: { $book: 'b' }, options: { issuerKeys: s.issuer } },
  );
  return s.done();
}

async function chainCarriedOn() {
  // recorder.test.mjs: opened on a book that already holds stubs
  const s = await setUp('opened on a book that holds stubs, the writer carries the chain on');
  await s.w.add({ value: 20, when: START });
  await s.w.add({ value: 20, when: START + 30 * MINUTE });
  s.open('a');
  s.step(act('a', order(20)), act('a', order(200)), record('a', order(1)), check('a'));
  return s.done();
}

async function openings() {
  // recorder.test.mjs and the checks at opening
  const s = await setUp('opening: a damaged book, a passkey not trusted, and settings that are refused');
  await s.w.add({ value: 10, when: START });
  const sound = s.w.book();
  const c = await s.cancel(s.start + 10 * MINUTE);
  const many = [];
  for (let i = 0; i < 17; i++) many.push((await s.cancel(s.start + (20 + i) * MINUTE)).ref);
  s.open('damaged', { book: s.ref('damaged', sound.replace(/\n$/, 'x\n')) });
  s.open('stranger', { issuerKeys: s.ref('strangers', ['A'.repeat(43)]) });
  s.open('none trusted', { issuerKeys: [] });
  s.open('trust not a list', { issuerKeys: 'A'.repeat(43) });
  s.open('empty book', { book: '' });
  s.open('no book', { book: null });
  s.open('no line feed', { book: s.ref('noFeed', sound.replace(/\n$/, '')) });
  for (const within of [0, 0.5, 2 ** 31, { $: 'NaN' }, { $: 'Infinity' }, '30', true, null]) s.open('wait', { countersignWithin: within });
  s.open('many cancellations', { options: { cancellations: many } });
  s.open('cancellations not a list', { options: { cancellations: 'none' } });
  s.open('too much beside a copy', { options: { cancellations: [{ cancellation: c.recordRef, m: { $fill: { $repeat: 'a', n: 20 }, n: 20000 } }] } });
  s.open('a copy that is not an object', { options: { cancellations: [5] } });
  s.open('a copy with a member not known', { options: { cancellations: [{ cancellation: c.recordRef, note: 'kept' }] } });
  s.open('options not an object', { options: 'trust me' });
  s.open('stamp services not a list', { options: { stampServices: 'x' } });
  s.open('blocks that are not blocks', { options: { blocks: ['x'] } });
  s.open('a', { book: s.ref('sound', sound), countersignWithin: 1, options: { issuerKeys: s.ref('strangers2', ['A'.repeat(43)]), withoutMethods: [SLH] } });
  s.step(act('a', order(10)), check('a'));
  s.open('last wait', { countersignWithin: 2 ** 31 - 1 });
  return s.done();
}

async function helper() {
  // recorder.test.mjs and acknowledgement.test.mjs: a helper agent
  const s = await setUp('a helper agent\'s writer acts under its pass, in its own chain, and acknowledges under it', { fields: { passes: 1 } });
  await s.w.add({ value: 10, when: START });
  const helperKeys = s.key('helper', seededKeySet());
  const pass = await s.w.pass({ limits: [{ action: ORDER, max: 30, unit: 'GBP' }], helper: helperKeys, when: START });
  const passRef = s.ref('pass', pass.fingerprint);
  s.open('h', { keys: 'helper', pass: passRef });
  const c = await s.cancel(s.start + 2 * HOUR);
  s.step(
    act('h', order(20)),
    act('h', order(11)),
    record('h', order(3)),
    clock({ add: 2 * HOUR }),
    add('h', c.ref),
    act('h', order(1)),
    check('h'),
  );
  s.open('wrong pass', { keys: 'helper', pass: s.slip });
  s.step(act('wrong pass', order(1)));
  s.open('no pass', { keys: 'helper', pass: '' });
  s.step(act('no pass', order(1)));
  return s.done();
}

async function approvals() {
  // recorder.test.mjs, review9.test.mjs (finding 3)
  const s = await setUp('approval: asked for, given, given for something else, used twice, dated ahead of the clock, and not a record', {
    fields: { requires: [{ above: 50, action: ORDER, need: 'approval', unit: 'GBP' }] },
  });
  const t = s.start;
  const approve = async (request, when) => s.ref(null, await s.w.approve({ slip: s.w.slipFingerprint, ...request, when }));
  const right = await approve(order(60), t - MINUTE);
  const other = await approve(order(70), t - MINUTE);
  const ahead = await approve(order(55), t + 598 * 1000);
  const near = await approve(order(55), t + 300 * 1000);
  s.open('a');
  s.step(
    act('a', order(60)),
    before('a', order(60), { approval: right }),
    before('a', order(60), { approval: other }),
    act('a', order(60), { approval: other }),
    act('a', order(60), { approval: right }),
    act('a', order(60), { approval: right }),
    act('a', order(55), { approval: ahead, when: t + 299 * 1000, countersign: SIGN }),
    record('a', order(55), { approval: ahead, when: t + 300 * 1000 }),
    act('a', order(55), { approval: near, when: t + 299 * 1000 }),
    act('a', order(51), { approval: { record: 'garbage' }, when: t + 299 * 1000 }),
    act('a', order(51), { approval: 'not a record', when: t + 299 * 1000 }),
    act('a', order(51), { approval: { record: null }, when: t + 299 * 1000 }),
    act('a', order(51), { approval: null, when: t + 299 * 1000 }),
    act('a', order(40), { approval: right, when: t + 299 * 1000 }),
    record('a', order(51), { approval: { record: { payload: 5, signatures: [] } }, when: t + 299 * 1000 }),
    record('a', order(51), { approval: 'not a record', when: t + 299 * 1000 }),
    record('a', order(51), { approval: other, when: t + 299 * 1000 }),
    check('a'),
  );
  return s.done();
}

async function terms() {
  const s = await setUp('a stub that relies on the service\'s terms, and terms that are not in the book');
  const published = await s.w.publishTerms();
  const termsRef = s.ref('terms', published.fingerprint);
  s.open('a');
  s.step(
    act('a', order(10), { terms: termsRef }),
    record('a', order(10), { terms: termsRef }),
    act('a', order(10), { terms: s.slip }),
    act('a', order(10), { terms: null }),
    record('a', order(10), { terms: null }),
    record('a', order(10), { terms: 5 }),
    act('a', { action: ORDER }, { terms: termsRef }),
    check('a'),
  );
  return s.done();
}

// --- the other side's countersignature ---

async function countersignatures() {
  // carried.test.mjs, review6 and review7: what the other side hands back
  const s = await setUp('the other side countersigns: in time, not at all, wrongly, too late, or by calling the writer');
  const otherStub = await writeStub({ slip: s.w.slipFingerprint, after: null, action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'supplier', when: START }, s.w.agent.privateKeys);
  const wrongStub = s.ref('wrongStub', await countersign(otherStub.record, s.w.service.privateKeys, s.start));
  const one = (value, more) => act('a', order(value), more);
  s.open('a', { countersignWithin: 400 });
  s.step(
    one(1, { countersign: { gives: null } }),
    one(1, { countersign: { gives: { payload: 'AAAA', signatures: [] } } }),
    one(1, { countersign: { gives: 'not a record' } }),
    one(1, { countersign: { gives: 0 } }),
    one(1, { countersign: { gives: {} } }),
    one(1, { countersign: { sign: 'stranger' } }),
    one(1, { countersign: { gives: wrongStub } }),
    one(1, { countersign: { sign: 'service', at: 400 * 1000 } }),
    one(1, { countersign: { sign: 'service', at: 299 * 1000 } }),
    one(1, { countersign: { throws: 'the supplier is away' } }),
    one(1, { countersign: { never: true } }),
    one(1, { countersign: { late: 1200, sign: 'service' } }),
    one(1, { countersign: { notFunction: true } }),
    one(1, { countersign: { inside: ['check', 'book', 'held', 'before', 'act', 'record', 'add'], sign: 'service' } }),
    act('a', { action: ORDER, amount: { unit: 'GBP', value: 1 } }, { countersign: SIGN }),
    act('a', { action: ORDER, amount: { unit: 'GBP', value: 1 }, with: 'nobody' }, { countersign: SIGN }),
    record('a', order(1), { countersign: SIGN }),
    record('a', order(1), { countersign: SIGN, when: START }),
    check('a'),
  );
  return s.done();
}

async function countersignatureAsked() {
  // review5, review12 (finding 5)
  const s = await setUp('the slip asks for a countersignature: no way to ask, a way, and one given', { fields: { requires: [{ need: 'countersignature', action: ORDER }] } });
  s.open('a');
  s.step(
    act('a', order(10)),
    act('a', order(10), { countersign: SIGN }),
    act('a', order(10), { countersign: { gives: null } }),
    act('a', { action: ORDER, amount: { unit: 'GBP', value: 1 } }, { countersign: SIGN }),
    before('a', order(10)),
    check('a'),
  );
  const both = await setUp('the slip asks for both an approval and a countersignature', { fields: { requires: [{ need: 'approval', action: ORDER }, { need: 'countersignature', action: ORDER }] } });
  both.open('b');
  both.step(act('b', order(10)), before('b', order(10)));
  return [s.done(), both.done()];
}

// --- the clock and the dates handed in ---

async function clocks() {
  // review11 (finding 1), review13 (finding 7), and the dates "act" takes
  const s = await setUp('the clock: one that fails at each reading, one that gives no time, and dates handed in');
  const t = s.start;
  s.open('a');
  s.step(act('a', order(1)));
  for (const gives of [{ $: 'NaN' }, { $: 'Infinity' }, { $: 'undefined' }, '12', null, true]) {
    s.step(clock({ gives }), act('a', order(1), { when: START + 100 * HOUR }), record('a', order(1), { when: START + 120 * HOUR }), before('a', order(1)), add('a', { neither: 'this' }), clock({ real: true }));
  }
  for (let at = 1; at <= 5; at++) s.step(clock({ failAt: at }), act('a', order(1), { countersign: SIGN }), clock({ failAt: 0 }));
  for (let at = 1; at <= 4; at++) s.step(clock({ failAt: at }), record('a', order(1), { countersign: SIGN }), clock({ failAt: 0 }));
  s.step(clock({ failAt: 1 }), before('a', order(1)), clock({ failAt: 0 }));
  s.step(
    check('a'),
    clock({ add: HOUR }),
    act('a', order(1), { when: t + HOUR - 301 * 1000 }),
    act('a', order(1), { when: t + HOUR + 301 * 1000 }),
    act('a', order(1), { when: t + HOUR + 299 * 1000 }),
    act('a', order(1), { when: new Date(t + HOUR + 300 * 1000).toISOString() }),
    clock({ add: 10 * MINUTE }),
    act('a', order(1), { when: '2026-10-05T11:10:00.500Z' }),
    act('a', order(1), { when: '2026-10-05T12:10:00+01:00' }),
    act('a', order(1), { when: '2026-10-05T11:10:00.999999Z' }),
    act('a', order(1), { when: '2026-10-05' }),
    act('a', order(1), { when: '2026-13-05T11:10:00Z' }),
    act('a', order(1), { when: '2026-02-30T11:10:00Z' }),
    act('a', order(1), { when: '+002026-10-05T11:11:00Z' }),
    act('a', order(1), { when: null }),
    act('a', order(1), { when: 'not a time' }),
    act('a', order(1), { when: true }),
    act('a', order(1), { when: { $: 'Infinity' } }),
    act('a', order(1), { when: t + HOUR + 11 * MINUTE + 0.75 }),
    record('a', order(1), { when: 'not a time' }),
    record('a', order(1), { when: t }),
    record('a', order(1), { when: t + HOUR + 10 * MINUTE + 301 * 1000 }),
    record('a', order(1), { when: t + HOUR + 10 * MINUTE + 300 * 1000 }),
    record('a', order(1), { when: 9e15 }),
    check('a'),
  );
  return s.done();
}

async function requests() {
  // what "act", "record" and "before" are handed
  const s = await setUp('requests: not an object, not plain data, members missing or wrong, and an empty list of documents');
  const doc = { name: 'Order form', sha256: 'A'.repeat(43) };
  s.open('a');
  for (const request of [null, 'supplies.order', 5, [], [order(1)], {}, { action: 'Not A Name' }, { action: ORDER, amount: null }, { action: ORDER, amount: { unit: 'GBP', value: -1 } }, { action: ORDER, with: 'Bad Name' }, { ...order(1), details: [] }, { ...order(1), details: [doc] }, { ...order(1), details: 'none' }, { ...order(1), note: 'not part of a stub' }, { action: 'provared.data.read' }]) {
    s.step(before('a', request), act('a', request), record('a', request));
  }
  s.step(act('a', order(1), 'not an object'), act('a', order(1), null), record('a', order(1), [1, 2]), check('a'));
  return s.done();
}

async function inside() {
  // the stub writer refuses a call from inside an action it is taking
  const s = await setUp('a call to the writer from inside an action, or from the other side while it countersigns');
  s.open('a');
  s.step(
    act('a', order(10), { countersign: { inside: ['check', 'book', 'add'], sign: 'service' } }, { inside: ['book', 'held', 'check', 'before', 'act', 'record', 'add'], gives: 'done' }),
    act('a', order(10), undefined, { notFunction: 'not a function' }),
    act('a', order(10), undefined, { notFunction: null }),
    act('a', order(10)),
    check('a'),
  );
  return s.done();
}

// --- cancellations ---

async function cancelled() {
  // acknowledgement.test.mjs: the stub writer acknowledges the person's cancellation
  const s = await setUp('the person cancels: the cancellation is added, acknowledged, and stops the writer, here and when opened again');
  const t = s.start;
  s.open('a');
  const c = await s.cancel(t);
  s.step(act('a', order(10)), add('a', c.ref, 'ack'), book('a'), check('a'), add('a', c.ref), act('a', order(1)), before('a', order(1)), record('a', order(1)));
  s.step({ op: 'open', as: 'b', book: { $book: 'a' }, slip: s.slip, keys: 'agent', issuerKeys: s.issuer }, add('b', c.ref), act('b', order(1)), held('b'));
  // A cancellation of another slip, or one signed with another passkey.
  const { other, issuerKeys, cancel } = await second(s);
  const two = s.ref('twoSlips', s.w.book().split('\n')[0] + '\n' + other.book());
  s.open('two', { book: two, issuerKeys });
  const theirs = await cancel(t);
  const forged = await s.cancel(t, { passkey: other.passkey });
  s.step(add('two', theirs.ref), act('two', order(1)), add('two', forged.ref), act('two', order(1)), check('two'));
  return s.done();
}

async function keptAhead() {
  // review10 (finding 2), acknowledgement.test.mjs
  const s = await setUp('a cancellation dated ahead of the clock is kept, handed back, and written once its date has come');
  const t = s.start;
  const c = await s.cancel(t + 10 * MINUTE, { stampTime: t + 10 * MINUTE + 5000 });
  const trust = s.ref('trust', [s.w.stampService.fingerprint]);
  s.open('a', { options: { stampServices: trust } });
  s.step(
    act('a', order(10)),
    add('a', c.ref, 'kept'),
    act('a', order(10)),
    held('a'),
    { op: 'checkBook', text: { $book: 'a' }, options: { issuerKeys: s.issuer, stampServices: trust, cancellations: { $held: 'a' } } },
  );
  s.open('forgetful', { book: { $book: 'a' }, options: { stampServices: trust } });
  s.open('told', { book: { $book: 'a' }, options: { stampServices: trust, cancellations: { $held: 'a' } } });
  s.step(before('forgetful', order(10)), before('told', order(10)), held('told'), clock({ add: 20 * MINUTE }), act('a', order(10)), check('a'), held('a'));
  s.open('again', { book: { $book: 'a' } });
  s.step(act('again', order(10)), act('told', order(10)), check('told'));
  return s.done();
}

async function shapes() {
  // review10 (finding 1)
  const s = await setUp('whatever stands beside the person\'s cancellation, it is added by itself and stops the writer');
  const c = await s.cancel(s.start);
  const r = c.recordRef;
  const shapes = [
    { cancellation: r, stamps: null },
    { cancellation: r, stamps: [null] },
    { cancellation: r, stamps: [1.5] },
    { cancellation: r, stamps: [true] },
    { cancellation: r, stamps: [-1] },
    { cancellation: r, stamps: ['\ud800'] },
    { cancellation: r, stamps: [[[[[[[[['x']]]]]]]]] },
    { cancellation: r, stamps: [{ $repeat: 'A', n: 140000 }] },
    { cancellation: r, stamps: ['AAAA'] },
    { cancellation: r, received: true },
    { cancellation: r, note: 'from the person' },
    { cancellation: r, stamps: [], acknowledgements: [] },
    { cancellation: r, acknowledgements: 'none' },
    { cancellation: r, acknowledgements: [{ payload: 'e30', signatures: [] }] },
  ];
  shapes.forEach((shape, i) => {
    s.open(`a${i}`);
    s.step(act(`a${i}`, order(10)), add(`a${i}`, shape), act(`a${i}`, order(10)), held(`a${i}`));
  });
  s.step(check('a0'), check('a11'));
  return s.done();
}

async function notCancellations() {
  // review10 (finding 1): what is not a cancellation record at all
  const s = await setUp('what is not a cancellation record at all is refused, and stops nothing');
  const t = s.start;
  const c = await s.cancel(t);
  const other = await makeWorld();
  const forged = await s.cancel(t, { passkey: other.passkey });
  const record = c.record;
  s.open('a');
  for (const entry of [
    { cancellation: { ...record, note: 'x' } },
    { cancellation: null },
    { cancellation: null, stamps: [] },
    { cancellation: forged.recordRef, stamps: ['AAAA'] },
    { cancellation: { payload: 'e30', signatures: [] } },
    JSON.stringify(c.entry),
    [c.ref],
    c.recordRef,
    null,
    5,
    true,
    {},
    { cancellation: { $shared: 6, width: 200, leaf: 'x' } },
    { cancellation: { $nest: 70, leaf: 'x' } },
  ]) {
    s.step(add('a', entry));
  }
  s.step(held('a'), act('a', order(10)), check('a'));
  return s.done();
}

async function otherSlips() {
  // review10 (finding 1), review9 (finding 4), review11
  const s = await setUp('cancellations of another slip: added by themselves, kept nowhere, and never crowding out the writer\'s own');
  const t = s.start;
  const { other, issuerKeys, cancel } = await second(s);
  const twoSlips = s.ref('twoSlips', writeBook([{ slip: s.w.slip }, { slip: other.slip }]));
  s.open('a', { book: twoSlips, issuerKeys });
  const theirs = await cancel(t);
  s.step(add('a', { cancellation: theirs.recordRef, stamps: [1.5] }), act('a', order(10)), check('a'));
  s.open('b', { book: twoSlips, issuerKeys });
  s.step(act('b', order(10)));
  for (let i = 0; i < 17; i++) s.step(add('b', (await cancel(t + DAY + i * 1000)).ref));
  const own = await s.cancel(t + 10 * MINUTE);
  s.step(act('b', order(10)), add('b', own.ref), add('b', own.ref), act('b', order(10)), held('b'));
  const past = [];
  for (let i = 0; i < 16; i++) past.push((await cancel(START + i * 1000)).ref);
  s.open('full', { book: twoSlips, issuerKeys, options: { cancellations: past } });
  s.step(add('full', own.ref), act('full', order(10)), held('full'), clock({ add: DAY }), act('full', order(1)), check('full'));
  // Sixteen given at opening, written into the book at the first call; then the writer's own, dated ahead.
  s.open('sixteen', { book: s.ref('slipsAgain', writeBook([{ slip: s.w.slip }, { slip: other.slip }])), issuerKeys, options: { cancellations: past } });
  const far = await s.cancel(t + 3 * DAY);
  s.step(act('sixteen', order(1)), check('sixteen'), add('sixteen', far.ref), act('sixteen', order(1)), before('sixteen', order(1)), held('sixteen'));
  return s.done();
}

async function alreadyInBook() {
  // review10 (finding 2), review15 (finding 6)
  const s = await setUp('a cancellation the book already holds is not kept beside it; the error says when it was written in that call');
  const t = s.start;
  const c = await s.cancel(t);
  const { trust, stamp } = await stampService(s);
  s.open('a');
  s.step(add('a', c.ref), add('a', c.ref), held('a'), check('a'));
  const later = await s.cancel(t + 400 * 1000);
  s.open('b', { options: { stampServices: trust } });
  s.step(
    add('b', { cancellation: later.recordRef }),
    clock({ add: 500 * 1000 }),
    add('b', { cancellation: later.recordRef, stamps: [await stamp(later, later.when + 5000)] }),
    add('b', { cancellation: later.recordRef }),
    held('b'),
    check('b'),
  );
  return s.done();
}

async function farAndNear() {
  // review11 (finding 4)
  const s = await setUp('every cancellation of its slip that the writer is handed is kept, and written when its date comes');
  const t = s.start;
  const far = await s.cancel(t + DAY);
  const near = await s.cancel(t + 10 * MINUTE);
  s.open('a');
  s.step(add('a', far.ref), add('a', near.ref), held('a'), clock({ add: 20 * MINUTE }), act('a', order(1)), held('a'), clock({ add: DAY }), act('a', order(1)), held('a'), check('a'));
  return s.done();
}

async function stampLater() {
  // review11, review13 (finding 4), review14 (finding 2), review15 (finding 2), review16
  const s = await setUp('time-stamps handed over later are taken, merged, the counted ones first and the earliest kept');
  const t = s.start;
  const { trust, stamp } = await stampService(s);
  const { stamp: otherStamp } = await stampService(s, 'otherService');
  const c = await s.cancel(t + 10 * MINUTE);
  // Kept without a time-stamp, then handed over with one.
  s.open('a', { options: { stampServices: trust } });
  s.step(add('a', { cancellation: c.recordRef }, 'bare'), add('a', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held('a'));
  // Given at opening, then handed over with one.
  s.open('b', { options: { stampServices: trust, cancellations: [{ cancellation: c.recordRef }] } });
  s.step(add('b', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held('b'));
  // One the writer does not count, then one it counts.
  s.open('c', { options: { stampServices: trust } });
  s.step(add('c', { cancellation: c.recordRef, stamps: [await otherStamp(c, c.when + 5000)] }), add('c', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held('c'));
  // Four it does not count, then one it counts.
  const four = [];
  for (let i = 1; i <= 4; i++) four.push(await otherStamp(c, c.when + i * 1000));
  s.open('d', { options: { stampServices: trust } });
  s.step(add('d', { cancellation: c.recordRef, stamps: four }), add('d', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held('d'), check('d'));
  // Four it counts, then an earlier one.
  const later = [];
  for (let i = 1; i <= 4; i++) later.push(await stamp(c, c.when + i * MINUTE));
  s.open('e', { options: { stampServices: trust } });
  s.step(add('e', { cancellation: c.recordRef, stamps: later }), add('e', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held('e'));
  // Sound ones among faulty ones, and one twice.
  const good = await stamp(c, c.when + 5000);
  s.open('f', { options: { stampServices: trust } });
  s.step(add('f', { cancellation: c.recordRef, stamps: ['AAAA', good, good, null, 5] }), held('f'));
  // A late time-stamp, and one of another cancellation.
  const other = await s.cancel(t + 11 * MINUTE);
  s.open('g', { options: { stampServices: trust } });
  s.step(add('g', { cancellation: c.recordRef, stamps: [await stamp(c, c.when + HOUR), await stamp(other, c.when + 5000)] }), held('g'));
  s.step(clock({ add: 20 * MINUTE }));
  for (const w of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) s.step(record(w, order(1)), held(w));
  s.step(check('a'), check('e'), { op: 'checkBook', text: { $book: 'g' }, options: { issuerKeys: s.issuer, stampServices: trust } });
  return s.done();
}

async function stampRoutes() {
  // review15 (finding 2): a time-stamp the writer does not count does not keep out one it counts
  const s = await setUp('a time-stamp the writer does not count keeps out none it counts, whichever way the cancellation came to be held');
  const t = s.start;
  const { trust, stamp } = await stampService(s);
  const { stamp: otherStamp } = await stampService(s, 'otherService');
  for (const route of ['the clock fails', 'dated ahead', 'kept without a time-stamp']) {
    const w = `w ${route}`;
    s.step(clock({ set: t }));
    s.open(w, { options: { stampServices: trust } });
    s.step(act(w, order(1)));
    const c = await s.cancel(route === 'the clock fails' ? t - 2 * MINUTE : t + 10 * MINUTE);
    if (route === 'kept without a time-stamp') s.step(add(w, { cancellation: c.recordRef }));
    if (route === 'the clock fails') s.step(clock({ fail: true }));
    s.step(add(w, { cancellation: c.recordRef, stamps: [await otherStamp(c, c.when + 5000)] }), clock({ fail: false }), add(w, { cancellation: c.recordRef, stamps: [await stamp(c, c.when + 5000)] }), held(w));
    if (route !== 'the clock fails') s.step(clock({ add: 20 * MINUTE }), act(w, order(1)));
    s.step({ op: 'checkBook', text: { $book: w }, options: { issuerKeys: s.issuer, stampServices: trust } });
  }
  return s.done();
}

async function clockFails() {
  // review13 (finding 5), review14 (finding 2), review15 (findings 3 and 8), review17
  const s = await setUp('a clock that fails while the person\'s cancellation is handed over loses nothing', { fields: { passes: 1 } });
  const t = s.start;
  const { trust, stamp } = await stampService(s);
  const helperKeys = s.key('helper', seededKeySet());
  const pass = await s.w.pass({ when: START, helper: helperKeys });
  const c1 = await s.cancel(t);
  s.open('a');
  s.step(clock({ fail: true }), add('a', c1.ref), clock({ fail: false }), held('a'), act('a', order(10)), check('a'));
  const c2 = await s.cancel(t);
  s.open('b', { options: { stampServices: trust } });
  s.step(clock({ fail: true }), add('b', { cancellation: c2.recordRef, stamps: [await stamp(c2, c2.when + 5000)] }), clock({ fail: false }), held('b'), act('b', order(1)), check('b'));
  const c3 = await s.cancel(t);
  s.open('c');
  s.step(clock({ fail: true }), add('c', { cancellation: c3.recordRef, stamps: ['AAAA'] }), clock({ fail: false }), held('c'), act('c', order(1)), check('c'));
  // The acknowledgements handed over with it are kept.
  const c4 = await s.cancel(t + 10 * MINUTE);
  const helperAck = await s.acknowledgement(c4, t, helperKeys.privateKeys, pass.fingerprint);
  s.open('d');
  s.step(add('d', { cancellation: c4.recordRef, acknowledgements: [helperAck] }, 'own4'), held('d'));
  s.open('e');
  s.step(clock({ fail: true }), add('e', { $held: 'd', index: 0 }), clock({ fail: false }), held('e'), add('e', { $held: 'd', index: 0 }), check('e'));
  // Sixteen kept, and the clock fails at the seventeenth.
  s.open('f');
  for (let i = 0; i < 16; i++) s.step(add('f', (await s.cancel(t + (10 + i) * MINUTE)).ref));
  s.step(clock({ fail: true }), add('f', (await s.cancel(t + 30 * MINUTE)).ref), clock({ fail: false }), held('f'));
  // An acknowledgement of the agent's own, for a cancellation the book holds, handed over while the clock fails.
  const c5 = await s.w.cancel({ when: t - 10 * MINUTE });
  const ack5 = await s.acknowledgement(c5, t - 9 * MINUTE);
  s.open('g');
  s.w.entries.pop();
  s.step(clock({ fail: true }), add('g', { cancellation: s.ref(null, c5.record), acknowledgements: [ack5] }), clock({ fail: false }), held('g'), act('g', order(1)), book('g'), held('g'));
  // The clock fails at each reading while entries of each kind are added.
  const terms = s.ref(null, { terms: (await s.w.publishTerms()).record });
  s.w.entries.pop();
  const refusal = s.ref(null, { refusal: (await s.w.refuse({ when: t })).record });
  s.w.entries.pop();
  const now = await s.cancel(t);
  const ahead = await s.cancel(t + 10 * MINUTE);
  for (const [kind, entry] of [['terms', terms], ['refusal', refusal], ['cancellation', now.ref], ['ahead', ahead.ref], ['none', { neither: 'this nor that' }]]) {
    for (let at = 1; at <= 2; at++) {
      const w = `${kind} ${at}`;
      s.open(w);
      s.step(act(w, order(10)), clock({ failAt: at }), add(w, entry), clock({ failAt: 0 }), held(w), before(w, order(1)));
    }
  }
  return s.done();
}

async function acknowledgementDates() {
  // review12 (finding 1), review13 (findings 1 and 8)
  const s = await setUp('the acknowledgement is never dated before the writer\'s own last stub, nor before a pass its agent handed on', { fields: { passes: 1 } });
  const t = s.start;
  s.open('a');
  const c1 = await s.cancel(t + 10 * 1000);
  s.step(act('a', order(10), { when: t + 200 * 1000 }), clock({ add: 10 * 1000 }), add('a', c1.ref, 'a1'), check('a'));
  s.step({ op: 'checkBook', text: { $lines: { $book: 'a' }, from: 0, to: 2 }, options: { issuerKeys: s.issuer, cancellations: [{ cancellation: c1.recordRef, acknowledgements: [{ $ack: 'a1' }] }] } });
  // The clock steps back between the stub and the cancellation.
  s.step(clock({ set: t }));
  s.open('b');
  const c2 = await s.cancel(t - 5000);
  s.step(act('b', order(10)), clock({ add: -5000 }), add('b', c2.ref), check('b'));
  // A stub dated ahead, then the clock steps back: the acknowledgement waits, and follows later.
  s.step(clock({ set: t }));
  s.open('c');
  const c3 = await s.cancel(t - 100 * 1000);
  s.step(act('c', order(10), { when: t + 250 * 1000 }), clock({ add: -100 * 1000 }), add('c', c3.ref), held('c'), clock({ add: 10 * MINUTE }), act('c', order(1)), check('c'), held('c'));
  // A pass dated ahead, and the helper's stub under it.
  s.step(clock({ set: t }));
  const helperKeys = s.key('helper', seededKeySet());
  const p = await s.w.pass({ when: t + 200 * 1000, helper: helperKeys });
  s.w.entries.pop();
  const h = await p.add({ when: t + 200 * 1000 });
  s.w.entries.pop();
  s.open('d');
  const c4 = await s.cancel(t + 10 * 1000);
  s.step(add('d', s.ref(null, { pass: p.record })), add('d', s.ref(null, h.entry)), clock({ add: 10 * 1000 }), add('d', c4.ref, 'd4'), check('d'));
  s.step({ op: 'checkBook', text: { $lines: { $book: 'd' }, from: 0, to: 3 }, options: { issuerKeys: s.issuer, cancellations: [{ cancellation: c4.recordRef, acknowledgements: [{ $ack: 'd4' }] }] } });
  return s.done();
}

async function openedAgain() {
  // review12 (finding 6), review13 (findings 3 and 4), review15 (finding 7)
  const s = await setUp('a writer opened again from what the first hands back hands back the same acknowledgement, and writes it');
  const t = s.start;
  const { trust, stamp } = await stampService(s);
  const c = await s.cancel(t + 10 * MINUTE);
  s.open('first');
  s.step(add('first', c.ref, 'k1'), clock({ add: 2 * MINUTE }));
  s.open('again', { book: { $book: 'first' }, options: { cancellations: { $held: 'first' } } });
  s.step(add('again', c.ref), clock({ add: 20 * MINUTE }), act('again', order(1)), check('again'), held('again'));
  // Given at opening.
  s.step(clock({ set: t }));
  s.open('given', { options: { cancellations: [c.ref] } });
  s.step(add('given', c.ref), held('given'), clock({ add: 2 * MINUTE }));
  s.open('given again', { book: { $book: 'given' }, options: { cancellations: { $held: 'given' } } });
  s.step(add('given again', c.ref));
  // The form that "cancellations" gives back, handed to "add".
  s.step(clock({ set: t }));
  const c2 = await s.cancel(t);
  const form = { cancellation: c2.recordRef, stamps: [await stamp(c2, c2.when + 5000)], acknowledgements: [] };
  s.step(clock({ add: MINUTE }));
  s.open('form', { options: { stampServices: trust } });
  s.step(add('form', form), check('form'));
  // An acknowledgement of the writer's own agent that comes with the cancellation is the one handed back.
  s.step(clock({ set: t }));
  s.open('first2');
  s.step(add('first2', c.ref), held('first2'), clock({ add: 2 * MINUTE }));
  s.open('second2');
  s.step(add('second2', { $held: 'first2', index: 0 }), held('second2'));
  // An acknowledgement that waits (a stub dated ten minutes ahead) is handed back, and written by a writer opened again.
  s.step(clock({ set: t }));
  await s.w.add({ when: t + 10 * MINUTE });
  s.open('ahead');
  const c3 = await s.cancel(t);
  s.step(add('ahead', c3.ref), check('ahead'), held('ahead'), clock({ add: 20 * MINUTE }));
  s.open('ahead again', { book: { $book: 'ahead' }, options: { cancellations: { $held: 'ahead' } } });
  s.step(act('ahead again', order(1)), book('ahead again'), held('ahead again'));
  return s.done();
}

async function strangerKeys() {
  // review12 (a design remark)
  const s = await setUp('a writer opened with keys that are not the agent\'s hands back no acknowledgement, and is still stopped');
  const c = await s.cancel(s.start);
  s.open('a', { keys: 'stranger' });
  s.step(act('a', order(1)), add('a', c.ref), check('a'), before('a', order(1)));
  s.open('b', { keys: 'stranger' });
  const ahead = await s.cancel(s.start + 10 * MINUTE);
  s.step(add('b', ahead.ref), held('b'));
  return s.done();
}

async function forgedAcknowledgements() {
  // review14 (finding 1)
  const s = await setUp('an acknowledgement that does not check is never taken for the agent\'s own');
  const t = s.start;
  for (const ahead of [true, false]) {
    for (const bad of ['other keys', 'another cancellation']) {
      const w = `${bad}, ${ahead ? 'ahead' : 'now'}`;
      s.step(clock({ set: t }));
      const c = await s.cancel(ahead ? t + 10 * MINUTE : t);
      s.open(`${w} first`);
      s.step(add(`${w} first`, c.ref, w));
      const other = await s.cancel(t + MINUTE);
      const forged = bad === 'other keys' ? await s.acknowledgement(c, t, s.stranger.privateKeys) : await s.acknowledgement(other, t);
      s.open(w);
      s.step(add(w, { cancellation: c.recordRef, acknowledgements: [forged, { $ack: w }] }), check(w), held(w), clock({ add: 20 * MINUTE }), act(w, order(1)), check(w));
    }
  }
  return s.done();
}

async function helperAcknowledgements() {
  // review14 (finding 3), review15 (finding 3 and "held in place"), review16 (finding 8)
  const s = await setUp('acknowledgements of helper agents go with the copy, four at most, and the writer\'s own is never pushed out', { fields: { passes: 1 } });
  const t = s.start;
  const c = await s.cancel(t + 10 * MINUTE);
  const helpers = [];
  for (let i = 0; i < 4; i++) {
    const keys = s.key(`helper${i}`, seededKeySet());
    const p = await s.w.pass({ when: START, helper: keys });
    helpers.push(await s.acknowledgement(c, t, keys.privateKeys, p.fingerprint));
  }
  const own = await s.acknowledgement(c, t);
  const ownLater = await s.acknowledgement(c, t + MINUTE);
  s.open('first', { options: { cancellations: [{ cancellation: c.recordRef, acknowledgements: helpers }] } });
  s.step(add('first', { cancellation: c.recordRef }, 'first'), held('first'), check('first'), clock({ add: MINUTE }));
  s.open('again', { book: { $book: 'first' }, options: { cancellations: { $held: 'first' } } });
  s.step(add('again', { cancellation: c.recordRef }), clock({ set: t }));
  s.open('one helper');
  s.step(add('one helper', { cancellation: c.recordRef, acknowledgements: [helpers[0]] }), held('one helper'), check('one helper'));
  s.open('among five');
  s.step(add('among five', { cancellation: c.recordRef, acknowledgements: [...helpers, own] }), held('among five'));
  s.open('two own');
  s.step(add('two own', { cancellation: c.recordRef, acknowledgements: [own, ownLater] }), held('two own'));
  s.open('two own given', { options: { cancellations: [{ cancellation: c.recordRef, acknowledgements: [ownLater, own] }] } });
  s.step(add('two own given', { cancellation: c.recordRef }), held('two own given'));
  s.open('kept then helper');
  s.step(add('kept then helper', { cancellation: c.recordRef }, 'kept'), add('kept then helper', { cancellation: c.recordRef, acknowledgements: [helpers[0]] }), held('kept then helper'));
  s.open('given then helper', { options: { cancellations: [{ cancellation: c.recordRef }] } });
  s.step(add('given then helper', { cancellation: c.recordRef, acknowledgements: [helpers[0]] }), held('given then helper'));
  s.open('full', { options: { cancellations: [{ cancellation: c.recordRef, acknowledgements: [...helpers.slice(0, 3), { $ack: 'kept' }] }] } });
  s.step(add('full', { cancellation: c.recordRef, acknowledgements: [helpers[3]] }), held('full'));
  s.open('four', { options: { cancellations: [{ cancellation: c.recordRef, acknowledgements: helpers }] } });
  s.step(add('four', { cancellation: c.recordRef }), held('four'));
  // The book holds two acknowledgements of the agent's own: the first is handed back.
  const inBook = await s.w.cancel({ when: t - 10 * MINUTE });
  await s.w.acknowledge(inBook.fingerprint, { when: t - 9 * MINUTE });
  const second2 = await s.w.acknowledge(inBook.fingerprint, { when: t - 8 * MINUTE });
  s.open('two in the book');
  s.step(add('two in the book', { cancellation: s.ref(null, inBook.record) }));
  s.open('given one of two', { options: { cancellations: [{ cancellation: s.ref(null, inBook.record), acknowledgements: [s.ref(null, second2.record)] }] } });
  s.step(add('given one of two', { cancellation: s.ref(null, inBook.record) }), held('given one of two'));
  return s.done();
}

async function crowding() {
  // review14, review16 (findings 1 and 2), review17 (finding 2), review18 (finding 5)
  const s = await setUp('sixteen at most beside the book: what gives way, and what never does');
  const t = s.start;
  const { other, issuerKeys, cancel } = await second(s);
  // Seventeen of its own slip: the last is not kept, and the error says so.
  s.open('seventeen');
  const own = [];
  for (let i = 0; i < 17; i++) own.push(await s.cancel(t + (10 + i) * MINUTE));
  for (const c of own) s.step(add('seventeen', c.ref));
  s.step(held('seventeen'));
  // Sixteen copies of another slip given at opening do not crowd out the writer's own.
  s.w.entries.push({ slip: other.slip });
  const others = [];
  for (let i = 0; i < 16; i++) others.push({ cancellation: (await cancel(t + (30 + i) * MINUTE)).recordRef });
  s.open('others', { issuerKeys, options: { cancellations: others } });
  s.step(add('others', own[0].ref), held('others'));
  s.open('others again', { book: { $book: 'others' }, issuerKeys, options: { cancellations: { $held: 'others' } } });
  s.step(act('others again', order(1)));
  const given = await s.cancel(t + 12 * MINUTE);
  s.open('third', { issuerKeys, options: { cancellations: [...others.slice(0, 15), { cancellation: given.recordRef }] } });
  s.step(add('third', own[0].ref), held('third'));
  // Sixteen of its own slip given at opening: a seventeenth is not kept.
  s.w.entries.pop();
  s.open('own given', { options: { cancellations: own.slice(0, 16).map((c) => ({ cancellation: c.recordRef })) } });
  s.step(add('own given', own[16].ref), held('own given'));
  // An acknowledgement that waits (a stub dated ahead) is not cut off by cancellations kept after it.
  await s.w.add({ when: t + 10 * MINUTE });
  s.open('waiting');
  const first = await s.cancel(t);
  s.step(add('waiting', first.ref, 'waits'));
  for (let i = 0; i < 16; i++) s.step(add('waiting', (await s.cancel(t + (20 + i) * MINUTE)).ref));
  s.step(held('waiting'), check('waiting'));
  s.open('waiting again', { book: { $book: 'waiting' }, options: { cancellations: { $held: 'waiting' } } });
  s.step(add('waiting again', first.ref));
  // A copy given at opening that carries a waiting acknowledgement takes up room, and is the last to give way.
  s.open('carrying', { book: { $book: 'waiting' }, options: { cancellations: [{ cancellation: first.recordRef, acknowledgements: [{ $ack: 'waits' }] }] } });
  for (let i = 1; i <= 16; i++) s.step(add('carrying', (await s.cancel(t + i * 1000)).ref));
  s.step(held('carrying'));
  return s.done();
}

async function emptyList() {
  // review16 (finding 9)
  const s = await setUp('an empty list of cancellations is none at all');
  s.open('a', { options: { cancellations: [] } });
  s.step(held('a'), act('a', order(1)));
  s.open('b', { book: { $book: 'a' }, options: { cancellations: { $held: 'a' } } });
  s.step(act('b', order(1)), check('b'));
  return s.done();
}

async function sizes() {
  // review18, review19: what is handed to "add" is copied once, and refused if it holds more than a line could
  const s = await setUp('what is handed to "add": too much beside a cancellation, and values that cannot be a line');
  const c = await s.cancel(s.start);
  const cases = [
    { cancellation: c.recordRef, junk: { $fill: { $repeat: 'x', n: 100000 }, n: 3 } },
    { cancellation: c.recordRef, many: { $shared: 1, width: 2000, leaf: { $fill: 'a', n: 20000 } } },
    { cancellation: c.recordRef, deep: { $nest: 70, leaf: 'x' } },
    { cancellation: c.recordRef, stamps: { $fill: 'AAAA', n: 40 } },
    { cancellation: c.recordRef, stamps: [{ $repeat: 'A', n: 140000 }], acknowledgements: [{ $repeat: 'A', n: 140000 }] },
    { cancellation: c.recordRef, a: { $repeat: 'x', n: 70000 }, b: { $repeat: 'y', n: 70000 } },
  ];
  cases.forEach((entry, i) => {
    s.open(`a${i}`);
    s.step(add(`a${i}`, entry), act(`a${i}`, order(1)), held(`a${i}`));
  });
  s.open('b');
  s.step(add('b', { cancellation: { $shared: 6, width: 200, leaf: 'x' } }), add('b', ['a', 'b']), add('b', 'text'), add('b', null), act('b', order(1)), check('a0'));
  s.open('opening', { options: { cancellations: [{ cancellation: c.recordRef, m: { $shared: 1, width: 2000, leaf: { $fill: 'a', n: 20000 } } }] } });
  s.open('opening deep', { options: { cancellations: [{ cancellation: c.recordRef, stamps: [{ $nest: 70, leaf: 'x' }] }] } });
  return s.done();
}

async function others() {
  // carried.test.mjs: entries that someone else made
  const s = await setUp('entries that someone else made: terms, a refusal, a pass and a helper\'s stub, a vouching record, a seal', { fields: { passes: 1 } });
  const t = s.start;
  await s.w.add({ value: 10, when: START });
  const opening = s.book();
  const sealed = await s.w.seal({ when: t - MINUTE });
  s.w.entries.pop();
  const seal = s.ref('seal', sealed.entry);
  const published = await s.w.publishTerms();
  s.w.entries.pop();
  const terms = s.ref(null, { terms: published.record });
  const termsFingerprint = s.ref(null, published.fingerprint);
  const refusal = s.ref(null, { refusal: (await s.w.refuse({ when: t })).record });
  s.w.entries.pop();
  const lateRefusal = s.ref(null, { refusal: (await s.w.refuse({ when: t + 10 * MINUTE })).record });
  s.w.entries.pop();
  const helperKeys = s.key('helper', seededKeySet());
  const p = await s.w.pass({ when: t, helper: helperKeys });
  s.w.entries.pop();
  const h = await p.add({ when: t + MINUTE });
  s.w.entries.pop();
  const organisation = seededKeySet();
  const vouching = await writeVouching({ by: { keys: organisation.keys, name: 'Example Organisation (invented)' }, for: { kind: 'agent', keys: s.w.agent.keys, name: 'Office supplies agent' }, validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z', when: t }, organisation.privateKeys);
  const withdrawal = await writeWithdrawal({ vouching: vouching.fingerprint, when: t }, organisation.privateKeys);
  const options = { withoutMethods: [SLH] };
  s.open('a', { book: opening, options });
  s.step(
    add('a', seal),
    add('a', seal),
    act('a', order(1)),
    check('a'),
  );
  s.open('b', { book: opening, options });
  s.step(
    add('b', terms),
    add('b', terms),
    act('b', order(10), { terms: termsFingerprint }),
    add('b', refusal),
    add('b', lateRefusal),
    add('b', s.ref(null, { pass: p.record })),
    add('b', s.ref(null, h.entry)),
    add('b', s.ref(null, h.entry)),
    add('b', s.ref(null, { vouching: vouching.record })),
    add('b', s.ref(null, { withdrawal: withdrawal.record })),
    add('b', { neither: 'this nor that' }),
    add('b', { stub: { payload: 'e30', signatures: [] } }),
    act('b', order(10)),
    check('b'),
    book('b'),
  );
  return s.done();
}

async function afterEveryCall() {
  // carried.test.mjs: the stub writer's view of its book, after every call
  const s = await setUp('the writer\'s view of its book is the view a whole check gives, after every call', {
    fields: {
      passes: 1,
      limits: [
        { action: ORDER, max: 120, unit: 'GBP' },
        { action: ORDER, max: 60, per: 3600, unit: 'GBP' },
      ],
      requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }],
    },
  });
  let t = START + MINUTE;
  s.start = t;
  const helperKeys = s.key('helper', seededKeySet());
  await s.w.pass({ when: START, helper: helperKeys });
  s.open('a');
  const whole = () => ({ op: 'checkBook', text: { $book: 'a' }, options: { issuerKeys: s.issuer, cancellations: { $held: 'a' } } });
  s.step(check('a'), act('a', order(10), { countersign: SIGN }), check('a'), clock({ add: MINUTE }), act('a', order(20)), clock({ add: MINUTE }), act('a', order(45)), act('a', order(31)), check('a'));
  s.step(act('a', order(5), undefined, { throws: 'the supplier did not answer' }));
  t += 2 * MINUTE + 2 * HOUR;
  const approval = s.ref(null, await s.w.approve({ slip: s.w.slipFingerprint, ...order(50), when: t }));
  s.step(clock({ add: 2 * HOUR }), act('a', order(50), { approval, countersign: SIGN }), check('a'));
  s.step(clock({ add: MINUTE }), act('a', order(5), { countersign: { gives: { payload: 'AAAA', signatures: [] } } }), whole());
  t += 2 * MINUTE;
  s.step(clock({ add: MINUTE }), record('a', order(100)), record('a', order(1), { when: t - HOUR }), whole());
  const refusal = s.ref(null, { refusal: (await s.w.refuse({ when: t })).record });
  s.w.entries.pop();
  s.step(add('a', refusal), whole(), clock({ add: MINUTE }), act('a', order(1)));
  t += MINUTE;
  const c = await s.cancel(t + 10 * MINUTE);
  s.step(add('a', c.ref), whole(), before('a', order(1)), clock({ add: 20 * MINUTE }), act('a', order(1)), check('a'), whole());
  return s.done();
}

// --- the connector for an agent's tools ---

async function toolsUsed() {
  // tools.test.mjs
  const s = await setUp('tools behind the writer: each call asks first, runs only if allowed, and leaves a stub that fixes what was asked for', { fields: { actions: [ORDER, LOOK] } });
  s.start = START + MINUTE;
  s.open('a');
  s.step({
    op: 'tools',
    w: 'a',
    as: 't',
    tools: {
      placeOrder: { action: ORDER, with: 'supplier', amount: { fn: { unit: 'GBP', field: 'total' } }, run: { fn: { field: 'item', prefix: 'accepted ' } }, countersign: { fn: SIGN } },
      readStock: { action: LOOK, run: { fn: { field: 'item', prefix: 'stock of ' } } },
    },
    onStub: {},
  });
  s.step(
    { op: 'call', t: 't', tool: 'placeOrder', args: { item: 'paper', boxes: 5, total: 45 } },
    { op: 'call', t: 't', tool: 'readStock', args: { item: 'toner' } },
    { op: 'call', t: 't', tool: 'placeOrder', args: { item: 'desks', total: 500 } },
    { op: 'fingerprint', args: { total: 45, boxes: 5, item: 'paper' } },
    check('a'),
  );
  return s.done();
}

async function toolsCopied() {
  // tools.test.mjs, review12 (findings 3 and 4)
  const s = await setUp('a tool is handed copies: nothing its functions do to them changes what is recorded', {
    fields: { actions: [ORDER, LOOK], requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }] },
  });
  const t = s.start;
  const meddlingArgs = { item: 'toner' };
  const meddlingRequest = { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 45 }, details: [{ name: 'arguments', sha256: await argumentsFingerprint(meddlingArgs) }] };
  const fixedRequest = { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 150 }, details: [{ name: 'arguments', sha256: await argumentsFingerprint({ item: 'desk' }) }] };
  const approve = async (request) => s.ref(null, await s.w.approve({ slip: s.w.slipFingerprint, ...request, when: t }));
  s.open('a');
  s.step({
    op: 'tools',
    w: 'a',
    as: 't',
    tools: {
      look: { action: LOOK, run: { fn: { meddle: true, gives: 'done' } } },
      fixedPrice: { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 150 }, run: { fn: { gives: 'ordered' } }, approve: { fn: { gives: await approve(fixedRequest) } } },
      meddling: {
        action: ORDER,
        with: 'supplier',
        amount: { fn: { meddle: true, gives: { unit: 'GBP', value: 45 } } },
        approve: { fn: { meddle: true, gives: await approve(meddlingRequest) } },
        countersign: { fn: { meddle: true, gives: null } },
        run: { fn: { field: 'item' } },
      },
    },
    onStub: {},
  });
  s.step(
    { op: 'call', t: 't', tool: 'look', args: { item: 'paper', where: ['shelf', 2] } },
    { op: 'call', t: 't', tool: 'fixedPrice', args: { item: 'desk' } },
    { op: 'call', t: 't', tool: 'meddling', args: meddlingArgs },
    check('a'),
  );
  return s.done();
}

async function toolsDetails() {
  // tools.test.mjs, review13 (finding 2)
  const s = await setUp('a tool may name other documents, or none; a call with no arguments names none', { fields: { actions: [ORDER, LOOK], limits: [{ action: ORDER, max: 20, unit: 'GBP' }] } });
  const document = { name: 'Order form', sha256: 'A'.repeat(42) + 'E' };
  s.open('a');
  s.step({
    op: 'tools',
    w: 'a',
    as: 't',
    tools: {
      bare: { action: LOOK, details: false, run: { fn: { gives: 1 } } },
      own: { action: LOOK, details: { fn: { gives: [document] } }, run: { fn: { gives: 2 } } },
      none: { action: LOOK, details: { fn: { gives: null } }, run: { fn: { gives: 3 } } },
      notAList: { action: LOOK, details: { fn: { gives: 'none' } }, run: { fn: { gives: 4 } } },
      plain: { action: LOOK, run: { fn: { gives: 5 } } },
      fixed: { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 15 }, details: { fn: { gives: [{ name: 'arguments', sha256: 'A'.repeat(43) }] } }, run: { fn: { gives: 'ordered' } } },
      withWhom: { action: ORDER, with: { fn: { field: 'who' } }, amount: { fn: { unit: 'GBP', field: 'total' } }, run: { fn: { gives: 'ordered' } } },
    },
  });
  for (const [tool, args] of [['bare', { secret: 'not fingerprinted' }], ['own', { anything: true }], ['none', {}], ['notAList', {}], ['plain', undefined], ['plain', null], ['plain', [1, 'two', { three: 3 }]], ['fixed', { item: 'pens' }], ['fixed', { item: 'toner' }], ['withWhom', { who: 'supplier', total: 1 }], ['withWhom', { who: 'nobody', total: 1 }], ['withWhom', { total: 1 }]]) {
    s.step(args === undefined ? { op: 'call', t: 't', tool } : { op: 'call', t: 't', tool, args });
  }
  s.step(check('a'));
  return s.done();
}

async function toolsApproval() {
  // tools.test.mjs, review12 (finding 5), review14 (finding 5), review15 ("held in place")
  const s = await setUp('where the slip asks for the person\'s approval, the tool\'s "approve" is asked once, and only where it is the one thing missing', {
    fields: { requires: [{ above: 40, action: ORDER, need: 'approval', unit: 'GBP' }] },
  });
  const t = s.start;
  const requestFor = async (args, amount = args.total) => ({ action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: amount }, details: [{ name: 'arguments', sha256: await argumentsFingerprint(args) }] });
  const approve = async (request) => s.ref(null, await s.w.approve({ slip: s.w.slipFingerprint, ...request, when: t }));
  const yes = await approve(await requestFor({ item: 'toner', total: 60 }));
  const forOther = await approve(await requestFor({ item: 'chairs', total: 70 }, 1));
  const changed = await approve({ ...(await requestFor({ total: 45 })), amount: { unit: 'GBP', value: 46 } });
  const changedDetails = await approve({ action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 45 }, details: [{ name: 'order', sha256: 'E'.repeat(43) }] });
  const base = { action: ORDER, with: 'supplier', amount: { fn: { unit: 'GBP', field: 'total' } }, run: { fn: { field: 'item', prefix: 'ordered ' } } };
  s.open('a');
  s.step({
    op: 'tools',
    w: 'a',
    as: 't',
    tools: {
      yes: { ...base, approve: { fn: { gives: yes } } },
      no: { ...base, approve: { fn: { gives: null } } },
      other: { ...base, approve: { fn: { gives: forOther } } },
      keptAmount: { ...base, approve: { fn: { mutateKept: true, gives: changed } } },
      keptDetails: { ...base, amount: { unit: 'GBP', value: 45 }, details: { fn: { gives: [{ name: 'order', sha256: 'A'.repeat(43) }] } }, approve: { fn: { mutateKept: true, gives: changedDetails } } },
      forbidden: { action: 'provared.data.delete', run: { fn: { gives: 'deleted' } }, approve: { fn: { gives: null } } },
    },
  });
  s.step(
    { op: 'call', t: 't', tool: 'yes', args: { item: 'pens', total: 10 } },
    { op: 'call', t: 't', tool: 'yes', args: { item: 'toner', total: 60 } },
    { op: 'call', t: 't', tool: 'no', args: { item: 'chairs', total: 70 } },
    { op: 'call', t: 't', tool: 'other', args: { item: 'chairs', total: 70 } },
    { op: 'call', t: 't', tool: 'keptAmount', args: { total: 45 } },
    { op: 'call', t: 't', tool: 'keptDetails', args: { total: 45 } },
    { op: 'call', t: 't', tool: 'forbidden', args: {} },
    check('a'),
  );
  const both = await setUp('the person is not asked to approve where the action could not be taken anyway', { fields: { requires: [{ need: 'approval', action: ORDER }, { need: 'countersignature', action: ORDER }] } });
  both.open('b');
  both.step(
    { op: 'tools', w: 'b', as: 't', tools: { placeOrder: { action: ORDER, with: 'supplier', amount: { fn: { gives: { unit: 'GBP', value: 10 } } }, run: { fn: { gives: 1 } }, approve: { fn: { gives: null } } } } },
    { op: 'call', t: 't', tool: 'placeOrder', args: { item: 'pens' } },
  );
  return [s.done(), both.done()];
}

async function toolsFailing() {
  // tools.test.mjs, review13 (finding 10)
  const s = await setUp('a tool that fails passes its error on and leaves no stub; arguments that are not JSON are refused before anything is asked', { fields: { actions: [ORDER, LOOK] } });
  s.open('a', { countersignWithin: 300 });
  s.step({
    op: 'tools',
    w: 'a',
    as: 't',
    tools: {
      broken: { action: LOOK, run: { fn: { throws: 'the shelf fell over' } } },
      look: { action: LOOK, run: { fn: { gives: 'looked' } } },
      slow: { action: ORDER, with: 'supplier', amount: { unit: 'GBP', value: 1 }, run: { fn: { gives: 'ordered' } }, countersign: { fn: { never: true } } },
    },
    onStub: { throws: 'the book could not be kept' },
  });
  for (const args of [{}, { n: { $: 'NaN' } }, { n: { $: 'Infinity' } }, ['\ud800'], { $nest: 70, leaf: 1 }, { $nest: 64, leaf: 1 }, { $nest: 63, leaf: 1 }]) s.step({ op: 'call', t: 't', tool: 'broken', args });
  s.step({ op: 'call', t: 't', tool: 'look', args: { q: 1 } }, { op: 'call', t: 't', tool: 'slow', args: { q: 2 } }, check('a'));
  const c = await s.cancel(s.start);
  s.step(add('a', c.ref), { op: 'call', t: 't', tool: 'look', args: { q: 3 } });
  return s.done();
}

async function toolsDescribed() {
  // tools.test.mjs: a tool that is not described as it must be
  const s = await setUp('a tool that is not described as it must be is refused when the tools are put behind the writer', { fields: { actions: [ORDER, LOOK] } });
  s.open('a');
  const run = { fn: { gives: 1 } };
  for (const tools of [
    { a: { run } },
    { a: { action: 'Not A Name', run } },
    { a: { action: 'provared.not.on.the.list', run } },
    { a: { action: LOOK } },
    { a: { action: LOOK, run: 'not a function' } },
    { a: { action: LOOK, run, countersign: 'yes' } },
    { a: { action: LOOK, run, countersign: null } },
    { a: { action: LOOK, run, approve: true } },
    { a: { action: LOOK, run, details: 'none' } },
    { a: { action: LOOK, run, details: 0 } },
    { a: { action: LOOK, run, amount: { fn: { gives: 1 } } } },
    { a: null },
    { a: 'tool' },
    { a: { action: LOOK, run }, b: { action: ORDER, run, with: 'supplier', amount: { unit: 'GBP', value: 1 } } },
  ]) {
    s.step({ op: 'tools', w: 'a', as: 't', tools });
  }
  s.step({ op: 'call', t: 't', tool: 'b', args: { x: 1 } }, { op: 'call', t: 't', tool: 'a' });
  for (const recorder of [{}, null, 'writer', [], { act: 'not a function' }]) s.step({ op: 'tools', w: 'a', as: 'u', recorder, tools: { a: { action: LOOK, run } } });
  for (const tools of [[], null, 'tools', 5]) s.step({ op: 'tools', w: 'a', as: 'u', tools: { $whole: tools } });
  return s.done();
}

async function fingerprints() {
  // tools.test.mjs, review12 (finding 2), review13 (finding 10): the one form of RFC 8785
  const s = await setUp('the fingerprint of the arguments: one form whatever the order of the members, numbers as JavaScript writes them, and only for JSON');
  let seed = 7;
  const next = () => {
    seed ^= seed << 13;
    seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed >>>= 0;
    return seed;
  };
  const view = new DataView(new ArrayBuffer(8));
  const doubles = [];
  while (doubles.length < 400) {
    view.setUint32(0, next());
    view.setUint32(4, next());
    const x = view.getFloat64(0);
    if (Number.isFinite(x)) doubles.push(x);
  }
  const edges = [0, 1, -1, 0.1, 0.2, 0.30000000000000004, 1e21, 1e20, 123456789012345680000, 1.5e-7, 1e-6, 1e-7, 5e-324, 1.7976931348623157e308, 2 ** 53, 2 ** 53 + 2, 2 ** 64, 12345678901234567000, 4.35, 0.5, 100, 1e16, 1e-300, 9.999999999999999e20];
  const values = [
    { b: [1, 2.5, 0, true, null, 'x'], a: { d: 'é', c: 1e21 } },
    { a: { c: 1e21, d: 'é' }, b: [1, 2.5, 0, true, null, 'x'] },
    { a: { c: 1e21, d: 'é' }, b: [1, 2.5, { $: '-0' }, true, null, 'x'] },
    'paper',
    null,
    true,
    false,
    0,
    { $: '-0' },
    [],
    {},
    edges,
    doubles.slice(0, 200),
    doubles.slice(200),
    { '\u{1F600}': 1, '￿': 2, 10: 3, 2: 4, a: 5, '': 6 },
    { text: 'line\nfeed "quoted" \\ back \u0001 \u007f   \u{1F600}' },
    [null, null, null],
    { $nest: 64, leaf: 'x' },
    { $nest: 65, leaf: 'x' },
    { $nest: 64, leaf: {} },
    { $nest: 64, leaf: { a: 1 } },
    { $nest: 70, leaf: 'x' },
    { $: 'NaN' },
    { $: 'Infinity' },
    { $: 'undefined' },
    '\ud800',
    { a: '\udc00' },
    12345678901234567890,
  ];
  for (const args of values) s.step({ op: 'fingerprint', args });
  return s.done();
}

export const CASES = {
  'recorder-scenarios': async () => {
    const cases = [];
    for (const make of [actions, chainCarriedOn, openings, helper, approvals, terms, countersignatures, countersignatureAsked, clocks, requests, inside, cancelled, keptAhead, shapes, notCancellations, otherSlips, alreadyInBook, farAndNear, stampLater, stampRoutes, clockFails, acknowledgementDates, openedAgain, strangerKeys, forgedAcknowledgements, helperAcknowledgements, crowding, emptyList, sizes, others, afterEveryCall]) {
      const made = await make();
      cases.push(...(Array.isArray(made) ? made : [made]));
    }
    return finish('The stub writer beside an agent (openRecorder): scenarios played step by step, each with its transcript (test/helpers/scenarios.mjs).', 'recorderScenario', cases, ANSWER);
  },
  'tool-scenarios': async () => {
    const cases = [];
    for (const make of [toolsUsed, toolsCopied, toolsDetails, toolsApproval, toolsFailing, toolsDescribed, fingerprints]) {
      const made = await make();
      cases.push(...(Array.isArray(made) ? made : [made]));
    }
    return finish('The connector for an agent\'s tools (recordTools) and the fingerprint of their arguments: scenarios played step by step, each with its transcript (test/helpers/scenarios.mjs).', 'recorderScenario', cases, ANSWER);
  },
};
