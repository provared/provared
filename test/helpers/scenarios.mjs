// Scenarios for the stub writer (openRecorder) and the connector for an
// agent's tools (recordTools): a world of records made beforehand, and a
// list of steps to play against it. This library plays a scenario here;
// the Python version plays the same one (python/tests/scenarios.py). Both
// write a transcript of what happened, which must be the same.
//
// Records that the writer makes while a scenario is played (stubs,
// acknowledgements, and the countersignatures the other side gives) differ
// from one run to the next. Their unique numbers are made the same in both
// runners for the length of a scenario: the n-th is the first 16 bytes of
// SHA-256 of "provared-scenario-id-n". ML-DSA signatures are randomised as
// they are made; in the transcript each new one is named by the first
// place it was seen ("sig1", "sig2", ...), and so is each top fingerprint
// of a book, which covers them ("root1", ...). Every other long value is
// shortened to the start of its SHA-256 ("h:..."), which keeps it exact.
//
// The keys of the agent and of the services are made from seeds that are
// kept in the scenario, so that the Python version signs with the same
// keys. The person's passkey stays here: slips, approvals and cancellations
// are made beforehand and handed to both runners as records.
//
// A scenario: {name, world: {start, keys: {name: {ed, ml}}, records: {...}}, steps: [...]}.
// A value in a step may be an expression:
//   {$ref: name}                  a record of the world
//   {$ack: label}                 the acknowledgement handed back by the step with that label
//   {$book: writer}, {$held: writer, index?}   what that writer's book() or cancellations() gives now
//   {$lines: text, from, to}      those lines of a book, each with its line feed
//   {$with: value, set: {...}}    the value with these members put in
//   {$concat: [...]}              texts joined
//   {$repeat: text, n}, {$fill: value, n}, {$nest: depth, leaf}, {$shared: levels, width, leaf}
//   {$: 'NaN' | 'Infinity' | '-Infinity' | '-0' | 'undefined'}

import { createHash, createPrivateKey, randomBytes } from 'node:crypto';
import { NotTaken, argumentsFingerprint, checkBook, countersign, openRecorder, recordTools } from '../../src/index.js';
import { Refusal, toBase64url } from '../../src/encoding.js';

// --- keys made from seeds ---

const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const ML_PKCS8 = Buffer.from('3034020100300b0609608648016503040313042280' + '20', 'hex');

/**
 * A key set for an agent or a service, made from its two 32-byte seeds
 * (Ed25519, then ML-DSA-87), in the form generateKeySet gives.
 * @param {string|Uint8Array} ed @param {string|Uint8Array} ml base64url text, or bytes
 */
export function keySetFromSeeds(ed, ml) {
  const bytes = (s) => (typeof s === 'string' ? Buffer.from(s, 'base64url') : Buffer.from(s));
  const edKey = createPrivateKey({ key: Buffer.concat([ED_PKCS8, bytes(ed)]), format: 'der', type: 'pkcs8' });
  const mlKey = createPrivateKey({ key: Buffer.concat([ML_PKCS8, bytes(ml)]), format: 'der', type: 'pkcs8' });
  return {
    keys: [
      { alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: edKey.export({ format: 'jwk' }).x },
      { alg: 'ML-DSA-87', kty: 'AKP', pub: mlKey.export({ format: 'jwk' }).pub },
    ],
    privateKeys: [edKey.toCryptoKey({ name: 'Ed25519' }, false, ['sign']), mlKey.toCryptoKey({ name: 'ML-DSA-87' }, false, ['sign'])],
    seeds: { ed: toBase64url(bytes(ed)), ml: toBase64url(bytes(ml)) },
  };
}

/** A new key set whose seeds are known. */
export function seededKeySet() {
  return keySetFromSeeds(randomBytes(32), randomBytes(32));
}

// --- the same unique numbers in both runners ---

const scenarioId = (n) => createHash('sha256').update(`provared-scenario-id-${n}`).digest().subarray(0, 16);

function fixIds() {
  const c = globalThis.crypto;
  const own = Object.getOwnPropertyDescriptor(c, 'getRandomValues');
  const original = c.getRandomValues.bind(c);
  let n = 0;
  c.getRandomValues = (array) => {
    if (!(array instanceof Uint8Array) || array.length !== 16) return original(array);
    array.set(scenarioId(++n));
    return array;
  };
  return () => {
    if (own) Object.defineProperty(c, 'getRandomValues', own);
    else delete c.getRandomValues;
  };
}

// --- the transcript ---

const TOKEN = /[A-Za-z0-9_-]{20,}/g;
const SIGNATURE_LENGTH = 6170; // ML-DSA-87: 4,627 bytes in base64url
const INSIDE = 'The stub writer was called from inside an action it is taking. Call it once the action has ended.';
const MESSAGES = new Set(['the clock failed', 'no answer in time', INSIDE, 'Invalid time value']);

function strings(value, out) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out);
  else if (value && typeof value === 'object') for (const k of Object.keys(value)) strings(value[k], out);
  return out;
}

const hashed = (token) => 'h:' + createHash('sha256').update(token).digest('hex').slice(0, 16);

function token(t, ctx) {
  if (t.length === SIGNATURE_LENGTH && !ctx.known.has(t)) return ctx.name(t, 'sig');
  return t.length > 64 ? hashed(t) : t;
}

/** A value as the transcript holds it: as JSON would carry it, with long and random values named. */
export function norm(value, ctx, key) {
  if (value === undefined || value === null) return null;
  if (typeof value === 'string') return key === 'root' ? ctx.name(value, 'root') : value.replace(TOKEN, (t) => token(t, ctx));
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map((v) => norm(v, ctx));
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) {
      if (value[k] === undefined || typeof value[k] === 'function') continue;
      out[k] = norm(value[k], ctx, k);
    }
    return out;
  }
  return null;
}

/** An error as the transcript holds it. */
function failure(e, ctx) {
  if (e instanceof NotTaken) return { error: { kind: 'NotTaken', tool: e.tool, message: e.message, answer: norm(e.answer, ctx) } };
  if (e instanceof Refusal) {
    const out = { kind: 'Refusal', code: e.code, message: norm(e.message, ctx) };
    if (e.acknowledgement) out.acknowledgement = norm(e.acknowledgement, ctx);
    if (e.cause) out.cause = message(e.cause, ctx);
    return { error: out };
  }
  return { error: { kind: 'Error', message: message(e, ctx) } };
}

function message(e, ctx) {
  const text = e && typeof e.message === 'string' ? e.message : String(e);
  return MESSAGES.has(text) || ctx.thrown.has(text) ? text : 'unexpected';
}

// --- the values in a step ---

const SPECIAL = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity, '-0': -0, undefined: undefined };

function resolve(value, ctx) {
  if (Array.isArray(value)) return value.map((v) => resolve(v, ctx));
  if (value === null || typeof value !== 'object') return value;
  if (Object.hasOwn(value, '$ref')) return resolve(structuredClone(ctx.world.records[value.$ref]), ctx);
  if (Object.hasOwn(value, '$ack')) return structuredClone(ctx.acks[value.$ack] ?? null);
  if (Object.hasOwn(value, '$book')) return ctx.writers[value.$book].book();
  if (Object.hasOwn(value, '$held')) {
    const held = ctx.writers[value.$held].cancellations();
    return Object.hasOwn(value, 'index') ? held[value.index] : held;
  }
  if (Object.hasOwn(value, '$lines')) return resolve(value.$lines, ctx).split('\n').slice(value.from, value.to).join('\n') + '\n';
  if (Object.hasOwn(value, '$with')) return { ...resolve(value.$with, ctx), ...resolve(value.set, ctx) };
  if (Object.hasOwn(value, '$concat')) return value.$concat.map((v) => resolve(v, ctx)).join('');
  if (Object.hasOwn(value, '$repeat')) return value.$repeat.repeat(value.n);
  if (Object.hasOwn(value, '$fill')) return new Array(value.n).fill(resolve(value.$fill, ctx));
  if (Object.hasOwn(value, '$nest')) {
    let v = resolve(value.leaf, ctx);
    for (let i = 0; i < value.$nest; i++) v = [v];
    return v;
  }
  if (Object.hasOwn(value, '$shared')) {
    let v = resolve(value.leaf, ctx);
    for (let i = 0; i < value.$shared; i++) {
      const next = {};
      for (let b = 0; b < value.width; b++) next['m' + b] = v;
      v = next;
    }
    return v;
  }
  if (Object.hasOwn(value, '$')) return SPECIAL[value.$];
  const out = {};
  for (const k of Object.keys(value)) out[k] = resolve(value[k], ctx);
  return out;
}

// --- the clock ---

function makeClock(start) {
  const clock = { time: start, fail: false, left: 0, readings: 0, gives: undefined, giving: false };
  clock.now = () => {
    clock.readings++;
    if (clock.fail) throw new Error('the clock failed');
    if (clock.left > 0 && --clock.left === 0) throw new Error('the clock failed');
    return clock.giving ? clock.gives : clock.time;
  };
  return clock;
}

// --- what the caller hands to the writer ---

const order = (value) => ({ action: 'supplies.order', amount: { unit: 'GBP', value }, with: 'supplier' });

// A call to the writer from inside something it runs: what came of it.
async function inside(names, ctx, writer) {
  const out = [];
  for (const name of names) {
    let got;
    try {
      if (name === 'book') got = { value: norm(writer.book(), ctx) };
      else if (name === 'held') got = { value: norm(writer.cancellations(), ctx) };
      else if (name === 'check') got = { value: (await writer.check()).summary };
      else if (name === 'before') got = { value: await writer.before(order(1)) };
      else if (name === 'act') got = { value: (await writer.act(order(1), async () => null)).done };
      else if (name === 'record') got = { value: (await writer.record(order(1))).seq };
      else if (name === 'add') got = { value: await writer.add({ neither: 'this nor that' }) };
      got.value = norm(got.value, ctx);
    } catch (e) {
      got = failure(e, ctx);
    }
    out.push(got);
  }
  return out;
}

// The other side, asked to countersign. "seen" gathers what it was handed and did.
function countersigner(spec, ctx, writer, seen) {
  if (Object.hasOwn(spec, 'notFunction')) return resolve(spec.notFunction, ctx);
  return (stub) => {
    seen.asked = (seen.asked ?? 0) + 1;
    (seen.handed ??= []).push(norm(stub.payload, ctx));
    const answer = async () => {
      if (spec.inside) (seen.inside ??= []).push(await inside(spec.inside, ctx, writer));
      if (Object.hasOwn(spec, 'throws')) throw new Error(spec.throws);
      if (Object.hasOwn(spec, 'gives')) return resolve(spec.gives, ctx);
      return countersign(stub, ctx.keys[spec.sign].privateKeys, ctx.clock.time + (spec.at ?? 1000));
    };
    if (spec.never) return new Promise(() => {});
    if (spec.late) {
      const when = ctx.clock.time + (spec.at ?? 1000);
      return new Promise((resolveIt) => setTimeout(() => resolveIt(countersign(stub, ctx.keys[spec.sign].privateKeys, when)), spec.late));
    }
    return answer();
  };
}

function moreOf(spec, ctx, writer, seen) {
  if (spec === undefined) return undefined;
  // Anything but an object is handed to the writer as it is.
  if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) return resolve(spec, ctx);
  const more = {};
  for (const name of ['when', 'terms', 'approval']) if (Object.hasOwn(spec, name)) more[name] = resolve(spec[name], ctx);
  if (spec.countersign) more.countersign = countersigner(spec.countersign, ctx, writer, (seen.countersign = {}));
  return more;
}

function performer(spec, ctx, writer, seen) {
  if (Object.hasOwn(spec, 'notFunction')) return resolve(spec.notFunction, ctx);
  return async () => {
    seen.performed = (seen.performed ?? 0) + 1;
    if (spec.inside) seen.inside = await inside(spec.inside, ctx, writer);
    if (Object.hasOwn(spec, 'throws')) throw new Error(spec.throws);
    return resolve(spec.gives ?? null, ctx);
  };
}

// --- a tool's description ---

function toolOf(name, spec, ctx, writer, seens) {
  const seen = () => (seens.current[name] ??= {});
  const note = (member, value) => (seen()[member] ??= []).push(norm(value === undefined ? null : value, ctx));
  const meddle = (args, member) => {
    if (args && typeof args === 'object' && !Array.isArray(args)) args.item = `changed by ${member}`;
  };
  const fn = (member, make) => {
    const value = spec[member];
    if (value && typeof value === 'object' && Object.hasOwn(value, 'fn')) return make(value.fn);
    return resolve(value, ctx);
  };
  const tool = {};
  if (Object.hasOwn(spec, 'action')) tool.action = resolve(spec.action, ctx);
  if (Object.hasOwn(spec, 'run')) {
    tool.run = fn('run', (f) => (args) => {
      note('run', args);
      if (f.meddle) meddle(args, 'run');
      if (Object.hasOwn(f, 'throws')) throw new Error(f.throws);
      if (Object.hasOwn(f, 'field')) return `${f.prefix ?? ''}${args?.[f.field]}`;
      return resolve(f.gives ?? null, ctx);
    });
  }
  for (const member of ['amount', 'with']) {
    if (!Object.hasOwn(spec, member)) continue;
    tool[member] = fn(member, (f) => (args) => {
      note(member, args);
      if (f.meddle) meddle(args, member);
      if (member === 'amount') return (seens.kept.amount = Object.hasOwn(f, 'gives') ? resolve(f.gives, ctx) : { unit: f.unit, value: args?.[f.field] });
      return Object.hasOwn(f, 'gives') ? resolve(f.gives, ctx) : args?.[f.field];
    });
  }
  if (Object.hasOwn(spec, 'details')) {
    tool.details = fn('details', (f) => (args) => {
      note('details', args);
      if (f.meddle) meddle(args, 'details');
      return (seens.kept.details = resolve(f.gives ?? null, ctx));
    });
  }
  if (Object.hasOwn(spec, 'countersign')) {
    tool.countersign = fn('countersign', (f) => {
      const other = countersigner(f, ctx, writer, {});
      return (stub, args) => {
        note('countersign', args);
        if (f.meddle) meddle(args, 'countersign');
        return other(stub);
      };
    });
  }
  if (Object.hasOwn(spec, 'approve')) {
    tool.approve = fn('approve', (f) => async (request, args) => {
      note('approve', [request, args]);
      if (f.meddle) {
        meddle(args, 'approve');
        if (request && request.amount) request.amount.value = 1;
      }
      if (f.mutateKept) {
        if (seens.kept.amount) seens.kept.amount.value = 46;
        if (seens.kept.details) seens.kept.details[0].sha256 = 'E'.repeat(43);
      }
      return resolve(f.gives ?? null, ctx);
    });
  }
  return tool;
}

// --- one step ---

async function playStep(step, ctx) {
  const w = step.w === undefined ? undefined : ctx.writers[step.w];
  const seen = {};
  try {
    switch (step.op) {
      case 'open': {
        const o = {
          book: resolve(step.book, ctx),
          slip: resolve(step.slip, ctx),
          privateKeys: ctx.keys[step.keys].privateKeys,
          issuerKeys: resolve(step.issuerKeys, ctx),
          now: ctx.clock.now,
        };
        if (Object.hasOwn(step, 'pass')) o.pass = resolve(step.pass, ctx);
        if (Object.hasOwn(step, 'options')) o.options = resolve(step.options, ctx);
        if (Object.hasOwn(step, 'countersignWithin')) o.countersignWithin = resolve(step.countersignWithin, ctx);
        ctx.writers[step.as] = await openRecorder(o);
        return { ok: true };
      }
      case 'clock': {
        const c = ctx.clock;
        if (Object.hasOwn(step, 'set')) c.time = step.set;
        if (Object.hasOwn(step, 'add')) c.time += step.add;
        if (Object.hasOwn(step, 'fail')) c.fail = step.fail;
        if (Object.hasOwn(step, 'failAt')) c.left = step.failAt;
        if (Object.hasOwn(step, 'gives')) {
          c.giving = true;
          c.gives = resolve(step.gives, ctx);
        }
        if (step.real) c.giving = false;
        return null;
      }
      case 'act': {
        const r = await w.act(resolve(step.request, ctx), performer(step.perform ?? {}, ctx, w, seen), moreOf(step.more, ctx, w, seen));
        return { done: r.done, answer: norm(r.answer, ctx), result: norm(r.result, ctx), stub: norm(r.stub, ctx), seen: norm(seen, ctx) };
      }
      case 'record': {
        const r = await w.record(resolve(step.request, ctx), moreOf(step.more, ctx, w, seen));
        return { stub: norm(r, ctx), seen: norm(seen, ctx) };
      }
      case 'before':
        return { answer: norm(await w.before(resolve(step.request, ctx), moreOf(step.more, ctx, w, seen)), ctx) };
      case 'add': {
        let r;
        try {
          r = await w.add(resolve(step.entry, ctx));
        } catch (e) {
          if (step.label) ctx.acks[step.label] = e.acknowledgement ?? null;
          throw e;
        }
        if (step.label) ctx.acks[step.label] = r.acknowledgement ?? null;
        return { keys: Object.keys(r).sort(), acknowledgement: norm(r.acknowledgement, ctx) };
      }
      case 'book':
        return { book: norm(w.book(), ctx) };
      case 'check':
        return { check: norm(await w.check(), ctx) };
      case 'held':
        return { held: norm(w.cancellations(), ctx) };
      case 'checkBook':
        return { check: norm(await checkBook(resolve(step.text, ctx), resolve(step.options, ctx)), ctx) };
      case 'tools': {
        const seens = { current: {}, kept: {} };
        // "$whole" hands over a value in place of the tools; "recorder" hands over another value in place of the writer.
        let tools = {};
        if (Object.hasOwn(step.tools, '$whole')) tools = resolve(step.tools.$whole, ctx);
        else for (const [name, spec] of Object.entries(step.tools)) tools[name] = spec === null || typeof spec !== 'object' || Array.isArray(spec) ? resolve(spec, ctx) : toolOf(name, spec, ctx, w, seens);
        const options = {};
        if (step.onStub) {
          options.onStub = (stub, tool) => {
            (seens.current.onStub ??= []).push([tool, stub.seq]);
            if (Object.hasOwn(step.onStub, 'throws')) throw new Error(step.onStub.throws);
          };
        }
        ctx.tools[step.as] = { made: recordTools(Object.hasOwn(step, 'recorder') ? resolve(step.recorder, ctx) : w, tools, options), seens };
        return { names: Object.keys(ctx.tools[step.as].made) };
      }
      case 'call': {
        const t = ctx.tools[step.t];
        t.seens.current = {};
        t.seens.kept = {};
        const run = t.made[step.tool];
        try {
          const r = Object.hasOwn(step, 'args') ? await run(resolve(step.args, ctx)) : await run();
          return { result: norm(r, ctx), seen: norm(t.seens.current, ctx) };
        } catch (e) {
          return { ...failure(e, ctx), seen: norm(t.seens.current, ctx) };
        }
      }
      case 'fingerprint':
        return { fingerprint: await argumentsFingerprint(resolve(step.args, ctx)) };
      default:
        throw new Error(`no such step: ${step.op}`);
    }
  } catch (e) {
    const out = failure(e, ctx);
    if (Object.keys(seen).length) out.seen = norm(seen, ctx);
    return out;
  }
}

/**
 * Play a scenario. Returns its transcript: for each step, what it gave and
 * how many times the clock was read.
 */
export async function playScenario(scenario) {
  const known = new Set();
  for (const s of strings([scenario.world, scenario.steps], [])) for (const t of s.match(TOKEN) ?? []) if (t.length === SIGNATURE_LENGTH) known.add(t);
  const thrown = new Set();
  const gather = (v) => {
    if (Array.isArray(v)) v.forEach(gather);
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) k === 'throws' && typeof x === 'string' ? thrown.add(x) : gather(x);
  };
  gather(scenario.steps);
  const names = new Map();
  const counts = {};
  const ctx = {
    world: scenario.world,
    keys: {},
    writers: {},
    tools: {},
    acks: {},
    clock: makeClock(scenario.world.start),
    known,
    thrown,
    name(value, kind) {
      if (!names.has(value)) names.set(value, kind + (counts[kind] = (counts[kind] ?? 0) + 1));
      return names.get(value);
    },
  };
  for (const [name, s] of Object.entries(scenario.world.keys)) ctx.keys[name] = keySetFromSeeds(s.ed, s.ml);
  const transcript = [];
  const restore = fixIds();
  try {
    for (const step of scenario.steps) {
      ctx.clock.readings = 0;
      const out = await playStep(step, ctx);
      transcript.push({ op: step.op, reads: ctx.clock.readings, out });
    }
  } finally {
    restore();
  }
  return transcript;
}
