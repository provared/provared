// Signers: a key held elsewhere (a key service, a hardware module) that
// signs on request. Wherever "privateKeys" is taken, each item may be a key
// or a signer. A record made through signers is the same record; a signer
// that fails in any way leaves no record, and the error names the method
// and the key.

import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import {
  checkBook,
  countersign,
  entryLine,
  fromBase64url,
  generateKeySet,
  generateSealKeySet,
  signerFromKey,
  thumbprint,
  writeAcknowledgement,
  writeBook,
  writePass,
  writeRefusal,
  writeSeal,
  writeStub,
  writeTerms,
  writeVouching,
  writeWithdrawal,
} from '../src/index.js';
import { fromUtf8 } from '../src/encoding.js';
import { signingInput } from '../src/jws.js';
import { verifySignature } from '../src/signatures.js';
import { signWithKeySet } from '../src/stub.js';
import { START, makeWorld, openWriter } from './helpers/world.mjs';

const HOUR = 3600 * 1000;
const ORDER = 'supplies.order';
const FP = 'A'.repeat(43);
const ID = 'B'.repeat(21) + 'A';
const subtle = globalThis.crypto.subtle;

const real = (set, i) => signerFromKey(set.keys[i].alg, set.privateKeys[i], set.keys[i]);
const asSigners = (set) => set.keys.map((_, i) => real(set, i));
const order = (value) => ({ action: ORDER, amount: { unit: 'GBP', value }, with: 'supplier' });
const stubFields = { slip: FP, after: null, action: ORDER, when: START, id: ID };

async function verifies(record, keys) {
  for (let i = 0; i < record.signatures.length; i++) {
    const s = record.signatures[i];
    assert.equal(await verifySignature(keys[i], fromBase64url(s.signature), signingInput(s.protected, record.payload)), 'valid', `signature ${i}`);
  }
}

// The same record: the same content and labels, and the same Ed25519
// signature, which is deterministic (RFC 8032). ML-DSA-87 and SLH-DSA
// signatures are made afresh each time (FIPS 204 and FIPS 205, hedged), so
// they differ between any two signings, with a key or through a signer.
function sameRecord(a, b) {
  assert.equal(b.payload, a.payload);
  assert.deepEqual(
    b.signatures.map((s) => s.protected),
    a.signatures.map((s) => s.protected),
  );
  assert.equal(b.signatures[0].signature, a.signatures[0].signature);
}

// Whether an error is a refusal by a signer, naming the method, the key and its place.
function bySigner(i, alg, thumb, why) {
  return (e) => {
    assert.equal(e.code, 'signature-invalid');
    assert.ok(e.message.startsWith(`privateKeys[${i}]: the signer for the ${alg} key ${thumb} `), e.message);
    assert.match(e.message, why);
    assert.match(e.message, /No record was made\.$/);
    return true;
  };
}

test('every writer makes the same record through signers as with keys, and it checks', async () => {
  const set = await generateKeySet();
  const signers = asSigners(set);
  const by = { keys: set.keys, name: 'Example (invented)' };
  const writers = {
    stub: (keys) => writeStub(stubFields, keys),
    refusal: (keys) => writeRefusal({ slip: FP, by, action: ORDER, reason: 'over-limit', when: START, id: ID }, keys),
    terms: (keys) => writeTerms({ by, accepts: [ORDER], validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z', id: ID }, keys),
    pass: (keys) => writePass({ slip: FP, to: by, actions: [ORDER], validFrom: '2026-10-05T08:00:00Z', validUntil: '2026-10-06T08:00:00Z', when: START, id: ID }, keys),
    acknowledgement: (keys) => writeAcknowledgement({ slip: FP, cancellation: FP, when: START, id: ID }, keys),
    vouching: (keys) => writeVouching({ by, for: { kind: 'agent', keys: set.keys, name: 'Agent (invented)' }, validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z', when: START, id: ID }, keys),
    withdrawal: (keys) => writeWithdrawal({ vouching: FP, when: START, id: ID }, keys),
  };
  for (const [kind, write] of Object.entries(writers)) {
    const withKeys = (await write(set.privateKeys)).record;
    const through = await write(signers);
    sameRecord(withKeys, through.record);
    await verifies(through.record, set.keys);
    assert.equal(through.fingerprint, (await write(set.privateKeys)).fingerprint, kind);
  }
  const stub = (await writeStub(stubFields, set.privateKeys)).record;
  const a = await countersign(stub, set.privateKeys, START);
  const b = await countersign(stub, signers, START);
  sameRecord(a, b);
  await verifies(b, set.keys);
});

test('a seal through signers is the same seal as with keys, and a book sealed through them checks', async () => {
  const w = await makeWorld();
  await w.add();
  const recorder = await generateSealKeySet();
  const fields = { by: { keys: recorder.keys, name: 'Example recorder (invented)' }, when: START + HOUR, id: ID };
  const withKeys = await writeSeal(w.book(), fields, recorder.privateKeys);
  const through = await writeSeal(w.book(), fields, asSigners(recorder));
  sameRecord(withKeys.record, through.record);
  assert.equal(through.fingerprint, withKeys.fingerprint);
  await verifies(through.record, recorder.keys);
  const book = writeBook([...w.entries, { seal: through.record }]);
  const r = await checkBook(book, { issuerKeys: [await thumbprint(w.passkey.key)] });
  assert.equal(r.summary.problemFound, false);
  assert.equal(r.summary.fullyChecked, true);
  assert.deepEqual(r.entries.at(-1).signatures.map((s) => s.state), ['valid', 'valid', 'valid']);
});

test('keys and signers may be mixed, in either order', async () => {
  const set = await generateKeySet();
  const withKeys = (await writeStub(stubFields, set.privateKeys)).record;
  for (const mixed of [
    [real(set, 0), set.privateKeys[1]],
    [set.privateKeys[0], real(set, 1)],
  ]) {
    const record = (await writeStub(stubFields, mixed)).record;
    sameRecord(withKeys, record);
    await verifies(record, set.keys);
  }
});

test('a signer may be any object with "key" and "sign": its own "this" is kept, and Web Crypto\'s own answer is taken', async () => {
  const set = await generateKeySet();
  class Remote {
    #key;
    constructor(key) {
      this.#key = key;
    }
    get key() {
      return set.keys[0];
    }
    async sign(data) {
      return subtle.sign({ name: 'Ed25519' }, this.#key, data); // an ArrayBuffer, as Web Crypto gives it
    }
  }
  const record = (await writeStub(stubFields, [new Remote(set.privateKeys[0]), real(set, 1)])).record;
  await verifies(record, set.keys);
  // A Node.js Buffer is bytes too.
  const buffer = { key: set.keys[0], sign: async (d) => Buffer.from(await real(set, 0).sign(d)) };
  await verifies((await writeStub(stubFields, [buffer, set.privateKeys[1]])).record, set.keys);
});

test('a signer\'s two members are read once, and what it does to the bytes it is handed changes nothing', async () => {
  const set = await generateKeySet();
  let reads = 0;
  const inner = real(set, 1);
  const signer = {
    get key() {
      reads++;
      return reads === 1 ? set.keys[1] : (() => { throw new Error('read twice'); })();
    },
    async sign(data) {
      const signature = await inner.sign(data);
      data.fill(0); // the signer spoils what it was handed
      return signature;
    },
  };
  const record = (await writeStub(stubFields, [set.privateKeys[0], signer])).record;
  assert.equal(reads, 1);
  await verifies(record, set.keys);
});

test('a signer\'s key is copied before anything is signed: a key that changes once "sign" is called is refused', async () => {
  const set = await generateKeySet();
  const other = await generateKeySet();
  const by = { keys: set.keys, name: 'Example (invented)' };
  let flipped = false;
  const key = {
    kty: 'OKP',
    crv: 'Ed25519',
    alg: 'Ed25519',
    get x() {
      return flipped ? other.keys[0].x : set.keys[0].x;
    },
  };
  const signer = {
    key,
    sign(d) {
      flipped = true; // from now on the key it shows is another
      return real(other, 0).sign(d);
    },
  };
  const thumb = await thumbprint(set.keys[0]);
  await assert.rejects(
    writeTerms({ by, accepts: [ORDER], validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' }, [signer, real(set, 1)]),
    bySigner(0, 'Ed25519', thumb, /does not check against its key/),
  );
});

test('the signature a signer gives is copied before it is checked: a change it makes afterwards changes nothing', async () => {
  const set = await generateKeySet();
  const inner = real(set, 0);
  let given = null;
  const signer = {
    key: set.keys[0],
    async sign(d) {
      given = await inner.sign(d);
      return given;
    },
  };
  // The signer spoils what it gave as soon as the check of it has ended.
  const verify = subtle.verify;
  subtle.verify = async function (...args) {
    const answer = await verify.apply(this, args);
    if (given) given.fill(0);
    return answer;
  };
  let record;
  try {
    record = (await writeStub(stubFields, [signer, set.privateKeys[1]])).record;
  } finally {
    subtle.verify = verify;
  }
  assert.ok(given.every((b) => b === 0));
  await verifies(record, set.keys);
});

test('a signature of the wrong length is refused, and the error names the method and the key', async () => {
  const set = await generateKeySet();
  const cut = (i, length) => ({ key: set.keys[i], sign: async (d) => (await real(set, i).sign(d)).subarray(0, length) });
  await assert.rejects(writeStub(stubFields, [cut(0, 63), set.privateKeys[1]]), bySigner(0, 'Ed25519', await thumbprint(set.keys[0]), /gave a signature of 63 bytes, where an Ed25519 signature is 64\./));
  await assert.rejects(writeStub(stubFields, [set.privateKeys[0], cut(1, 4626)]), bySigner(1, 'ML-DSA-87', await thumbprint(set.keys[1]), /of 4626 bytes, where an ML-DSA-87 signature is 4627\./));
});

test('a signature from another key, or over other bytes, is refused', async () => {
  const set = await generateKeySet();
  const other = await generateKeySet();
  const why = /does not check against its key: it holds another key, or signed other bytes\./;
  const thumb = await thumbprint(set.keys[0]);
  // The right key named, another key used: a mistyped key name in a key service's settings.
  const wrongKey = { key: set.keys[0], sign: (d) => real(other, 0).sign(d) };
  await assert.rejects(writeStub(stubFields, [wrongKey, set.privateKeys[1]]), bySigner(0, 'Ed25519', thumb, why));
  // A service that signs a fingerprint of the bytes, where the bytes themselves were meant.
  const hashedFirst = { key: set.keys[0], sign: async (d) => subtle.sign({ name: 'Ed25519' }, set.privateKeys[0], await subtle.digest('SHA-256', d)) };
  await assert.rejects(writeStub(stubFields, [hashedFirst, set.privateKeys[1]]), bySigner(0, 'Ed25519', thumb, why));
  // Other bytes, for the quantum-safe half.
  const otherBytes = { key: set.keys[1], sign: (d) => real(set, 1).sign(new Uint8Array([...d, 0])) };
  await assert.rejects(writeStub(stubFields, [set.privateKeys[0], otherBytes]), bySigner(1, 'ML-DSA-87', await thumbprint(set.keys[1]), why));
});

test('a signer that throws, or gives something other than bytes, is refused', async () => {
  const set = await generateKeySet();
  const thumb = await thumbprint(set.keys[0]);
  const broken = new Error('the key service is down');
  const throwing = [
    { key: set.keys[0], sign: () => { throw broken; } },
    { key: set.keys[0], sign: async () => { throw broken; } },
  ];
  for (const signer of throwing) {
    await assert.rejects(writeStub(stubFields, [signer, set.privateKeys[1]]), (e) => bySigner(0, 'Ed25519', thumb, /failed with an error\./)(e) && e.cause === broken);
  }
  for (const given of ['a'.repeat(64), Array(64).fill(1), new Int16Array(32), new DataView(new ArrayBuffer(64)), { length: 64 }, null, undefined, 64]) {
    await assert.rejects(writeStub(stubFields, [{ key: set.keys[0], sign: async () => given }, set.privateKeys[1]]), bySigner(0, 'Ed25519', thumb, /gave something other than bytes\./));
  }
});

test('anything that is neither a key nor a signer is refused, in plain words', async () => {
  const set = await generateKeySet();
  const shape = /must be a private key for Ed25519 \(a Web Crypto CryptoKey\), or a signer: an object with "key"/;
  for (const item of ['text', null, undefined, 42, {}, { key: set.keys[0] }, { sign: async () => new Uint8Array(64) }, { key: null, sign: async () => new Uint8Array(64) }, set.keys[0]]) {
    await assert.rejects(writeStub(stubFields, [item, set.privateKeys[1]]), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys[0]: ') && shape.test(e.message));
  }
  // A public key where a private one belongs is refused too.
  const pair = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  await assert.rejects(writeStub(stubFields, [{ key: set.keys[0], sign: pair.publicKey }, set.privateKeys[1]]), (e) => e.code === 'bad-field');
  // What only looks like a private key of its place is refused in the same words, not with the platform's own error:
  // a public key, a key of another method, an object made from CryptoKey's own prototype, a key of the wrong kind for SLH-DSA.
  for (const item of [pair.publicKey, set.privateKeys[1], Object.create(CryptoKey.prototype)]) {
    await assert.rejects(writeStub(stubFields, [item, set.privateKeys[1]]), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys[0]: ') && shape.test(e.message));
  }
  const recorder = await generateSealKeySet();
  const w = await makeWorld();
  for (const third of [set.privateKeys[0], recorder.privateKeys[0]]) {
    await assert.rejects(writeSeal(w.book(), { by: { keys: recorder.keys, name: 'r' } }, [...recorder.privateKeys.slice(0, 2), third]), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys[2]: must be a private key for SLH-DSA-SHA2-256s (a Node.js KeyObject, or what Node.js reads as one'));
  }
  for (const list of ['text', undefined, null, { 0: set.privateKeys[0], 1: set.privateKeys[1] }]) {
    await assert.rejects(writeStub(stubFields, list), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys: must be a list'));
  }
  await assert.rejects(writeStub(stubFields, [set.privateKeys[0]]), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys[1]: '));
  // A list that cannot be read is refused, not crashed on.
  const unreadable = new Proxy([], { get: (t, name) => (name === 'length' ? 2 : (() => { throw new Error('no'); })()) });
  await assert.rejects(writeStub(stubFields, unreadable), (e) => e.code === 'bad-field');
  // A value that cannot even be looked into (a revoked Proxy), as an item, as the list, or as the key handed to signerFromKey.
  const revoked = () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  };
  await assert.rejects(writeStub(stubFields, [revoked(), set.privateKeys[1]]), (e) => e.code === 'bad-field' && e.message === 'privateKeys[0]: could not be read.');
  await assert.rejects(writeStub(stubFields, revoked()), (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys: must be a list'));
  assert.throws(() => signerFromKey('Ed25519', revoked(), set.keys[0]), (e) => e.code === 'bad-field');
});

test('in a seal\'s third place, a private SLH-DSA key written out is taken as Node.js took it before; a public key, or a private key of another kind, is not', async () => {
  const w = await makeWorld();
  await w.add();
  const recorder = await generateSealKeySet();
  const slh = recorder.privateKeys[2];
  const fields = { by: { keys: recorder.keys, name: 'Example recorder (invented)' }, when: START + HOUR, id: ID };
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const withKeyObject = await writeSeal(w.book(), fields, recorder.privateKeys);
  const written = {
    'PEM text': slh.export({ format: 'pem', type: 'pkcs8' }),
    'DER bytes with their format': { key: slh.export({ format: 'der', type: 'pkcs8' }), format: 'der', type: 'pkcs8' },
    'a JSON Web Key with its format': { key: slh.export({ format: 'jwk' }), format: 'jwk' },
  };
  for (const [form, third] of Object.entries(written)) {
    const sealed = await writeSeal(w.book(), fields, [...recorder.privateKeys.slice(0, 2), third]);
    sameRecord(withKeyObject.record, sealed.record);
    await verifies(sealed.record, recorder.keys);
    const r = await checkBook(writeBook([...w.entries, { seal: sealed.record }]), { issuerKeys });
    assert.equal(r.summary.problemFound, false, form);
    assert.equal(r.summary.fullyChecked, true, form);
  }
  // A public key, in any of these forms, and a private key of another kind are refused before anything is signed.
  const publicKey = createPublicKey(slh);
  const ed25519 = generateKeyPairSync('ed25519').privateKey;
  const refused = {
    'a public KeyObject': publicKey,
    'public PEM text': publicKey.export({ format: 'pem', type: 'spki' }),
    'public DER bytes': { key: publicKey.export({ format: 'der', type: 'spki' }), format: 'der', type: 'spki' },
    'a public JSON Web Key': { key: publicKey.export({ format: 'jwk' }), format: 'jwk' },
    'a private Ed25519 KeyObject': ed25519,
    'private Ed25519 PEM text': ed25519.export({ format: 'pem', type: 'pkcs8' }),
    'text that is not a key': 'not a key',
    'an object that is not a key': { format: 'jwk' },
  };
  for (const [form, third] of Object.entries(refused)) {
    await assert.rejects(
      writeSeal(w.book(), fields, [...recorder.privateKeys.slice(0, 2), third]),
      (e) => e.code === 'bad-field' && e.message.startsWith('privateKeys[2]: must be a private key for SLH-DSA-SHA2-256s (a Node.js KeyObject, or what Node.js reads as one'),
      form,
    );
  }
});

test('a signer\'s key must be exactly a key of the method of its place', async () => {
  const set = await generateKeySet();
  const sign = async () => new Uint8Array(64);
  for (const key of [set.keys[1], { ...set.keys[0], kid: 'x' }, { ...set.keys[0], x: 'A'.repeat(43) }, 'text', [set.keys[0]], { toJSON: () => set.keys[0] }]) {
    await assert.rejects(writeStub(stubFields, [{ key, sign }, set.privateKeys[1]]), (e) => e.code === 'bad-key' && e.message.startsWith('privateKeys[0].key: '));
  }
  await assert.rejects(writeStub(stubFields, [{ key: () => set.keys[0], sign }, set.privateKeys[1]]), (e) => e.code === 'bad-key');
});

test('a writer that knows the key a record must be signed with refuses a signer that holds another', async () => {
  const set = await generateKeySet();
  const other = await generateKeySet();
  const by = { keys: set.keys, name: 'Example (invented)' };
  const mixed = [real(other, 0), set.privateKeys[1]];
  const holds = await thumbprint(other.keys[0]);
  const must = await thumbprint(set.keys[0]);
  const named = (e) => {
    assert.equal(e.code, 'bad-key');
    assert.ok(e.message.startsWith(`privateKeys[0]: the signer holds the Ed25519 key ${holds}, which is not the key this record must be signed with (${must}).`), e.message);
    return true;
  };
  await assert.rejects(writeRefusal({ slip: FP, by, action: ORDER, reason: 'over-limit', when: START }, mixed), named);
  await assert.rejects(writeTerms({ by, accepts: [ORDER], validFrom: '2026-10-01T00:00:00Z', validUntil: '2027-10-01T00:00:00Z' }, mixed), named);
  await assert.rejects(writeVouching({ by, for: { kind: 'agent', keys: other.keys, name: 'A' }, validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' }, mixed), named);
  // A key in memory is used as it always was: the record is made, and fails its own check.
  const made = await writeRefusal({ slip: FP, by, action: ORDER, reason: 'over-limit', when: START }, other.privateKeys);
  assert.equal(await verifySignature(set.keys[0], fromBase64url(made.record.signatures[0].signature), signingInput(made.record.signatures[0].protected, made.record.payload)), 'invalid');
  // A seal: the recorder's three keys.
  const w = await makeWorld();
  const recorder = await generateSealKeySet();
  const otherRecorder = await generateSealKeySet();
  const sealSigners = [...asSigners(recorder).slice(0, 2), real(otherRecorder, 2)];
  const third = await thumbprint(otherRecorder.keys[2]);
  await assert.rejects(writeSeal(w.book(), { by: { keys: recorder.keys, name: 'r' } }, sealSigners), (e) => {
    assert.equal(e.code, 'bad-key');
    assert.ok(e.message.startsWith(`privateKeys[2]: the signer holds the SLH-DSA-SHA2-256s key ${third}`), e.message);
    return true;
  });
});

test('signerFromKey takes only a private key of the method it names, with its public key', async () => {
  const set = await generateKeySet();
  const recorder = await generateSealKeySet();
  assert.deepEqual(real(set, 0).key, set.keys[0]);
  assert.ok(Object.isFrozen(real(set, 0)) && Object.isFrozen(real(set, 0).key));
  assert.throws(() => signerFromKey('ES256', set.privateKeys[0], set.keys[0]), (e) => e.code === 'bad-field');
  assert.throws(() => signerFromKey('Ed25519', set.privateKeys[1], set.keys[0]), (e) => e.code === 'bad-field' && /a private key for Ed25519/.test(e.message));
  assert.throws(() => signerFromKey('ML-DSA-87', recorder.privateKeys[2], set.keys[1]), (e) => e.code === 'bad-field');
  assert.throws(() => signerFromKey('SLH-DSA-SHA2-256s', set.privateKeys[0], recorder.keys[2]), (e) => e.code === 'bad-field');
  assert.throws(() => signerFromKey('Ed25519', 'text', set.keys[0]), (e) => e.code === 'bad-field');
  const pair = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  assert.throws(() => signerFromKey('Ed25519', pair.publicKey, set.keys[0]), (e) => e.code === 'bad-field');
  assert.throws(() => signerFromKey('Ed25519', set.privateKeys[0], set.keys[1]), (e) => e.code === 'bad-key');
  assert.throws(() => signerFromKey('Ed25519', set.privateKeys[0], () => 1), (e) => e.code === 'bad-key');
  // A public key that does not belong to the private key makes a signer whose every signature is refused.
  const other = await generateKeySet();
  const mismatched = signerFromKey('Ed25519', other.privateKeys[0], set.keys[0]);
  await assert.rejects(writeStub(stubFields, [mismatched, set.privateKeys[1]]), (e) => e.code === 'signature-invalid');
});

// --- the stub writer ---

async function opened(w, more = {}) {
  return openWriter({ book: w.book(), slip: w.slipFingerprint, privateKeys: w.agent.privateKeys, issuerKeys: [await thumbprint(w.passkey.key)], ...more });
}

// What a check says, without the fingerprints that differ from one world to another.
function shapeOf(r) {
  return {
    summary: r.summary,
    entries: r.entries.map((e) => ({
      kind: e.kind,
      problems: e.problems.map((p) => p.code),
      breaches: e.breaches.map((b) => b.code),
      signatures: (e.signatures ?? []).map((s) => s.state),
      countersignature: e.countersignature ? e.countersignature.state : null,
    })),
  };
}

test('the stub writer through signers: the same run gives the same record, and its view is the whole check\'s', async () => {
  const run = async (useSigners) => {
    const agent = await generateKeySet();
    const service = await generateKeySet();
    const w = await makeWorld({ agent: useSigners ? { keys: agent.keys, privateKeys: asSigners(agent) } : agent, service });
    const issuerKeys = [await thumbprint(w.passkey.key)];
    let clock = START;
    const writer = await opened(w, { now: () => clock });
    const countersigner = useSigners ? asSigners(service) : service.privateKeys;
    const outcomes = [];
    outcomes.push((await writer.act(order(150), async () => 1, { countersign: (stub) => countersign(stub, countersigner, clock + 1000) })).done);
    clock += HOUR;
    outcomes.push((await writer.act(order(60), async () => 2)).done);
    outcomes.push((await writer.record(order(60))).seq);
    clock += HOUR;
    const cancelled = await w.cancel({ when: clock - 1000 });
    const added = await writer.add(cancelled.entry);
    outcomes.push(Boolean(added.acknowledgement));
    clock += HOUR;
    outcomes.push((await writer.act(order(1), async () => 3)).done);
    const whole = await checkBook(writer.book(), { issuerKeys });
    assert.deepEqual(await writer.check(), whole);
    return { outcomes, shape: shapeOf(whole) };
  };
  const withKeys = await run(false);
  const through = await run(true);
  assert.deepEqual(withKeys.outcomes, [true, false, 1, true, false]);
  assert.deepEqual(through, withKeys);
  assert.equal(through.shape.summary.problemFound, false);
  assert.deepEqual(
    through.shape.entries.map((e) => e.kind),
    ['slip', 'stub', 'stub', 'cancellation', 'acknowledgement'],
  );
});

test('a book written through signers checks exactly as the same book written with keys', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  await w.add();
  await w.add({ value: 300 });
  const helper = await w.pass();
  await helper.add();
  await w.refuse();
  await w.publishTerms();
  const cancelled = await w.cancel();
  await w.acknowledge(cancelled.fingerprint);
  const vouching = await w.vouch({ kind: 'agent', keys: w.agent.keys, name: 'Office supplies agent' });
  await w.withdraw(vouching.fingerprint);
  const book = w.book();
  // Each record signed with keys is signed again, through signers, from its own content.
  const sets = [w.agent, w.service, helper.helper, w.organisation];
  const again = async (kind, record) => {
    const s = record.signatures[0];
    let set;
    for (const candidate of sets) {
      if ((await verifySignature(candidate.keys[0], fromBase64url(s.signature), signingInput(s.protected, record.payload))) === 'valid') set = candidate;
    }
    const content = JSON.parse(fromUtf8(fromBase64url(record.payload)));
    const made = (await signWithKeySet(kind, content, asSigners(set))).record;
    sameRecord(record, made);
    return made;
  };
  const kinds = ['stub', 'countersignature', 'refusal', 'terms', 'pass', 'acknowledgement', 'vouching', 'withdrawal'];
  const lines = [];
  let signedAgain = 0;
  for (const line of book.trimEnd().split('\n')) {
    const entry = JSON.parse(line);
    for (const kind of kinds) {
      if (entry[kind]) {
        entry[kind] = await again(kind, entry[kind]);
        signedAgain++;
      }
    }
    lines.push(entryLine(entry));
  }
  assert.equal(signedAgain, 12);
  const options = { issuerKeys: [await thumbprint(w.passkey.key)] };
  const a = await checkBook(book, options);
  const b = await checkBook(lines.join('\n') + '\n', options);
  assert.notEqual(b.root, a.root); // the lines hold other ML-DSA-87 signatures
  assert.deepEqual({ ...b, root: null }, { ...a, root: null });
  assert.equal(a.summary.problemFound, false);
});

test('in the stub writer, a signer that fails leaves nothing written, and the writer\'s view of its book stays exact', async () => {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const broken = new Error('the key service is down');
  let failing = true;
  const ml = real(w.agent, 1);
  const signers = [real(w.agent, 0), { key: w.agent.keys[1], sign: async (d) => { if (failing) throw broken; return ml.sign(d); } }];
  const writer = await opened(w, { privateKeys: signers });
  const thumb = await thumbprint(w.agent.keys[1]);
  const book = writer.book();
  let taken = 0;
  const out = await writer.act(order(10), async () => ++taken, { when: START });
  assert.equal(out.done, false);
  assert.equal(taken, 0);
  assert.deepEqual(out.answer.problems.at(-1), { code: 'signature-invalid', message: `privateKeys[1]: the signer for the ML-DSA-87 key ${thumb} failed with an error. No record was made.` });
  await assert.rejects(writer.record(order(10), { when: START }), (e) => e.code === 'signature-invalid' && e.cause === broken);
  assert.equal(writer.book(), book);
  assert.deepEqual(await writer.check(), await checkBook(book, { issuerKeys }));
  failing = false;
  const next = await writer.act(order(10), async () => ++taken, { when: START + 1000 });
  assert.equal(next.done, true);
  assert.equal(next.stub.seq, 0);
  assert.deepEqual(await writer.check(), await checkBook(writer.book(), { issuerKeys }));
});

test('in the stub writer, a signer that never answers is given "signWithin", then nothing is written and the writer goes on', { timeout: 20000 }, async () => {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const ml = real(w.agent, 1);
  let mode = 'hang';
  const late = [];
  const signer = {
    key: w.agent.keys[1],
    sign(d) {
      if (mode === 'hang') return new Promise(() => {});
      if (mode === 'late') {
        const p = new Promise((resolve) => setTimeout(() => resolve(ml.sign(d)), 300));
        late.push(p);
        return p;
      }
      return ml.sign(d);
    },
  };
  const writer = await opened(w, { privateKeys: [real(w.agent, 0), signer], signWithin: 100 });
  const book = writer.book();
  const thumb = await thumbprint(w.agent.keys[1]);
  const started = Date.now();
  const out = await writer.act(order(10), async () => 'taken', { when: START });
  assert.equal(out.done, false);
  assert.deepEqual(out.answer.problems.at(-1), { code: 'signature-invalid', message: `privateKeys[1]: the signer for the ML-DSA-87 key ${thumb} gave no answer within 100 milliseconds. No record was made.` });
  assert.ok(Date.now() - started < 5000);
  // The writer's turn was let go: the next call is answered.
  assert.equal((await writer.before(order(10), { when: START })).allowed, true);
  // A late answer is not used.
  mode = 'late';
  await assert.rejects(writer.record(order(10), { when: START }), (e) => e.code === 'signature-invalid' && /gave no answer within 100 milliseconds/.test(e.message));
  await Promise.all(late);
  assert.equal(writer.book(), book);
  assert.deepEqual(await writer.check(), await checkBook(book, { issuerKeys }));
  mode = 'answer';
  assert.equal((await writer.act(order(10), async () => 'taken', { when: START + 1000 })).stub.seq, 0);
  // A time that is not a number of milliseconds from 1 to 2^31 - 1 is refused when the writer is opened.
  for (const signWithin of [0, -1, NaN, 2 ** 31, '100', Infinity]) {
    await assert.rejects(opened(w, { signWithin }), (e) => e.code === 'bad-field' && e.message.startsWith('signWithin: '));
  }
});

test('in the stub writer, a signer that calls the writer is refused at once, as an action is', { timeout: 20000 }, async () => {
  const w = await makeWorld();
  const ml = real(w.agent, 1);
  let writer;
  const signer = {
    key: w.agent.keys[1],
    async sign(d) {
      await writer.before(order(1), { when: START });
      return ml.sign(d);
    },
  };
  writer = await opened(w, { privateKeys: [real(w.agent, 0), signer], signWithin: 4000 });
  const started = Date.now();
  await assert.rejects(writer.record(order(10), { when: START }), (e) => e.code === 'signature-invalid' && /called from inside an action/.test(e.cause?.message));
  assert.ok(Date.now() - started < 2000, 'refused at once, not after signWithin');
});

test('in the stub writer, a signer that hangs while a cancellation is added does not hold the writer: the cancellation goes in, with no acknowledgement', { timeout: 20000 }, async () => {
  const w = await makeWorld();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const ml = real(w.agent, 1);
  let hang = false;
  const signer = { key: w.agent.keys[1], sign: (d) => (hang ? new Promise(() => {}) : ml.sign(d)) };
  let clock = START;
  const writer = await opened(w, { privateKeys: [real(w.agent, 0), signer], signWithin: 100, now: () => clock });
  assert.equal((await writer.act(order(10), async () => 1)).done, true);
  clock += HOUR;
  hang = true;
  const cancelled = await w.cancel({ when: clock - 1000 });
  const added = await writer.add(cancelled.entry);
  assert.equal(added.acknowledgement, undefined);
  const whole = await checkBook(writer.book(), { issuerKeys });
  assert.deepEqual(
    whole.entries.map((e) => e.kind),
    ['slip', 'stub', 'cancellation'],
  );
  assert.equal(whole.summary.problemFound, false);
  assert.deepEqual(await writer.check(), whole);
  // The writer goes on: it is stopped by the cancellation, and says so at once.
  assert.equal((await writer.act(order(1), async () => 2)).done, false);
});

test('the stub writer refuses, when it is opened, a signer that holds another key than its agent\'s', async () => {
  const w = await makeWorld({ fields: { passes: 1 } });
  const other = await generateKeySet();
  const holds = await thumbprint(other.keys[0]);
  const must = await thumbprint(w.agent.keys[0]);
  await assert.rejects(opened(w, { privateKeys: [real(other, 0), w.agent.privateKeys[1]] }), (e) => {
    assert.equal(e.code, 'bad-key');
    assert.ok(e.message.startsWith(`privateKeys[0]: the signer holds the Ed25519 key ${holds}, which is not the key this record must be signed with (${must}).`), e.message);
    return true;
  });
  await assert.rejects(opened(w, { privateKeys: ['text', w.agent.privateKeys[1]] }), (e) => e.code === 'bad-field');
  // A helper agent under a pass: its own keys, as the pass names them; not the slip's agent's.
  const helper = await w.pass();
  const issuerKeys = [await thumbprint(w.passkey.key)];
  const under = { book: w.book(), slip: w.slipFingerprint, issuerKeys, pass: helper.fingerprint };
  const helperThumb = await thumbprint(helper.helper.keys[0]);
  await assert.rejects(openWriter({ ...under, privateKeys: asSigners(w.agent) }), (e) => e.code === 'bad-key' && e.message.includes(`(${helperThumb})`));
  const writer = await openWriter({ ...under, privateKeys: asSigners(helper.helper) });
  const out = await writer.act(order(10), async () => 'taken', { when: START + HOUR, countersign: (stub) => countersign(stub, w.service.privateKeys, START + HOUR) });
  assert.equal(out.done, true);
  assert.equal((await checkBook(writer.book(), { issuerKeys })).summary.problemFound, false);
});
