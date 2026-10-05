// Outside time-stamps (RFC 3161): what is accepted, and what is refused.
// The time-stamps are made by a made-up service (helpers/stamp.mjs) and,
// for a second opinion, by the OpenSSL program (fixtures/stamps.json).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ecdsaToRaw, readElement, timeOf } from '../src/der.js';
import { fromBase64url, sha256, utf8 } from '../src/encoding.js';
import { MAX_STAMP_BYTES, checkStamp } from '../src/timestamp.js';
import { makeStampService } from './helpers/stamp.mjs';

const WHEN = Date.parse('2026-10-05T12:00:00Z');
const stamped = await sha256(utf8('what was stamped'));

const code = (expected) => (e) => e.code === expected;

test('a time-stamp from a service the checker trusts is valid, with each signing method', async () => {
  for (const method of ['ECDSA', 'RSA', 'Ed25519']) {
    const service = await makeStampService(method);
    const token = await service.stamp(stamped, WHEN);
    const r = await checkStamp(token, stamped, { trusted: [service.fingerprint] });
    assert.deepEqual(r, { state: 'valid', when: '2026-10-05T12:00:00Z', time: WHEN, authority: service.fingerprint }, method);
  }
});

test('a sound time-stamp from a service the checker did not name is "untrusted", never valid', async () => {
  const service = await makeStampService();
  const other = await makeStampService();
  const token = await service.stamp(stamped, WHEN);
  for (const trusted of [undefined, [], [other.fingerprint], 'everything']) {
    const r = await checkStamp(token, stamped, { trusted });
    assert.equal(r.state, 'untrusted');
    assert.equal(r.authority, service.fingerprint);
  }
});

test('a time-stamp made for something else is refused', async () => {
  const service = await makeStampService();
  const token = await service.stamp(await sha256(utf8('something else')), WHEN);
  await assert.rejects(checkStamp(token, stamped, { trusted: [service.fingerprint] }), code('stamp-wrong-data'));
  // The same 32 bytes, said to be made with another fingerprint method.
  const otherHash = await service.stamp(stamped, WHEN, { hash: '608648016503040203' });
  await assert.rejects(checkStamp(otherHash, stamped, { trusted: [service.fingerprint] }), code('stamp-wrong-data'));
});

test('a time-stamp whose statement, attributes or signature were changed is refused', async () => {
  const service = await makeStampService();
  const trusted = [service.fingerprint];
  const flip = (s) => {
    const changed = s.slice();
    changed[changed.length - 1] ^= 1;
    return changed;
  };
  const bad = [
    await service.stamp(stamped, WHEN, { signature: flip }),
    await service.stamp(stamped, WHEN, { digest: await sha256(utf8('x')) }),
    await service.stamp(stamped, WHEN, { kind: '2a864886f70d010701' }),
    await service.stamp(stamped, WHEN, { attributes: (a) => [a[0]] }),
    await service.stamp(stamped, WHEN, { attributes: (a) => [a[1]] }),
    await service.stamp(stamped, WHEN, { attributes: (a) => [a[0], a[0], a[1]] }),
    await service.stamp(stamped, WHEN, { noCertificate: true }),
    await service.stamp(stamped, WHEN, { certificate: (await makeStampService()).certificate }),
  ];
  for (const [i, token] of bad.entries()) {
    await assert.rejects(checkStamp(token, stamped, { trusted }), code('stamp-invalid'), `case ${i}`);
  }
});

test('the time in a time-stamp cannot be changed without breaking it', async () => {
  const service = await makeStampService();
  const token = await service.stamp(stamped, WHEN);
  // "20261005120000Z" appears once, in the statement. Make it a day earlier.
  const text = Buffer.from(token).toString('latin1');
  const at = text.indexOf('20261005120000Z');
  assert.ok(at > 0);
  const changed = token.slice();
  changed[at + 7] = '4'.charCodeAt(0);
  await assert.rejects(checkStamp(changed, stamped, { trusted: [service.fingerprint] }), code('stamp-invalid'));
});

test('a time-stamp dated outside the time its certificate was in force is refused', async () => {
  const service = await makeStampService('ECDSA', { notBefore: WHEN - 1000, notAfter: WHEN + 1000 });
  const trusted = [service.fingerprint];
  assert.equal((await checkStamp(await service.stamp(stamped, WHEN), stamped, { trusted })).state, 'valid');
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN - 2000), stamped, { trusted }), code('stamp-invalid'));
  await assert.rejects(checkStamp(await service.stamp(stamped, WHEN + 2000), stamped, { trusted }), code('stamp-invalid'));
});

test('bytes that are not a time-stamp are refused, never crashed on', async () => {
  const service = await makeStampService();
  const token = await service.stamp(stamped, WHEN);
  const cases = [
    new Uint8Array(0),
    new Uint8Array([0x30]),
    new Uint8Array([0x30, 0x80, 0, 0]), // the indefinite form
    new Uint8Array([0x30, 0x81, 0x01, 0x00]), // a length not in its shortest form
    new Uint8Array([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
    new Uint8Array([0x1f, 0x81, 0x00]),
    token.subarray(0, token.length - 1),
    new Uint8Array([...token, 0]),
    new Uint8Array(MAX_STAMP_BYTES + 1).fill(0x30),
    await service.stamp(stamped, WHEN, { version: 2 }),
    await service.stamp(stamped, WHEN, { enclosed: new Uint8Array([0x30, 0x00]) }),
    await service.stamp(stamped, WHEN, { statement: new Uint8Array([0x04, 0x00]) }),
  ];
  for (const [i, bytes] of cases.entries()) {
    await assert.rejects(checkStamp(bytes, stamped), code('stamp-bad-data'), `case ${i}`);
  }
  for (const notBytes of [null, 'text', 42, {}, [1, 2]]) await assert.rejects(checkStamp(notBytes, stamped), code('stamp-bad-data'));
  // Every single byte changed in turn: never a crash. Some bytes of the
  // wrapper are not covered by the service's signature: its version
  // numbers, the list of fingerprint methods, and the lines that say which
  // certificate signed (the checker finds that out from the key instead).
  // Changing those leaves the time-stamp valid, and must leave what it says
  // exactly as it was. Every byte of the statement, the signed attributes,
  // the signature and the certificate is covered.
  let stillValid = 0;
  for (let i = 0; i < token.length; i++) {
    const changed = token.slice();
    changed[i] ^= 0x01;
    let r = null;
    try {
      r = await checkStamp(changed, stamped, { trusted: [service.fingerprint] });
    } catch (e) {
      assert.match(String(e.code), /^stamp-/, `byte ${i}: ${e.message}`);
    }
    if (r && r.state === 'valid') {
      stillValid++;
      assert.deepEqual(r, { state: 'valid', when: '2026-10-05T12:00:00Z', time: WHEN, authority: service.fingerprint }, `byte ${i}`);
    }
  }
  assert.ok(stillValid > 0 && stillValid < token.length / 4, `${stillValid} of ${token.length} bytes could be changed`);
});

test('where the device lacks the service\'s signing method, the time-stamp is not confirmed', async () => {
  const service = await makeStampService('ECDSA');
  const token = await service.stamp(stamped, WHEN);
  const r = await checkStamp(token, stamped, { trusted: [service.fingerprint], without: ['ECDSA'] });
  assert.equal(r.state, 'unavailable');
  assert.equal(r.authority, null);
});

test('times are read only in the forms DER allows', () => {
  const time = (tag, text) => {
    const bytes = new Uint8Array([tag, text.length, ...Buffer.from(text)]);
    return timeOf(bytes, readElement(bytes, 0));
  };
  assert.equal(time(0x18, '20261005120000Z'), WHEN);
  assert.equal(time(0x18, '20261005120000.5Z'), WHEN + 500);
  assert.equal(time(0x17, '261005120000Z'), WHEN);
  assert.equal(time(0x17, '991231235959Z'), Date.parse('1999-12-31T23:59:59Z'));
  for (const [tag, text] of [
    [0x18, '20261005120000'],
    [0x18, '20261005120000+0100'],
    [0x18, '20261005120000.50Z'],
    [0x18, '20261305120000Z'],
    [0x18, '20260230120000Z'],
    [0x18, '20261005250000Z'],
    [0x17, '2610051200Z'],
    [0x04, '20261005120000Z'],
  ]) {
    assert.throws(() => time(tag, text), code('stamp-bad-data'), text);
  }
});

test('an ECDSA signature is read only in its one strict form', () => {
  const good = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07]);
  const raw = ecdsaToRaw(good, 32);
  assert.equal(raw.length, 64);
  assert.equal(raw[31], 5);
  assert.equal(raw[63], 7);
  for (const bad of [
    [0x30, 0x06, 0x02, 0x01, 0x85, 0x02, 0x01, 0x07], // negative
    [0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x07], // not shortest
    [0x30, 0x03, 0x02, 0x01, 0x05], // one number
    [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07, 0x00], // bytes left over
    [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x07], // an empty number
  ]) {
    assert.throws(() => ecdsaToRaw(new Uint8Array(bad), 32), code('stamp-bad-data'));
  }
});

test('time-stamps made by the OpenSSL program check, and say what they said when they were made', async () => {
  const fixtures = JSON.parse(readFileSync(new URL('./fixtures/stamps.json', import.meta.url), 'utf8'));
  assert.ok(fixtures.stamps.length >= 2);
  for (const s of fixtures.stamps) {
    const r = await checkStamp(fromBase64url(s.token), fromBase64url(s.stamped), { trusted: [s.authority] });
    assert.deepEqual({ state: r.state, when: r.when, authority: r.authority }, { state: 'valid', when: s.when, authority: s.authority }, s.about);
    assert.equal((await checkStamp(fromBase64url(s.token), fromBase64url(s.stamped))).state, 'untrusted');
    await assert.rejects(checkStamp(fromBase64url(s.token), stamped, { trusted: [s.authority] }), code('stamp-wrong-data'));
  }
});
