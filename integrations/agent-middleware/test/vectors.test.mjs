// AMW's own published test data (vectors/), every case: the reader must
// give the answer the data expects. The data is read as data; no AMW
// program is run.

import './local-library.mjs';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const { STATUSES, readKeys, verifyRecord } = await import('../verify.mjs');

const read = (name) => JSON.parse(readFileSync(new URL(`vectors/${name}`, import.meta.url), 'utf8'));
const keys = read('keys.json');
const files = [
  ['permit', 'permits.json'],
  ['receipt', 'receipts.json'],
  ['receipt', 'rotation.json'],
];

test('the published key list reads as a list of keys', () => {
  const list = readKeys(keys);
  assert.equal(list.length, 1);
  assert.equal(list[0].kid, 'sk_golden_0001');
  assert.deepEqual(readKeys(list), list);
  assert.throws(() => readKeys({}), /must be a list/);
  assert.throws(() => readKeys([{ alg: 'Ed25519' }]), /text "kid"/);
});

let total = 0;
for (const [kind, file] of files) {
  const { cases } = read(file);
  for (const c of cases) {
    total += 1;
    test(`${file}: ${c.name} is ${c.expect}`, () => {
      assert.ok(STATUSES.includes(c.expect), 'the expected answer is one of the six');
      const answer = verifyRecord(c.bundle, c.keys ?? keys, kind);
      assert.equal(answer.status, c.expect, answer.reason);
      assert.equal(answer.kind, kind);
      assert.equal(typeof answer.reason, 'string');
      // What a record that did not verify says is not shown.
      if (c.expect === 'verified') {
        assert.ok(answer.content && typeof answer.content === 'object');
        assert.equal(answer.content[`${kind}_id`], answer.id);
        assert.equal(answer.key.kid, answer.content.kid);
      } else {
        assert.equal(answer.content, null);
      }
    });
  }
}

test('every case of the three files was run', () => {
  assert.equal(total, 28 + 67 + 1);
});

test('a receipt presented as a permit, and a permit as a receipt, are malformed', () => {
  const receipt = read('receipts.json').cases.find((c) => c.name === 'success_legacy.valid').bundle;
  const permit = read('permits.json').cases.find((c) => c.name === 'active_minimal.valid').bundle;
  assert.equal(verifyRecord(receipt, keys, 'permit').status, 'malformed');
  assert.equal(verifyRecord(permit, keys, 'receipt').status, 'malformed');
  assert.equal(verifyRecord(receipt, keys, 'receipt').status, 'verified');
  assert.equal(verifyRecord(permit, keys, 'permit').status, 'verified');
  assert.throws(() => verifyRecord(receipt, keys, 'approval'), /kind must be/);
});

test('an Ed25519 signature whose S is not below the group order is invalid (RFC 8032, section 5.1.7)', () => {
  const valid = read('receipts.json').cases.find((c) => c.name === 'success_legacy.valid').bundle;
  const sig = Buffer.from(valid.signature, 'base64');
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const S = BigInt('0x' + Buffer.from(sig.subarray(32)).reverse().toString('hex'));
  const big = (S + L).toString(16).padStart(64, '0');
  const forged = Buffer.concat([sig.subarray(0, 32), Buffer.from(big, 'hex').reverse()]);
  assert.equal(forged.length, 64);
  const answer = verifyRecord({ ...valid, signature: forged.toString('base64') }, keys, 'receipt');
  assert.equal(answer.status, 'invalid');
  assert.equal(verifyRecord(valid, keys, 'receipt').status, 'verified');
});

test('a signature is read only in its one strict base64 spelling', () => {
  const valid = read('receipts.json').cases.find((c) => c.name === 'success_legacy.valid').bundle;
  assert.ok(valid.signature.endsWith('=='));
  // The same 64 bytes without their padding: a lenient reader decodes them; this one refuses them.
  const unpadded = verifyRecord({ ...valid, signature: valid.signature.slice(0, -2) }, keys, 'receipt');
  assert.equal(unpadded.status, 'malformed');
  assert.match(unpadded.reason, /strict base64/);
  // Another spelling of the same 64 bytes: the last character before the
  // padding with its lowest bit flipped, which a lenient reader drops.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const last = valid.signature[valid.signature.length - 3];
  const other = alphabet[alphabet.indexOf(last) ^ 1];
  const bent = valid.signature.slice(0, -3) + other + '==';
  assert.deepEqual(Buffer.from(bent, 'base64'), Buffer.from(valid.signature, 'base64'), 'the same bytes, spelt another way');
  const answer = verifyRecord({ ...valid, signature: bent }, keys, 'receipt');
  assert.equal(answer.status, 'malformed');
  assert.match(answer.reason, /strict base64/);
});

test('the reasons name the check that failed, and copy no text from the record', () => {
  const { cases } = read('receipts.json');
  const by = (name) => verifyRecord(cases.find((c) => c.name === name).bundle, cases.find((c) => c.name === name).keys ?? keys, 'receipt');
  assert.match(by('synthetic.envelope_kid_mismatch').reason, /"kid"/);
  assert.match(by('synthetic.envelope_alg_mismatch').reason, /"alg"/);
  assert.match(by('synthetic.envelope_canonicalization_mismatch').reason, /"canonicalization"/);
  assert.match(by('success_legacy.envelope_receipt_id_mismatch').reason, /"receipt_id"/);
  assert.match(by('synthetic.disabled_key').reason, /"disabled"/);
  assert.match(by('synthetic.malformed_signature_length').reason, /64 bytes/);
  assert.match(by('synthetic.unsupported_alg').reason, /other than Ed25519/);
  assert.match(by('unsupported.future_canonicalization').reason, /other than awi-canonical-json\/1/);
  assert.match(by('p256.valid').reason, /other than Ed25519/);
  assert.doesNotMatch(by('synthetic.envelope_kid_mismatch').reason, /sk_envelope_only/);
  assert.doesNotMatch(by('success_legacy.envelope_receipt_id_mismatch').reason, /rcpt_not_the_signed_one/);
});
