// A signer for a method this device does not have built in, as in a browser
// without ML-DSA: it is refused before any signer is asked to sign. This
// file runs in a process of its own, in which the device is made to say,
// from the start, that it has no ML-DSA-87.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeySet, signerFromKey, thumbprint, writeStub } from '../src/index.js';
import { START } from './helpers/world.mjs';

test('a signer for a method this device does not have built in is refused before any signer is asked', async () => {
  const set = await generateKeySet(); // made before the device is made to lack the method
  const subtle = globalThis.crypto.subtle;
  const generateKey = subtle.generateKey;
  // How the library asks whether a method is built in: by trying to make a key with it.
  subtle.generateKey = function (algorithm, ...rest) {
    if (algorithm && algorithm.name === 'ML-DSA-87') return Promise.reject(new Error('not built in'));
    return generateKey.call(this, algorithm, ...rest);
  };
  try {
    const asked = [];
    const asking = (i) => {
      const inner = signerFromKey(set.keys[i].alg, set.privateKeys[i], set.keys[i]);
      return { key: set.keys[i], sign: (d) => (asked.push(set.keys[i].alg), inner.sign(d)) };
    };
    const fields = { slip: 'A'.repeat(43), after: null, action: 'supplies.order', when: START, id: 'B'.repeat(21) + 'A' };
    const thumb = await thumbprint(set.keys[1]);
    await assert.rejects(writeStub(fields, [asking(0), asking(1)]), (e) => {
      assert.equal(e.code, 'bad-key');
      assert.equal(e.message, `privateKeys[1]: this device does not have ML-DSA-87 built in, so it cannot check a signature from the signer for the ML-DSA-87 key ${thumb}. No record was made.`);
      return true;
    });
    assert.deepEqual(asked, []);
  } finally {
    subtle.generateKey = generateKey;
  }
});
