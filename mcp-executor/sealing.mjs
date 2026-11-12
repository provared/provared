// Sealing: the recorder's three keys, and the one object that signs a seal.
//
// A seal is the library's own (format description, section 21.1): the
// recorder signs the number of entries a book holds and their top
// fingerprint, with Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s. The executor
// writes no record of its own kind and no signature of its own making: the
// seal is made by the library's writeSeal and goes into the book through
// the stub writer's "add", which takes it only if the whole book still
// passes its check with it.
//
// Every use of the recorder's key file by the executor goes through this
// file: making it ("keys"), reading it to see that it is whole ("check"),
// and reading it to seal. The file itself is read and written by files.mjs,
// as every key file is. The executor asks a "sealer" for a seal over a book
// and is handed the record; it never holds the keys. That is the place
// where a later step can hand the signing to a central sealer (section
// 21.7), which holds the keys away from the executor: an object with the
// same "seal" takes this one's place, and a book looks the same.

import nodeCrypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { keySetFingerprint, writeSeal } from 'provared';
import { loadKeyFile, makeKeyFile } from './files.mjs';

/** Make the recorder's key file where there is none (three keys), and give its public keys. */
export function makeRecorderKeyFile(path) {
  return makeKeyFile(path, 'recorder');
}

/** Read the recorder's key file to see that it is a recorder's: its public keys. Throws where it is not. */
export async function readRecorderKeyFile(path) {
  return (await loadKeyFile(path, 'recorder')).keys;
}

/**
 * The recorder as the settings name it: its key file read, with the
 * fingerprint of its key set (how a person checking says which recorder
 * they expect). The third key signs through Node.js's thread pool, not in
 * the program's own thread, where the library's signer for a key in memory
 * would hold up every agent for the second or so that an SLH-DSA signature
 * takes: the same Node.js function, in its form with a callback.
 * @param {{keys: string, name: string}} recorder the path of its key file, and its name (a label on each seal)
 */
export async function loadRecorder(recorder) {
  const { keys, privateKeys } = await loadKeyFile(recorder.keys, 'recorder');
  const slh = nodeCrypto.createPrivateKey({ key: JSON.parse(readFileSync(recorder.keys, 'utf8')).keys[2], format: 'jwk' });
  const third = Object.freeze({
    key: keys[2],
    sign: (data) => new Promise((done, failed) => nodeCrypto.sign(null, data, slh, (e, signature) => (e ? failed(e) : done(new Uint8Array(signature))))),
  });
  return { name: recorder.name, keys, privateKeys: [privateKeys[0], privateKeys[1], third], fingerprint: await keySetFingerprint(keys) };
}

/**
 * A sealer that signs here, with the recorder's keys from its key file.
 * @param {{name: string, keys: object[], privateKeys: any[], fingerprint: string}} recorder as loadRecorder gives it
 * @returns {{fingerprint: string, name: string, seal: (book: string, fields: {previous?: string, when: number}) => Promise<{record: object, fingerprint: string}>}}
 */
export function localSealer(recorder) {
  return {
    /** The fingerprint of the recorder's key set. */
    fingerprint: recorder.fingerprint,
    name: recorder.name,
    /** A seal over the book as it stands, naming the seal before it where there is one. */
    async seal(book, { previous, when }) {
      const sealed = await writeSeal(book, { by: { keys: recorder.keys, name: recorder.name }, ...(previous ? { previous } : {}), when }, recorder.privateKeys);
      return { record: sealed.record, fingerprint: sealed.fingerprint };
    },
  };
}
