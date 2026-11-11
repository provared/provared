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
// Everything that touches the recorder's private keys is in this file. The
// executor asks a "sealer" for a seal over a book and is handed the record;
// it never sees the keys. That is the place where a later step can hand
// the signing to a central sealer (section 21.7), which holds the keys away
// from the executor and is sent each line's leaf fingerprint: an object
// with the same "seal" takes this one's place, and a book looks the same.

import { keySetFingerprint, writeSeal } from 'provared';
import { loadKeyFile } from './files.mjs';

/**
 * The recorder as the settings name it: its key file read, with the
 * fingerprint of its key set (how a person checking says which recorder
 * they expect).
 * @param {{keys: string, name: string}} recorder the path of its key file, and its name (a label on each seal)
 */
export async function loadRecorder(recorder) {
  const { keys, privateKeys } = await loadKeyFile(recorder.keys, 'recorder');
  return { name: recorder.name, keys, privateKeys, fingerprint: await keySetFingerprint(keys) };
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
