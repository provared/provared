#!/usr/bin/env node
// An example adapter written only on the public interface of Provared's
// JavaScript library: the functions a program gets from `import ... from
// 'provared'` and `'provared/check'`, as the npm package offers them. It is
// here to show how an adapter for another implementation can be written:
// it decodes each case, calls the implementation's own functions, and puts
// the answer in the shape the shared test files store.
//
//   node conformance/run.mjs -- node --disable-warning=ExperimentalWarning conformance/adapters/provared-public.mjs
//   node conformance/run.mjs -- node --disable-warning=ExperimentalWarning conformance/adapters/provared-public.mjs --package node_modules/provared
//
// It loads the library through the "exports" list of the package's own
// package.json (the entry points "." and "./check"), from this repository
// by default, or from the folder given with --package (an installed copy of
// the npm package). It imports no other file of the library.
//
// Some sets of cases test parts of the library that are not offered to
// other programs (reading DER, the tree's inner steps, the checks of each
// record's content, and so on). The public functions cannot answer them,
// so this adapter skips them and says why, case by case. SKIPPED, below,
// lists them. adapters/provared.mjs answers every case, through the
// library's own test table.

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// --- the library, through its public entry points only ---

const at = process.argv.indexOf('--package');
const folder = at >= 0 ? resolve(process.argv[at + 1]) : join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(readFileSync(join(folder, 'package.json'), 'utf8'));
if (pkg.name !== 'provared') throw new Error(`${folder} does not hold the provared package`);
const entry = (name) => {
  const e = pkg.exports?.[name];
  const file = typeof e === 'string' ? e : e?.default;
  if (typeof file !== 'string') throw new Error(`the package offers no entry point ${name}`);
  return import(pathToFileURL(join(folder, file)).href);
};
const P = { ...(await entry('./check')), ...(await entry('.')) };

// --- decoding the cases, as the shared test files write them ---

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const H = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
const bytesOf = (value) => (typeof value === 'string' ? H(value) : value);
const listOf = (value) => (Array.isArray(value) ? value.map(bytesOf) : value);
/** Bytes changed as a case says: one byte flipped, cut short, or added to. */
function changed(bytes, change) {
  let out = Uint8Array.from(bytes);
  if (!change) return out;
  if (change.flip) out[change.flip[0]] ^= change.flip[1];
  if (change.cut !== undefined) out = out.subarray(0, change.cut);
  if (change.append) {
    const more = H(change.append);
    const joined = new Uint8Array(out.length + more.length);
    joined.set(out);
    joined.set(more, out.length);
    out = joined;
  }
  return out;
}

// A refusal from the library is an error named "Refusal" with a code (the
// type declarations call it so). A RangeError is the library refusing an
// argument outside what a function takes (a place among the leaves that is
// not there, a Show of no pages, a time beyond what a date can hold): the
// shared test files store those 13 cases as "check-failed", the library's
// own catch-all code, which is particular to the JavaScript library
// (conformance/README.md). Anything else is a fault in this adapter or in
// the library, and is reported as one: the adapter says what it met on its
// standard error and stops, and the kit counts the case as failed.
const CHECK_FAILED = { code: 'check-failed', message: 'The checker met something it did not expect here. This is treated as not intact.' };
async function answer(work) {
  try {
    return { ok: await work() };
  } catch (e) {
    if (e && e.name === 'Refusal' && typeof e.code === 'string') return { refused: { code: e.code, message: String(e.message) } };
    if (e instanceof RangeError) return { refused: CHECK_FAILED };
    process.stderr.write(`the adapter met an error it does not expect: ${e && e.stack ? e.stack : String(e)}\n`);
    process.exit(1);
  }
}

/** A record put together from a passkey's preparation: its bytes in hexadecimal. */
const prepared = (prepare) => (c) =>
  answer(async () => {
    const p = await prepare(c.fields);
    return { contentBytes: hex(p.contentBytes), payloadB64: p.payloadB64, protectedB64: p.protectedB64, challenge: hex(p.challenge), fingerprint: p.fingerprint };
  });

/** A passkey record put together from a preparation and the passkey's three values. */
const assembled = (assemble) => (c) =>
  answer(() => assemble(c.prepared, { authenticatorData: H(c.authenticatorData), clientDataJSON: H(c.clientDataJSON), signature: H(c.signature) }));

// The fixed start of the PKCS #8 form of an Ed25519 private key (RFC 8410), before its 32 bytes.
const ED25519_PKCS8 = '302e020100300506032b657004220420';

/**
 * A record written and signed with an Ed25519 key made from the case's seed
 * and a fresh ML-DSA-87 key: its fingerprint, its content and its Ed25519
 * signature exactly, and whether its ML-DSA-87 signature checks ("valid" or
 * "invalid", by Web Crypto, over the JSON Web Signature signing input of
 * RFC 7515, section 5.1).
 */
const written = (write) => (c) =>
  answer(async () => {
    const subtle = globalThis.crypto.subtle;
    const ed = await subtle.importKey('pkcs8', H(ED25519_PKCS8 + c.seed), { name: 'Ed25519' }, false, ['sign']);
    const ml = await subtle.generateKey({ name: 'ML-DSA-87' }, false, ['sign', 'verify']);
    const { record, fingerprint } = await write(c.fields, [ed, ml.privateKey]);
    const [first, second] = record.signatures;
    const input = new TextEncoder().encode(`${second.protected}.${record.payload}`);
    const check = (await subtle.verify({ name: 'ML-DSA-87' }, ml.publicKey, P.fromBase64url(second.signature), input)) ? 'valid' : 'invalid';
    return { fingerprint, payload: record.payload, signatures: [first, { protected: second.protected, check }] };
  });

/** How each kind of case is answered, through public functions only. */
const ANSWER = {
  // Whole books, Shows, slips and the check before acting.
  checkSlip: (c) => answer(() => P.checkSlip(c.record, c.options, c.disclosures)),
  checkBook: (c) => answer(() => P.checkBook(c.text, c.options)),
  checkShow: (c) => answer(() => P.checkShow(c.show, c.options)),
  checkBefore: (c) => answer(() => P.checkBefore(c.text, c.proposal, c.options)),
  makeShow: (c) => answer(() => P.makeShow(c.text, c.indexes, c.showOptions)),

  // Records signed by a passkey, prepared and put together.
  prepareApproval: prepared(P.prepareApproval),
  assembleApproval: assembled(P.assembleApproval),
  prepareCancellation: prepared(P.prepareCancellation),
  assembleCancellation: assembled(P.assembleCancellation),

  // Records signed by an agent, a service or an organisation.
  writeRefusal: written(P.writeRefusal),
  writeTerms: written(P.writeTerms),
  writeAcknowledgement: written(P.writeAcknowledgement),
  writeVouching: written(P.writeVouching),
  writeWithdrawal: written(P.writeWithdrawal),
  writePass: written(P.writePass),
  writeDenial: written(P.writeDenial),
  writeWitness: written(P.writeWitness),
  denialCodes: (c) => answer(() => P.denialCodes(c.answer)),

  // Fingerprints, trees and block time-stamps.
  fromBase64url: (c) => answer(() => hex(P.fromBase64url(c.text))),
  keySetFingerprint: (c) => answer(() => P.keySetFingerprint(c.keys)),
  inclusionPath: (c) => answer(async () => (await P.inclusionPath(c.leaves.map(H), c.index)).map(hex)),
  verifyInclusion: (c) => answer(() => P.verifyInclusion(c.index, c.size, H(c.leaf), c.path.map(H), H(c.root))),
  verifyConsistency: (c) => answer(() => P.verifyConsistency(c.m, c.n, bytesOf(c.rootM), bytesOf(c.rootN), listOf(c.proof))),
  blockFingerprint: (c) => answer(() => P.blockFingerprint(H(c.header))),
  blockStampItem: (c) =>
    answer(() => P.blockStampItem(Object.hasOwn(c, 'proofValue') ? c.proofValue : H(c.proof), Object.hasOwn(c, 'headerValue') ? c.headerValue : H(c.header))),
  checkHeaderChain: (c) =>
    answer(async () => {
      const r = await P.checkHeaderChain(Object.hasOwn(c, 'bytesValue') ? c.bytesValue : changed(H(c.bytes), c.change), { now: c.now });
      return { height: r.height, tip: r.tip, tipWhen: r.tipWhen };
    }),
  blocksInChain: (c) =>
    answer(() => {
      const table = c.chain;
      return P.blocksInChain(c.result, { find: (fp) => (Object.hasOwn(table, fp) ? table[fp] : null) });
    }),

  // The names of the documents a stub may give, and the fingerprint of an
  // identifier. The two other kinds of case also ask for the text a web
  // request's or answer's fingerprint is made from, which no public
  // function gives; they are skipped.
  documentFingerprint: async (c) => {
    if (c.kind === 'names') return answer(() => P.DOCUMENT_NAMES);
    if (c.kind === 'identifier') return answer(async () => ({ fingerprint: await P.identifierFingerprint(c.input) }));
    return { skip: 'the text a fingerprint of a web request or answer is made from is not offered by a public function' };
  },
};

/** The sets the public functions cannot answer, and why. */
const SKIPPED = {
  consistencyProof: 'checking each proof needs the root of a tree of leaves, which no public function gives',
  sealerTree: "the sealer's tree grown one leaf at a time is not offered by a public function",
  leafHash: 'the fingerprint of a leaf given as bytes is not offered by a public function (leafFingerprint takes a line of text)',
  treeRoot: 'the root of a tree of leaves is not offered by a public function',
  treeBuilder: 'the tree builder is not offered by a public function',
  recorderScenario: "the stub writer's scenarios are played by the repository's own test code (test/helpers/scenarios.mjs)",
  recordConstants: 'MAX_PASSES is not offered by the package',
  denialConstants: 'MAX_DENIAL_CODES is not offered by the package',
};
const INNER = 'a part of the library that is not offered to other programs';

async function reply(line) {
  const request = JSON.parse(line);
  const work = ANSWER[request.function];
  if (!work) return { id: request.id, skip: SKIPPED[request.function] ?? `${request.function} tests ${INNER}` };
  const result = await work(request.case);
  return result.skip ? { id: request.id, skip: result.skip } : { id: request.id, answer: result };
}

let rest = '';
let queue = Promise.resolve();
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  rest += chunk;
  let at;
  while ((at = rest.indexOf('\n')) >= 0) {
    const text = rest.slice(0, at).trim();
    rest = rest.slice(at + 1);
    if (text === '') continue;
    queue = queue.then(async () => process.stdout.write(`${JSON.stringify(await reply(text))}\n`));
  }
});
