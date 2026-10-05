// Writes the sample record in samples/: the demonstration scenario, with a
// software stand-in for the person's passkey (test/helpers/passkey.mjs).
//
// Run once. A signature is different every time it is made, so running this
// again gives a different sample: the files in samples/ are kept as written,
// and test/sample.test.mjs checks that today's code still reads them.
//
//   node --disable-warning=ExperimentalWarning tools/make-sample.mjs

import { writeFileSync } from 'node:fs';
import { finishRun, sealBook, slipFields, startRun } from '../demo/scenario.mjs';
import {
  assembleApproval,
  assembleSlip,
  checkBook,
  entryLine,
  fingerprint,
  fromBase64url,
  generateKeySet,
  generateSealKeySet,
  keySetFingerprint,
  makeShow,
  prepareApproval,
  prepareSlip,
  thumbprint,
  writeBook,
} from '../src/index.js';
import { makePasskey } from '../test/helpers/passkey.mjs';
import { makeStampService } from '../test/helpers/stamp.mjs';

const start = Date.parse('2026-10-05T08:00:00Z');

const passkey = await makePasskey('ES256', { rpId: 'localhost', origin: 'http://localhost:8787' });
const agent = await generateKeySet();
const service = await generateKeySet();

const prepared = await prepareSlip({
  ...slipFields({ agentKeys: agent.keys, serviceKeys: service.keys }, start),
  issuer: { name: 'Sam Example (invented)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
});
const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
const slipFingerprint = await fingerprint(fromBase64url(slip.payload));

// The agent works until it needs the person's approval of one order; the
// person approves it with the (stand-in) passkey; the agent finishes.
const { run, ask } = await startRun({
  slipFingerprint,
  agentPrivateKeys: agent.privateKeys,
  serviceKeys: service.keys,
  servicePrivateKeys: service.privateKeys,
  start: start + 3600 * 1000,
});
const approval = await prepareApproval(ask);
const approved = { record: assembleApproval(approval, await passkey.sign(approval.challenge)), fingerprint: approval.fingerprint };
const entries = [{ slip }, ...(await finishRun(run, approved))];
// Whoever keeps the book seals it, and a made-up time-stamp service (a
// stand-in, like the passkey) states when.
const recorder = await generateSealKeySet();
const stampService = await makeStampService();
const unsealed = writeBook(entries);
const book = unsealed + entryLine(await sealBook(unsealed, { recorder, stampService, when: start + 3600 * 1000 + 75 * 60 * 1000 })) + '\n';
const trust = { sealKeys: [await keySetFingerprint(recorder.keys)], stampServices: [stampService.fingerprint] };
const result = await checkBook(book, trust);
// The Show: the slip, the supplier's terms, and the order the person
// approved, under the seal and its time-stamp.
const show = await makeShow(book, [0, 1, 4], { seal: entries.length });

const expected = {
  about: 'What a checker must find in office-supplies.jsonl. Written once, with the sample.',
  size: result.size,
  root: result.root,
  issuerKey: await thumbprint(passkey.key),
  sealKeys: trust.sealKeys,
  stampServices: trust.stampServices,
  sealed: result.summary.sealed,
  fingerprints: result.entries.map((e) => e.fingerprint),
  summary: {
    intact: result.summary.intact,
    fullyChecked: result.summary.fullyChecked,
    withinSlips: result.summary.withinSlips,
    firstBreach: result.summary.firstBreach,
    counts: result.summary.counts,
  },
  breaches: result.entries.map((e) => e.breaches.map((b) => b.code)),
  running: result.entries.map((e) => (e.running ? e.running.total : null)),
};

const dir = new URL('../samples/', import.meta.url);
writeFileSync(new URL('office-supplies.jsonl', dir), book);
writeFileSync(new URL('office-supplies.expected.json', dir), JSON.stringify(expected, null, 2) + '\n');
writeFileSync(new URL('office-supplies.show.json', dir), JSON.stringify(show, null, 2) + '\n');
console.log(`written: ${result.size} entries, top fingerprint ${result.root}`);
console.log(JSON.stringify(expected.summary));
