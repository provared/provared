// The development stand-in for a passkey ("provared/dev"): a record made
// with it checks exactly as one signed by a person would, and every slip
// it signs says in its issuer's name that it is for development.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkBook, checkSlip, thumbprint } from '../src/index.js';
import { DEVELOPMENT_MARK, developmentPasskey, developmentRecorder, developmentSlip } from '../src/dev.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const SEND = 'provared.message.send';

test('a development slip checks as a slip, and its issuer is marked as a stand-in', async () => {
  const made = await developmentSlip({ actions: [SEND], limits: [{ action: SEND, count: 2 }] });
  const checked = await checkSlip(made.slip, { issuerKeys: made.issuerKeys });
  assert.equal(checked.problems.length, 0, JSON.stringify(checked.problems));
  assert.equal(checked.content.issuer.name, `Development passkey ${DEVELOPMENT_MARK}`);
  assert.equal(checked.content.issuer.origin, 'http://localhost');
  assert.equal(checked.content.agent.name, 'Development agent');
  assert.deepEqual(checked.content.actions, [SEND]);
  assert.deepEqual(checked.content.with, []);
  assert.match(checked.content.purpose, /development/);
  assert.equal(made.issuerKeys[0], await thumbprint(made.passkey.key));
  // The book it hands back holds the slip alone, and checks.
  const book = await checkBook(made.book, { issuerKeys: made.issuerKeys });
  assert.equal(book.summary.intact, true);
  assert.equal(book.summary.counts.slips, 1);
});

test('a name given for the issuer keeps the mark; one that already has it is not marked twice', async () => {
  const named = await developmentSlip({ actions: [SEND], issuer: { name: 'Sam' }, agent: { name: 'Mailer' }, purpose: 'Send three messages.' });
  const checked = await checkSlip(named.slip, { issuerKeys: named.issuerKeys });
  assert.equal(checked.content.issuer.name, 'Sam (development)');
  assert.equal(checked.content.agent.name, 'Mailer');
  assert.equal(checked.content.purpose, 'Send three messages.');
  const twice = await developmentSlip({ actions: [SEND], issuer: { name: 'Sam (development)' } });
  assert.equal((await checkSlip(twice.slip, { issuerKeys: twice.issuerKeys })).content.issuer.name, 'Sam (development)');
  // The issuer's key and page address cannot be replaced: they are the stand-in's.
  const forced = await developmentSlip({ actions: [SEND], issuer: { name: 'Sam', origin: 'https://sign.example.org', rpId: 'sign.example.org' } });
  assert.equal((await checkSlip(forced.slip, { issuerKeys: forced.issuerKeys })).content.issuer.origin, 'http://localhost');
});

test('the stand-in refuses what prepareSlip refuses, and what is not an object', async () => {
  await assert.rejects(developmentSlip(), /actions/);
  await assert.rejects(developmentSlip('send'), TypeError);
  await assert.rejects(developmentSlip({ actions: [SEND], limits: [{ action: 'other', count: 1 }] }), /limits\[0\]\.action/);
});

test('the stand-in signs an approval and a cancellation too, as a passkey would', async () => {
  const passkey = await developmentPasskey();
  const first = await passkey.sign(new Uint8Array(32));
  const second = await passkey.sign(new Uint8Array(32));
  assert.equal(first.authenticatorData.length, 37);
  assert.equal(first.authenticatorData[32], 0x05);
  assert.notDeepEqual(first.signature, second.signature, 'a signature differs each time it is made');
  assert.match(new TextDecoder().decode(first.clientDataJSON), /"origin":"http:\/\/localhost"/);
});

test('the stub writer opened under a development slip: within the limit, then outside it', async () => {
  const { recorder, issuerKeys, slipFingerprint } = await developmentRecorder({ actions: [SEND], limits: [{ action: SEND, count: 2 }] });
  const sent = [];
  for (let i = 1; i <= 3; i++) {
    const outcome = await recorder.act({ action: SEND }, async () => sent.push(i));
    assert.equal(outcome.done, i <= 2, `message ${i}`);
    if (i === 3) assert.equal(outcome.answer.breaches[0].code, 'over-count-limit');
  }
  assert.deepEqual(sent, [1, 2]);
  const result = await checkBook(recorder.book(), { issuerKeys });
  assert.equal(result.summary.intact, true);
  assert.equal(result.summary.withinSlips, true);
  assert.equal(result.summary.counts.stubs, 2);
  assert.equal(result.entries[0].fingerprint, slipFingerprint);
  // What the checker shows a reader: the slip is marked, in its own words.
  assert.equal(result.entries[0].content.issuer.name, 'Development passkey (development)');
});

test('the first-record example runs, writes a book, and the checker reads it with the thumbprint it prints', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-first-'));
  const run = (file, ...args) => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', file, ...args], { encoding: 'utf8', cwd: dir });
  const example = run(join(root, 'examples', 'first-record.mjs'));
  assert.equal(example.status, 0, example.stderr);
  assert.match(example.stdout, /message 1 sent/);
  assert.match(example.stdout, /message 3 not sent: .*over-count-limit/);
  const command = example.stdout.match(/npx provared-check book\.jsonl --issuer ([A-Za-z0-9_-]{43})/);
  assert.ok(command, example.stdout);
  const book = readFileSync(join(dir, 'book.jsonl'), 'utf8');
  assert.equal(book.split('\n').filter(Boolean).length, 3, 'a slip and two stubs');
  const checked = run(join(root, 'bin', 'provared-check.mjs'), join(dir, 'book.jsonl'), '--issuer', command[1]);
  assert.equal(checked.status, 0, checked.stdout + checked.stderr);
  assert.match(checked.stdout, /Did the agent stay within its slip\?\s+yes/);
  assert.match(checked.stdout, /\(development\)/);
});
