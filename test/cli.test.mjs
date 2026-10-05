// The command-line checker, run as a person would run it.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'bin', 'provared-check.mjs');
const sample = join(root, 'samples', 'office-supplies.jsonl');
const expected = JSON.parse(readFileSync(join(root, 'samples', 'office-supplies.expected.json'), 'utf8'));

function run(...args) {
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', cli, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test('the sample book: intact, and outside the slip at entry 5, so exit code 1', () => {
  const r = run(sample);
  assert.equal(r.code, 1);
  assert.match(r.out, /Evidence, not a verdict\./);
  assert.match(r.out, /Is the record intact\?\s+yes/);
  assert.match(r.out, /Did the agent stay within its slip\?\s+NO: first at entry 5/);
  for (const code of ['countersignature-missing', 'over-limit', 'approval-missing', 'action-not-allowed', 'prohibited']) {
    assert.ok(r.out.includes(`OUTSIDE THE SLIP [${code}]`), code);
  }
  assert.match(r.out, /ONE-SIDED/);
  assert.match(r.out, /Approved by the person, with the passkey the slip names: valid/);
  assert.match(r.out, /REFUSAL/);
  assert.match(r.out, /TERMS FOR AGENTS/);
  assert.match(r.out, /Limit:\s+provared\.order\.place: no single action above 100 GBP/);
  assert.match(r.out, /Condition:\s+provared\.order\.place: needs the person's own approval above 60 GBP/);
  assert.match(r.out, /Stated rule:\s+Never go around an access control, a block or a refusal\./);
  assert.match(r.out, /Approved by the person 1, refusals 1, terms for agents 1/);
  assert.match(r.out, /SEAL/);
  assert.match(r.out, /Recorder's signatures: Ed25519 valid; ML-DSA-87 valid; SLH-DSA-SHA2-256s valid/);
  // No time-stamp service was named as trusted, so the time-stamp is not counted.
  assert.match(r.out, /Outside time-stamp, NOT COUNTED/);
  assert.match(r.out, /Time-stamped in a way you trust\?\s+no/);
  const trusting = run(sample, '--stamp-service', expected.stampServices[0], '--sealer', expected.sealKeys[0], '--issuer', expected.issuerKey);
  assert.equal(trusting.code, 1);
  assert.match(trusting.out, /OUTSIDE TIME-STAMP: 2026-10-05T10:16:00Z, from a service you named as trusted/);
  assert.match(trusting.out, /Time-stamped in a way you trust\?\s+yes: the first 9 entries existed by 2026-10-05T10:16:00Z/);
  assert.doesNotMatch(trusting.out, /Note:/);
  assert.equal(run(sample, '--sealer', 'A'.repeat(43)).code, 2);
  assert.match(r.out, /What this check does not show/);
  assert.match(r.out, /was not compared with a key you already trust/);
  assert.equal(r.err, '');
});

test('--issuer with the right key leaves no note; with a wrong key the record is not intact', () => {
  const right = run(sample, '--issuer', expected.issuerKey);
  assert.equal(right.code, 1);
  assert.doesNotMatch(right.out, /was not compared with a key you already trust/);
  const wrong = run(sample, '--issuer', 'A'.repeat(43));
  assert.equal(wrong.code, 2);
  assert.match(wrong.out, /PROBLEM \[issuer-not-expected\]/);
});

test('--json prints the whole result', () => {
  const r = run(sample, '--json');
  const result = JSON.parse(r.out);
  assert.equal(result.root, expected.root);
  assert.equal(result.summary.firstBreach, 5);
});

test('a Show is recognised and checked', () => {
  const show = join(root, 'samples', 'office-supplies.show.json');
  // The Show is of the book as it stood when it was sealed; its seal and
  // time-stamp come with it, so no copy of the top fingerprint is needed.
  const ok = run(show, '--stamp-service', expected.stampServices[0]);
  assert.match(ok.out, /Provared Show/);
  assert.match(ok.out, /Is the record intact\?\s+yes/);
  const wrong = run(show, '--root', 'A'.repeat(43));
  assert.equal(wrong.code, 2);
  assert.match(wrong.out, /root-mismatch/);
});

test('a sound book within its slip gives exit code 0', () => {
  // The first four entries of the sample: the slip and three orders.
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'within.jsonl');
  writeFileSync(file, readFileSync(sample, 'utf8').split('\n').slice(0, 4).join('\n') + '\n');
  const r = run(file, '--issuer', expected.issuerKey);
  assert.equal(r.code, 0);
  assert.match(r.out, /Did the agent stay within its slip\?\s+yes, as far as this record shows/);
  // Without the passkey you trust, the same book is not a pass.
  assert.equal(run(file).code, 1);
});

test('a damaged book gives exit code 2, and text from a record cannot move the cursor', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'damaged.jsonl');
  writeFileSync(file, readFileSync(sample, 'utf8').replace('"payload":"ey', '"payload":"ez') + 'not a record \u001b[2J\n');
  const r = run(file);
  assert.equal(r.code, 2);
  assert.match(r.out, /Is the record intact\?\s+NO/);
  assert.doesNotMatch(r.out, /\u001b/);
});

test('what a failed entry says is not printed as if it were fact', () => {
  // The first order's amount is changed from 45 to 1 after it was signed.
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'changed.jsonl');
  const lines = readFileSync(sample, 'utf8').split('\n');
  const entry = JSON.parse(lines[2]);
  const content = Buffer.from(entry.stub.payload, 'base64url').toString().replace('"value":45', '"value":1');
  entry.stub.payload = Buffer.from(content).toString('base64url');
  lines[2] = JSON.stringify(entry);
  writeFileSync(file, lines.join('\n'));
  const r = run(file);
  assert.equal(r.code, 2);
  assert.match(r.out, /PROBLEM \[signature-invalid\]/);
  assert.match(r.out, /What this entry says is not shown/);
  assert.doesNotMatch(r.out, /order\.place, 1 GBP/);
  // The whole result, with the unverified content, is there for whoever asks for it.
  assert.equal(JSON.parse(run(file, '--json').out).entries[2].content.amount.value, 1);
});

test('--root and --size are applied to a book as well as to a Show', () => {
  assert.equal(run(sample, '--root', expected.root, '--size', '10').code, 1);
  const wrongRoot = run(sample, '--root', 'A'.repeat(43));
  assert.equal(wrongRoot.code, 2);
  assert.match(wrongRoot.out, /PROBLEM \[root-mismatch\]/);
  assert.equal(run(sample, '--root', expected.root, '--size', '11').code, 2);
  assert.equal(run(sample, '--size', 'many').code, 2);
});

test('a Show of single pages says what single pages cannot show', () => {
  // The sample Show holds the slip, the supplier's terms and the order the
  // person approved: 80 against a limit of 200 in total. One page cannot
  // show the running total. The seal and its time-stamp come with the Show.
  const r = run(join(root, 'samples', 'office-supplies.show.json'), '--stamp-service', expected.stampServices[0], '--issuer', expected.issuerKey, '--sealer', expected.sealKeys[0]);
  assert.equal(r.code, 0);
  assert.match(r.out, /Time-stamped in a way you trust\?\s+yes: the first 9 entries/);
  assert.match(r.out, /Do these pages show the agent outside its slip\? no \(single pages cannot show whether a limit was kept\)/);
});

test('--json writes text that could disturb a terminal as escapes, and stays exact JSON', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'controls.jsonl');
  writeFileSync(file, '{"\u009b2J\u202e":"x"}\n');
  const r = run(file, '--json');
  assert.doesNotMatch(r.out, /[\u007f-\u009f\u202a-\u202e]/);
  assert.equal(JSON.parse(r.out).summary.problemFound, true);
});

test('a record that crashed an earlier checker is refused with exit code 2', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'hostile.jsonl');
  writeFileSync(
    file,
    '{"stub":{"payload":"eyJ0eXBlIjp7InRvU3RyaW5nIjowfX0","signatures":[{"protected":"eyJ0eXAiOiJ2bmQucHJvdmFyZWQuc3R1Yi52MCtqc29uIiwiYWxnIjoiRWQyNTUxOSJ9","signature":""},{"protected":"eyJ0eXAiOiJ2bmQucHJvdmFyZWQuc3R1Yi52MCtqc29uIiwiYWxnIjoiTUwtRFNBLTg3In0","signature":""}]}}\n',
  );
  const r = run(file);
  assert.equal(r.code, 2);
  assert.match(r.out, /PROBLEM \[payload-type-mismatch\]/);
  assert.equal(r.err, '');
});

test('no file, a missing file and an unknown option give exit code 2 and say how to use it', () => {
  assert.equal(run().code, 2);
  assert.match(run().err, /Usage: provared-check/);
  assert.equal(run(join(root, 'no-such-file.jsonl')).code, 2);
  assert.equal(run(sample, '--nonsense').code, 2);
});

test('characters that cannot be seen are shown as a mark, in words and in --json', async () => {
  // Found by the second independent review: zero-width characters, soft
  // hyphens and line separators passed through, so two labels could look
  // the same and differ.
  const { makeWorld } = await import('./helpers/world.mjs');
  const hidden = ['\u200b', '\u200d', '\u2060', '\u2028', '\u2029', '\ufeff', '\u00ad', '\u3164', '\u{e0001}', '\u202e', '\u0007'];
  const w = await makeWorld({ fields: { purpose: 'Buy' + hidden.join('x') + 'paper' } });
  await w.add();
  const dir = mkdtempSync(join(tmpdir(), 'provared-'));
  const file = join(dir, 'hidden.jsonl');
  writeFileSync(file, w.book());
  for (const out of [run(file).out, run(file, '--json').out]) {
    for (const character of hidden) assert.ok(!out.includes(character), 'U+' + character.codePointAt(0).toString(16));
  }
  assert.match(run(file).out, /Purpose:\s+"Buy\ufffdx\ufffd/);
  assert.equal(JSON.parse(run(file, '--json').out).entries[0].content.purpose, 'Buy' + hidden.join('x') + 'paper');
});
