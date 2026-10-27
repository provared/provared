// The conformance kit's own tests: it passes Provared's own library, and it
// reports, rightly, an adapter that answers wrongly, stops, hangs or prints
// what is not JSON.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { asciiJson, difference, readSets, runKit } from '../kit.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const kit = join(here, '..');
const vectors = join(kit, '..', 'test-vectors');
const node = process.execPath;
const quiet = '--disable-warning=ExperimentalWarning';
const provared = [quiet, join(kit, 'adapters', 'provared.mjs')];
const faulty = (...a) => [quiet, join(here, 'adapters', 'faulty.mjs'), ...a];
const small = () => readSets(vectors, ['base64url.json', 'canonical-json.json']);
const run = (args, more = {}) => runKit({ command: node, args, sets: small(), ...more });

// A case of base64url.json that is refused.
const REFUSED = 'an impossible length';

test('the comparison: codes and shape by default, every word with words', () => {
  const expected = { refused: { code: 'bad-field', message: 'These words.' } };
  assert.equal(difference(expected, { refused: { code: 'bad-field', message: 'Other words.' } }), null);
  assert.match(difference(expected, { refused: { code: 'bad-field', message: 'Other words.' } }, true), /answer\.refused\.message: expected "These words\."/);
  assert.match(difference(expected, { refused: { code: 'bad-key', message: 'These words.' } }), /answer\.refused\.code: expected "bad-field", got "bad-key"/);
  assert.match(difference(expected, { refused: { code: 'bad-field', message: 7 } }), /expected a text, got 7/);
  assert.match(difference(expected, { refused: { code: 'bad-field' } }), /answer\.refused\.message: missing/);
  assert.match(difference(expected, { refused: { code: 'bad-field', message: 'x', more: 1 } }), /answer\.refused\.more: not expected/);
  // The texts of "notes" and "limits" are words; their number, and anything
  // in them that is not a text (such as a slip's limits), are compared.
  const book = { ok: { notes: ['One.', 'Two.'], limits: ['Three.'], slip: { limits: [{ action: 'a', max: 2 }] } } };
  assert.equal(difference(book, { ok: { notes: ['Un.', 'Deux.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 2 }] } } }), null);
  assert.match(difference(book, { ok: { notes: ['Un.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 2 }] } } }), /answer\.ok\.notes: expected a list of 2, got a list of 1/);
  assert.match(difference(book, { ok: { notes: ['Un.', 'Deux.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 3 }] } } }), /answer\.ok\.slip\.limits\[0\]\.max: expected 2, got 3/);
  // Anything else is compared exactly.
  assert.match(difference({ ok: { name: 'x' } }, { ok: { name: 'y' } }), /answer\.ok\.name/);
  assert.match(difference({ ok: [1] }, { ok: { 0: 1 } }), /expected a list/);
});

test('every line the kit writes is ASCII, so no reader ends a line early', () => {
  const value = { t: 'a b cé😀\ud800' };
  const text = asciiJson(value);
  assert.match(text, /^[\x20-\x7e]*$/);
  assert.deepEqual(JSON.parse(text), value);
});

test("the kit passes Provared's own library on every shared test file, words included", { timeout: 600000 }, async () => {
  const r = await runKit({ command: node, args: provared, sets: readSets(vectors), words: true });
  assert.deepEqual(r.failures, []);
  assert.equal(r.totals.failed + r.totals.skipped + r.totals.notRun, 0);
  assert.ok(r.totals.passed > 1000);
  assert.equal(r.ok, true);
});

test('a wrong code fails, with the case and the place named', async () => {
  const r = await run(faulty('wrong-code'));
  assert.equal(r.ok, false);
  const f = r.failures.find((x) => x.name === REFUSED);
  assert.equal(f.file, 'base64url.json');
  assert.equal(f.why, 'answer.refused.code: expected "bad-base64url", got "not-the-right-code"');
  const refused = small().flatMap((s) => s.cases.filter((c) => c.expected.refused)).length;
  assert.equal(r.totals.failed, refused);
  assert.equal(r.totals.passed + r.totals.failed, 48);
});

test('other words pass by codes and shape, and fail word for word', async () => {
  assert.equal((await run(faulty('wrong-words'))).ok, true);
  const r = await run(faulty('wrong-words'), { words: true });
  assert.equal(r.ok, false);
  assert.match(r.failures[0].why, /^answer\.refused\.message: expected ".*", got "Other words that say the same\."$/);
});

test('cases the adapter sets aside are skipped, and with nothing compared the kit does not pass', async () => {
  const r = await run(faulty('skip'));
  assert.equal(r.totals.skipped, 48);
  assert.equal(r.totals.passed, 0);
  assert.equal(r.ok, false);
});

test('an adapter that stops is reported for that case, with what it said, and started again', async () => {
  const r = await run(faulty('crash', REFUSED));
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].why, 'the adapter stopped (exit code 5)');
  assert.ok(r.failures[0].stderr.some((l) => l.includes('the faulty adapter stops here')));
  assert.equal(r.totals.passed, 47);
});

test('an adapter that hangs is stopped at the time limit, and the rest is still run', async () => {
  const started = Date.now();
  const r = await run(faulty('hang', REFUSED), { timeout: 1500 });
  assert.ok(Date.now() - started < 30000);
  assert.equal(r.failures.length, 1);
  assert.equal(r.failures[0].why, 'no answer within 1.5 seconds');
  assert.equal(r.totals.passed, 47);
});

test('a line that is not JSON, or an answer to another request, is a failure of that case', async () => {
  const junk = await run(faulty('junk', REFUSED));
  assert.equal(junk.failures.length, 1);
  assert.equal(junk.failures[0].why, 'the adapter printed a line that is not JSON: "this is not JSON"');
  assert.equal(junk.totals.passed, 47);
  const id = await run(faulty('wrong-id', REFUSED));
  assert.equal(id.failures.length, 1);
  assert.match(id.failures[0].why, /^the adapter answered request \d+, not request \d+$/);
  assert.equal(id.totals.passed, 47);
});

test('an adapter that never starts properly is given up after a few tries', async () => {
  const r = await run(faulty('crash-always'), { maxRestarts: 2 });
  assert.equal(r.totals.failed, 3);
  assert.equal(r.totals.notRun, 45);
  assert.match(r.gaveUp, /failed 3 times in a row/);
  assert.equal(r.ok, false);
  const missing = await runKit({ command: join(here, 'no-such-program'), sets: small(), maxRestarts: 0 });
  assert.match(missing.failures[0].why, /could not be started/);
});

test('the command: its summary and its exit codes', () => {
  const cli = (...a) => spawnSync(node, [join(kit, 'run.mjs'), ...a], { encoding: 'utf8' });
  const good = cli('--file', 'base64url.json', '--', node, ...provared);
  assert.equal(good.status, 0, good.stderr);
  assert.match(good.stdout, /base64url\.json\s+11\s+0\s+0\s+0/);
  assert.match(good.stdout, /Files: 1\. Cases: 11\. Passed: 11\. Failed: 0\. Skipped: 0\. Not run: 0\./);
  assert.match(good.stdout, /it is not a certificate/);
  const bad = cli('--file', 'base64url.json', '--', node, ...faulty('wrong-code'));
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /- base64url\.json: an impossible length\n {4}answer\.refused\.code: expected "bad-base64url", got "not-the-right-code"/);
  assert.match(bad.stdout, /Not every case matched\./);
  assert.equal(cli('--file', 'no-such.json', '--', node).status, 2);
  assert.equal(cli('--file', 'base64url.json').status, 2);
  assert.equal(cli('--bogus', '--', node).status, 2);
  assert.equal(cli('--help').status, 0);
});
