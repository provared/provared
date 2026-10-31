// The conformance kit's own tests: it passes Provared's own library, and it
// reports, rightly, an adapter that answers wrongly, stops, hangs or prints
// what is not JSON.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { asciiJson, describe, difference, readSets, runKit } from '../kit.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const kit = join(here, '..');
const vectors = join(kit, '..', 'test-vectors');
const node = process.execPath;
const quiet = '--disable-warning=ExperimentalWarning';
const provared = [quiet, join(kit, 'adapters', 'provared.mjs')];
const publicOnly = [quiet, join(kit, 'adapters', 'provared-public.mjs')];
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
  // The texts of "notes" and "limits" are words: neither their words nor
  // their number are compared (choice K-6). Anything in those lists that is
  // not a text (such as a slip's limits) is compared in full.
  const book = { ok: { notes: ['One.', 'Two.'], limits: ['Three.'], slip: { limits: [{ action: 'a', max: 2 }] } } };
  assert.equal(difference(book, { ok: { notes: ['Un.', 'Deux.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 2 }] } } }), null);
  assert.equal(difference(book, { ok: { notes: ['Un.'], limits: ['Trois.', 'Quatre.', 'Cinq.'], slip: { limits: [{ action: 'a', max: 2 }] } } }), null);
  assert.equal(difference(book, { ok: { notes: [], limits: [], slip: { limits: [{ action: 'a', max: 2 }] } } }), null);
  assert.match(difference(book, { ok: { notes: ['Un.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 2 }] } } }, true), /answer\.ok\.notes: expected a list of 2, got a list of 1/);
  assert.match(difference(book, { ok: { notes: ['Un.', 'Deux.'], limits: ['Trois.'], slip: { limits: [{ action: 'a', max: 3 }] } } }), /answer\.ok\.slip\.limits\[0\]\.max: expected 2, got 3/);
  assert.match(difference(book, { ok: { notes: 'One. Two.', limits: ['Three.'], slip: { limits: [{ action: 'a', max: 2 }] } } }), /answer\.ok\.notes: expected a list/);
  // In a list of that name, the items that are not texts keep their number and order.
  const mixed = { ok: { limits: ['Words.', { action: 'a', max: 2 }, 'More words.'] } };
  assert.equal(difference(mixed, { ok: { limits: [{ action: 'a', max: 2 }] } }), null);
  assert.match(difference(mixed, { ok: { limits: ['Words.'] } }), /answer\.ok\.limits: expected 1 item\(s\) that are not texts, got 0/);
  assert.match(difference(mixed, { ok: { limits: [{ action: 'a', max: 2 }, 7] } }), /answer\.ok\.limits: expected 1 item\(s\) that are not texts, got 2/);
  assert.match(difference(mixed, { ok: { limits: ['x', { action: 'b', max: 2 }] } }), /answer\.ok\.limits\[1\]\.action: expected "a", got "b"/);
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

test('the example adapter uses only the public entry points of the package', () => {
  const source = readFileSync(join(kit, 'adapters', 'provared-public.mjs'), 'utf8');
  const specifiers = [...source.matchAll(/^\s*import\b[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.ok(specifiers.length > 0);
  for (const s of specifiers) assert.match(s, /^node:/, `only Node.js's own modules are imported by name, not ${s}`);
  // The one dynamic import is of a file the package's "exports" list names.
  assert.equal([...source.matchAll(/\bimport\(/g)].length, 1);
  assert.match(source, /import\(pathToFileURL\(join\(folder, file\)\)\.href\)/);
  assert.match(source, /pkg\.exports/);
  assert.match(source, /entry\('\.'\)/);
  assert.match(source, /entry\('\.\/check'\)/);
});

test('the example adapter on public functions matches every case it answers, words included, and says why it skips the rest', { timeout: 600000 }, async () => {
  const r = await runKit({ command: node, args: publicOnly, sets: readSets(vectors), words: true });
  assert.deepEqual(r.failures, []);
  assert.equal(r.ok, true);
  assert.ok(r.totals.passed > 3000, `${r.totals.passed} cases answered`);
  assert.ok(r.totals.skipped > 0);
  const answered = new Set(r.files.filter((f) => f.passed > 0).map((f) => f.function));
  for (const fn of ['checkSlip', 'checkBook', 'checkShow', 'checkBefore', 'makeShow', 'writeDenial', 'prepareApproval', 'verifyInclusion', 'checkHeaderChain']) {
    assert.ok(answered.has(fn), `${fn} is answered through public functions`);
  }
  // Nothing that only the inner parts can answer is answered.
  for (const fn of ['validateDer', 'checkStamp', 'treeRoot', 'recorderScenario']) assert.ok(!answered.has(fn), fn);
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

test('other sentences, more or fewer, in real answers pass by codes and shape, and fail word for word', async () => {
  const sets = readSets(vectors, ['renewal-books.json', 'slips.json']);
  const r = await runKit({ command: node, args: faulty('other-sentences'), sets });
  assert.deepEqual(r.failures, []);
  assert.equal(r.ok, true);
  const w = await runKit({ command: node, args: faulty('other-sentences'), sets, words: true });
  assert.equal(w.ok, false);
  assert.ok(w.failures.some((f) => /(notes|limits): expected a list of \d+, got a list of \d+/.test(f.why)));
  // A code changed inside the same answers is still caught.
  const c = await runKit({ command: node, args: faulty('other-sentences-and-code'), sets });
  assert.equal(c.ok, false);
  assert.ok(c.failures.some((f) => /got "not-the-right-code"|not among the stored findings.*"not-the-right-code"/.test(f.why)));
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
  assert.match(bad.stdout, /Not every case matched: 6 of 11 compared failed\./);
  assert.equal(cli('--file', 'no-such.json', '--', node).status, 2);
  assert.equal(cli('--file', 'base64url.json').status, 2);
  assert.equal(cli('--bogus', '--', node).status, 2);
  assert.equal(cli('--help').status, 0);
});

test('findings: any order by codes and shape, the stored order word for word (choice K-30)', () => {
  const a = { code: 'chain-broken', message: 'A.' };
  const b = { code: 'time-went-backwards', message: 'B.' };
  const c = { code: 'over-limit', message: 'C.', at: 3 };
  const d = { code: 'over-count-limit', message: 'D.' };
  const book = (problems, breaches) => ({ ok: { problems: [], entries: [{ index: 2, kind: 'stub', problems, breaches }] } });
  const stored = book([a, b], [c, d]);
  assert.equal(difference(stored, book([b, a], [d, c])), null);
  assert.match(difference(stored, book([b, a], [c, d]), true), /entries\[0\]\.problems\[0\]\.code: expected "chain-broken"/);
  // A breach left out, or one added, or one given twice, fails.
  assert.match(difference(stored, book([a, b], [c])), /breaches: 1 finding\(s\) missing/);
  assert.match(difference(stored, book([a, b], [c, d, { code: 'prohibited', message: 'E.' }])), /breaches\[2\]: not among the stored findings/);
  assert.match(difference(stored, book([a, b], [c, d, d])), /breaches\[2\]: not among the stored findings/);
  assert.match(difference(stored, book([a, b], [{ ...c, at: 4 }, d])), /breaches\[0\]: not among the stored findings/);
  // A list of findings that is not an entry's problems must be whole, in any order.
  const top = { ok: { problems: [a, b] } };
  assert.equal(difference(top, { ok: { problems: [b, a] } }), null);
  assert.match(difference(top, { ok: { problems: [a] } }), /problems: 1 finding\(s\) missing/);
  // Messages are still only texts.
  assert.equal(difference(stored, book([{ ...b, message: 'X.' }, a], [d, c])), null);
  assert.match(difference(stored, book([{ ...b, message: 7 }, a], [d, c])), /expected a text, got 7/);
});

test("an entry's problems may stop at the first, never at none (choices K-31, K-32)", () => {
  const a = { code: 'signature-invalid', message: 'A.' };
  const b = { code: 'countersignature-wrong-stub', message: 'B.' };
  const entry = (problems, countersignature) => ({ ok: { entries: [{ index: 1, kind: 'stub', problems, countersignature }] } });
  const stored = entry([a, b], { state: 'invalid', signatures: [] });
  assert.equal(difference(stored, entry([a], { state: 'invalid', signatures: [] })), null);
  assert.equal(difference(stored, entry([b], { state: 'invalid', signatures: [] })), null);
  assert.match(difference(stored, entry([], { state: 'invalid', signatures: [] })), /problems: expected at least one of 2 finding\(s\), got none/);
  assert.match(difference(stored, entry([a, a], { state: 'invalid', signatures: [] })), /problems\[1\]: not among the stored findings/);
  assert.match(difference(stored, entry([a], { state: 'invalid', signatures: [] }), true), /problems: expected a list of 2, got a list of 1/);
  // Stopped before the countersignature: "unchecked" is taken in place of its stored state.
  assert.equal(difference(stored, entry([a], { state: 'unchecked', signatures: [] })), null);
  assert.match(difference(stored, entry([a, b], { state: 'unchecked', signatures: [] })), /countersignature\.state: expected "invalid", got "unchecked"/);
  assert.match(difference(stored, entry([a], { state: 'valid', signatures: [] })), /countersignature\.state: expected "invalid", got "valid"/);
  // An entry with no stored problem must give none.
  assert.match(difference(entry([], { state: 'valid', signatures: [] }), entry([a], { state: 'valid', signatures: [] })), /problems\[0\]: not among the stored findings/);
});

const BOOK_FILES = ['books.json', 'chained-books.json', 'held-seals.json', 'witness-books.json', 'check-before.json'];
test('in real answers: findings reordered, or problems cut to the first, pass; a finding dropped, added or emptied fails', { timeout: 600000 }, async () => {
  const sets = readSets(vectors, BOOK_FILES);
  const go = (mode, words = false) => runKit({ command: node, args: faulty(mode), sets, words });
  for (const mode of ['reorder', 'first-problem']) {
    const r = await go(mode);
    assert.deepEqual(r.failures, [], mode);
    assert.equal(r.ok, true, mode);
    const w = await go(mode, true);
    assert.equal(w.ok, false, `${mode} fails word for word`);
  }
  for (const mode of ['drop-finding', 'extra-finding', 'drop-breach', 'no-problems']) {
    const r = await go(mode);
    assert.equal(r.ok, false, mode);
    assert.ok(r.totals.failed > 0, mode);
  }
});

test('a line holding both "skip" and "answer" is a fault of the adapter, not a skip', async () => {
  const r = await run(faulty('skip-and-answer'));
  assert.equal(r.totals.skipped, 0);
  assert.equal(r.totals.failed, 48);
  assert.equal(r.failures[0].why, 'the adapter\'s line holds both "answer" and "skip"');
});

test('skips: named in the verdict, whole functions listed, and failures with --no-skip', async () => {
  const r = await run(faulty('skip'));
  assert.deepEqual(r.skippedFunctions, ['fromBase64url', 'parseCanonical']);
  const text = describe(r).join('\n');
  assert.match(text, /Functions skipped entirely \(2\): fromBase64url, parseCanonical\./);
  assert.match(text, /No case was compared; 48 skipped and not tested\./);
  const cli = (...a) => spawnSync(node, [join(kit, 'run.mjs'), ...a], { encoding: 'utf8' });
  const files = ['--file', 'base64url.json', '--file', 'canonical-json.json'];
  const skipOne = [quiet, join(here, 'adapters', 'skip-one-file.mjs')];
  const some = cli(...files, '--', node, ...skipOne);
  assert.equal(some.status, 0, some.stderr);
  assert.match(some.stdout, /11 case\(s\) compared, all matched; 37 skipped and not tested\./);
  assert.match(some.stdout, /Functions skipped entirely \(1\): parseCanonical\./);
  const strict = cli('--no-skip', ...files, '--', node, ...skipOne);
  assert.equal(strict.status, 1);
  assert.match(strict.stdout, /--no-skip counts a skip as a failure/);
  const quietRun = cli('--quiet', '--file', 'base64url.json', '--', node, ...faulty('crash-always'));
  assert.equal(quietRun.status, 1);
  assert.match(quietRun.stdout, /^Stopped early: the adapter failed 4 times in a row/m);
});
