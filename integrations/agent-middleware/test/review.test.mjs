// The findings of the first independent review, each held by a test that
// failed before its fix: conditions not judged, the key's own method,
// untrusted text in the command's output, the command run from a copy of
// the repository, what cannot be shown, malformed signed text, periods to
// the nanosecond, a receipt handed over twice, the identifier of a receipt
// that failed, and the edges of the slip's time, its periods and its
// conditions.

import './local-library.mjs';
import { execFile } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { before, test } from 'node:test';
import assert from 'node:assert/strict';

const { developmentSlip } = await import('provared/dev');
const { CANNOT_SHOW, judgeReceipts } = await import('../judge.mjs');
const { verifyRecord } = await import('../verify.mjs');
const { makeGateway, permit, receipt } = await import('./amw-world.mjs');

const run = promisify(execFile);
const toPath = (url) => url.pathname.replace(/^\/([A-Za-z]:)/, '$1');
const BIN = toPath(new URL('../bin.mjs', import.meta.url));
const ROOT = toPath(new URL('../../../', import.meta.url));
const vectors = (name) => JSON.parse(readFileSync(new URL(`vectors/${name}`, import.meta.url), 'utf8'));
const CREDITS = { unit: 'credits', decimals: 2 };
const SERVICE = { id: 'amw', name: 'The AMW gateway' };
const DAY = { validFrom: '2026-09-14T00:00:00Z', validUntil: '2026-09-15T00:00:00Z' };
const codes = (item) => item.findings.map((f) => f.code);

async function slipWith(fields) {
  return developmentSlip({ actions: ['echo'], with: [SERVICE], ...DAY, ...fields });
}

async function judge(made, gateway, receipts, more = {}) {
  return judgeReceipts({ slip: made.slip, issuerKeys: made.issuerKeys, keys: gateway.keys, receipts, service: 'amw', credits: CREDITS, ...more });
}

// Without the tests' own loader: as a person runs the command.
function plainEnv() {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  return env;
}

async function command(args, { cwd, env, node = [] } = {}) {
  try {
    const { stdout, stderr } = await run(process.execPath, ['--disable-warning=ExperimentalWarning', ...node, ...args], { encoding: 'utf8', cwd, env });
    return { code: 0, stdout, stderr };
  } catch (e) {
    if (typeof e.code !== 'number') throw e;
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
}

// An AMW envelope over an exact signed text, signed with an Ed25519 key of the test's own.
function signedText(signingInput, privateKey, id, kid = 'k') {
  return { receipt_id: id, kid, alg: 'Ed25519', signing_input: signingInput, signature: sign(null, Buffer.from(signingInput, 'utf8'), privateKey).toString('base64') };
}

function edKeys(kid = 'k') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  return { privateKey, keys: { keys: [{ kid, alg: 'Ed25519', status: 'active', public_key_b64: raw.toString('base64') }] } };
}

let dir;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'provared-amw-review-'));
});

const put = async (name, value) => {
  const path = join(dir, name);
  await writeFile(path, typeof value === 'string' ? value : JSON.stringify(value));
  return path;
};

// 1 (serious)

test('a countersignature the slip asks for is not judged: the receipt is never within the slip, and the command does not end with 0', async () => {
  const gw = makeGateway();
  const made = await slipWith({ actions: ['echo', 'other'], requires: [{ need: 'countersignature', action: 'echo' }] });
  const r = await judge(made, gw, [receipt(gw)]);
  assert.equal(r.judged, true);
  assert.deepEqual(r.receipts[0].findings, []);
  assert.deepEqual(r.receipts[0].notJudged, ['countersignature']);
  assert.equal(r.summary.notJudged, 1);
  assert.equal(r.summary.withinSlip, null, 'not known, never true');
  // The condition applies to no compared receipt: the receipts are within the slip.
  const other = await judge(made, gw, [receipt(gw, { tool: 'other' })]);
  assert.equal(other.summary.notJudged, 0);
  assert.equal(other.summary.withinSlip, true);
  // A finding elsewhere still makes the answer "no".
  const over = await judge(await slipWith({ actions: ['echo'], requires: [{ need: 'countersignature' }], limits: [{ action: 'echo', count: 1 }] }), gw, [receipt(gw), receipt(gw, { created_at: '2026-09-14T17:01:00+00:00' })]);
  assert.equal(over.summary.withinSlip, false);

  const slip = await put('cs-slip.json', made.slip);
  const keys = await put('cs-keys.json', gw.keys);
  const receipts = await put('cs-receipts.json', [receipt(gw)]);
  const out = await command([BIN, 'judge', '--slip', slip, '--keys', keys, '--receipts', receipts, '--service', 'amw', '--issuer-key', made.issuerKeys[0]]);
  assert.equal(out.code, 1, out.stdout + out.stderr);
  assert.match(out.stdout, /NOT KNOWN whether within the slip: countersignature not judged/);
  assert.match(out.stdout, /Within the slip, as far as these receipts show\? NOT KNOWN: 1 compared receipt\(s\) fall under a condition of the slip this reader cannot judge/);
});

test('an approval named by identifier only is not judged: the receipt is never within the slip', async () => {
  const gw = makeGateway();
  const made = await slipWith({ requires: [{ need: 'approval' }] });
  const r = await judge(made, gw, [receipt(gw, { approval_id: 'apr_test_0001' })]);
  assert.deepEqual(r.receipts[0].notJudged, ['approval']);
  assert.equal(r.summary.withinSlip, null);
  assert.match(r.receipts[0].notes.join(' '), /by identifier only/);
  const none = await judge(made, gw, [receipt(gw)]);
  assert.deepEqual(codes(none.receipts[0]), ['approval-missing']);
  assert.deepEqual(none.receipts[0].notJudged, []);
  assert.equal(none.summary.withinSlip, false);
});

// 2

test('a P-256 key is outside the contract whatever method the content and the envelope name', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keys = { keys: [{ kid: 'p', alg: 'ECDSA-P256-SHA256', status: 'active', public_key_b64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }] };
  const text = '{"alg":"Ed25519","kid":"p","outcome":"success","receipt_id":"r1","tool":"echo"}';
  const bundle = { receipt_id: 'r1', kid: 'p', alg: 'Ed25519', signing_input: text, signature: sign('sha256', Buffer.from(text), privateKey).toString('base64') };
  const answer = verifyRecord(bundle, keys);
  assert.equal(answer.status, 'unsupported');
  assert.match(answer.reason, /key named signs with a method other than Ed25519/);
  assert.equal(answer.content, null);
  // A changed text still reads "invalid": the signature is checked first.
  assert.equal(verifyRecord({ ...bundle, signing_input: text.replace('echo', 'echp') }, keys).status, 'invalid');
});

// 3

test('the command shows control and invisible characters from a key list or a permit as a mark', async () => {
  const kid = 'sk\u001b[2J\u202eevil';
  const gw = makeGateway(kid);
  const keys = await put('esc-keys.json', gw.keys);
  const one = await put('esc-receipt.json', receipt(gw));
  const out = await command([BIN, 'verify', '--keys', keys, '--receipt', one]);
  assert.equal(out.code, 0, out.stdout + out.stderr);
  assert.doesNotMatch(out.stdout, /[\u001b\u202e]/);
  assert.match(out.stdout, /Key: sk\ufffd\[2J\ufffdevil/);
  const json = await command([BIN, 'verify', '--keys', keys, '--receipt', one, '--json']);
  assert.doesNotMatch(json.stdout, /[\u001b\u202e]/);
  assert.equal(JSON.parse(json.stdout).key.kid, kid, 'the JSON stays exact');

  const made = await slipWith({});
  const slip = await put('esc-slip.json', made.slip);
  const permits = await put('esc-permits.json', [permit(gw, { allowed_tools: ['echo', 'a\u0007b\u200bc'] })]);
  const judged = await command([BIN, 'judge', '--slip', slip, '--keys', keys, '--receipts', one, '--permits', permits, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0]]);
  assert.doesNotMatch(judged.stdout, /[\u0007\u001b\u200b\u202e]/);
  assert.match(judged.stdout, /tools echo, a\ufffdb\ufffdc/);
});

// 4

test('the README\'s commands work from a copy of the repository as written, and verify needs no library', async () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const VERIFY = 'node integrations/agent-middleware/bin.mjs verify';
  const JUDGE = 'node --import ./integrations/agent-middleware/test/local-library.mjs integrations/agent-middleware/bin.mjs judge';
  assert.ok(readme.includes(VERIFY), 'the README gives the verify command');
  assert.ok(readme.includes(JUDGE), 'the README gives the judge command');
  const cases = vectors('receipts.json').cases;
  const keys = await put('copy-keys.json', vectors('keys.json'));
  const valid = await put('copy-valid.json', cases.find((c) => c.name === 'success_legacy.valid').bundle);
  const verify = await command(['integrations/agent-middleware/bin.mjs', 'verify', '--keys', keys, '--receipt', valid], { cwd: ROOT, env: plainEnv() });
  assert.equal(verify.code, 0, verify.stderr);
  assert.match(verify.stdout, /rcpt_golden_0001: verified/);

  const gw = makeGateway();
  const made = await slipWith({});
  const slip = await put('copy-slip.json', made.slip);
  const ownKeys = await put('copy-own-keys.json', gw.keys);
  const receipts = await put('copy-receipts.json', [receipt(gw)]);
  const args = ['judge', '--slip', slip, '--keys', ownKeys, '--receipts', receipts, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0]];
  const judged = await command(['integrations/agent-middleware/bin.mjs', ...args], { cwd: ROOT, env: plainEnv(), node: ['--import', './integrations/agent-middleware/test/local-library.mjs'] });
  assert.equal(judged.code, 0, judged.stdout + judged.stderr);
  // The package names the library only as a peer, 0.7.0 or later, and pins no other.
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.peerDependencies.provared, '^0.7.0');
  assert.equal(pkg.devDependencies?.provared, undefined);
});

// 5

test('what cannot be shown includes cancellations, outcomes other than success, and retired keys', () => {
  assert.ok(CANNOT_SHOW.some((s) => /^No cancellation\./.test(s) && /cannot be handed/.test(s)));
  assert.ok(CANNOT_SHOW.some((s) => /^Only successes are counted\./.test(s) && /left out of every total/.test(s)));
  assert.ok(CANNOT_SHOW.some((s) => /^Retired keys\./.test(s) && /of any date/.test(s)));
});

// 6 and 7

test('signed text that is not well-formed Unicode, names a member twice, or gives a "kid" that is not text is malformed', () => {
  const { privateKey, keys } = edKeys();
  const sound = '{"alg":"Ed25519","kid":"k","outcome":"success","receipt_id":"r1","tool":"a\ufffdb"}';
  assert.equal(verifyRecord(signedText(sound, privateKey, 'r1'), keys).status, 'verified');
  // A lone surrogate: Node.js signs it as the replacement character, so the
  // signature over the sound text fits this text too.
  const lone = { ...signedText(sound, privateKey, 'r1'), signing_input: sound.replace('\ufffd', '\ud800') };
  const loneAnswer = verifyRecord(lone, keys);
  assert.equal(loneAnswer.status, 'malformed');
  assert.match(loneAnswer.reason, /well-formed Unicode/);

  const twice = '{"alg":"Ed25519","kid":"k","outcome":"denied","receipt_id":"r2","outcome":"success"}';
  const twiceAnswer = verifyRecord(signedText(twice, privateKey, 'r2'), keys);
  assert.equal(twiceAnswer.status, 'malformed');
  assert.match(twiceAnswer.reason, /one member twice/);
  const escaped = '{"alg":"Ed25519","kid":"k","receipt_id":"r3","a":1,"\\u0061":2}';
  assert.equal(verifyRecord(signedText(escaped, privateKey, 'r3'), keys).status, 'malformed');
  const nested = '{"alg":"Ed25519","kid":"k","receipt_id":"r4","x":{"b":1,"b":2}}';
  assert.equal(verifyRecord(signedText(nested, privateKey, 'r4'), keys).status, 'malformed');
  // One name in two objects, and a name that is also a value, are sound.
  const apart = '{"alg":"Ed25519","kid":"k","receipt_id":"r5","x":{"tool":"y"},"y":[{"tool":"tool"},{"tool":"\\"}"}],"tool":"x"}';
  assert.equal(verifyRecord(signedText(apart, privateKey, 'r5'), keys).status, 'verified');

  const numberKid = '{"alg":"Ed25519","kid":5,"receipt_id":"r6"}';
  const kidAnswer = verifyRecord(signedText(numberKid, privateKey, 'r6'), keys);
  assert.equal(kidAnswer.status, 'malformed');
  assert.match(kidAnswer.reason, /"kid" is not text/);
});

// 8 and 12

test('periods are counted to the nanosecond, and a period ends just before its full length', async () => {
  const gw = makeGateway();
  const made = await slipWith({ limits: [{ action: 'echo', count: 1, per: 3600 }] });
  // 3,599.9996 seconds apart: in the same hour.
  const close = await judge(made, gw, [receipt(gw, { created_at: '2026-09-14T17:00:00.0009+00:00' }), receipt(gw, { created_at: '2026-09-14T18:00:00.0005+00:00' })]);
  assert.deepEqual(codes(close.receipts[1]), ['over-period-limit']);
  const nano = await judge(made, gw, [receipt(gw, { created_at: '2026-09-14T17:00:00.000000001+00:00' }), receipt(gw, { created_at: '2026-09-14T18:00:00+00:00' })]);
  assert.deepEqual(codes(nano.receipts[1]), ['over-period-limit']);
  // Exactly an hour apart: not in the same hour.
  const apart = await judge(made, gw, [receipt(gw, { created_at: '2026-09-14T17:00:00.5+00:00' }), receipt(gw, { created_at: '2026-09-14T18:00:00.500000000+00:00' })]);
  assert.equal(apart.summary.withinSlip, true);
});

test('a receipt dated at the slip\'s end is outside it, and one just before it is inside', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const r = await judge(made, gw, [
    receipt(gw, { created_at: '2026-09-15T00:00:00+00:00' }),
    receipt(gw, { created_at: '2026-09-14T23:59:59.999999999+00:00' }),
    receipt(gw, { created_at: '2026-09-14T00:00:00+00:00' }),
    receipt(gw, { created_at: '2026-09-13T23:59:59.9999999+00:00' }),
  ]);
  assert.deepEqual(r.receipts.map(codes), [['outside-valid-time'], [], [], ['outside-valid-time']]);
});

test('a condition "above" an amount does not apply to an amount equal to it', async () => {
  const gw = makeGateway();
  const made = await slipWith({ requires: [{ need: 'approval', action: 'echo', above: 250, unit: 'credits' }] });
  const r = await judge(made, gw, [receipt(gw, { credits_charged: '2.5' }), receipt(gw, { credits_charged: '2.51', created_at: '2026-09-14T17:01:00+00:00' })]);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.deepEqual(codes(r.receipts[1]), ['approval-missing']);
});

// 9

test('a receipt handed over twice is counted once, and the answer says so', async () => {
  const gw = makeGateway();
  const made = await slipWith({ limits: [{ action: 'echo', max: 300, unit: 'credits' }] });
  const one = receipt(gw);
  const r = await judge(made, gw, [one, one]);
  assert.deepEqual(codes(r.receipts[0]), []);
  assert.equal(r.receipts[1].kind, 'duplicate');
  assert.equal(r.receipts[1].duplicateOf, 0);
  assert.equal(r.receipts[1].compared, false);
  assert.match(r.receipts[1].notes[0], /the same receipt as number 1 handed over, which is counted once/);
  assert.equal(r.summary.duplicates, 1);
  assert.equal(r.summary.compared, 1);
  assert.equal(r.summary.withinSlip, true, 'the total is 250, not 500');
  // Another record signed with the same identifier: the first counts, and the answer says so.
  const other = receipt(gw, { receipt_id: JSON.parse(one.signing_input).receipt_id, credits_charged: '1' });
  const r2 = await judge(made, gw, [one, other]);
  assert.match(r2.receipts[1].notes[0], /another receipt the gateway signed with the same identifier as number 1/);
  // A set with a second copy is not "every receipt compared": the command ends with 1.
  const slip = await put('dup-slip.json', made.slip);
  const keys = await put('dup-keys.json', gw.keys);
  const both = await put('dup-receipts.json', [one, one]);
  const out = await command([BIN, 'judge', '--slip', slip, '--keys', keys, '--receipts', both, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0]]);
  assert.equal(out.code, 1);
  assert.match(out.stdout, /1 handed over more than once/);
});

// 10

test('a receipt that failed its check shows no identifier, in the answer or the output', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const cases = vectors('receipts.json').cases;
  const mismatch = cases.find((c) => c.name === 'success_legacy.envelope_receipt_id_mismatch');
  const answer = verifyRecord(mismatch.bundle, mismatch.keys ?? vectors('keys.json'));
  assert.equal(answer.status, 'mismatch');
  assert.equal(answer.id, null);
  const forged = { ...receipt(gw, { receipt_id: 'rcpt_SHOWN_IF_WRONG' }), signature: 'A'.repeat(86) + '==' };
  const r = await judge(made, gw, [forged]);
  assert.equal(r.receipts[0].status, 'invalid');
  assert.equal(r.receipts[0].id, null);
  assert.equal(r.receipts[0].place, 0);
  assert.doesNotMatch(JSON.stringify(r), /SHOWN_IF_WRONG/);
  const slip = await put('fail-slip.json', made.slip);
  const keys = await put('fail-keys.json', gw.keys);
  const file = await put('fail-receipts.json', [forged]);
  const out = await command([BIN, 'judge', '--slip', slip, '--keys', keys, '--receipts', file, '--service', 'amw', '--issuer-key', made.issuerKeys[0]]);
  assert.doesNotMatch(out.stdout, /SHOWN_IF_WRONG/);
  assert.match(out.stdout, /1\. \(identifier not shown\): invalid/);
  const verify = await command([BIN, 'verify', '--keys', keys, '--receipt', await put('fail-one.json', forged)]);
  assert.doesNotMatch(verify.stdout, /SHOWN_IF_WRONG/);
});

// 12

test('the command does not end with 0 where any receipt was not compared', async () => {
  const gw = makeGateway();
  const made = await slipWith({});
  const slip = await put('nc-slip.json', made.slip);
  const keys = await put('nc-keys.json', gw.keys);
  const base = ['judge', '--slip', slip, '--keys', keys, '--service', 'amw', '--issuer-key', made.issuerKeys[0]];
  const within = await command([BIN, ...base, '--receipts', await put('nc-within.json', [receipt(gw)])]);
  assert.equal(within.code, 0, within.stdout);
  const denied = await command([BIN, ...base, '--receipts', await put('nc-denied.json', [receipt(gw), receipt(gw, { outcome: 'denied' })])]);
  assert.equal(denied.code, 1);
  const noTime = await command([BIN, ...base, '--receipts', await put('nc-time.json', [receipt(gw), receipt(gw, { created_at: 'yesterday' })])]);
  assert.equal(noTime.code, 1);
});
