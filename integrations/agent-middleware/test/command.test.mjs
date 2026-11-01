// The command, run as a program on files in a temporary folder.

import './local-library.mjs';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { readFileSync } from 'node:fs';
import { before, test } from 'node:test';
import assert from 'node:assert/strict';

const { developmentSlip } = await import('provared/dev');
const { makeGateway, receipt } = await import('./amw-world.mjs');

const run = promisify(execFile);
const BIN = new URL('../bin.mjs', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const vectors = (name) => JSON.parse(readFileSync(new URL(`vectors/${name}`, import.meta.url), 'utf8'));

async function command(...args) {
  try {
    const { stdout, stderr } = await run(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, ...args], { encoding: 'utf8' });
    return { code: 0, stdout, stderr };
  } catch (e) {
    if (typeof e.code !== 'number') throw e;
    return { code: e.code, stdout: e.stdout, stderr: e.stderr };
  }
}

let dir;
let files;
let gw;
let made;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'provared-amw-'));
  gw = makeGateway();
  made = await developmentSlip({
    actions: ['echo'],
    limits: [{ action: 'echo', max: 600, unit: 'credits' }],
    with: [{ id: 'amw', name: 'The AMW gateway' }],
    validFrom: '2026-09-14T00:00:00Z',
    validUntil: '2026-09-15T00:00:00Z',
  });
  const put = async (name, value) => {
    const path = join(dir, name);
    await writeFile(path, JSON.stringify(value));
    return path;
  };
  const cases = vectors('receipts.json').cases;
  files = {
    keys: await put('keys.json', vectors('keys.json')),
    valid: await put('valid.json', cases.find((c) => c.name === 'success_legacy.valid').bundle),
    bad: await put('bad.json', cases.find((c) => c.name === 'success_legacy.bad_signature').bundle),
    malformed: await put('malformed.json', cases.find((c) => c.name === 'synthetic.malformed_signature').bundle),
    permit: await put('permit.json', vectors('permits.json').cases.find((c) => c.name === 'active_minimal.valid').bundle),
    notJson: await put('not.json', 'x').then(() => join(dir, 'not.json')),
    slip: await put('slip.json', made.slip),
    ownKeys: await put('own-keys.json', gw.keys),
    within: await put('within.json', [receipt(gw), receipt(gw, { created_at: '2026-09-14T17:05:00+00:00' })]),
    over: await put('over.json', [receipt(gw), receipt(gw, { created_at: '2026-09-14T17:05:00+00:00' }), receipt(gw, { created_at: '2026-09-14T17:10:00+00:00' })]),
    mapped: await put('mapped.json', receipt(gw, { tool: 'golden-path-echo' })),
  };
  await writeFile(files.notJson, 'not json');
});

test('verify: 0 for verified, 1 for any other answer, 2 for malformed', async () => {
  const ok = await command('verify', '--keys', files.keys, '--receipt', files.valid);
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /rcpt_golden_0001: verified/);
  assert.match(ok.stdout, /Key: sk_golden_0001 \(Ed25519, active\)/);
  assert.match(ok.stdout, /Evidence, not a verdict/);
  const bad = await command('verify', '--keys', files.keys, '--receipt', files.bad);
  assert.equal(bad.code, 1);
  assert.match(bad.stdout, /: invalid\./);
  const malformed = await command('verify', '--keys', files.keys, '--receipt', files.malformed);
  assert.equal(malformed.code, 2);
  const permit = await command('verify', '--keys', files.keys, '--permit', files.permit, '--json');
  assert.equal(permit.code, 0);
  const answer = JSON.parse(permit.stdout);
  assert.equal(answer.status, 'verified');
  assert.equal(answer.kind, 'permit');
  assert.equal(answer.content.permit_id, 'pmt_golden_0001');
  const asReceipt = await command('verify', '--keys', files.keys, '--receipt', files.permit);
  assert.equal(asReceipt.code, 2);
});

test('verify: the command refuses what it does not understand, with code 2', async () => {
  assert.equal((await command('verify', '--receipt', files.valid)).code, 2);
  assert.equal((await command('verify', '--keys', files.keys)).code, 2);
  assert.equal((await command('verify', '--keys', files.keys, '--receipt', files.valid, '--permit', files.permit)).code, 2);
  assert.equal((await command('verify', '--keys', files.keys, '--receipt')).code, 2);
  assert.equal((await command('verify', '--keys', files.keys, '--receipt', files.valid, '--what')).code, 2);
  assert.equal((await command('verify', '--keys', files.keys, '--keys', files.keys, '--receipt', files.valid)).code, 2);
  const missing = await command('verify', '--keys', files.keys, '--receipt', join(dir, 'none.json'));
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /could not be read/);
  const notJson = await command('verify', '--keys', files.keys, '--receipt', files.notJson);
  assert.equal(notJson.code, 2);
  assert.match(notJson.stderr, /not JSON/);
  assert.equal((await command('what')).code, 2);
  assert.equal((await command()).code, 2);
  const help = await command('--help');
  assert.equal(help.code, 0);
  assert.match(help.stdout, /provared-agent-middleware judge/);
});

test('judge: 0 only where everything verified, was compared, is within the slip and rests on a passkey you named', async () => {
  const base = ['judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'amw', '--credits', 'credits:2'];
  const ok = await command(...base, '--issuer-key', made.issuerKeys[0]);
  assert.equal(ok.code, 0, ok.stderr + ok.stdout);
  assert.match(ok.stdout, /Within the slip, as far as these receipts show\? yes/);
  assert.match(ok.stdout, /Rests on a passkey you named\? yes/);
  assert.match(ok.stdout, /1\. rcpt_test_\d+: verified; echo at 2026-09-14T17:00:00\.000Z; 250 credits; permit pmt_test_0001; within the slip/);
  assert.match(ok.stdout, /What this judgement cannot show:/);
  assert.match(ok.stdout, /No chain\./);
  const untrusted = await command(...base);
  assert.equal(untrusted.code, 1);
  assert.match(untrusted.stdout, /Rests on a passkey you named\? NO: name one with --issuer-key/);
  const over = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.over, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0]);
  assert.equal(over.code, 1);
  assert.match(over.stdout, /3\. rcpt_test_\d+: verified; .*; OUTSIDE the slip/);
  assert.match(over.stdout, /- over-limit: With this AMW receipt the total is 750 credits/);
  assert.match(over.stdout, /Within the slip, as far as these receipts show\? NO/);
  const json = await command(...base, '--issuer-key', made.issuerKeys[0], '--json');
  assert.equal(json.code, 0);
  const r = JSON.parse(json.stdout);
  assert.equal(r.judged, true);
  assert.equal(r.summary.withinSlip, true);
  assert.equal(r.receipts.length, 2);
});

test('judge: a tool is mapped to an action, the AMW vectors\' key can be named, and a receipt not verified gives code 1', async () => {
  const mapped = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.mapped, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0], '--tool', 'golden-path-echo=echo');
  assert.equal(mapped.code, 0, mapped.stdout);
  assert.match(mapped.stdout, /verified; echo at/);
  const unmapped = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.mapped, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0]);
  assert.equal(unmapped.code, 1);
  assert.match(unmapped.stdout, /action-not-allowed/);
  // A receipt signed by the published test key, under keys that do not hold it.
  const unknown = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.valid, '--service', 'amw', '--credits', 'credits:2', '--issuer-key', made.issuerKeys[0], '--tool', 'golden-path-echo=echo');
  assert.equal(unknown.code, 1);
  assert.match(unknown.stdout, /unknown_key/);
  assert.match(unknown.stdout, /Every AMW receipt verified\? NO/);
});

test('judge: nothing judged gives code 2, as does a command not understood', async () => {
  const noCredits = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'amw', '--issuer-key', made.issuerKeys[0]);
  assert.equal(noCredits.code, 2);
  assert.match(noCredits.stdout, /Problem amw-credits-not-stated/);
  assert.match(noCredits.stdout, /Nothing was judged\./);
  const wrongService = await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'shop', '--credits', 'credits:2');
  assert.equal(wrongService.code, 2);
  assert.match(wrongService.stdout, /amw-service-not-in-slip/);
  assert.equal((await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within)).code, 2);
  assert.equal((await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'amw', '--credits', 'credits')).code, 2);
  assert.equal((await command('judge', '--slip', files.slip, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'amw', '--tool', 'noequals')).code, 2);
  assert.equal((await command('judge', '--slip', files.notJson, '--keys', files.ownKeys, '--receipts', files.within, '--service', 'amw')).code, 2);
});
