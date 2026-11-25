// The first permission from end to end, as a person and the uploader meet
// it: "init" in a fresh folder, run as the command a person runs, leaves a
// recorder that waits; a feed reader stands in for the uploader, reads the
// agent's key set from GET /agent, and hands over a first permission signed
// by passkey A for that key set and one of the same wording signed by
// passkey B, and both wait for the person's "yes" with nothing taken;
// "admit-passkey" alone lists them and takes nothing; from a pipe it takes
// nothing; with the first 16 characters of A's thumbprint and "yes" (given
// through the function the command calls, since a test has no terminal to
// type at) A's permission is taken, and B's still waits and is not taken;
// the first tool call inside the permission is allowed and recorded, and one
// outside it is refused; "check" passes on the book, which names passkey A
// only, and the trusted list holds A only.
//
// Everything runs in temporary folders and on a port of the test's own, never
// on the recorder's own port or in its folder. Every wait has a time limit on
// the monotonic clock, and the recorder "init" starts is stopped at the end,
// whether the test passes or fails.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

const { keySetFingerprint, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { feedReader } = await import('../feed.mjs');
const { ADMIT_THUMBPRINT_LEAST, admitWaiting, loadAgentKeys, readTrusted, readWaitingPermissions } = await import('../recorder.mjs');
const { freePort, runCommand, runHook, signSlip, status, stopService, tempFolder, within } = await import('./world.mjs');

// The development stand-in for a passkey signs at http://localhost, so the
// recorder is told to take that signing address, as a test may.
const SETTINGS = { PROVARED_CLAUDE_CODE_SIGNING_ORIGIN: 'http://localhost' };
// Time limits, in milliseconds. "init" waits up to 20 seconds for the recorder it starts.
const INIT_MS = 90000;
const COMMAND_MS = 60000;
const ASK_MS = 15000;
const STOP_MS = 20000;

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const bookLines = (folder) => read(folder, 'book.jsonl').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const says = (r) => `code ${r.code}${r.signal ? ` (ended: ${r.signal})` : ''}\n${r.out}\n${r.err}`;

/** True once nothing answers on the port, asked again until "ms" have passed on the monotonic clock. */
async function quietWithin(port, ms) {
  for (const until = performance.now() + ms; performance.now() < until;) {
    try {
      await fetch(`http://127.0.0.1:${port}/status`, { signal: AbortSignal.timeout(2000) });
    } catch {
      return true;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

test('from "init" to a checked book: the first permission is taken only with passkey A\'s thumbprint and "yes", B\'s of the same wording waits and is not taken, the first call is allowed and recorded, and the book names A only', { timeout: 600000 }, async () => {
  const folder = join(tempFolder('provared-cc-e2e-'), 'claude-code'); // the folder does not exist yet
  const project = tempFolder('provared-project-');
  const port = await freePort();
  assert.ok(port < 8794 || port > 8797, 'never one of the live recorder\'s ports');
  const command = (args, more = {}) => runCommand(args, { folder, port, cwd: project, env: SETTINGS, ms: COMMAND_MS, ...more });
  let stopped = null;
  try {
    // 1. "init", as a person runs it: a recorder that waits, in a fresh folder.
    const init = await command(['init'], { ms: INIT_MS });
    assert.equal(init.code, 0, says(init));
    const printed = (init.out.match(/The fingerprint of the agent's key set: ([A-Za-z0-9_-]{43})/) ?? [])[1];
    assert.ok(printed, init.out);
    let st = await within(status(port), ASK_MS, '/status after init');
    assert.equal(st.waiting, true, 'the recorder waits for its first permission');
    assert.equal(st.folder, folder);
    assert.equal(st.waitingPermissions, 0);

    // 2. The uploader's stand-in: the agent's key set from the feed, then two permissions of the same wording.
    const reader = feedReader({ address: `http://127.0.0.1:${port}`, token: read(folder, 'feed-token').trim() });
    const agent = await within(reader.get('/agent'), ASK_MS, 'GET /agent');
    assert.equal(agent.code, 200);
    assert.equal(agent.proved, true, 'the answer carries the recorder\'s proof');
    assert.deepEqual(agent.body.agent.keys, (await loadAgentKeys(folder)).keys);
    assert.equal(agent.body.fingerprint, printed, 'the fingerprint init printed is the one the feed gives');
    assert.equal(await keySetFingerprint(agent.body.agent.keys), printed);
    const passkeyA = await developmentPasskey();
    const passkeyB = await developmentPasskey();
    const A = await thumbprint(passkeyA.key);
    const B = await thumbprint(passkeyB.key);
    assert.equal(ADMIT_THUMBPRINT_LEAST, 16);
    const startA = A.slice(0, 16);
    assert.ok(!B.startsWith(startA), 'the two thumbprints start differently');
    // The same wording, field for field: only the passkey differs.
    const wording = { agentKeys: agent.body.agent.keys, agentName: agent.body.agent.name, actions: ['provared.code.read'], from: Date.now() - 60000, until: Date.now() + 3600000, purpose: 'Read the project, and nothing else.' };
    const slipA = await signSlip({ ...wording, passkey: passkeyA });
    const slipB = await signSlip({ ...wording, passkey: passkeyB });
    const handedA = (await within(reader.post('/hand-over', { kind: 'renewal', slip: slipA }), ASK_MS, 'hand-over A')).body;
    assert.equal(handedA.outcome, 'refused', JSON.stringify(handedA));
    assert.equal(handedA.code, 'waits-for-yes', JSON.stringify(handedA));
    assert.equal(handedA.thumbprint, A);
    const handedB = (await within(reader.post('/hand-over', { kind: 'renewal', slip: slipB }), ASK_MS, 'hand-over B')).body;
    assert.equal(handedB.code, 'waits-for-yes', JSON.stringify(handedB));
    assert.equal(handedB.thumbprint, B);
    const fpA = handedA.fingerprint;
    const fpB = handedB.fingerprint;
    assert.notEqual(fpA, fpB);
    const nothingTaken = async (when) => {
      for (const name of ['slip.json', 'trusted-passkeys.json', 'book.jsonl']) assert.equal(existsSync(join(folder, name)), false, `${when}: ${name} is not written`);
      const now = await within(status(port), ASK_MS, `/status ${when}`);
      assert.equal(now.waiting, true, `${when}: still waiting`);
      assert.equal(now.waitingPermissions, 2, `${when}: both wait`);
      assert.deepEqual(readWaitingPermissions(folder).map((p) => p.fingerprint).sort(), [fpA, fpB].sort(), `${when}: both wait`);
    };
    await nothingTaken('after the two hand-overs');

    // 3. "admit-passkey" alone lists what waits and takes nothing.
    const listed = await command(['admit-passkey'], { input: 'yes\n' });
    assert.equal(listed.code, 0, says(listed));
    assert.match(listed.out, new RegExp(`passkey ${A}: the permission ${fpA}`));
    assert.match(listed.out, new RegExp(`passkey ${B}: the permission ${fpB}`));
    assert.match(listed.out, /Nothing is taken without a thumbprint/);
    await nothingTaken('after the listing');
    // From a pipe, "yes" is not taken: the answer must be typed at a terminal.
    const piped = await command(['admit-passkey', startA], { input: 'yes\n' });
    assert.equal(piped.code, 1, says(piped));
    assert.match(piped.out, /must be typed at a terminal/);
    await nothingTaken('after "yes" from a pipe');
    // With A's first 16 characters and "yes" typed: the function the command calls, given its answer,
    // as the existing tests do (a test cannot give the command a terminal to type at).
    const said = [];
    const asked = [];
    const code = await within(admitWaiting(folder, port, startA, { answer: async (prompt) => { asked.push(prompt); return 'yes'; }, terminal: true, say: (words) => said.push(words) }), COMMAND_MS, 'admit-passkey with A\'s thumbprint');
    const words = said.join('\n');
    assert.equal(code, 0, words);
    assert.equal(asked.length, 1, 'asked once');
    assert.match(words, new RegExp(`Passkey \\(thumbprint\\) +${A}`));
    assert.match(words, new RegExp(`Fingerprint +${fpA}`));
    assert.doesNotMatch(words, new RegExp(B), 'B\'s permission is not shown for A\'s thumbprint');
    st = await within(status(port), ASK_MS, '/status after yes');
    assert.equal(st.waiting, undefined, 'no longer waiting');
    assert.equal(st.slip, fpA);
    assert.equal(st.issuer, A);
    assert.deepEqual(st.trusted, [A]);
    assert.deepEqual(readTrusted(folder), [A]);
    assert.deepEqual(JSON.parse(read(folder, 'slip.json')), slipA);
    assert.deepEqual(bookLines(folder), [{ slip: slipA }], 'the book\'s first line is A\'s permission');
    // B's still waits, and is not taken, handed over again through the same reader after the switch.
    assert.deepEqual(readWaitingPermissions(folder).map((p) => p.fingerprint), [fpB], 'B\'s still waits');
    const again = (await within(reader.post('/hand-over', { kind: 'renewal', slip: slipB }), ASK_MS, 'hand-over B again')).body;
    assert.equal(again.outcome, 'refused', JSON.stringify(again));
    assert.equal(again.code, 'passkey-not-trusted', `the full recorder answers it now: ${JSON.stringify(again)}`);
    assert.equal(again.thumbprint, B);
    st = await within(status(port), ASK_MS, '/status after B again');
    assert.equal(st.slip, fpA, 'A\'s permission is still the one in force');
    assert.deepEqual(readTrusted(folder), [A], 'B is not trusted');

    // 4. The first tool call inside the permission: allowed by /before, recorded by /record. One outside it is refused.
    const before = await runHook(port, 'PreToolUse', 'Read', { file_path: 'README.md' }, { ms: COMMAND_MS });
    assert.equal(before.code, 0, says(before));
    assert.equal(before.out, '', 'a call inside the permission is allowed');
    const after = await runHook(port, 'PostToolUse', 'Read', { file_path: 'README.md' }, { ms: COMMAND_MS });
    assert.equal(after.code, 0, says(after));
    const recorded = bookLines(folder);
    assert.equal(recorded.length, 2, 'the permission and the call\'s stub');
    assert.equal(recorded[1].slip, undefined, 'the second line is the call, not a permission');
    const outside = await runHook(port, 'PreToolUse', 'Bash', { command: 'npm test' }, { ms: COMMAND_MS });
    assert.equal(outside.decision?.permissionDecision, 'deny', says(outside));
    assert.equal(bookLines(folder).length, 2, 'the refused call writes nothing in the book');

    // 5. Seal, then "check", the command: the checker passes the book under A, and the book names A only.
    const sealed = await command(['seal']);
    assert.equal(sealed.code, 0, says(sealed));
    const checked = await command(['check', '--issuer', A]);
    assert.equal(checked.code, 0, says(checked));
    assert.match(checked.out, /Did the agent stay within its slip\? +yes/);
    assert.match(checked.out, /Checked against keys you named\? +yes/);
    const unnamed = await command(['check']);
    const named = [...unnamed.err.matchAll(/^ {2}passkey ([A-Za-z0-9_-]{43}): the permission /gm)].map((m) => m[1]);
    assert.deepEqual(named, [A], `the book names passkey A only\n${says(unnamed)}`);
    const underB = await command(['check', '--issuer', B]);
    assert.equal(underB.code, 2, `the book is not B's: ${says(underB)}`);
    const permissions = bookLines(folder).filter((line) => line.slip);
    assert.deepEqual(permissions, [{ slip: slipA }], 'one permission in the book, A\'s');
    assert.deepEqual(readTrusted(folder), [A], 'the trusted list holds A only');
  } finally {
    await stopService(port);
    stopped = await quietWithin(port, STOP_MS);
    if (!stopped) console.error(`The recorder on port ${port} still answers ${STOP_MS} ms after it was asked to stop.`);
  }
  assert.equal(stopped, true, 'the recorder init started is stopped');
});
