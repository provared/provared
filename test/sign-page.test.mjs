// The signing page names the agent's keys, before the passkey is asked, by
// the fingerprint of their key set, worked out by the library's own
// function, so that the person can compare it with what the agent's
// software printed. A link, or a permission pasted from elsewhere, could
// otherwise carry someone else's keys under a familiar name. The page's
// words for the keys are a plain function (agentKeySet in
// page/sign-page.js), tested here without a browser; the page's reading
// step shows them for whatever is in its box, from a link or typed.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeySet, keySetFingerprint, toBase64url, utf8 } from '../src/index.js';
import { agentKeySet, fingerprintStartRefusal, handedBackAtOnce, newAgentWords, readStartingPermission } from '../page/sign-page.js';

const linkFor = (permission) => `#permission=${toBase64url(utf8(JSON.stringify(permission)))}`;

test('the page names the agent\'s keys by the fingerprint of their key set, as the library does, and asks the person to compare it', async () => {
  const agent = await generateKeySet();
  const shown = await agentKeySet(agent.keys);
  assert.equal(shown.fingerprint, await keySetFingerprint(agent.keys));
  assert.equal(
    shown.words,
    `${shown.fingerprint}. Compare this fingerprint with the one the agent's software printed when it made its keys. If they differ, these are not your agent's keys: do not sign.`,
  );

  // The keys a link carries are the ones named, whatever name comes with them.
  const { permission } = readStartingPermission(linkFor({ agent: { name: 'My agent', keys: agent.keys } }));
  assert.equal((await agentKeySet(permission.agent.keys)).fingerprint, shown.fingerprint);
  const stranger = await generateKeySet();
  const crafted = readStartingPermission(linkFor({ agent: { name: 'My agent', keys: stranger.keys } })).permission;
  assert.notEqual((await agentKeySet(crafted.agent.keys)).fingerprint, shown.fingerprint, 'someone else\'s keys under the same name');
});

test('keys that are not a key set get no fingerprint, and the library\'s own words say why', async () => {
  const agent = await generateKeySet();
  for (const [keys, words] of [
    [[agent.keys[1], agent.keys[0]], 'agent.keys[0]: the signing method must be one of Ed25519.'],
    [[agent.keys[0]], 'agent.keys: a key set is exactly two keys: Ed25519, then ML-DSA-87.'],
    [[agent.keys[0], { ...agent.keys[1], pub: 'AAAA' }], 'agent.keys[1]: an ML-DSA-87 public key is 2,592 bytes.'],
  ]) {
    await assert.rejects(agentKeySet(keys), (e) => e.name === 'Refusal' && e.code === 'bad-key' && e.message === words, words);
  }
});

// Design P-19, 2.8, as the founder decided after the review of step 9: a
// permission goes back at once only where a checked earlier permission
// vouches for both the passkey that signs and the agent's key set, whatever
// kind the page that asked names; a cancellation always does.
test('handed back at once: a cancellation, and a permission only where an earlier one vouches for passkey and key set', () => {
  assert.equal(handedBackAtOnce('cancellation', false), true);
  assert.equal(handedBackAtOnce('renewal', true), true, 'a true renewal');
  assert.equal(handedBackAtOnce('renewal', false), false, 'a "renewal" nothing vouches for');
  assert.equal(handedBackAtOnce('permission', false), false, 'a first permission');
  assert.equal(handedBackAtOnce('permission', 'yes'), false, 'only true vouches');
});

// 6.B and 6.C(b): for a key set new to this device, the signing window signs
// only once the person gives the start of the fingerprint the agent's
// software printed, of at least 16 characters, or the whole of it. The page
// takes the last run of fingerprint characters (letters, digits, "-", "_")
// of 16 to 43 in what was pasted, so that the whole line init prints can be
// pasted; that run must match the start exactly (base64url mixes upper and
// lower case).
test('the start of the fingerprint the agent\'s software printed: 16 characters or more, or the whole, matched exactly', async () => {
  const fp = await keySetFingerprint((await generateKeySet()).keys);
  assert.equal(fp.length, 43);
  const other = await keySetFingerprint((await generateKeySet()).keys);
  for (const good of [
    fp, fp.slice(0, 16), fp.slice(0, 30), `  ${fp}\n`, `\r\n${fp.slice(0, 16)} `, `\t${fp}\t`,
    `The fingerprint of the agent's key set: ${fp}`, // the whole line init prints
    `The fingerprint of the agent's key set: ${fp}.`,
    `${other} ${fp}`, // the last run is the one taken
  ]) {
    assert.equal(fingerprintStartRefusal(good, fp), null, JSON.stringify(good));
  }
  const swapCase = (c) => (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase());
  const letter = [...fp.slice(0, 16)].findIndex((c) => /[A-Za-z]/.test(c));
  const wrongCase = fp.slice(0, letter) + swapCase(fp[letter]) + fp.slice(letter + 1, 16);
  for (const [bad, words] of [
    ['', /^Paste the fingerprint your agent's software printed on the agent's computer in the box above/],
    ['   \n', /^Paste the fingerprint your agent's software printed/],
    [undefined, /^Paste the fingerprint your agent's software printed/],
    [fp.slice(0, 15), /^That is 15 characters: give at least 16/],
    [fp.slice(0, 1), /^That is 1 character: give at least 16/],
    [other.slice(0, 16), /^That is not the start of the fingerprint of the agent's key set in this permission/],
    [wrongCase, /^That is not the start/],
    [fp.slice(1, 17), /^That is not the start/],
    [`${fp} ${other}`, /^That is not the start/],
    [`The fingerprint of the agent's key set: ${other}`, /^That is not the start/],
    [`${fp.slice(0, 8)} ${fp.slice(8, 20)}`, /^What you pasted holds no fingerprint: .*Paste the fingerprint alone/],
    [`${fp}A`, /^What you pasted holds no fingerprint/],
    [`key set: ${fp.slice(0, 10)}`, /^What you pasted holds no fingerprint/],
    [`${fp.slice(0, 10)}​${fp.slice(10, 30)}`, /^That is not the start/], // a zero-width space splits it
  ]) {
    assert.match(fingerprintStartRefusal(bad, fp) ?? 'matched', words, JSON.stringify(bad));
  }
});

// 2.8 item 3, for every key set new to this device that no earlier
// permission vouches for: expected for a new agent, and compared with what
// the agent's software printed, never with the application.
test('the warning for a key set new to this device: expected, and compared with what the agent\'s software printed', () => {
  const fp = 'A'.repeat(43);
  assert.equal(
    newAgentWords(fp),
    `This is the first permission for this agent's key set on this device, as is expected for a new agent: ${fp}. Compare it with the fingerprint your agent's software printed on the agent's computer (for Claude Code, the one init printed), never with the application or another page: whoever filled in this permission could have put another agent's keys in it. A permission for someone else's keys lets their agent act in your name.`,
  );
});
