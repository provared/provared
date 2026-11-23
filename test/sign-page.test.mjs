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
import { agentKeySet, fingerprintStartRefusal, firstPermission, newAgentWords, readRequest, readStartingPermission } from '../page/sign-page.js';

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

// A first permission (design P-19, section 2.8): a request of kind
// "permission", which names no earlier permission. Renewals, cancellations
// and a page opened without a request are not first permissions.
test('a first permission is a request for a new permission, and nothing else', async () => {
  const agent = await generateKeySet();
  const fields = { agent: { name: 'A', keys: agent.keys }, actions: [], limits: [], requires: [], never: [], with: [], validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-01-02T00:00:00Z', purpose: 'p' };
  const asked = (request) => readRequest(`#request=${toBase64url(utf8(JSON.stringify(request)))}`).request;
  assert.equal(firstPermission(asked({ kind: 'permission', fields })), true);
  assert.equal(firstPermission(asked({ kind: 'renewal', fields, earlier: { payload: 'x' } })), false);
  assert.equal(firstPermission(asked({ kind: 'cancellation', earlier: { payload: 'x' } })), false);
  assert.equal(firstPermission(null), false, 'no request: the page was opened from a link');
  assert.equal(firstPermission({ kind: 'permission', earlier: {} }), false, 'one that names an earlier permission is not a first one');
});

// 6.B and 6.C(b): for a key set new to this device, the signing window signs
// only once the person gives the start of the fingerprint init printed, of
// at least 16 characters, or the whole of it. init prints the fingerprint
// at the end of a line, so a copy can carry spaces or a line break around
// it, and those are ignored; the printed fingerprint holds none inside it,
// so anything inside counts, and the comparison is exact (base64url mixes
// upper and lower case).
test('the start of the fingerprint init printed: 16 characters or more, or the whole, matched exactly', async () => {
  const fp = await keySetFingerprint((await generateKeySet()).keys);
  assert.equal(fp.length, 43);
  for (const good of [fp, fp.slice(0, 16), fp.slice(0, 30), `  ${fp}\n`, `\r\n${fp.slice(0, 16)} `, `\t${fp}\t`]) {
    assert.equal(fingerprintStartRefusal(good, fp), null, JSON.stringify(good));
  }
  const swapCase = (c) => (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase());
  const letter = [...fp.slice(0, 16)].findIndex((c) => /[A-Za-z]/.test(c));
  const wrongCase = fp.slice(0, letter) + swapCase(fp[letter]) + fp.slice(letter + 1, 16);
  const other = await keySetFingerprint((await generateKeySet()).keys);
  for (const [bad, words] of [
    ['', /^Paste the fingerprint init printed on the agent's computer in the box above/],
    ['   \n', /^Paste the fingerprint init printed/],
    [undefined, /^Paste the fingerprint init printed/],
    [fp.slice(0, 15), /^That is 15 characters: give at least 16/],
    [fp.slice(0, 1), /^That is 1 character: give at least 16/],
    [other.slice(0, 16), /^That is not the start of the fingerprint of the agent's key set in this permission/],
    [wrongCase, /^That is not the start/],
    [`${fp.slice(0, 8)} ${fp.slice(8, 20)}`, /^That is not the start/],
    [`${fp}A`, /^That is not the start/],
    [fp.slice(1, 17), /^That is not the start/],
  ]) {
    assert.match(fingerprintStartRefusal(bad, fp) ?? 'matched', words, JSON.stringify(bad));
  }
});

// 2.8 item 3: for a first permission, a key set new to this device is
// expected, and the person compares with what init printed on the agent's
// computer, never with the application. Otherwise the words are today's.
test('the warning for a key set new to this device: for a first permission, expected, and compared with what init printed', () => {
  const fp = 'A'.repeat(43);
  assert.equal(
    newAgentWords(fp, true),
    `This is the first permission for this agent's key set on this device, as is expected for a new agent: ${fp}. Compare it with the fingerprint init printed on the agent's computer, never with the application: the application's server could have put another agent's keys here. A permission for someone else's keys lets their agent act in your name.`,
  );
  assert.equal(
    newAgentWords(fp, false),
    `You have not signed a permission for this agent's key set on this device before: ${fp}. Compare it with the fingerprint the agent's software printed when it made its keys. A permission for someone else's keys lets their agent act in your name.`,
  );
});
