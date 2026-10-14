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
import { agentKeySet, readStartingPermission } from '../page/sign-page.js';

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
