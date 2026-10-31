// The link "init" prints, read by the signing page's own code: the page's
// reading of its address is a plain function (readStartingPermission in
// page/sign-page.js), tested here without a browser. The page's other
// behaviour is tried in a browser by hand; the repository has no browser
// in its tests.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { keySetFingerprint, toBase64url, utf8 } = await import('provared');
const { EXAMPLE, agentKeySet, readStartingPermission, serviceWords, shownByItself } = await import('../../../page/sign-page.js');
const { loadAgentKeys, makeAgentKeys, signingLink, startingPermission } = await import('../recorder.mjs');
const { freePort, runCommand, tempFolder } = await import('./world.mjs');

test('the page offers to sign only where it is shown by itself, not inside another page', () => {
  const alone = {};
  alone.top = alone;
  assert.equal(shownByItself(alone), true);
  assert.equal(shownByItself({ top: {} }), false, 'inside a frame of another page');
  assert.equal(shownByItself({ get top() { throw new Error('blocked'); } }), false, 'where the top cannot even be compared');
});

test('the summary names each service\'s keys by the fingerprint of their key set, as a checker names them', async () => {
  const keys = (await makeAgentKeys(tempFolder())).keys;
  const words = await serviceWords([{ id: 'bank', name: 'Your bank', keys }, { id: 'shop', name: 'A shop' }]);
  assert.match(words, new RegExp(`Your bank \\(bank\\), countersigning with the key set ${await keySetFingerprint(keys)}`));
  assert.match(words, /A shop \(shop\), no keys of its own, so it cannot countersign/);
  assert.equal(await serviceWords([]), 'no other party');
  await assert.rejects(serviceWords([{ id: 'x', name: 'X', keys: [{ alg: 'Ed25519' }] }]));
});

const fragment = (text) => `#permission=${toBase64url(utf8(text))}`;

test('init and keys print the fingerprint of the agent\'s key set, exactly as the signing page works it out', async () => {
  const folder = tempFolder();
  const project = tempFolder('provared-project-');
  const port = await freePort();
  const printed = (out) => (out.match(/The fingerprint of the agent's key set: ([A-Za-z0-9_-]{43})/) ?? [])[1];
  const init = await runCommand(['init'], { folder, port, cwd: project });
  assert.equal(init.code, 0, init.err);
  const keys = await runCommand(['keys'], { folder, port });
  assert.equal(keys.code, 0, keys.err);
  const { fingerprint } = await agentKeySet((await loadAgentKeys(folder)).keys);
  assert.equal(printed(init.out), fingerprint);
  assert.equal(printed(keys.out), fingerprint);
  // The page shows the same, for the permission the link carries.
  const link = init.out.split('\n').map((l) => l.trim()).find((l) => l.startsWith('https://sign.prova.red/#permission='));
  assert.equal((await agentKeySet(readStartingPermission(new URL(link).hash).permission.agent.keys)).fingerprint, fingerprint);
});

test('the link init prints opens the page with the agent\'s permission filled in, and the page\'s own times', async () => {
  const agent = await makeAgentKeys(tempFolder());
  const link = signingLink(startingPermission(agent.keys));
  const { permission, message } = readStartingPermission(new URL(link).hash);
  assert.deepEqual(permission.agent.keys, agent.keys);
  assert.equal(permission.validFrom, EXAMPLE.validFrom, 'the times are the page\'s, set when it opens');
  assert.equal(permission.validUntil, EXAMPLE.validUntil);
  assert.match(message, /came with the link you opened/);
  // The same with the fragment handed over without its "#".
  assert.deepEqual(readStartingPermission(new URL(link).hash.slice(1)).permission, permission);
});

test('init\'s starting permission is the page\'s own starting point, with the agent\'s name, keys and purpose', () => {
  const ours = startingPermission([{ alg: 'Ed25519' }, { alg: 'ML-DSA-87' }]);
  for (const member of ['actions', 'limits', 'requires', 'never', 'with']) assert.deepEqual(ours[member], EXAMPLE[member], member);
  assert.deepEqual(Object.keys(ours).sort(), ['actions', 'agent', 'limits', 'never', 'purpose', 'requires', 'with']);
});

test('a fragment that cannot be read leaves the page\'s starting point, and says why in plain words', () => {
  assert.deepEqual(readStartingPermission(''), { permission: EXAMPLE, message: null });
  assert.deepEqual(readStartingPermission('#other=1'), { permission: EXAMPLE, message: null });
  const cases = [
    ['#permission=not*base64url!', /not written in base64url/],
    [`#permission=${toBase64url(new Uint8Array([0xff, 0xfe, 0x41]))}`, /it is not text/],
    [fragment('{"agent": '), /is not JSON: /],
    [fragment('[1, 2]'), /not one JSON object/],
    [fragment('null'), /not one JSON object/],
    [fragment('"text"'), /not one JSON object/],
  ];
  for (const [hash, words] of cases) {
    const { permission, message } = readStartingPermission(hash);
    assert.equal(permission, EXAMPLE, hash);
    assert.match(message, words, hash);
    assert.match(message, /The page's own starting point is shown instead\./);
  }
  // Members it gives take the place of the page's; an "issuer" is left for the page's reading step to refuse.
  const { permission } = readStartingPermission(fragment('{"purpose": "Mine.", "issuer": {}}'));
  assert.equal(permission.purpose, 'Mine.');
  assert.deepEqual(permission.issuer, {});
  assert.deepEqual(permission.actions, EXAMPLE.actions);
});
