// The signing page opened by another page (the Provared application) with
// a request after "#request=": what kind of record is wanted, the fields
// to fill, the earlier signed permission, the passkey expected to sign,
// where to hand the result back to. The parts that need no browser are
// plain functions of page/sign-page.js, tested here: how a request and a
// return address are read, what a renewal changes against the earlier
// permission, and the message handed back. The page itself, driven in a
// browser with a virtual passkey, is test/sign-window.test.mjs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { assembleSlip, entryLine, fromBase64url, generateKeySet, keySetFingerprint, prepareSlip, thumbprint, toBase64url, utf8 } from '../src/index.js';
import { checkSlip } from '../src/check.js';
import { KNOWN_RETURN_HOSTS, REQUEST_KINDS, readRequest, returnAddress, signedLink, signedMessage, whatChanged } from '../page/sign-page.js';
import { makePasskey } from './helpers/passkey.mjs';

const requestLink = (request) => `#request=${toBase64url(utf8(JSON.stringify(request)))}`;
const decode = (b64) => JSON.parse(new TextDecoder().decode(fromBase64url(b64)));

function permission(agentKeys) {
  return {
    agent: { name: 'My agent', keys: agentKeys },
    actions: ['provared.code.read', 'provared.code.change'],
    limits: [{ action: 'provared.code.change', count: 100, per: 3600 }],
    requires: [],
    never: ['conceal'],
    with: [],
    validFrom: '2026-11-01T09:00:00Z',
    validUntil: '2026-11-08T09:00:00Z',
    purpose: 'Building the software.',
  };
}

test('the return address is read strictly, and only the application\'s own name over https is known', () => {
  assert.deepEqual(KNOWN_RETURN_HOSTS, ['app.prova.red']);
  assert.deepEqual(returnAddress('https://app.prova.red/'), { origin: 'https://app.prova.red', address: 'https://app.prova.red/', host: 'app.prova.red', known: true });
  assert.deepEqual(returnAddress('https://app.prova.red:8443'), { origin: 'https://app.prova.red:8443', address: 'https://app.prova.red:8443/', host: 'app.prova.red', known: true });
  assert.equal(returnAddress('http://localhost:8088/').known, false, 'a page tried on this computer is not a known address');
  assert.equal(returnAddress('http://localhost:8088/').origin, 'http://localhost:8088');
  assert.equal(returnAddress('https://sign.example.org/app').known, false);
  assert.equal(returnAddress('https://sign.example.org/app').address, 'https://sign.example.org/app');
  const bad = ['http://app.prova.red/', 'https://app.prova.red/?x=1', 'https://app.prova.red/#frag', 'https://app.prova.red/#', 'https://app.prova.red/?', 'https://user:pw@app.prova.red/', 'ftp://app.prova.red/', 'app.prova.red', 'http://127.0.0.1:8088/', '', 42, null, `https://${'a'.repeat(3000)}/`];
  for (const text of bad) assert.equal(returnAddress(text), null, String(text));
});

test('a request is read by its shape, and every fault is refused in plain words', async () => {
  const agent = await generateKeySet();
  const fields = permission(agent.keys);
  const earlier = { payload: 'x', signatures: [] };
  assert.deepEqual(REQUEST_KINDS, ['permission', 'renewal', 'cancellation']);
  assert.deepEqual(readRequest(''), { request: null, message: null });
  assert.deepEqual(readRequest('#permission=abc'), { request: null, message: null }, 'a link of the other form is not a request');
  const ok = readRequest(requestLink({ kind: 'permission', fields, name: 'Me', returnTo: 'https://app.prova.red/', state: 'book 7' }));
  assert.equal(ok.message, null);
  assert.deepEqual(ok.request, { kind: 'permission', fields, name: 'Me', returnTo: returnAddress('https://app.prova.red/'), state: 'book 7' });
  const renewal = readRequest(requestLink({ kind: 'renewal', fields, earlier, issuerKey: { kty: 'EC' } }));
  assert.deepEqual(renewal.request, { kind: 'renewal', fields, earlier, issuerKey: { kty: 'EC' } });
  const cancellation = readRequest(requestLink({ kind: 'cancellation', earlier }));
  assert.deepEqual(cancellation.request, { kind: 'cancellation', earlier });
  const refused = (request, words) => {
    const r = readRequest(requestLink(request));
    assert.equal(r.request, null, JSON.stringify(request));
    assert.match(r.message, /^The request in this page's address could not be used: /);
    assert.match(r.message, words, r.message);
    assert.match(r.message, /Nothing is offered to sign\. Close this window and try again from the page that opened it\.$/);
  };
  refused({ kind: 'approval', fields }, /"kind" must be "permission", "renewal" or "cancellation"/);
  refused({ kind: 'permission', fields, extra: 1 }, /does not know, "extra"/);
  refused({ kind: 'permission' }, /"fields" must be one JSON object/);
  refused({ kind: 'permission', fields: [] }, /"fields" must be one JSON object/);
  refused({ kind: 'permission', fields: { ...fields, issuer: {} } }, /must not hold an "issuer"/);
  refused({ kind: 'permission', fields: { ...fields, purpose: undefined } }, /has no "purpose" member/);
  refused({ kind: 'permission', fields, name: 7 }, /"name" must be text/);
  refused({ kind: 'permission', fields, earlier }, /takes no "earlier" permission; ask for a renewal/);
  refused({ kind: 'renewal', fields }, /a renewal needs the earlier signed permission/);
  refused({ kind: 'cancellation' }, /a cancellation needs the earlier signed permission/);
  refused({ kind: 'cancellation', earlier, fields }, /a cancellation takes no "fields"/);
  refused({ kind: 'renewal', fields, earlier, issuerKey: 'abc' }, /"issuerKey" must be the passkey's public key/);
  refused({ kind: 'permission', fields, returnTo: 'http://app.prova.red/' }, /"returnTo" must be a page address that begins https:\/\//);
  refused({ kind: 'permission', fields, state: 'x'.repeat(257) }, /"state" must be text of at most 256 characters/);
  assert.match(readRequest('#request=%%%').message, /not written in base64url/);
  assert.match(readRequest(`#request=${toBase64url(utf8('[1]'))}`).message, /not one JSON object/);
  assert.match(readRequest(`#request=${toBase64url(utf8('{'))}`).message, /not JSON/);
});

test('what a renewal changes against the earlier permission is listed part by part, in the words the page shows', async () => {
  const agent = await generateKeySet();
  const other = await generateKeySet();
  const earlier = { ...permission(agent.keys), type: 'provared.slip.v0', id: 'x', issuer: { name: 'Me' } };
  const same = await whatChanged(earlier, permission(agent.keys));
  assert.equal(same.length, 12);
  assert.ok(same.every((p) => !p.changed));
  assert.deepEqual(same.map((p) => p.term), ['Agent', 'Agent\'s key set', 'Agent\'s software', 'May do', 'Limits', 'Conditions', 'Never', 'With', 'From', 'Until', 'Purpose', 'May pass on']);
  assert.equal(same[1].now, await keySetFingerprint(agent.keys));
  assert.match(same[4].now, /100/);
  const changed = await whatChanged(earlier, {
    ...permission(other.keys),
    actions: ['provared.code.read'],
    limits: [{ action: 'provared.code.change', count: 20, per: 86400 }],
    validUntil: '2026-12-31T00:00:00Z',
    passes: 2,
  });
  const by = Object.fromEntries(changed.map((p) => [p.term, p]));
  assert.equal(by['Agent\'s key set'].changed, true);
  assert.equal(by['Agent\'s key set'].was, await keySetFingerprint(agent.keys));
  assert.equal(by['Agent\'s key set'].now, await keySetFingerprint(other.keys));
  assert.deepEqual([by['May do'].was, by['May do'].now], ['provared.code.read, provared.code.change', 'provared.code.read']);
  assert.equal(by.Limits.changed, true);
  assert.deepEqual([by.Until.was, by.Until.now], ['2026-11-08T09:00:00Z', '2026-12-31T00:00:00Z']);
  assert.deepEqual([by['May pass on'].was, by['May pass on'].now], ['not at all', '2 time(s) in a row']);
  assert.equal(by.Purpose.changed, false);
  // What cannot be put into words is shown as it is written, never thrown.
  const odd = await whatChanged(earlier, { ...permission(agent.keys), limits: 'none', agent: { name: 'x', keys: [1] } });
  assert.equal(odd.find((p) => p.term === 'Limits').now, '"none"');
  assert.equal(odd.find((p) => p.term === 'Agent\'s key set').now, '[1]');
});

test('the message handed back carries the signed record, its kind and the request\'s state; the link back carries the same after "#signed="', async () => {
  const agent = await generateKeySet();
  const passkey = await makePasskey('ES256', { rpId: 'sign.example.org', origin: 'https://sign.example.org' });
  const prepared = await prepareSlip({ ...permission(agent.keys), issuer: { name: 'Me', key: passkey.key, rpId: 'sign.example.org', origin: 'https://sign.example.org' } });
  const slip = assembleSlip(prepared, await passkey.sign(prepared.challenge));
  assert.deepEqual(signedMessage('renewal', slip, 'book 7'), { provared: 'signed', kind: 'renewal', record: slip, state: 'book 7' });
  assert.deepEqual(Object.keys(signedMessage('permission', slip)), ['provared', 'kind', 'record']);
  const link = signedLink('https://app.prova.red/', signedMessage('cancellation', slip));
  assert.match(link, /^https:\/\/app\.prova\.red\/#signed=[A-Za-z0-9_-]+$/);
  const back = decode(new URLSearchParams(link.split('#')[1]).get('signed'));
  assert.deepEqual(back, { provared: 'signed', kind: 'cancellation', record: slip });
  // What comes back is a record the checker reads as it would any other.
  const result = await checkSlip(back.record, { issuerKeys: [await thumbprint(passkey.key)], issuerOrigins: ['https://sign.example.org'] });
  assert.deepEqual(result.problems, []);
  assert.ok(entryLine({ slip: back.record }).length > 100);
});

test('the page names its return address, its warnings and its way back in the HTML the script expects', () => {
  const html = readFileSync(new URL('../page/sign.html', import.meta.url), 'utf8');
  for (const id of ['return-address', 'return-warning', 'warnings', 'changed', 'changed-heading', 'back', 'back-line', 'cancel-words', 'cancel-return-address', 'cancel-back', 'cancel-save-status']) {
    assert.ok(html.includes(`id="${id}"`), id);
  }
  assert.doesNotMatch(html, /https?:\/\//, 'the page names no address with a scheme');
});
