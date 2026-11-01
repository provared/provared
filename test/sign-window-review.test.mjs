// The signing window under the cases an independent review found (probes P1
// to P4, and the checks no test held), driven in a browser with a virtual
// passkey. The pages are served at made-up https addresses that the browser
// is handed by the test itself (nothing leaves this computer), so that the
// application's own known address can be used:
//
//   https://sign.prova.example      the signing page, from this repository
//   https://app.prova.red:8443      a page at the application's address
//   https://evil.example            a page at any other address
//
// Covered: a passkey prompt that fails takes the warnings back, and a new
// passkey is made only after its own warning (P1); a cancellation request
// for a permission whose passkey belongs to a parent website name is
// refused, and no passkey is ever made for it (P2); a cancellation for an
// address that is not the application's needs a second press (P3); a record
// sent to a page that is not at the return address is not said to be
// handed over, does not arrive there, and that page's answer is not taken
// (P4); an answer from another window at the right address is not taken; a
// permission signed at another address of the same website cannot be
// cancelled here; a signature that arrives after a change is dropped; and a
// cancellation signed by another passkey is refused in the window.
//
// Skipped with one line where playwright-core (or the folder that
// PROVARED_PLAYWRIGHT_CORE names) or its browser is missing.

import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign as signBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assembleSlip, generateKeySet, prepareSlip, toBase64url, utf8 } from '../src/index.js';
import { checkSlip } from '../src/check.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SIGN = 'https://sign.prova.example';
const SIGN_HOST = 'sign.prova.example';
const APP = 'https://app.prova.red:8443';
const EVIL = 'https://evil.example';
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

// The page that opens the window. It keeps every message it receives, and
// answers that it kept a record only where window.answer is set.
const OPENER = `<!doctype html><html><head><meta charset="utf-8"><title>opener</title></head><body><script>
window.events = []; window.answer = null;
window.openSign = (u) => { window.popup = window.open(u, 'provared-sign', 'popup,width=520,height=760'); return Boolean(window.popup); };
window.tell = (data) => window.popup.postMessage(data, '${SIGN}');
addEventListener('message', (e) => {
  window.events.push({ origin: e.origin, data: e.data });
  if (window.answer !== null && e.data && e.data.provared === 'signed') e.source.postMessage({ provared: 'received', kind: e.data.kind, ...(typeof e.data.state === 'string' ? { state: e.data.state } : {}), kept: window.answer }, e.origin);
});
</script></body></html>`;
// A frame at the opener's own address, which reaches the window through its
// parent and hands it the message in its fragment: another window, at the
// right address.
const FRAME = `<!doctype html><html><head><meta charset="utf-8"></head><body><script>
parent.popup.postMessage(JSON.parse(decodeURIComponent(location.hash.slice(1))), '${SIGN}');
window.sent = true;
</script></body></html>`;

let chromium = null;
let browser = null;
let why = '';

before(async () => {
  const where = process.env.PROVARED_PLAYWRIGHT_CORE;
  try {
    ({ chromium } = await import(where ? pathToFileURL(join(where, 'index.mjs')).href : 'playwright-core'));
    browser = await chromium.launch();
  } catch (e) {
    why = `no browser driver (playwright-core) or browser here (${e.message.split('\n')[0]}); name one with PROVARED_PLAYWRIGHT_CORE`;
    console.log(`(${why}: the signing window review tests are skipped)`);
  }
});
after(async () => {
  if (browser) await browser.close();
});
const skip = (t) => {
  if (browser) return false;
  t.skip(why);
  return true;
};

async function newContext() {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const problems = [];
  context.on('page', (p) => p.on('pageerror', (e) => problems.push(e.message)));
  await context.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.origin === SIGN && /^\/(page|src)\/[A-Za-z0-9_.-]+$/.test(url.pathname)) {
      const file = normalize(join(ROOT, url.pathname));
      try {
        return route.fulfill({ status: 200, contentType: TYPES[extname(url.pathname)] ?? 'application/octet-stream', body: readFileSync(file) });
      } catch {
        return route.fulfill({ status: 404, body: 'not found' });
      }
    }
    if ((url.origin === APP || url.origin === EVIL) && url.pathname === '/opener.html') return route.fulfill({ status: 200, contentType: TYPES['.html'], body: OPENER });
    if (url.origin === APP && url.pathname === '/frame.html') return route.fulfill({ status: 200, contentType: TYPES['.html'], body: FRAME });
    return route.fulfill({ status: 404, body: 'not found' });
  });
  // A passkey prompt that can be held open by the test (window.__hold), to
  // change the page while the passkey is being asked.
  await context.addInitScript(() => {
    if (!navigator.credentials) return;
    const get = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (options) => {
      if (window.__hold) {
        window.__asked = true;
        await new Promise((resolve) => { window.__release = resolve; });
      }
      return get(options);
    };
  });
  return { context, problems };
}

// A passkey whose private key the test holds: the virtual authenticator is
// given it, and the test signs permissions with it as the signing page would.
function heldPasskey(rpId = SIGN_HOST) {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const credentialId = toBase64url(new Uint8Array(16).map(() => Math.floor(Math.random() * 256)));
  return {
    key: { alg: 'ES256', crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y },
    rpId,
    credential: {
      credentialId: Buffer.from(credentialId, 'base64url').toString('base64'),
      isResidentCredential: true,
      rpId,
      privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      userHandle: Buffer.from('the person').toString('base64'),
      signCount: 1,
    },
    async sign(origin, challenge) {
      const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge: toBase64url(challenge), origin, crossOrigin: false }));
      const authenticatorData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x05, 0, 0, 0, 1])]);
      const signature = signBytes('sha256', Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]), pair.privateKey);
      return { authenticatorData: new Uint8Array(authenticatorData), clientDataJSON, signature: new Uint8Array(signature) };
    },
  };
}

function fields(keys, purpose = 'Building the software.') {
  const now = Date.now();
  return {
    agent: { name: 'My agent', keys },
    actions: ['provared.code.read'],
    limits: [],
    requires: [],
    never: [],
    with: [],
    validFrom: new Date(now - 60e3).toISOString().slice(0, 19) + 'Z',
    validUntil: new Date(now + 7 * 86400e3).toISOString().slice(0, 19) + 'Z',
    purpose,
  };
}

async function slipBy(passkey, origin, f) {
  const prepared = await prepareSlip({ ...f, issuer: { name: 'The person', key: passkey.key, rpId: passkey.rpId, origin } });
  return assembleSlip(prepared, await passkey.sign(origin, prepared.challenge));
}

const link = (request) => `${SIGN}/page/sign.html#request=${toBase64url(utf8(JSON.stringify(request)))}`;
const text = async (p, sel) => (await p.textContent(sel)).replace(/\s+/g, ' ').trim();
const settle = (ms = 800) => new Promise((r) => setTimeout(r, ms));

async function authenticator(context, page, credentials = []) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  for (const credential of credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { credentials: async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials };
}

async function openFrom(context, origin, request, credentials = []) {
  const page = await context.newPage();
  await page.goto(`${origin}/opener.html`);
  const [popup] = await Promise.all([page.waitForEvent('popup'), page.evaluate((u) => window.openSign(u), link(request))]);
  await popup.waitForLoadState();
  const holder = await authenticator(context, popup, credentials);
  await popup.waitForFunction(() => document.getElementById('read-status').textContent !== '' || document.getElementById('cancel-status').textContent !== '', null, { timeout: 20000 });
  return { page, popup, holder };
}

const warningsOf = (p, id = 'warnings') => p.$$eval(`#${id} li`, (items) => items.map((li) => li.textContent));
const enabled = (p, id) => p.waitForFunction((x) => !document.getElementById(x).disabled, id, { timeout: 60000 });

test('P1: a passkey prompt that fails takes the warnings back, and a new passkey is made only after the warning that says so', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const { page, popup, holder } = await openFrom(context, APP, { kind: 'permission', fields: fields(agent.keys), name: 'P', returnTo: `${APP}/opener.html`, state: 's' });
  // A passkey this browser remembers, which the device no longer holds.
  const ghost = heldPasskey();
  await popup.evaluate((g) => localStorage.setItem('provared-signing-passkeys', JSON.stringify([g])), { credentialId: 'AAAAAAAAAAAAAAAAAAAAAA', key: ghost.key, rpId: SIGN_HOST, origin: SIGN });
  await popup.click('#read');
  await enabled(popup, 'sign');
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden);
  const first = await warningsOf(popup);
  assert.equal(first.length, 1, first.join('\n'));
  assert.match(first[0], /not signed a permission for this agent's key set/);
  // The second press asks the remembered passkey, which the device does not hold.
  await popup.click('#sign');
  await popup.waitForFunction(() => /You can try again/.test(document.getElementById('sign-status').textContent), null, { timeout: 60000 });
  await enabled(popup, 'sign');
  assert.equal(await text(popup, '#sign'), 'Sign this permission with a passkey', 'the confirmation is taken back');
  // The third press shows the warnings again, now with the new passkey, and makes nothing.
  await popup.click('#sign');
  await popup.waitForFunction(() => /press the button again/.test(document.getElementById('sign-status').textContent), null, { timeout: 20000 });
  const third = await warningsOf(popup);
  assert.ok(third.some((w) => /A new passkey will be made for this website/.test(w)), third.join('\n'));
  assert.equal((await holder.credentials()).length, 0, 'no passkey made without its warning');
  assert.equal(await page.evaluate(() => window.events.length), 0);
  // The fourth press, the warning read, makes the passkey and signs.
  await popup.click('#sign');
  await page.waitForFunction(() => window.events.length > 0, null, { timeout: 20000 });
  assert.equal((await holder.credentials()).length, 1);
  const { data } = await page.evaluate(() => window.events[0]);
  assert.deepEqual((await checkSlip(data.record, { issuerOrigins: [SIGN] })).problems, []);
  assert.deepEqual(problems, []);
});

test('a warning that stands only after the others were confirmed is shown before anything is made', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const { page, popup, holder } = await openFrom(context, APP, { kind: 'permission', fields: fields(agent.keys), name: 'P', returnTo: `${APP}/opener.html`, state: 's' });
  const kept = heldPasskey();
  await popup.evaluate((g) => localStorage.setItem('provared-signing-passkeys', JSON.stringify([g])), { credentialId: 'AAAAAAAAAAAAAAAAAAAAAA', key: kept.key, rpId: SIGN_HOST, origin: SIGN });
  await popup.click('#read');
  await enabled(popup, 'sign');
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden);
  assert.ok((await warningsOf(popup)).every((w) => !/A new passkey/.test(w)));
  // The passkey this browser remembered is forgotten (another tab, or the person) before the second press.
  await popup.evaluate(() => localStorage.removeItem('provared-signing-passkeys'));
  await popup.click('#sign');
  await popup.waitForFunction(() => /press the button again/.test(document.getElementById('sign-status').textContent), null, { timeout: 20000 });
  assert.ok((await warningsOf(popup)).some((w) => /A new passkey will be made for this website/.test(w)));
  assert.equal((await holder.credentials()).length, 0, 'nothing made before its warning was read');
  assert.equal(await page.evaluate(() => window.events.length), 0);
  assert.deepEqual(problems, []);
});

test('P2: a cancellation for a permission whose passkey belongs to a parent website name is refused, with nothing offered and no passkey made', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const forger = heldPasskey('prova.example');
  const earlier = await slipBy(forger, SIGN, fields(agent.keys));
  const { page, popup, holder } = await openFrom(context, EVIL, { kind: 'cancellation', earlier, returnTo: `${EVIL}/opener.html` });
  assert.match(await text(popup, '#cancel-status'), /signed with a passkey for the website name prova\.example, not sign\.prova\.example, so it cannot be cancelled on this page\. Nothing is offered to sign\./);
  assert.equal(await popup.isDisabled('#cancel'), true);
  assert.equal(await popup.inputValue('#cancel-of'), '', 'the permission is not offered');
  // Pressed anyway, twice: nothing of the request is left to sign with, nothing is made, nothing is sent, and the page does not fail.
  for (let i = 0; i < 2; i++) {
    await popup.evaluate(() => { document.getElementById('cancel').disabled = false; document.getElementById('cancel').click(); });
    await settle();
    assert.equal(await popup.isHidden('#cancel-warnings'), true, 'no warning offered for the request refused');
    assert.match(await text(popup, '#cancel-status'), /A fingerprint is 43 letters/);
  }
  assert.equal((await holder.credentials()).length, 0);
  assert.equal(await page.evaluate(() => window.events.length), 0);
  assert.deepEqual(problems, []);
});

test('P3: a cancellation for an address that is not the application\'s needs a second press; for the application\'s own address, one', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const person = heldPasskey();
  const slip = await slipBy(person, SIGN, fields(agent.keys));
  const a = await openFrom(context, EVIL, { kind: 'cancellation', earlier: slip, returnTo: `${EVIL}/opener.html` }, [person.credential]);
  assert.match(await text(a.popup, '#cancel-return-warning'), /not a known address/);
  await a.popup.click('#cancel');
  await a.popup.waitForFunction(() => !document.getElementById('cancel-warnings').hidden);
  assert.match((await warningsOf(a.popup, 'cancel-warnings'))[0], /signed cancellation will be handed to https:\/\/evil\.example\/opener\.html, which is not a known address/);
  await settle();
  assert.equal(await a.page.evaluate(() => window.events.length), 0, 'the first press signs nothing');
  await a.popup.click('#cancel');
  await a.page.waitForFunction(() => window.events.length > 0, null, { timeout: 20000 });
  assert.equal(await a.page.evaluate(() => window.events[0].data.kind), 'cancellation');

  const b = await openFrom(context, APP, { kind: 'cancellation', earlier: slip, returnTo: `${APP}/opener.html` }, [person.credential]);
  assert.equal(await text(b.popup, '#cancel-return-warning'), '', 'the application\'s own address is not warned of');
  await b.popup.click('#cancel');
  await b.page.waitForFunction(() => window.events.length > 0, null, { timeout: 20000 });
  assert.equal(await b.popup.isHidden('#cancel-warnings'), true);
  assert.deepEqual(problems, []);
});

test('P4: a record sent to a page that is not at the return address is not said to be handed over, does not arrive there, and that page\'s answer is not taken', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const { page, popup } = await openFrom(context, EVIL, { kind: 'permission', fields: fields(agent.keys), name: 'P', returnTo: `${APP}/opener.html`, state: 's' });
  await popup.click('#read');
  await enabled(popup, 'sign');
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden);
  await popup.click('#sign');
  await popup.waitForFunction(() => /Waiting for it to confirm/.test(document.getElementById('sign-status').textContent), null, { timeout: 20000 });
  assert.match(await text(popup, '#sign-status'), /^Signed, and sent to the page that opened this window, for https:\/\/app\.prova\.red:8443\/opener\.html\. Waiting/);
  assert.doesNotMatch(await text(popup, '#sign-status'), /handed to/);
  await settle();
  assert.equal(await page.evaluate(() => window.events.length), 0, 'the record went to the return address only, and did not arrive at another');
  // The page that opened the window answers as if it had kept it: not taken, from another address.
  await page.evaluate(() => window.tell({ provared: 'received', kind: 'permission', state: 's', kept: true }));
  await settle(1500);
  assert.equal(popup.isClosed(), false);
  assert.doesNotMatch(await text(popup, '#sign-status'), /kept there/);
  assert.deepEqual(problems, []);
});

test('an answer from another window at the return address is not taken; the answer of the window that opened it is', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const { page, popup } = await openFrom(context, APP, { kind: 'permission', fields: fields(agent.keys), name: 'P', returnTo: `${APP}/opener.html`, state: 's' });
  await popup.click('#read');
  await enabled(popup, 'sign');
  assert.equal(await text(popup, '#return-address'), `${APP}/opener.html`);
  assert.equal(await text(popup, '#return-warning'), '', 'the application\'s exact address is known');
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden);
  assert.ok((await warningsOf(popup)).every((w) => !/not a known address/.test(w)));
  await popup.click('#sign');
  await page.waitForFunction(() => window.events.length > 0, null, { timeout: 20000 });
  // A frame at the application's address, not the window that opened this one, says it was kept.
  const kept = { provared: 'received', kind: 'permission', state: 's', kept: true };
  await page.evaluate((h) => { const f = document.createElement('iframe'); f.src = `/frame.html#${h}`; document.body.append(f); }, encodeURIComponent(JSON.stringify(kept)));
  await page.waitForFunction(() => document.querySelector('iframe') && document.querySelector('iframe').contentWindow.sent === true, null, { timeout: 20000 });
  await settle(1500);
  assert.equal(popup.isClosed(), false, 'not taken from another window');
  assert.doesNotMatch(await text(popup, '#sign-status'), /kept there/);
  // The window that opened it says the same: taken, and the window closes.
  await page.evaluate((k) => window.tell(k), kept);
  await popup.waitForEvent('close', { timeout: 20000 });
  assert.deepEqual(problems, []);
});

test('a permission signed at another address of the same website cannot be cancelled here', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const person = heldPasskey();
  const slip = await slipBy(person, `${SIGN}:8443`, fields(agent.keys));
  const { page, popup, holder } = await openFrom(context, APP, { kind: 'cancellation', earlier: slip, returnTo: `${APP}/opener.html` }, [person.credential]);
  assert.match(await text(popup, '#cancel-status'), /signed at https:\/\/sign\.prova\.example:8443, and a checker holds a cancellation to that same address, so it cannot be cancelled here, at https:\/\/sign\.prova\.example\./);
  assert.equal(await popup.isDisabled('#cancel'), true);
  await popup.evaluate(() => { document.getElementById('cancel').disabled = false; document.getElementById('cancel').click(); });
  await settle();
  assert.equal(await page.evaluate(() => window.events.length), 0);
  assert.equal((await holder.credentials()).length, 1);
  assert.deepEqual(problems, []);
});

test('a signature that arrives after the permission was changed is not kept or handed back', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const person = heldPasskey();
  const earlier = await slipBy(person, SIGN, fields(agent.keys));
  const { page, popup } = await openFrom(context, APP, { kind: 'renewal', fields: fields(agent.keys, 'Renewed.'), earlier, returnTo: `${APP}/opener.html` }, [person.credential]);
  await popup.click('#read');
  await enabled(popup, 'sign');
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden);
  await popup.evaluate(() => { window.__hold = true; });
  await popup.click('#sign');
  await popup.waitForFunction(() => window.__asked === true, null, { timeout: 20000 });
  // While the passkey is being asked, the permission is changed.
  await popup.evaluate(() => { const f = document.getElementById('fields'); f.value = f.value.replace('Renewed.', 'Renewed, and changed.'); f.dispatchEvent(new Event('input')); });
  await popup.evaluate(() => { window.__hold = false; window.__release(); });
  await popup.waitForFunction(() => /changed while your passkey was being asked, so what was signed is not kept/.test(document.getElementById('sign-status').textContent), null, { timeout: 20000 });
  await settle();
  assert.equal(await page.evaluate(() => window.events.length), 0, 'nothing handed back');
  assert.equal(await popup.isDisabled('#sign'), true, 'it must be read again');
  assert.deepEqual(problems, []);
});

test('a cancellation signed in the window by another passkey is refused there, and nothing is handed back', async (t) => {
  if (skip(t)) return;
  const { context, problems } = await newContext();
  t.after(() => context.close());
  const agent = await generateKeySet();
  const person = heldPasskey();
  const stranger = heldPasskey();
  const slip = await slipBy(person, SIGN, fields(agent.keys));
  const { page, popup, holder } = await openFrom(context, APP, { kind: 'cancellation', earlier: slip, returnTo: `${APP}/opener.html` }, [stranger.credential]);
  await popup.click('#cancel');
  await popup.waitForFunction(() => /You can try again/.test(document.getElementById('cancel-status').textContent), null, { timeout: 20000 });
  assert.match(await text(popup, '#cancel-status'), /The passkey you chose is not the one that signed the earlier permission \(.+\), so nothing is offered\./);
  await settle();
  assert.equal(await page.evaluate(() => window.events.length), 0);
  assert.equal(await popup.isHidden('#cancel-save-line'), true, 'no file offered');
  assert.equal((await holder.credentials()).length, 1, 'nothing new made');
  assert.deepEqual(problems, []);
});
