// The signing page opened as a small window by another page, driven in a
// browser with a virtual passkey, at phone width: a new permission signed
// after the warnings and handed back by postMessage to the exact address;
// a renewal with a passkey this browser has forgotten, found from the
// expected public key by the person's choice and checked, with what
// changed shown; a cancellation handed back and checked against the
// permission; the wrong passkey refused with nothing new made; a page not
// opened as a window going back by a link with the result after "#"; a
// request that cannot be read offering nothing; and a framed page offering
// nothing.
//
// The browser driver is not a dependency of the library: these tests use
// playwright-core where it can be found (installed here, or in the folder
// that PROVARED_PLAYWRIGHT_CORE names), with a browser it already has, and
// are skipped with one line otherwise. The page is served from this
// repository by a small server on localhost; the page that opens the
// window is served by a second server, so that the two are different
// origins, as app.prova.red and sign.prova.red are.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assembleSlip, entryLine, fromBase64url, generateKeySet, keySetFingerprint, prepareSlip, thumbprint, toBase64url, utf8 } from '../src/index.js';
import { checkBook, checkSlip } from '../src/check.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

// The page that opens the window, as the application does: it keeps every
// message it receives, with the sender's origin and whether the sender is
// the window it opened, and answers that it kept the record (window.answer:
// true, false, or null for no answer at all).
const OPENER = `<!doctype html><html><head><meta charset="utf-8"><title>opener</title></head><body><p>the opener</p><script>
window.result = null; window.events = []; window.answer = true;
window.openSign = (url) => { window.popup = window.open(url, 'provared-sign', 'popup,width=520,height=760'); return Boolean(window.popup); };
window.addEventListener('message', (e) => {
  window.events.push({ origin: e.origin, fromPopup: e.source === window.popup, data: e.data });
  if (e.data && e.data.provared === 'signed') {
    window.result = e.data;
    if (window.answer !== null) e.source.postMessage({ provared: 'received', kind: e.data.kind, ...(typeof e.data.state === 'string' ? { state: e.data.state } : {}), kept: window.answer }, e.origin);
  }
});
</script></body></html>`;
const BACK = '<!doctype html><html><head><meta charset="utf-8"><title>back</title></head><body><p>back</p></body></html>';

function serve(files) {
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    const body = files(path);
    if (body === null) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    res.end(body);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ origin: `http://localhost:${server.address().port}`, close: () => new Promise((r) => server.close(r)) })));
}

let chromium = null;
let browser = null;
let why = '';
let sign = null;
let opener = null;

before(async () => {
  sign = await serve((path) => {
    const file = normalize(join(ROOT, path));
    if (!file.startsWith(ROOT) || !/^\/(page|src)\/[A-Za-z0-9_.-]+$/.test(path)) return null;
    try {
      return readFileSync(file);
    } catch {
      return null;
    }
  });
  opener = await serve((path) => (path === '/opener.html' ? OPENER : path === '/back.html' ? BACK : null));
  const where = process.env.PROVARED_PLAYWRIGHT_CORE;
  try {
    ({ chromium } = await import(where ? pathToFileURL(join(where, 'index.mjs')).href : 'playwright-core'));
    browser = await chromium.launch();
  } catch (e) {
    why = `no browser driver (playwright-core) or browser here (${e.message.split('\n')[0]}); name one with PROVARED_PLAYWRIGHT_CORE`;
    console.log(`(${why}: the signing window tests are skipped)`);
  }
});
after(async () => {
  if (browser) await browser.close();
  if (sign) await sign.close();
  if (opener) await opener.close();
});
const skip = (t) => {
  if (browser) return false;
  t.skip(why);
  return true;
};

const SIGN_PAGE = () => `${sign.origin}/page/sign.html`;
const requestLink = (request) => `${SIGN_PAGE()}#request=${toBase64url(utf8(JSON.stringify(request)))}`;
const text = async (page, sel) => (await page.innerText(sel)).replace(/\s+/g, ' ').trim();

function permission(agentKeys) {
  const now = Date.now();
  return {
    agent: { name: 'My agent', keys: agentKeys },
    actions: ['provared.code.read', 'provared.code.change'],
    limits: [{ action: 'provared.code.change', count: 100, per: 3600 }],
    requires: [],
    never: ['conceal'],
    with: [],
    validFrom: new Date(now - 60e3).toISOString().slice(0, 19) + 'Z',
    validUntil: new Date(now + 7 * 86400e3).toISOString().slice(0, 19) + 'Z',
    purpose: 'Building the software.',
  };
}

// A context at phone width, with the problems a page reports and the
// requests that leave the two servers.
async function newContext(viewport = { width: 390, height: 844 }) {
  const context = await browser.newContext({ viewport });
  const problems = [];
  const outside = [];
  context.on('page', (page) => {
    page.on('pageerror', (e) => problems.push(e.message));
    page.on('console', (m) => {
      if (m.type() === 'error') problems.push(m.text());
    });
    page.on('request', (r) => {
      if (!r.url().startsWith(sign.origin) && !r.url().startsWith(opener.origin) && !r.url().startsWith('blob:')) outside.push(r.url());
    });
  });
  return { context, problems, outside };
}

// A virtual passkey holder on a page: one that confirms the person at once.
async function authenticator(context, page, credentials = []) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  for (const credential of credentials) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { credentials: async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials };
}

// Open the signing window from the opener page, with a virtual passkey holder on it.
async function openWindow(context, page, link, credentials) {
  const [popup] = await Promise.all([page.waitForEvent('popup'), page.evaluate((u) => window.openSign(u), link)]);
  await popup.waitForLoadState();
  const holder = await authenticator(context, popup, credentials);
  await popup.waitForFunction(() => document.getElementById('read-status').textContent !== '' || document.getElementById('cancel-status').textContent !== '', null, { timeout: 20000 });
  return { popup, holder };
}

// A cancellation for an address that is not the application's: the first
// press shows the warning and signs nothing, the second signs.
async function cancelTwice(p) {
  await p.click('#cancel');
  await p.waitForFunction(() => !document.getElementById('cancel-warnings').hidden && !document.getElementById('cancel').disabled, null, { timeout: 20000 });
  await p.click('#cancel');
}

const waitForResult = (page) => page.waitForFunction(() => window.result !== null, null, { timeout: 20000 }).then(() => page.evaluate(() => ({ result: window.result, events: window.events })));

// What the first test signs, for the ones after it.
let first = null;

test('a new permission: the warnings shown first, a passkey made on the second press, the record handed back by postMessage to the exact address, and the window closes', async (t) => {
  if (skip(t)) return;
  const { context, problems, outside } = await newContext();
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  const agent = await generateKeySet();
  const fields = permission(agent.keys);
  const { popup, holder } = await openWindow(context, page, requestLink({ kind: 'permission', fields, name: 'The person', returnTo: `${opener.origin}/opener.html`, state: 'book 7' }));
  assert.match(await text(popup, '#read-status'), /asks you to sign a new permission/);
  assert.equal(await popup.inputValue('#issuer-name'), 'The person');
  assert.deepEqual(JSON.parse(await popup.inputValue('#fields')), fields);
  assert.ok(await popup.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'nothing scrolls sideways in the window');

  await popup.click('#read');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  assert.match(await text(popup, '#slip-words'), /Signed by "The person" \(a label\), with a new passkey, made for this website when you sign/);
  assert.match(await text(popup, '#slip-words'), new RegExp(await keySetFingerprint(agent.keys)));
  // The return address, with the warning: a page on this computer is not the application.
  assert.equal(await popup.isHidden('#return-line'), false);
  assert.equal(await text(popup, '#return-address'), `${opener.origin}/opener.html`);
  assert.match(await text(popup, '#return-warning'), /not a known address of the Provared application \(app\.prova\.red:8443 or app\.prova\.red, over https\)/);
  assert.equal(await popup.isHidden('#changed-box'), true, 'nothing to compare with');

  // The first press shows the warnings and signs nothing.
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  const warnings = await popup.$$eval('#warnings li', (items) => items.map((li) => li.textContent));
  assert.equal(warnings.length, 3, warnings.join('\n'));
  assert.match(warnings[0], /not signed a permission for this agent's key set on this device before/);
  assert.match(warnings[1], /A new passkey will be made for this website/);
  assert.match(warnings[2], /not a known address of the Provared application/);
  assert.equal(await text(popup, '#sign'), 'I have read the warnings: sign this permission');
  assert.equal((await holder.credentials()).length, 0, 'no passkey made yet');

  // The second press makes the passkey and signs.
  await popup.click('#sign');
  const { result, events } = await waitForResult(page);
  assert.equal(events.length, 1);
  assert.equal(events[0].origin, sign.origin);
  assert.equal(events[0].fromPopup, true);
  assert.deepEqual(Object.keys(result), ['provared', 'kind', 'record', 'state']);
  assert.equal(result.kind, 'permission');
  assert.equal(result.state, 'book 7');
  const credentials = await holder.credentials();
  assert.equal(credentials.length, 1);
  // The record checks with the passkey made, at the signing page's address, and nowhere else.
  const checked = await checkSlip(result.record, { issuerOrigins: [sign.origin] });
  assert.deepEqual(checked.problems, []);
  assert.equal(checked.signature.state, 'valid');
  assert.equal(checked.content.issuer.name, 'The person');
  assert.equal(checked.content.issuer.rpId, 'localhost');
  assert.equal(checked.content.issuer.origin, sign.origin);
  assert.equal((await checkSlip(result.record, { issuerOrigins: [opener.origin] })).problems[0].code, 'issuer-origin-not-expected');
  first = { record: result.record, content: checked.content, thumbprint: checked.issuerKey, credential: credentials[0], agent };
  // The window says so and closes itself.
  await popup.waitForEvent('close', { timeout: 20000 });
  assert.deepEqual(problems, []);
  assert.deepEqual(outside, []);
  await context.close();
});

test('a renewal with a passkey this browser has forgotten: what changed is shown, the passkey is found by the person\'s choice and checked against the expected key, and the record goes back', async (t) => {
  if (skip(t)) return;
  assert.ok(first, 'the first test signed');
  // A fresh context: the browser remembers nothing, and the device holds the passkey made before.
  const { context, problems } = await newContext();
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  const fields = { ...permission(first.agent.keys), validFrom: first.content.validFrom, validUntil: first.content.validUntil, limits: [{ action: 'provared.code.change', count: 20, per: 3600 }], purpose: 'Building the software, more carefully.' };
  const { popup, holder } = await openWindow(context, page, requestLink({ kind: 'renewal', fields, earlier: first.record, returnTo: `${opener.origin}/opener.html` }), [first.credential]);
  assert.match(await text(popup, '#read-status'), /asks you to renew a permission/);
  assert.equal(await popup.inputValue('#issuer-name'), 'The person', 'the name comes from the earlier permission');
  await popup.click('#read');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  assert.match(await text(popup, '#slip-words'), new RegExp(`with the passkey ${first.thumbprint}, which signed the earlier permission \\(this browser does not remember it`));
  assert.equal(await popup.isHidden('#changed-box'), false);
  assert.match(await text(popup, '#changed-heading'), /^What changes against the permission being renewed \(2 of 12 parts\)/);
  const rows = await popup.$$eval('#changed dt', (items) => items.map((dt) => dt.textContent));
  assert.ok(rows.includes('Limits: changed') && rows.includes('Purpose: changed') && rows.includes('Agent\'s key set: the same'), rows.join('\n'));
  assert.match(await text(popup, '#changed'), /Limits: changed Was: provared.code.change: no more than 100 actions in any hour Now: provared.code.change: no more than 20 actions in any hour/);

  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  const warnings = await popup.$$eval('#warnings li', (items) => items.map((li) => li.textContent));
  assert.equal(warnings.length, 2, warnings.join('\n'));
  assert.match(warnings[0], new RegExp(`does not remember the passkey that signed the earlier permission.*checks that the passkey you chose is the one expected \\(${first.thumbprint}\\)`));
  assert.match(warnings[1], /not a known address/);
  await popup.click('#sign');
  const { result, events } = await waitForResult(page);
  assert.equal(events[0].origin, sign.origin);
  assert.equal(result.kind, 'renewal');
  assert.equal(result.state, undefined);
  assert.equal((await holder.credentials()).length, 1, 'no new passkey was made');
  const checked = await checkSlip(result.record, { issuerKeys: [first.thumbprint], issuerOrigins: [sign.origin] });
  assert.deepEqual(checked.problems, []);
  assert.deepEqual(checked.content.limits, fields.limits);
  first.renewed = { record: result.record, fingerprint: checked.fingerprint };
  await popup.waitForEvent('close', { timeout: 20000 });

  // Once found, the passkey is remembered: a cancellation in the same browser asks it directly, and the checker holds it against the permission.
  const page2 = await context.newPage();
  await page2.goto(`${opener.origin}/opener.html`);
  const second = await openWindow(context, page2, requestLink({ kind: 'cancellation', earlier: result.record, returnTo: `${opener.origin}/opener.html`, state: 'cancel 7' }), [first.credential]);
  assert.equal(await second.popup.isHidden('#steps'), true, 'the permission steps are hidden');
  assert.equal(await second.popup.inputValue('#cancel-of'), checked.fingerprint);
  assert.match(await second.popup.textContent('#cancel-status'), new RegExp(`asks you to cancel the permission below, signed by "The person" \\(a label\\).*passkey ${first.thumbprint}`));
  assert.match(await text(second.popup, '#cancel-words'), /Building the software, more carefully/);
  assert.equal(await text(second.popup, '#cancel-return-address'), `${opener.origin}/opener.html`);
  assert.match(await text(second.popup, '#cancel-return-warning'), /not a known address/);
  await cancelTwice(second.popup);
  const cancelled = await waitForResult(page2);
  assert.equal(cancelled.result.kind, 'cancellation');
  assert.equal(cancelled.result.state, 'cancel 7');
  const book = await checkBook(`${entryLine({ slip: result.record })}\n`, { issuerKeys: [first.thumbprint], issuerOrigins: [sign.origin], cancellations: [{ cancellation: cancelled.result.record }] });
  assert.equal(book.summary.problemFound, false);
  assert.equal(book.held[0].used, true);
  assert.equal(book.held[0].slip, checked.fingerprint);
  assert.equal(book.held[0].signature.state, 'valid');
  await second.popup.waitForEvent('close', { timeout: 20000 });
  assert.deepEqual(problems, []);
  await context.close();
});

test('the wrong passkey is refused: nothing goes back, and no new passkey is made', async (t) => {
  if (skip(t)) return;
  assert.ok(first, 'the first test signed');
  const { context } = await newContext();
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  // The device holds another passkey for this website, not the one that signed.
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const stranger = {
    credentialId: Buffer.from(new Uint8Array(16).map((_, i) => i + 1)).toString('base64'),
    isResidentCredential: true,
    rpId: 'localhost',
    privateKey: other.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    userHandle: Buffer.from('someone else').toString('base64'),
    signCount: 1,
  };
  const { popup, holder } = await openWindow(context, page, requestLink({ kind: 'renewal', fields: permission(first.agent.keys), earlier: first.record, returnTo: `${opener.origin}/opener.html` }), [stranger]);
  await popup.click('#read');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  await popup.click('#sign');
  await popup.waitForFunction(() => /not the one that signed the earlier permission/.test(document.getElementById('sign-status').textContent), null, { timeout: 20000 });
  assert.match(await text(popup, '#sign-status'), new RegExp(`The passkey you chose is not the one that signed the earlier permission \\(${first.thumbprint}\\), so nothing is offered\\. Press the button again and choose that one\\. You can try again\\.`));
  assert.equal((await holder.credentials()).length, 1, 'nothing new was made');
  assert.equal(await page.evaluate(() => window.events.length), 0, 'nothing was handed back');
  assert.equal(popup.isClosed(), false);
  await context.close();
});

test('a page not opened as a window goes back by a link with the signed record after "#signed=", which the address then carries once', async (t) => {
  if (skip(t)) return;
  const { context } = await newContext();
  const page = await context.newPage();
  const agent = await generateKeySet();
  await page.goto(requestLink({ kind: 'permission', fields: permission(agent.keys), name: 'Me', returnTo: `${opener.origin}/back.html`, state: 's' }));
  await authenticator(context, page);
  await page.waitForFunction(() => document.getElementById('read-status').textContent !== '', null, { timeout: 20000 });
  await page.evaluate(() => { document.getElementById('cancel-details').open = true; });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'nothing scrolls sideways at phone width, the cancel part open');
  await page.click('#read');
  await page.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  await page.click('#sign');
  await page.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  await page.click('#sign');
  await page.waitForFunction(() => !document.getElementById('back-line').hidden, null, { timeout: 20000 });
  assert.match(await text(page, '#sign-status'), /not opened as a window by .*back\.html, so the signed permission is not handed back by itself\. Save it first as a file, then go back there with it\./);
  assert.equal(await text(page, '#back'), `Then go back to ${opener.origin}/back.html with the signed permission`);
  // The file is offered first: it comes before the way back on the page, and has the focus.
  assert.equal(await page.evaluate(() => document.getElementById('save-line').compareDocumentPosition(document.getElementById('back-line')) & Node.DOCUMENT_POSITION_FOLLOWING), 4);
  assert.equal(await page.evaluate(() => document.activeElement && document.activeElement.id), 'save');
  assert.equal(await page.isHidden('#save-line'), false, 'the file stays offered');
  await Promise.all([page.waitForURL((u) => u.href.startsWith(`${opener.origin}/back.html#signed=`), { timeout: 20000 }), page.click('#back')]);
  const message = JSON.parse(new TextDecoder().decode(fromBase64url(new URLSearchParams(new URL(page.url()).hash.slice(1)).get('signed'))));
  assert.equal(message.provared, 'signed');
  assert.equal(message.kind, 'permission');
  assert.equal(message.state, 's');
  const checked = await checkSlip(message.record, { issuerOrigins: [sign.origin] });
  assert.deepEqual(checked.problems, []);
  await context.close();
});

test('a request that cannot be read offers nothing to sign, and a framed page offers nothing at all', async (t) => {
  if (skip(t)) return;
  const { context } = await newContext();
  const page = await context.newPage();
  await page.goto(`${SIGN_PAGE()}#request=${toBase64url(utf8(JSON.stringify({ kind: 'renewal', fields: {} })))}`);
  await page.waitForFunction(() => document.getElementById('read-status').textContent !== '', null, { timeout: 20000 });
  assert.match(await text(page, '#read-status'), /^The request in this page's address could not be used: its "fields" has no "agent" member/);
  assert.equal(await page.isDisabled('#read'), true);
  assert.equal(await page.inputValue('#fields'), '');
  // An earlier permission that does not check is not trusted, and nothing is offered.
  const agent = await generateKeySet();
  await page.goto(requestLink({ kind: 'renewal', fields: permission(agent.keys), earlier: { ...first.record, payload: `${first.record.payload.slice(0, -2)}AA` } }));
  await page.waitForFunction(() => /earlier permission/.test(document.getElementById('read-status').textContent), null, { timeout: 20000 });
  assert.match(await text(page, '#read-status'), /^The earlier permission handed to this page does not pass its check \(.*\), so it is not trusted\. Nothing is offered to sign\./);
  assert.equal(await page.isDisabled('#read'), true);
  // Framed, the page says so and offers nothing.
  await page.goto(`${opener.origin}/opener.html`);
  await page.evaluate((src) => {
    const f = document.createElement('iframe');
    f.src = src;
    f.id = 'f';
    document.body.append(f);
  }, requestLink({ kind: 'permission', fields: permission(agent.keys), returnTo: `${opener.origin}/opener.html` }));
  const frame = await (await page.waitForSelector('#f')).contentFrame();
  await frame.waitForFunction(() => document.getElementById('read-status').textContent !== '', null, { timeout: 20000 });
  assert.match(await frame.textContent('#read-status'), /shown inside another page, so it offers nothing to sign or cancel/);
  await frame.click('#read');
  assert.equal(await frame.isDisabled('#sign'), true);
  await context.close();
});

const DESKTOP = { width: 1280, height: 800 };

test('a renewal of a permission whose passkey belongs to another website: the page says so, warns before a new passkey is made, and signs with one for this website', async (t) => {
  if (skip(t)) return;
  const { makePasskey } = await import('./helpers/passkey.mjs');
  const old = await makePasskey('ES256', { rpId: 'old.example.org', origin: 'https://old.example.org' });
  const agent = await generateKeySet();
  const prepared = await prepareSlip({ ...permission(agent.keys), issuer: { name: 'The person', key: old.key, rpId: old.rpId, origin: old.origin } });
  const earlier = assembleSlip(prepared, await old.sign(prepared.challenge));
  const { context, problems } = await newContext(DESKTOP);
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  const { popup, holder } = await openWindow(context, page, requestLink({ kind: 'renewal', fields: permission(agent.keys), earlier, returnTo: `${opener.origin}/opener.html`, state: 'w' }));
  assert.match(await text(popup, '#read-status'), /asks you to renew a permission.*belongs to the website old\.example\.org, and a browser lets it sign only there/);
  await popup.click('#read');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  const warnings = await popup.$$eval('#warnings li', (items) => items.map((li) => li.textContent));
  assert.ok(warnings.some((w) => /signed with a passkey other than the one that signed the earlier permission/.test(w)), warnings.join('\n'));
  assert.ok(warnings.some((w) => /A new passkey will be made for this website/.test(w)), warnings.join('\n'));
  // The earlier permission's passkey is not the person's own here, so it vouches for nothing: the agent's key set is warned of.
  assert.ok(warnings.some((w) => /not signed a permission for this agent's key set on this device before/.test(w)), warnings.join('\n'));
  assert.equal((await holder.credentials()).length, 0, 'nothing made before the second press');
  await popup.click('#sign');
  const { result } = await waitForResult(page);
  assert.equal(result.kind, 'renewal');
  assert.equal((await holder.credentials()).length, 1);
  const checked = await checkSlip(result.record, { issuerOrigins: [sign.origin] });
  assert.deepEqual(checked.problems, []);
  assert.notEqual(checked.issuerKey, await thumbprint(old.key));
  await popup.waitForEvent('close', { timeout: 20000 });
  assert.deepEqual(problems, []);
  await context.close();
});

test('at desktop width, the window stays open with the file offered when the page that opened it says it did not keep the record, or says nothing at all', async (t) => {
  if (skip(t)) return;
  assert.ok(first && first.renewed, 'the earlier tests signed');
  const { context, problems, outside } = await newContext(DESKTOP);
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  await page.evaluate(() => { window.answer = false; });
  const { popup } = await openWindow(context, page, requestLink({ kind: 'cancellation', earlier: first.renewed.record, returnTo: `${opener.origin}/opener.html`, state: 'c1' }), [first.credential]);
  assert.ok(await popup.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'nothing scrolls sideways');
  await cancelTwice(popup);
  await waitForResult(page);
  await popup.waitForFunction(() => /did not keep it/.test(document.getElementById('cancel-status').textContent), null, { timeout: 20000 });
  assert.equal(await popup.isHidden('#cancel-save-line'), false, 'the file stays offered');
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(popup.isClosed(), false, 'the window stays open');
  // Handed back once: no second cancellation can be signed from this window, warned or not.
  assert.equal(await popup.isDisabled('#cancel'), true, 'the button stays off after the page said it did not keep it');
  assert.equal(await popup.isHidden('#cancel-save-line'), false, 'the file is still offered');

  // No answer at all: after the wait, the window says so and offers the file.
  const page2 = await context.newPage();
  await page2.goto(`${opener.origin}/opener.html`);
  await page2.evaluate(() => { window.answer = null; });
  const second = await openWindow(context, page2, requestLink({ kind: 'cancellation', earlier: first.renewed.record, returnTo: `${opener.origin}/opener.html`, state: 'c2' }), [first.credential]);
  await cancelTwice(second.popup);
  await waitForResult(page2);
  assert.match(await text(second.popup, '#cancel-status'), /Waiting for it to confirm that it kept the signed cancellation/);
  assert.equal(await second.popup.isDisabled('#cancel'), true, 'the button stays off while the page waits');
  await second.popup.waitForFunction(() => /has not confirmed that it kept/.test(document.getElementById('cancel-status').textContent), null, { timeout: 20000 });
  assert.match(await text(second.popup, '#cancel-save-status'), /Save it as a file instead/);
  assert.equal(second.popup.isClosed(), false);
  assert.equal(await second.popup.isDisabled('#cancel'), true, 'and after the wait');
  assert.deepEqual(problems, []);
  assert.deepEqual(outside, []);
  await context.close();
});

test('at desktop width, a renewal and a cancellation with no window go back by a link, with the signed record after "#signed="', async (t) => {
  if (skip(t)) return;
  assert.ok(first && first.renewed, 'the earlier tests signed');
  const { context, problems, outside } = await newContext(DESKTOP);
  const page = await context.newPage();
  const fields = { ...permission(first.agent.keys), purpose: 'Renewed with no window.' };
  await page.goto(requestLink({ kind: 'renewal', fields, earlier: first.renewed.record, returnTo: `${opener.origin}/back.html`, state: 'r' }));
  const holder = await authenticator(context, page, [first.credential]);
  await page.waitForFunction(() => document.getElementById('read-status').textContent !== '', null, { timeout: 20000 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'nothing scrolls sideways');
  await page.click('#read');
  await page.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  assert.match(await text(page, '#changed-heading'), /What changes against the permission being renewed/);
  await page.click('#sign');
  await page.waitForFunction(() => !document.getElementById('warnings').hidden, null, { timeout: 20000 });
  await page.click('#sign');
  await page.waitForFunction(() => !document.getElementById('back-line').hidden, null, { timeout: 20000 });
  assert.equal(await text(page, '#back'), `Then go back to ${opener.origin}/back.html with the signed permission`);
  await Promise.all([page.waitForURL((u) => u.href.startsWith(`${opener.origin}/back.html#signed=`), { timeout: 20000 }), page.click('#back')]);
  const renewal = JSON.parse(new TextDecoder().decode(fromBase64url(new URLSearchParams(new URL(page.url()).hash.slice(1)).get('signed'))));
  assert.equal(renewal.kind, 'renewal');
  assert.equal(renewal.state, 'r');
  const checked = await checkSlip(renewal.record, { issuerKeys: [first.thumbprint], issuerOrigins: [sign.origin] });
  assert.deepEqual(checked.problems, []);
  assert.equal(checked.content.purpose, 'Renewed with no window.');
  assert.equal((await holder.credentials()).length, 1, 'no new passkey was made');

  // The cancellation, in a new tab of the same browser: the passkey found above is remembered and asked directly.
  const tab = await context.newPage();
  await tab.goto(requestLink({ kind: 'cancellation', earlier: renewal.record, returnTo: `${opener.origin}/back.html`, state: 'x' }));
  await authenticator(context, tab, [first.credential]);
  await tab.waitForFunction(() => document.getElementById('cancel-status').textContent !== '', null, { timeout: 20000 });
  await cancelTwice(tab);
  await tab.waitForFunction(() => !document.getElementById('cancel-back-line').hidden, null, { timeout: 20000 });
  assert.equal(await tab.isDisabled('#cancel'), true, 'signed and offered to take back: no second cancellation from here');
  assert.equal(await text(tab, '#cancel-back'), `Then go back to ${opener.origin}/back.html with the signed cancellation`);
  await Promise.all([tab.waitForURL((u) => u.href.startsWith(`${opener.origin}/back.html#signed=`), { timeout: 20000 }), tab.click('#cancel-back')]);
  const cancelled = JSON.parse(new TextDecoder().decode(fromBase64url(new URLSearchParams(new URL(tab.url()).hash.slice(1)).get('signed'))));
  assert.equal(cancelled.kind, 'cancellation');
  assert.equal(cancelled.state, 'x');
  const book = await checkBook(`${entryLine({ slip: renewal.record })}\n`, { issuerKeys: [first.thumbprint], issuerOrigins: [sign.origin], cancellations: [{ cancellation: cancelled.record }] });
  assert.equal(book.summary.problemFound, false);
  assert.equal(book.held[0].used, true);
  assert.deepEqual(problems, []);
  assert.deepEqual(outside, []);
  await context.close();
});

// The page's two checks on the clock of the device a person signs on
// (page/sign-page.js: startRefusal, clockWarning; the plain functions are
// tested in test/sign-start.test.mjs).
test('a renewal that starts more than 300 seconds ahead is not signed and no passkey is asked; with a clock a day behind, a cancellation is signed only after the warning that the clock may be wrong', async (t) => {
  if (skip(t)) return;
  assert.ok(first, 'the first test signed');
  const { context, problems } = await newContext();
  const page = await context.newPage();
  await page.goto(`${opener.origin}/opener.html`);
  const ahead = new Date(Date.now() + 600e3).toISOString().slice(0, 19) + 'Z';
  const fields = { ...permission(first.agent.keys), validFrom: ahead, purpose: 'Starts ten minutes from now.' };
  const { popup, holder } = await openWindow(context, page, requestLink({ kind: 'renewal', fields, earlier: first.record, returnTo: `${opener.origin}/opener.html` }), [first.credential]);
  await popup.click('#read');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  await popup.click('#sign');
  await popup.waitForFunction(() => document.getElementById('sign-status').textContent !== '', null, { timeout: 20000 });
  assert.equal(
    await text(popup, '#sign-status'),
    `This renewal starts at ${ahead}, more than 5 minutes after this device's clock, so it is not signed: the agent's software does not take a permission from the application that starts later than that. If the clock of this device is right, ask again from the page that opened this window; if it is not, set it first. You can try again.`,
  );
  assert.equal(await popup.isHidden('#warnings'), true, 'refused before any warning');
  assert.equal(await popup.isHidden('#save-line'), true, 'nothing is offered to keep');
  assert.equal(await page.evaluate(() => window.result), null, 'nothing went back');
  assert.equal((await holder.credentials())[0].signCount, first.credential.signCount, 'the passkey was not asked');
  // A second press is refused the same way: there is nothing to confirm.
  await popup.click('#sign');
  await popup.waitForFunction(() => !document.getElementById('sign').disabled, null, { timeout: 20000 });
  assert.match(await text(popup, '#sign-status'), /^This renewal starts at .* so it is not signed/);
  assert.equal(await page.evaluate(() => window.result), null);
  assert.deepEqual(problems, []);
  await context.close();

  // A device whose clock is a day behind: by it, the permission to cancel has not started.
  const behind = await newContext();
  await behind.context.addInitScript(() => {
    const real = Date.now.bind(Date);
    Date.now = () => real() - 86400e3;
  });
  const page2 = await behind.context.newPage();
  await page2.goto(`${opener.origin}/opener.html`);
  const second = await openWindow(behind.context, page2, requestLink({ kind: 'cancellation', earlier: first.record, returnTo: `${opener.origin}/opener.html` }), [first.credential]);
  await second.popup.click('#cancel');
  await second.popup.waitForFunction(() => !document.getElementById('cancel-warnings').hidden && !document.getElementById('cancel').disabled, null, { timeout: 20000 });
  const warnings = await second.popup.$$eval('#cancel-warnings li', (items) => items.map((li) => li.textContent));
  assert.equal(warnings.length, 2, warnings.join('\n'));
  assert.equal(
    warnings[0],
    `The clock of this device may be wrong: by it, the earlier permission (which starts at ${first.content.validFrom}) will not start for more than 5 minutes yet. What you sign here is dated and judged by this clock. Check the date and time of this device; go on only if they are right.`,
  );
  assert.match(warnings[1], /not a known address/);
  assert.equal(await text(second.popup, '#cancel'), 'I have read the warnings: sign the cancellation');
  assert.equal(await text(second.popup, '#cancel-status'), 'Read the warnings above, then press the button again to sign the cancellation.');
  assert.equal(await page2.evaluate(() => window.result), null, 'the first press signs nothing');
  // The second press confirms what the first showed, and signs.
  await second.popup.click('#cancel');
  const cancelled = await waitForResult(page2);
  assert.equal(cancelled.result.kind, 'cancellation');
  assert.deepEqual(behind.problems, []);
  await behind.context.close();
});
