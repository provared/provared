// The signing page: a person writes a permission, this device's passkey
// signs it, and the person keeps the signed file. Everything happens in
// this browser. The page loads only its own files and sends nothing
// anywhere; the passkey is kept by the device, and this page remembers
// only its public key and identifier (in this browser's storage) so that
// the same passkey can sign again later.

import { conditionWords, limitWords, neverWords } from '../src/check.js';
import { cancelWithPasskey, createPasskey, signSlipWithPasskey } from '../src/passkey-browser.js';
import { fingerprint, fromBase64url } from '../src/encoding.js';
import { thumbprint } from '../src/keys.js';
import { el, shown } from './render.js';

const $ = (id) => document.getElementById(id);
const STORE = 'provared-signing-passkey';
const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;

function say(id, text) {
  $(id).textContent = text;
}

// A starting point: a coding agent on this computer, under limits.
const soon = (days) => new Date(Date.now() + days * 86400 * 1000).toISOString().slice(0, 19) + 'Z';
const EXAMPLE = {
  agent: {
    name: 'The agent, as you call it',
    keys: ['paste the agent\'s two public keys here, as its software printed them'],
  },
  actions: ['provared.code.read', 'provared.code.change', 'provared.code.run', 'provared.web.read', 'provared.agent.instruct'],
  limits: [
    { action: 'provared.code.run', count: 500, per: 3600 },
    { action: 'provared.code.change', count: 500, per: 3600 },
  ],
  requires: [],
  never: ['destroys', 'conceal', 'deceive', 'bypass', 'escalate', 'continue-after-stop'],
  with: [],
  validFrom: new Date(Date.now() - 60 * 1000).toISOString().slice(0, 19) + 'Z',
  validUntil: soon(7),
  purpose: 'What the agent is for, in a sentence.',
};

let fields = null;
let slip = null;
let cancellation = null;

function remembered() {
  try {
    const p = JSON.parse(localStorage.getItem(STORE));
    if (p && typeof p.credentialId === 'string' && p.key && p.rpId === location.hostname && p.origin === location.origin) return p;
  } catch {
    // Nothing remembered, or not readable: a new passkey is made.
  }
  return null;
}

// The permission in words, so that the person sees what they sign.
function showWords(f) {
  const dl = $('slip-words');
  dl.replaceChildren();
  const row = (term, text) => dl.append(el('dt', '', term), el('dd', '', text));
  row('Agent', shown(f.agent.name));
  row('May do', f.actions.map(shown).join(', '));
  row('Limits', f.limits.length ? f.limits.map(limitWords).join('; ') : 'none');
  row('Conditions', f.requires.length ? f.requires.map(conditionWords).join('; ') : 'none');
  row('Never', f.never.length ? f.never.map(neverWords).join(' ') : 'nothing stated');
  row('With', f.with.length ? f.with.map((s) => `${shown(s.name)} (${shown(s.id)})`).join(', ') : 'no other party');
  row('From', f.validFrom);
  row('Until', f.validUntil);
  row('Purpose', shown(f.purpose));
  if (f.passes) row('May pass on', `${f.passes} time(s) in a row`);
  dl.hidden = false;
}

$('fields').value = JSON.stringify(EXAMPLE, null, 2);

$('read').addEventListener('click', () => {
  slip = null;
  $('step2').classList.add('waiting');
  $('step3').classList.add('waiting');
  $('sign').disabled = true;
  $('save-line').hidden = true;
  $('fingerprint-line').hidden = true;
  let parsed;
  try {
    parsed = JSON.parse($('fields').value);
  } catch (e) {
    say('read-status', `This is not JSON: ${e.message}`);
    $('slip-words').hidden = true;
    return;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.hasOwn(parsed, 'issuer')) {
    say('read-status', 'The permission must be one JSON object, without an "issuer" member: your passkey and name are the issuer.');
    $('slip-words').hidden = true;
    return;
  }
  const name = $('issuer-name').value.trim();
  if (!name) {
    say('read-status', 'Write your name: it is the label the permission carries for the person who signed it.');
    return;
  }
  for (const member of ['agent', 'actions', 'limits', 'requires', 'never', 'with', 'validFrom', 'validUntil', 'purpose']) {
    if (!Object.hasOwn(parsed, member)) {
      say('read-status', `The permission has no "${member}" member. Every member is needed; an empty list is written as [].`);
      return;
    }
  }
  if (!Array.isArray(parsed.agent?.keys) || parsed.agent.keys.length !== 2 || parsed.agent.keys.some((k) => !k || typeof k !== 'object')) {
    say('read-status', 'agent.keys must hold the agent\'s two public keys, as its software printed them (Ed25519 first, ML-DSA-87 second).');
    return;
  }
  fields = parsed;
  try {
    showWords(fields);
  } catch (e) {
    say('read-status', `The permission could not be read: ${e.message}`);
    return;
  }
  say('read-status', 'Read. Check the words below, then sign. Anything the format refuses is reported when you sign.');
  $('step2').classList.remove('waiting');
  $('sign').disabled = false;
  $('sign').focus();
});

$('sign').addEventListener('click', async () => {
  $('sign').disabled = true;
  const name = $('issuer-name').value.trim();
  try {
    let passkey = remembered();
    if (!passkey) {
      say('sign-status', 'Your device is asking you to make a passkey for this website.');
      passkey = await createPasskey({ name, site: 'Provared' });
      localStorage.setItem(STORE, JSON.stringify(passkey));
    }
    say('sign-status', 'Your device is asking you to confirm it is you, to sign the permission.');
    slip = await signSlipWithPasskey(fields, passkey, name);
    const fp = await fingerprint(fromBase64url(slip.payload));
    $('thumbprint').textContent = await thumbprint(passkey.key);
    $('passkey-line').hidden = false;
    $('fingerprint').textContent = fp;
    $('fingerprint-line').hidden = false;
    say('sign-status', 'Signed.');
    say('save-status', 'The permission is signed. Save it, and keep the thumbprint above with it.');
    $('step3').classList.remove('waiting');
    $('save-line').hidden = false;
    $('save').focus();
  } catch (e) {
    if (e && e.name === 'PasskeyError' && e.code === 'cancelled') localStorage.removeItem(STORE);
    say('sign-status', `${e && e.message ? e.message : 'The permission was not signed.'} You can try again.`);
    $('sign').disabled = false;
  }
});

function download(name, text) {
  const link = el('a');
  link.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
}

$('save').addEventListener('click', () => {
  if (slip) download('slip.json', JSON.stringify(slip));
});

$('cancel').addEventListener('click', async () => {
  const of = $('cancel-of').value.trim();
  if (!FINGERPRINT.test(of)) {
    say('cancel-status', 'A fingerprint is 43 letters, digits, hyphens or underscores.');
    return;
  }
  $('cancel').disabled = true;
  $('cancel-save-line').hidden = true;
  try {
    const passkey = remembered();
    if (!passkey) throw new Error('No passkey is remembered in this browser. Sign a permission here first with the passkey that signed the one to cancel.');
    say('cancel-status', 'Your device is asking you to confirm it is you, to sign the cancellation.');
    cancellation = await cancelWithPasskey({ slip: of }, passkey);
    say('cancel-status', `Signed, dated ${new Date().toISOString().slice(0, 19)}Z. Save it, and hand it to the agent's software.`);
    $('cancel-save-line').hidden = false;
  } catch (e) {
    say('cancel-status', `${e && e.message ? e.message : 'The cancellation was not signed.'} You can try again.`);
  }
  $('cancel').disabled = false;
});

$('cancel-save').addEventListener('click', () => {
  if (cancellation) download('cancellation.json', JSON.stringify({ cancellation }));
});
