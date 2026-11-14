// The script of the owner's two pages (DESIGN.md, section 14.1): the setup
// page at /oauth/owner and the authorisation page at /oauth/authorize. The
// executor serves it as /oauth/owner/page.js, with the two packages' own
// files beside it, under /oauth/owner/lib/. Nothing is loaded from anywhere
// else, and nothing runs inline (X224).
//
// The steps are in owner-steps.mjs; this file only joins them to the page:
// the passkey through the package's WebAuthn functions, the executor through
// fetch() to its own addresses.

import { createCryptoCore } from './lib/crypto-core/index.js';
import * as id from './lib/identity/index.js';
import { NAMESPACE, RP_NAME, ON_DEVICE, ELSEWHERE, ELSEWHERE_AFTER, setUp, signIn, userName, FIELD_CHALLENGE, FIELD_SIGNATURE } from './steps.js';

const cc = createCryptoCore({ namespace: NAMESPACE });
const webauthn = id.createWebAuthn({ rpName: RP_NAME });
const passkey = {
  // On the device itself, or on a phone or a security key (X230): the package's own two attachments.
  create: (attachment) => webauthn.createPasskeyWithPrf(userName(location.host), { attachment }),
  // The transports the passkey was made with tell the browser where to ask for it.
  evaluate: (credentialId, prfSalt, transports) => webauthn.evaluatePrf(credentialId, prfSalt, transports),
};

/** POST a JSON value to one of the executor's own addresses; its JSON answer, or an Error with its message. */
async function send(path, value) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value), credentials: 'same-origin', cache: 'no-store' });
  let answer = null;
  try {
    answer = await r.json();
  } catch {
    answer = null;
  }
  if (!r.ok) throw new Error(answer?.message ?? `The executor answered ${r.status}.`);
  return answer;
}

const status = document.getElementById('owner-status');
const say = (text) => {
  if (status) status.textContent = text;
};
const problem = (e) => say(`Not done: ${e?.message ?? e}`);

// The setup page: the link's code is in the fragment, which the browser never sends.
const setupButton = document.getElementById('owner-setup');
if (setupButton) {
  const code = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  if (code === '') say('This page needs the link the command printed, with its code after the #.');
  // The second button is shown only once the passkey on this device has failed in a way that a phone or a security key may not (X230).
  const elsewhereButton = document.getElementById('owner-setup-elsewhere');
  const buttons = [setupButton, elsewhereButton].filter(Boolean);
  const make = async (attachment) => {
    for (const b of buttons) b.disabled = true;
    say(attachment === ELSEWHERE ? 'Waiting for the phone or the security key…' : 'Making the passkey…');
    try {
      const { recoveryCode } = await setUp({ cc, id, passkey, code, send, attachment });
      const shown = document.getElementById('owner-recovery');
      shown.textContent = recoveryCode;
      shown.hidden = false;
      say('The owner is set up. Write the recovery code down now: it is shown once, and it is the only way in if the passkey is lost or the executor\'s address changes.');
    } catch (e) {
      for (const b of buttons) b.disabled = false;
      problem(e);
      if (attachment === ON_DEVICE && elsewhereButton && ELSEWHERE_AFTER.includes(e?.code)) {
        elsewhereButton.hidden = false;
        say(`Not done: ${e.message}. Nothing was set up. The passkey may be kept on a phone or a security key instead: press the second button.`);
      }
    }
  };
  setupButton.addEventListener('click', () => make(ON_DEVICE));
  if (elsewhereButton) elsewhereButton.addEventListener('click', () => make(ELSEWHERE));
}

// The authorisation page: "Approve" first proves the owner, then sends the form.
const form = document.querySelector('form[action="/oauth/authorize"]');
if (form && form.elements[FIELD_CHALLENGE]) {
  let proved = false;
  form.addEventListener('submit', async (event) => {
    const submitter = event.submitter;
    if (proved || submitter?.value !== 'approve') return;
    event.preventDefault();
    say('Asking for the owner\'s passkey…');
    try {
      const recoveryCode = document.getElementById('owner-recovery-code')?.value ?? '';
      const fields = await signIn({ cc, id, passkey, recoveryCode, request: form.elements.request.value, origin: location.origin, send });
      // The request comes back with its challenge sealed in, and takes the place of the one the form had (X221).
      form.elements.request.value = fields.request;
      form.elements[FIELD_CHALLENGE].value = fields[FIELD_CHALLENGE];
      form.elements[FIELD_SIGNATURE].value = fields[FIELD_SIGNATURE];
      proved = true;
      say('Sending…');
      form.requestSubmit(submitter);
    } catch (e) {
      problem(e);
    }
  });
}
