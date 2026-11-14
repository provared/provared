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
import { NAMESPACE, RP_NAME, setUp, signIn, userName, FIELD_CHALLENGE, FIELD_SIGNATURE } from './steps.js';

const cc = createCryptoCore({ namespace: NAMESPACE });
const webauthn = id.createWebAuthn({ rpName: RP_NAME });
const passkey = {
  create: () => webauthn.createPasskeyWithPrf(userName(location.host)),
  evaluate: (credentialId, prfSalt) => webauthn.evaluatePrf(credentialId, prfSalt),
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
  setupButton.addEventListener('click', async () => {
    setupButton.disabled = true;
    say('Making the passkey…');
    try {
      const { recoveryCode } = await setUp({ cc, id, passkey, code, send });
      const shown = document.getElementById('owner-recovery');
      shown.textContent = recoveryCode;
      shown.hidden = false;
      say('The owner is set up. Write the recovery code down now: it is shown once, and it is the only way in if the passkey is lost or the executor\'s address changes.');
    } catch (e) {
      setupButton.disabled = false;
      problem(e);
    }
  });
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
