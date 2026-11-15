// The script of the owner's two pages (DESIGN.md, section 14.1): the setup
// page at /oauth/owner and the authorisation page at /oauth/authorize. The
// executor serves it as /oauth/owner/page.js, with the library's own files
// beside it, under /oauth/owner/lib/provared/. Nothing is loaded from
// anywhere else, and nothing runs inline (X224).
//
// The steps are in owner-steps.mjs; this file only joins them to the page:
// the passkey through the library's own browser functions (createPasskey,
// signChallengeWithPasskey), the executor through fetch() to its own
// addresses, and the browser's storage for the executor's address.

import { createPasskey, signChallengeWithPasskey } from './lib/provared/passkey-browser.js';
import { fromBase64url, sha256, toBase64url } from './lib/provared/encoding.js';
import { LINK_PATH, RP_NAME, STORE_CODE, STORE_WAITING, FIELD_CHALLENGE, FIELD_AUTHENTICATOR_DATA, FIELD_CLIENT_DATA, FIELD_SIGNATURE, setUp, signIn, userName } from './steps.js';

const passkey = {
  // One passkey for this address, wherever the browser offers to keep it: on this device, a phone or a security key (X275).
  create: async () => {
    const made = await createPasskey({ name: userName(location.host), site: RP_NAME });
    return { credentialId: made.credentialId, key: made.key };
  },
  // The passkey signs the SHA-256 of the executor's challenge: what the library's check takes a passkey to have signed (X273).
  sign: async (credentialId, challenge) => signChallengeWithPasskey(await sha256(fromBase64url(challenge)), { credentialId, rpId: location.hostname }),
};

/** POST a JSON value to one of the executor's own addresses; its JSON answer, or an Error with its message and its code. */
async function send(path, value) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(value), credentials: 'same-origin', cache: 'no-store' });
  let answer = null;
  try {
    answer = await r.json();
  } catch {
    answer = null;
  }
  if (!r.ok) throw Object.assign(new Error(answer?.message ?? `The executor answered ${r.status}.`), { code: answer?.error });
  return answer;
}

/** The browser's storage for the executor's address, which only the executor's own scripts read (X272). A browser that gives none loses only the one prompt. */
const store = {
  get(name) {
    try {
      return localStorage.getItem(name) ?? '';
    } catch {
      return '';
    }
  },
  set(name, value) {
    try {
      localStorage.setItem(name, value);
    } catch {
      // Not kept: the setup and the first approval then take a prompt each.
    }
  },
  drop(name) {
    try {
      localStorage.removeItem(name);
    } catch {
      // Nothing was kept.
    }
  },
};
/** The executor's answers that mean a setup link's code is of no more use. */
const LINK_OVER = ['owner-exists', 'setup-ended', 'setup-refused'];

const status = document.getElementById('owner-status');
const say = (text) => {
  if (status) status.textContent = text;
};
const problem = (e) => say(`Not done: ${e?.message ?? e}`);
/** Show the recovery code, once. */
const showRecovery = (code) => {
  const shown = document.getElementById('owner-recovery');
  if (!shown) return;
  shown.textContent = code;
  shown.hidden = false;
};
const WRITE_DOWN = 'Write the recovery code down now: it is shown once, and it is the only way to approve a connection if the passkey is lost.';

// The setup page: the link's code is in the fragment, which the browser never sends.
const setupButton = document.getElementById('owner-setup');
if (setupButton) {
  const fromLink = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);
  const code = fromLink || store.get(STORE_CODE);
  setupButton.disabled = true;
  if (code === '') say('This page needs the link the command printed, with its code after the #.');
  else {
    // A request that an authorisation page left here, where there was no owner to approve it (X272).
    const held = store.get(STORE_WAITING);
    try {
      const link = await send(LINK_PATH, held === '' ? { code } : { code, request: held });
      // Kept for the authorisation page, which may be opened next.
      store.set(STORE_CODE, code);
      setupButton.disabled = false;
      const review = document.getElementById('owner-review');
      const reviewRequest = document.getElementById('owner-review-request');
      if (held !== '' && typeof link.waiting === 'string' && review && reviewRequest) {
        reviewRequest.value = held;
        review.hidden = false;
        say(`${link.waiting} is waiting to connect to this executor. Review that connection: if you began it yourself, just now, one passkey prompt there makes the owner and approves it. Or make the passkey alone here, and approve nothing.`);
      } else {
        store.drop(STORE_WAITING);
        say('Make the passkey here; or add the executor in your client first, in this browser: its page then makes the passkey and approves that connection in one prompt.');
      }
    } catch (e) {
      if (LINK_OVER.includes(e?.code)) store.drop(STORE_CODE);
      problem(e);
    }
  }
  setupButton.addEventListener('click', async () => {
    setupButton.disabled = true;
    say('Making the passkey…');
    try {
      const { recoveryCode } = await setUp({ passkey, code, send });
      store.drop(STORE_CODE);
      showRecovery(recoveryCode);
      const review = document.getElementById('owner-review');
      if (review) review.hidden = true;
      const next = document.getElementById('owner-next');
      if (next) next.hidden = false;
      say(`The owner is set up. ${WRITE_DOWN}`);
    } catch (e) {
      if (LINK_OVER.includes(e?.code)) store.drop(STORE_CODE);
      else setupButton.disabled = false;
      problem(e);
    }
  });
}

// The authorisation page: "Approve" first proves the owner, then sends the form.
const form = document.querySelector('form[action="/oauth/authorize"]');
if (form && form.elements[FIELD_CHALLENGE]) {
  // Present where the executor has no owner yet: then Approve can only be the setup and the approval in one (X272).
  const first = document.getElementById('owner-first');
  let code = '';
  /** Whether this browser holds a setup link that still works: asked once, when the page opens. */
  const ready = (async () => {
    if (!first) return store.drop(STORE_WAITING);
    code = store.get(STORE_CODE);
    if (code !== '') {
      try {
        await send(LINK_PATH, { code });
      } catch (e) {
        if (LINK_OVER.includes(e?.code)) store.drop(STORE_CODE);
        code = '';
      }
    }
    if (code !== '') {
      store.drop(STORE_WAITING);
      first.textContent = `This executor has no owner yet, and this browser holds its setup link. Approve makes the owner's passkey for ${location.host} and approves this connection, in one prompt. If you did not begin this connection yourself, refuse, and make the passkey at the setup link instead.`;
    } else {
      // Left for the setup page, which shows it to the owner again while it still waits.
      store.set(STORE_WAITING, form.elements.request.value);
    }
  })();
  let proved = false;
  let busy = false;
  let owner = !first;
  form.addEventListener('submit', async (event) => {
    const submitter = event.submitter;
    if (proved || submitter?.value !== 'approve') return;
    if (busy) return event.preventDefault();
    if (!owner) {
      event.preventDefault();
      await ready;
      if (code === '') return say('Not done: this executor has no owner yet. Open the setup link in this browser first.');
      busy = true;
      say('Making the owner\'s passkey…');
      try {
        const done = await setUp({ passkey, code, request: form.elements.request.value, send });
        owner = true;
        store.drop(STORE_CODE);
        store.drop(STORE_WAITING);
        showRecovery(done.recoveryCode);
        if (typeof done.request === 'string') {
          // The request comes back approved by the setup, and takes the place of the one the form had: the form now needs no passkey.
          form.elements.request.value = done.request;
          proved = true;
          if (submitter) submitter.textContent = 'Continue';
          say(`The owner is set up, and this connection is approved once you continue. ${WRITE_DOWN} Then press Continue: no second prompt follows.`);
        } else {
          say(`The owner is set up, but this request had ended, so nothing was approved. ${WRITE_DOWN} Then begin the connection again from the client.`);
        }
      } catch (e) {
        if (LINK_OVER.includes(e?.code)) store.drop(STORE_CODE);
        problem(e);
      }
      busy = false;
      return;
    }
    // A recovery code typed in its box is the proof, and goes with the form as it is (X276).
    if ((document.getElementById('owner-recovery-code')?.value ?? '').trim() !== '') return;
    event.preventDefault();
    busy = true;
    say('Asking for the owner\'s passkey…');
    try {
      const fields = await signIn({ passkey, request: form.elements.request.value, send, encode: toBase64url });
      // The request comes back with its challenge sealed in, and takes the place of the one the form had (X273).
      form.elements.request.value = fields.request;
      for (const name of [FIELD_CHALLENGE, FIELD_AUTHENTICATOR_DATA, FIELD_CLIENT_DATA, FIELD_SIGNATURE]) form.elements[name].value = fields[name];
      proved = true;
      say('Sending…');
      form.requestSubmit(submitter);
    } catch (e) {
      problem(e);
    }
    busy = false;
  });
  await ready;
}
