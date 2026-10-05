// The demonstration page. It needs the demonstration's local server
// (demo/server.mjs), which plays the agent and the supplier.
//
//   1. The person signs the slip here, with a passkey.
//   2. The server's agent works. For one order it asks the person, who
//      approves it here with the same passkey. The record is written.
//   3. The record is checked here, by the same checker as the checking page.

import { checkBook, conditionWords, limitWords, neverWords, thumbprint } from '../src/check.js';
import { approveWithPasskey, createPasskey, signSlipWithPasskey } from '../src/passkey-browser.js';
import { el, renderResult, showTime } from './render.js';

const $ = (id) => document.getElementById(id);
const ISSUER_NAME = 'Demonstration user';
const STORE = 'provared-demonstration-passkey';

let start = null;
let ask = null;
let book = null;

function say(id, text) {
  $(id).textContent = text;
}

// The passkey's public details are remembered in this browser, so that the
// same passkey signs next time. The private key never leaves the device.
function remembered() {
  try {
    const p = JSON.parse(localStorage.getItem(STORE));
    return p && p.origin === location.origin ? p : null;
  } catch {
    return null;
  }
}

function showSlip(fields) {
  const list = $('slip-words');
  const row = (name, value) => list.append(el('dt', '', name), el('dd', '', value));
  row('Who may act', fields.agent.name);
  row('What it may do', fields.actions.join(', '));
  for (const l of fields.limits) row('Limit', limitWords(l));
  for (const r of fields.requires) row('Condition', conditionWords(r));
  for (const n of fields.never) row('Stated rule', neverWords(n));
  row('With whom', fields.with.map((s) => s.name).join(', '));
  row('From', showTime(fields.validFrom));
  row('Until', showTime(fields.validUntil));
  row('Why', fields.purpose);
}

async function load() {
  try {
    const response = await fetch('/demo/start');
    if (!response.ok) throw new Error('no server');
    start = await response.json();
  } catch {
    say('sign-status', 'The demonstration server is not running. In a terminal, in the project folder, type: npm run demo');
    return;
  }
  showSlip(start.fields);
  $('sign').disabled = false;
}

$('sign').addEventListener('click', async () => {
  $('sign').disabled = true;
  try {
    let passkey = remembered();
    if (!passkey) {
      say('sign-status', 'Your device is asking you to make a passkey for this demonstration.');
      passkey = await createPasskey({ name: ISSUER_NAME, site: 'Provared demonstration' });
      localStorage.setItem(STORE, JSON.stringify(passkey));
    }
    say('sign-status', 'Your device is asking you to confirm it is you, to sign the permission.');
    const slip = await signSlipWithPasskey(start.fields, passkey, ISSUER_NAME);
    const response = await fetch('/demo/slip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(slip) });
    const answer = await response.json();
    if (!response.ok) throw new Error(answer.error);
    say('sign-status', `Signed. The slip's fingerprint is ${answer.fingerprint}`);
    $('step2').classList.remove('waiting');
    $('run').disabled = false;
    $('run').focus();
  } catch (e) {
    // Forget the remembered passkey: it may have been removed from the device.
    localStorage.removeItem(STORE);
    say('sign-status', `${e && e.message ? e.message : 'The slip was not signed.'} You can try again.`);
    $('sign').disabled = false;
  }
});

function showSteps() {
  const body = $('orders').querySelector('tbody');
  body.replaceChildren();
  start.steps.forEach((step, i) => {
    const tr = el('tr');
    tr.append(el('td', '', String(i + 1)), el('td', '', step.what), el('td', 'number', step.value === null ? '' : `${step.value} GBP`));
    body.append(tr);
  });
  $('orders').hidden = false;
}

$('run').addEventListener('click', async () => {
  $('run').disabled = true;
  say('run-status', 'The agent is working …');
  try {
    const response = await fetch('/demo/run', { method: 'POST' });
    const answer = await response.json();
    if (!response.ok) throw new Error(answer.error);
    ask = answer.ask;
  } catch (e) {
    say('run-status', `${e && e.message ? e.message : 'The agent could not run.'}`);
    $('run').disabled = false;
    return;
  }
  say('run-status', `The agent has stopped to ask you. It wants to place an order of ${ask.amount.value} ${ask.amount.unit}, and the slip says an order above 60 GBP needs your own approval.`);
  $('approve-line').hidden = false;
  $('approve').disabled = false;
  $('approve').focus();
});

$('approve').addEventListener('click', async () => {
  $('approve').disabled = true;
  try {
    const passkey = remembered();
    if (!passkey) throw new Error('The passkey of step 1 was not found in this browser. Reload the page and start again.');
    say('run-status', 'Your device is asking you to confirm it is you, to approve this one order.');
    const approval = await approveWithPasskey(ask, passkey);
    const response = await fetch('/demo/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(approval) });
    if (!response.ok) throw new Error((await response.json()).error);
    book = await response.text();
  } catch (e) {
    say('run-status', `${e && e.message ? e.message : 'The order was not approved.'} Click "Run the agent" to start this step again.`);
    $('approve-line').hidden = true;
    $('run').disabled = false;
    return;
  }
  $('approve-line').hidden = true;
  say('run-status', 'Approved. The agent went on without asking again. This is what it did:');
  showSteps();
  $('step3').classList.remove('waiting');
  await check();
});

async function check() {
  say('check-status', 'Checking the record …');
  // The demonstration says whom to trust: its own keeper of the book, its
  // own made-up time-stamp service, and the passkey you signed with in
  // step 1. With a real record, you decide.
  const passkey = remembered();
  const trust = { ...start.trust, issuerKeys: passkey ? [await thumbprint(passkey.key)] : [] };
  let result = await checkBook(book, trust);
  let checkedBy = 'Checked in this browser.';
  if (result.summary.methodsMissing.length) {
    const missing = result.summary.methodsMissing.join(' or ');
    // Most browsers have no ML-DSA yet. The server's Node.js has, so it
    // makes the same check, and the page says plainly who checked.
    try {
      const response = await fetch('/demo/check');
      if (response.ok) {
        result = await response.json();
        checkedBy = `This browser has no built-in ${missing}, so this check was made by Node.js on this computer, which has.`;
      }
    } catch {
      // Keep the browser's own result, which says it is not fully checked.
    }
  }
  say('check-status', 'The record was checked.');
  renderResult($('result'), result, { checkedBy, options: trust });
  $('save-line').hidden = false;
}

$('save').addEventListener('click', () => {
  const link = el('a');
  link.href = URL.createObjectURL(new Blob([book], { type: 'text/plain' }));
  link.download = 'demonstration-record.jsonl';
  link.click();
  URL.revokeObjectURL(link.href);
});

load();
