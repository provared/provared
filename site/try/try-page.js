// The "try it" page. Everything happens in this browser: the record is made
// and checked here, nothing is sent anywhere, and nothing is kept once the
// page is closed. The one request it can make is for the sample record,
// from the place the page itself came from, and only where the browser
// cannot make a new record.

import { checkBook, conditionWords, limitWords, methodAvailable, neverWords, openChecker } from '../src/check.js';
import { developmentRecorder } from '../src/dev.js';
import { SHARED_ACTIONS } from '../src/actions.js';
import { fromBase64url, sha256, toBase64url, utf8 } from '../src/encoding.js';
import { el, label, renderResult, showTime } from '../check/render.js';
import { DEFAULT_LIMIT, MAX_LIMIT, MIN_LIMIT, ORDER, ORDERS, choosePath, makeRecord, readLimit } from './story.js';

const $ = (id) => document.getElementById(id);
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
const SAMPLE_LIMIT = 200;

let path = null;
let running = false;

function actionWords(name) {
  const shared = Object.hasOwn(SHARED_ACTIONS, name) ? SHARED_ACTIONS[name][1] : null;
  return shared ? `${name} (${shared.replace(/\.$/, '').toLowerCase()})` : name;
}

// The permission in the checker's own words, from the signed content.
function showPermission(content) {
  const list = $('permission-words');
  list.replaceChildren();
  const row = (name, value) => list.append(el('dt', '', name), el('dd', '', value));
  row('Signed by', `${label(content.issuer.name)}, with a passkey`);
  row('Who may act', label(content.agent.name));
  row('May do', content.actions.map(actionWords).join('; '));
  row('Limits', content.limits.length ? content.limits.map(limitWords).join('; ') : 'none');
  if (content.requires.length) row('Conditions', content.requires.map(conditionWords).join('; '));
  if (content.never.length) row('Never', content.never.map(neverWords).join('; '));
  if (content.with.length) row('With', content.with.map((s) => label(s.name)).join(', '));
  row('From', showTime(content.validFrom));
  row('Until', showTime(content.validUntil));
  row('Why', label(content.purpose));
  $('permission').hidden = false;
}

function contentOf(record) {
  return JSON.parse(new TextDecoder().decode(fromBase64url(record.payload)));
}

function step(className, did, found) {
  const item = el('li', className);
  item.append(el('span', 'did', did));
  for (const line of found) item.append(el('span', 'found', line));
  $('steps').append(item);
  return item;
}

function reset() {
  $('permission').hidden = true;
  $('acted').hidden = true;
  $('checked').hidden = true;
  $('steps').replaceChildren();
  $('result').replaceChildren();
}

// The live way: a new record, made and checked here.
async function runLive(limit) {
  const all = ORDERS.reduce((sum, o) => sum + o.value, 0);
  $('acted-lead').textContent = `The agent places ${ORDERS.length} orders, ${all} GBP in all, under a limit of ${limit} GBP. Before each order it asks the check before acting, which reads the record so far. In this story it then places the order whatever the answer, and signs a receipt for it, so that there is something for the checker to find. A well-made agent stops when the answer is no.`;
  const lib = { developmentRecorder, checkBook, sha256, utf8, toBase64url };
  const made = await makeRecord(lib, limit, async (s) => {
    if (s.kind === 'slip') {
      showPermission(contentOf(s.slip));
      $('acted').hidden = false;
      await pause(500);
      return;
    }
    const answer = s.allowed ? 'The check before acting said: allowed.' : `The check before acting said: NOT allowed. ${s.said.join(' ')} The agent placed the order anyway.`;
    step(s.allowed ? '' : 'outside', `Entry ${s.index}. ${s.order.what}, ${s.order.value} GBP.`, [
      answer,
      `The agent signed a receipt for it, with Ed25519 and ML-DSA-87, and added it to the record. The receipt's fingerprint: ${s.fingerprint}`,
      `Running total: ${s.total} GBP. The limit is ${limit} GBP.`,
    ]);
    await pause(450);
  });
  $('checked-lead').textContent = 'The free checker now reads the whole record, as a stranger would, and checks every signature in it. It is told to trust the stand-in passkey that signed the permission, which this page made a moment ago. With a real record, you name the passkey of the person you trust.';
  $('checked').hidden = false;
  renderResult($('result'), made.result, { options: { issuerKeys: made.issuerKeys } });
  const first = made.result.summary.firstBreach;
  $('status').textContent = first === null
    ? `Done. With a limit of ${limit} GBP, the record shows the agent within its permission. Try a lower limit.`
    : `Done. The checker found the agent outside its permission, first at entry ${first}. Try another limit.`;
}

// The other way: the published sample record, read one entry at a time.
async function runSample() {
  const response = await fetch('../samples/office-supplies.jsonl');
  const told = await fetch('../samples/office-supplies.expected.json');
  if (!response.ok || !told.ok) throw new Error('The sample record could not be fetched.');
  const book = await response.text();
  const expected = await told.json();
  const trust = { issuerKeys: [expected.issuerKey], sealKeys: expected.sealKeys, stampServices: expected.stampServices };
  $('acted-lead').textContent = 'The sample record holds the permission, the supplier\'s terms, six receipts, a refusal by the supplier and a seal. The checker reads it here one entry at a time, as it would read a record that grows.';
  $('acted').hidden = false;
  const checker = await openChecker('', trust);
  const lines = book.split('\n').filter((line) => line !== '');
  let total = 0;
  for (let i = 0; i < lines.length; i++) {
    await checker.add(lines[i] + '\n');
    const e = (await checker.result()).entries[i];
    if (!e || e.problems.length || e.verified === 'none') {
      const why = e && e.problems.length ? `Problem: ${e.problems.map((p) => p.message).join(' ')}` : 'This browser could not check any signature on this entry, so what it says is not shown, and it is not compared with the permission.';
      step(e && e.problems.length ? 'outside' : 'other', `Entry ${i}.`, [why]);
    } else if (e.kind === 'slip') {
      showPermission(e.content);
      step('', 'Entry 0. The permission, signed with a passkey.', ['Its signature is valid. It is shown above, in the checker\'s words.']);
    } else if (e.kind === 'stub') {
      const c = e.content;
      const order = c.action === ORDER && c.amount;
      if (order) total += c.amount.value;
      const what = c.details && c.details.length ? c.details[0].name : c.action;
      const found = e.breaches.length
        ? e.breaches.map((b) => `OUTSIDE THE PERMISSION: ${b.message} (${b.code})`)
        : [e.compared ? 'Within the permission.' : 'Not compared with the permission on this device.'];
      if (order) found.push(`Running total of orders: ${total} GBP. The limit is ${SAMPLE_LIMIT} GBP.`);
      step(e.breaches.length ? 'outside' : '', `Entry ${i}. A receipt: ${what}${c.amount ? `, ${c.amount.value} ${c.amount.unit}` : ''}.`, found);
    } else if (e.kind === 'terms') {
      step('other', `Entry ${i}. The supplier's signed terms for agents.`, ['What the supplier accepts from agents. Not counted for or against the agent.']);
    } else if (e.kind === 'refusal') {
      const asked = e.content.amount ? `${e.content.amount.value} ${e.content.amount.unit} of goods` : 'an action';
      step('other', `Entry ${i}. The supplier's signed refusal of a request for ${asked}.`, ['Shown as the supplier\'s statement, not as what the agent did. Not counted against the agent.']);
    } else if (e.kind === 'seal') {
      step('other', `Entry ${i}. The seal over the ${i} entries before it.`, ['Signed by whoever keeps the book, with three methods. No browser has the third (SLH-DSA), so the seal cannot be fully checked here.']);
    } else {
      step('other', `Entry ${i}. An entry of another kind.`, []);
    }
    await pause(450);
  }
  $('checked-lead').textContent = 'The checker\'s answer for the whole sample record, trusting the fingerprints that come with it:';
  $('checked').hidden = false;
  renderResult($('result'), await checker.result(), { options: trust });
  $('status').textContent = 'Done. The checker\'s answer is below.';
}

async function run() {
  if (running || !path) return;
  let limit = null;
  if (path === 'live') {
    limit = readLimit($('limit').value);
    if (limit === null) {
      $('status').textContent = `Give the limit as a whole number of GBP, from ${MIN_LIMIT} to ${MAX_LIMIT}.`;
      return;
    }
  }
  running = true;
  $('run').disabled = true;
  reset();
  $('status').textContent = path === 'live' ? 'Making the record …' : 'Reading the sample record …';
  try {
    if (path === 'live') await runLive(limit);
    else await runSample();
  } catch (e) {
    $('status').textContent = `${e && e.message ? e.message : 'Something went wrong.'} Nothing was sent anywhere. Try the checking page, or the command-line checker.`;
  } finally {
    running = false;
    $('run').disabled = false;
  }
}

async function start() {
  const chosen = choosePath({ ed25519: await methodAvailable('Ed25519'), mldsa: await methodAvailable('ML-DSA-87') });
  path = chosen.path;
  $('path').textContent = chosen.why;
  $('limit-line').hidden = path !== 'live';
  $('limit').value = String(DEFAULT_LIMIT);
  $('run').textContent = path === 'live' ? 'Make and check a record' : 'Check the sample record';
  $('run').disabled = false;
  document.documentElement.dataset.path = path;
}

$('run').addEventListener('click', run);
$('limit').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') run();
});
start();
