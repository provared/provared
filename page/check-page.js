// The checking page: the same checker as the library, run in the browser.
// The record is read from a file the person chooses and never leaves the
// page. The only request this page makes is for the sample record, from the
// place the page itself came from. The page built as a single file
// (tools/make-single-page.mjs) holds the sample record itself, and makes no
// request at all.

import { checkBook, checkShow } from '../src/check.js';
import { readBlocks, readFingerprints, renderResult, shown } from './render.js';

const status = document.getElementById('status');
const result = document.getElementById('result');

// This page reads the whole file into memory. A larger book is checked
// with the command-line checker.
const MAX_FILE_BYTES = 200000000;
// A copy of a cancellation, or a file of disclosures, is small.
const MAX_HANDED_BYTES = 1000000;
const MAX_COPIES = 16;

// What the person already trusts: one fingerprint to a line. A line that
// is not a fingerprint stops the check, and the person is told which box.
const BOXES = [
  ['trust-issuer', 'issuerKeys', 'the person\'s passkey'],
  ['trust-sealer', 'sealKeys', 'whoever keeps and seals the book'],
  ['trust-stamps', 'stampServices', 'time-stamp services'],
  ['trust-vouchers', 'vouchers', 'organisations whose vouching you trust'],
];

function trusted() {
  const options = {};
  for (const [id, name, words] of BOXES) {
    const { values, bad } = readFingerprints(document.getElementById(id).value);
    if (bad.length) throw new Error(`A line in the box for ${words} is not a fingerprint. A fingerprint is 43 letters, digits, hyphens or underscores. Correct it, or empty the box.`);
    if (values.length) options[name] = values;
  }
  const blocks = readBlocks(document.getElementById('trust-blocks').value);
  if (blocks.bad.length) {
    throw new Error('A line in the box for blocks is not the fingerprint of a block. It is 64 characters: the digits 0 to 9 and the letters a to f. Correct it, or empty the box.');
  }
  if (blocks.values.length) options.blocks = blocks.values;
  return options;
}

async function jsonFrom(file, what) {
  if (file.size > MAX_HANDED_BYTES) throw new Error(`The file of ${what}, ${shown(file.name)}, is too large. Nothing was checked.`);
  try {
    return JSON.parse(await file.text());
  } catch {
    throw new Error(`The file of ${what}, ${shown(file.name)}, is not JSON. Nothing was checked. Choose another file, or clear these files.`);
  }
}

// What the person was handed with the record: their own copies of
// cancellations, and disclosures for covered fields. A file that cannot be
// read stops the check: it is never set aside silently.
async function handedOver() {
  const options = {};
  const said = [];
  const copies = [...document.getElementById('cancellations').files];
  if (copies.length > MAX_COPIES) throw new Error('At most 16 copies of cancellations can be handed over at once. Nothing was checked.');
  if (copies.length) {
    options.cancellations = [];
    for (const file of copies) options.cancellations.push(await jsonFrom(file, 'a cancellation'));
    said.push(copies.length === 1 ? 'one copy of a cancellation' : `${copies.length} copies of cancellations`);
  }
  const [disclosures] = document.getElementById('disclosures').files;
  if (disclosures) {
    options.disclosures = await jsonFrom(disclosures, 'disclosures');
    said.push('disclosures for covered fields');
  }
  return { options, said };
}

async function check(text, name, { beside = true, trust = null } = {}) {
  status.textContent = `Checking ${name} …`;
  result.replaceChildren();
  // A Show is one JSON object with a "type". A book is entries, one to a line.
  let isShow = false;
  try {
    const whole = JSON.parse(text);
    isShow = whole !== null && typeof whole === 'object' && Object.hasOwn(whole, 'type');
  } catch {
    isShow = false;
  }
  let options;
  let said = [];
  try {
    options = trust ?? trusted();
    if (beside) {
      const handed = await handedOver();
      options = { ...options, ...handed.options };
      said = handed.said;
    }
  } catch (e) {
    status.textContent = e.message;
    return;
  }
  try {
    const r = isShow ? await checkShow(text, options) : await checkBook(text, options);
    status.textContent = `Checked: ${name}${said.length ? `, with ${said.join(' and ')} handed over beside it` : ''}`;
    renderResult(result, r, { isShow, options });
  } catch {
    status.textContent = 'The check could not be run in this browser. Try the command-line checker.';
  }
}

async function checkChosen(input) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    status.textContent = 'That file is too large for this page. Use the command-line checker.';
    return;
  }
  let text;
  try {
    text = await file.text();
  } catch {
    status.textContent = 'The file could not be read.';
    return;
  }
  await check(text, shown(file.name));
  input.value = '';
}

const chooser = document.getElementById('file');
chooser.addEventListener('change', () => checkChosen(chooser));
// A file chosen before this script started (the page built as one file
// starts its script a moment after it is shown) is checked now, not lost.
if (chooser.files.length > 0) checkChosen(chooser);

document.getElementById('clear-beside').addEventListener('click', () => {
  document.getElementById('cancellations').value = '';
  document.getElementById('disclosures').value = '';
  status.textContent = 'The files you were handed with a record are cleared.';
});

// The sample record and what its makers say to trust: held in the page
// itself where the page was built as a single file, fetched otherwise.
async function sampleRecord() {
  const inPage = document.getElementById('sample-record');
  if (inPage) return JSON.parse(inPage.textContent);
  const response = await fetch('../samples/office-supplies.jsonl');
  const told = await fetch('../samples/office-supplies.expected.json');
  if (!response.ok || !told.ok) throw new Error('not found');
  return { book: await response.text(), expected: await told.json() };
}

document.getElementById('sample').addEventListener('click', async () => {
  status.textContent = 'Fetching the sample record …';
  try {
    // The sample comes with the fingerprints its makers say to trust. It is
    // checked with them, and the boxes keep what the person put there, so
    // that the next record chosen is checked against the person's own.
    const { book, expected } = await sampleRecord();
    const trust = { issuerKeys: [expected.issuerKey], sealKeys: expected.sealKeys, stampServices: expected.stampServices };
    // Files handed over with some other record have nothing to do with the sample.
    await check(book, 'the sample record (an invented office agent), trusting the fingerprints that came with it', { beside: false, trust });
  } catch {
    status.textContent = 'The sample record could not be fetched.';
  }
});
