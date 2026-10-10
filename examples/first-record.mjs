// A first record, in one file. Run it, then check what it wrote:
//
//   npm install provared
//   node first-record.mjs
//   npx provared-check book.jsonl --issuer <the thumbprint it prints>
//
// The permission is signed with a DEVELOPMENT STAND-IN for a passkey: a key
// made in memory, which no person confirmed. Every slip it signs says so in
// its issuer's name, and the checker prints that name. A real permission is
// signed by a person, in a browser, with a real passkey.

import { writeFileSync } from 'node:fs';
import { developmentRecorder } from 'provared/dev';

const SEND = 'provared.message.send';

// A permission: the agent may send messages, at most two.
const { recorder, issuerKeys } = await developmentRecorder({
  actions: [SEND],
  limits: [{ action: SEND, count: 2 }],
  purpose: 'Send a few messages, to make a first record.',
});

// Each action is asked for first, taken only if the slip allows it, and
// receipted after. The third message is outside the slip, so it is not sent.
for (let i = 1; i <= 3; i++) {
  const outcome = await recorder.act({ action: SEND }, async () => console.log(`message ${i} sent`));
  if (!outcome.done) console.log(`message ${i} not sent: [${outcome.answer.breaches[0].code}] ${outcome.answer.breaches[0].message}`);
}

// The record: one line for the slip, then one for each receipt.
writeFileSync('book.jsonl', recorder.book());
console.log(`\nWritten: book.jsonl. To check it, naming the passkey you trust:\n  npx provared-check book.jsonl --issuer ${issuerKeys[0]}`);
