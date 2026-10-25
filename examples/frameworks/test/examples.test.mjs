// Runs the example with the guard of _offline.mjs open for the whole
// process (package.json loads _offline-whole-run.mjs with --import, before
// any other module, and runs this file in the same process), and checks
// what it shows: one order within the slip was run and receipted; one order
// over the limit was not run, left no stub, and the agent was told why; the
// checker finds the book intact and within its slip; and nothing was
// refused, during the run or after it, so nothing tried to reach the
// network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { argumentsFingerprint } from 'provared';
import { isOffline, refused } from '../_offline.mjs';
import { main } from '../vercel-ai-sdk.mjs';

function stubsOf(book) {
  return book.trim().split('\n').map((line) => JSON.parse(line))
    .filter((entry) => 'stub' in entry)
    .map((entry) => JSON.parse(Buffer.from(entry.stub.payload, 'base64url').toString('utf8')));
}

test('the guard is open for the whole process', () => {
  assert.equal(isOffline(), true, 'run this file through "npm test", which opens the guard first');
});

test('the Vercel AI SDK example', async () => {
  const said = [];
  const { world, check, seen } = await main((line) => said.push(line));

  // The model was asked three times: two tool calls, then its answer.
  assert.equal(seen.length, 3);

  // Only the order within the slip reached the supplier.
  assert.deepEqual(world.orders, [{ item: 'printer paper', totalGbp: 30 }]);

  // The book holds the slip and one stub: the order that was run.
  const stubs = stubsOf(world.recorder.book());
  assert.equal(stubs.length, 1);
  assert.equal(stubs[0].action, 'supplies.order');
  assert.equal(stubs[0].with, 'supplier');
  assert.deepEqual(stubs[0].amount, { unit: 'GBP', value: 30 });
  // The stub names the fingerprint of the call's arguments, not the arguments.
  assert.deepEqual(stubs[0].details, [{ name: 'provared.arguments', sha256: await argumentsFingerprint({ item: 'printer paper', totalGbp: 30 }) }]);

  // The agent was told why the second order was not run, as an error.
  assert.ok(said.some((line) => line.includes('(marked as an error)') &&
    line.includes('The tool "orderSupplies" was not run. With this action the total would be 280 GBP. The slip\'s limit is 100 GBP: over by 180.')));

  // The output says who signed the permission: a stand-in, not a person.
  assert.equal(said[0], 'The permission was signed by "Sam Example (invented) (development)": a development stand-in for a passkey, not a person.');

  // The checker's answer, naming the passkey it trusts.
  assert.equal(check.summary.intact, true);
  assert.equal(check.summary.withinSlips, true);
  assert.equal(check.summary.counts.stubs, 1);
  assert.ok(said.includes('The book checks as intact: yes. The agent stayed within its slip: yes. Stubs in the book: 1.'));
});

test('nothing was refused, during the run or in the second after it', async () => {
  await new Promise((done) => setTimeout(done, 1000));
  assert.deepEqual(refused, []);
  assert.equal(isOffline(), true);
});
