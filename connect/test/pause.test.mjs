// The uploader's rounds through the feed (upload.mjs, feedRounds) against a
// recorder that has no book yet: the waiting recorder, before the person's
// first permission is taken. A round that finds no book in force comes back
// at once, so the uploader waits before it asks again, instead of asking
// the recorder for its books without end. The time is the test's own: each
// pause moves it on at once, and the test ends within 10 seconds of the
// monotonic clock whatever the loop does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createCryptoCore } from '@microtoll/crypto-core';
import { NO_BOOK_PAUSE_MS, createUploader, feedRounds } from '../upload.mjs';
import { NAMESPACE } from '../entry.mjs';

const cc = createCryptoCore({ namespace: NAMESPACE });
const quiet = { info() {}, error() {} };

/** A feed that lists books as given, and counts the questions for its list. */
function feedOf(books) {
  const f = { asked: 0, books };
  f.client = {
    origin: 'http://127.0.0.1:1',
    async books() { f.asked++; return { books: f.books, version: 0 }; },
    async lines() { throw new Error('no book is asked for here'); },
  };
  return f;
}

function uploaderOn(feed) {
  const dir = mkdtempSync(join(tmpdir(), 'provared-connect-pause-'));
  const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  return createUploader({ connection, book: join(dir, 'book.jsonl'), log: quiet, append: async () => { throw new Error('nothing is sent here'); }, feed: feed.client });
}

/** Runs the rounds on the test's own time for "seconds" of it; ends after 50 rounds or 10 seconds of the monotonic clock. */
async function run(u, seconds, { wakeAt = null } = {}) {
  let clock = 0;
  let rounds = 0;
  const pauses = [];
  const at = [];
  const began = performance.now();
  const ended = await feedRounds({
    round: async (wait) => { rounds++; at.push(clock); await u.sync({ wait }); return true; },
    bookInForce: u.bookInForce,
    // The pause after a round that found no book: woken early at "wakeAt", if given, as the hand-over loop's wake does.
    pause: async (ms) => { pauses.push(ms); clock += wakeAt !== null && clock < wakeAt && clock + ms > wakeAt ? wakeAt - clock : ms; },
    sleep: async (ms) => { clock += ms; },
    stop: () => clock >= seconds * 1000 || rounds >= 50 || performance.now() - began > 10000,
  });
  return { ended, rounds, pauses, clock, at };
}

test('against a feed with no book, the uploader asks for its books no more than twice in 30 seconds', async () => {
  const feed = feedOf([]);
  const u = uploaderOn(feed);
  const r = await run(u, 30);
  assert.equal(u.bookInForce(), false);
  assert.ok(feed.asked <= 2, `it asked ${feed.asked} times in 30 seconds`);
  assert.ok(r.pauses.length >= 1 && r.pauses.every((ms) => ms === NO_BOOK_PAUSE_MS));
  assert.equal(NO_BOOK_PAUSE_MS, 25000);
  u.close();
});

test('a book kept but none in force is no book in force: the uploader still waits', async () => {
  const feed = feedOf([{ book: 'book-1.jsonl', number: 1, id: '9:1:1', inForce: false, bytes: 0 }]);
  const u = uploaderOn(feed);
  await run(u, 30);
  assert.equal(u.bookInForce(), false);
  assert.ok(feed.asked <= 2, `it asked ${feed.asked} times in 30 seconds`);
  u.close();
});

test('the pause ends at the hand-over loop\'s wake, and then the uploader asks again', async () => {
  const feed = feedOf([]);
  const u = uploaderOn(feed);
  // Woken 5 seconds into the first pause: the second round comes at 5 seconds, not 25.
  const r = await run(u, 6, { wakeAt: 5000 });
  assert.equal(feed.asked, 2);
  assert.deepEqual(r.at, [0, 5000]);
  u.close();
});

test('with a book in force there is no pause: the round itself waits at the recorder', async () => {
  const feed = feedOf([{ book: 'book.jsonl', number: null, id: '9:1:1', inForce: true, bytes: 0 }]);
  feed.client.lines = async ({ id, from }) => ({ book: 'book.jsonl', id, inForce: true, from, lines: [], starts: [], ends: [], previous: null, size: 0, bytes: 0, last: null, books: feed.books, version: 0 });
  const u = uploaderOn(feed);
  let rounds = 0;
  const pauses = [];
  await feedRounds({
    round: async (wait) => { rounds++; await u.sync({ wait }); return true; },
    bookInForce: u.bookInForce,
    pause: async (ms) => { pauses.push(ms); },
    sleep: async () => {},
    stop: () => rounds >= 3,
  });
  assert.equal(u.bookInForce(), true);
  assert.deepEqual(pauses, []);
  u.close();
});

test('a round that fails for now is tried again after the retry time; one that fails for good ends the rounds', async () => {
  const slept = [];
  let n = 0;
  const ended = await feedRounds({
    round: async () => (++n === 1 ? 'again' : false),
    bookInForce: () => null,
    pause: async () => { throw new Error('no pause after a failed round'); },
    sleep: async (ms) => { slept.push(ms); },
  });
  assert.equal(ended, false);
  assert.deepEqual(slept, [30000]);
});
