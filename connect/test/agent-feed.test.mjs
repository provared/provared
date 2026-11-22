// The uploader's question for the agent's public key set (upload.mjs,
// feedClient.agent, GET /agent), against the recorder's own feed (feed.mjs,
// beside the recorder named in PROVARED_RECORDER, as in
// feed-recorder.test.mjs), on a port of the test's own. An earlier recorder
// does not know the route and answers with its own 404, which carries no
// proof: the uploader reads that as "not given", takes nothing from it, and
// goes on with the books. An answer without the proof is never used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { feedClient } from '../upload.mjs';
import { readKeySet } from '../agent.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const recorderFile = resolve(process.env.PROVARED_RECORDER || join(here, '..', '..', 'integrations', 'claude-code', 'recorder.mjs'));
const feedFile = join(dirname(recorderFile), 'feed.mjs');
const found = existsSync(feedFile);
const expected = process.env.PROVARED_EXPECT_STACK === '1';
if (!found) console.log(`# No recorder's feed at ${feedFile}: these tests are ${expected ? 'failed' : 'skipped'}. Name the recorder in PROVARED_RECORDER.`);
const skip = !found && !expected ? 'no recorder\'s feed' : false;

const KEYS = [{ alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: 'x'.repeat(43) }, { alg: 'ML-DSA-87', kty: 'AKP', pub: 'p'.repeat(3456) }];
const GIVEN = { agent: { name: 'Claude Code', keys: KEYS }, fingerprint: 'F'.repeat(43) };

/**
 * A recorder's feed on a port of its own, with a book in force of one line.
 * agent: what the recorder gives for GET /agent (undefined: an earlier recorder, which does not know it).
 * before: answers a request before the feed does, where it gives true (a stand-in for another program).
 */
async function recorderOn({ agent, before = () => false } = {}) {
  const { createFeed, feedToken } = await import(pathToFileURL(feedFile));
  const folder = mkdtempSync(join(tmpdir(), 'provared-connect-agent-'));
  const token = feedToken(folder);
  const feed = createFeed({ folder, token, memory: () => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => '{"slip":1}\n', inForce: true }], agent });
  const server = createServer(async (req, res) => {
    if (before(req, res)) return;
    if (await feed.handle(req, res)) return;
    // The recorder's own answer to a path it does not know: outside the feed, with no proof, and with a key set in it that must not be used.
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found', ...GIVEN }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const client = feedClient({ address: `http://127.0.0.1:${server.address().port}`, token: token.token });
  return { client, close: () => new Promise((r) => server.close(r)) };
}

test('a recorder that gives the key set: the uploader reads it, proved, in its own form', { skip }, async () => {
  const r = await recorderOn({ agent: () => GIVEN });
  try {
    assert.deepEqual(await r.client.agent(), { given: true, agent: { name: 'Claude Code', keys: KEYS }, fingerprint: GIVEN.fingerprint });
  } finally {
    await r.close();
  }
});

test('an earlier recorder\'s 404, with no proof: "not given", nothing in it used, and the uploader goes on with the books', { skip }, async () => {
  const r = await recorderOn({ agent: undefined });
  try {
    assert.deepEqual(await r.client.agent(), { given: false });
    const books = await r.client.books();
    assert.equal(books.books.length, 1);
    const lines = await r.client.lines({ id: books.books[0].id, book: 'book.jsonl', from: 0 });
    assert.deepEqual(lines.lines, ['{"slip":1}']);
    // Asked again, the same: never a key set.
    assert.deepEqual(await r.client.agent(), { given: false });
  } finally {
    await r.close();
  }
});

test('a key set in an answer without the recorder\'s proof is never used', { skip }, async () => {
  const r = await recorderOn({
    agent: () => GIVEN,
    // Another program answers GET /agent with a key set of its own, 200 and no proof.
    before: (req, res) => {
      if (!req.url.startsWith('/agent')) return false;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ agent: { name: 'Someone else', keys: [KEYS[0]] }, fingerprint: 'S'.repeat(43) }));
      return true;
    },
  });
  try {
    await assert.rejects(r.client.agent(), (e) => e.reason === 'feed-error' && /does not carry the recorder's proof/.test(e.message));
  } finally {
    await r.close();
  }
});

test('a proved answer not in the form read is not used: a private member, a key set too long, no fingerprint', { skip }, async () => {
  for (const given of [
    { agent: { name: 'Claude Code', keys: [{ ...KEYS[0], d: 'd'.repeat(43) }] }, fingerprint: 'F'.repeat(43) },
    { agent: { name: 'Claude Code', keys: KEYS }, fingerprint: 'short' },
  ]) {
    const r = await recorderOn({ agent: () => given });
    try {
      // The recorder's own feed refuses to give a private member (500, proved); a bad fingerprint too.
      await assert.rejects(r.client.agent(), (e) => e.reason === 'feed-error');
    } finally {
      await r.close();
    }
  }
});

test('the key set\'s form: public members only, none dropped; a name, one to eight keys, at most 8,192 characters', () => {
  assert.deepEqual(readKeySet({ name: 'Claude Code', keys: KEYS }), { name: 'Claude Code', keys: KEYS });
  assert.equal(readKeySet({ name: 'Claude Code', keys: [{ ...KEYS[0], d: 'd'.repeat(43) }] }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [{ ...KEYS[0], priv: 'd'.repeat(43) }] }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [{ ...KEYS[0], use: 'sig' }] }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [{ ...KEYS[0], x: 'not base64url!' }] }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [{ alg: 'Ed25519', x: 'x'.repeat(43) }] }), null, 'no kty');
  assert.equal(readKeySet({ name: '', keys: KEYS }), null);
  assert.equal(readKeySet({ name: 'n'.repeat(201), keys: KEYS }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [] }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: Array(9).fill(KEYS[0]) }), null);
  assert.equal(readKeySet({ name: 'Claude Code', keys: [KEYS[1], KEYS[1], KEYS[1]] }), null, 'over 8,192 characters');
  // Made afresh: a change to what was read does not reach it.
  const given = { name: 'Claude Code', keys: [{ ...KEYS[0] }] };
  const read = readKeySet(given);
  given.keys[0].x = 'changed';
  assert.equal(read.keys[0].x, KEYS[0].x);
});
