// The feed's route GET /agent (feed.mjs): the agent's public key set,
// worked out by the recorder from the agent's key file, never the file, and
// its fingerprint, proved as every answer of the feed is; in the full
// recorder and in the waiting one. Without the feed's proof it is refused.
// It never gives a private member. Every test works in a temporary folder
// and on a port of its own.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';

const { keySetFingerprint } = await import('provared');
const { createFeed, feedReader, feedToken } = await import('../feed.mjs');
const { startService } = await import('../recorder.mjs');
const { startWaiting } = await import('../waiting.mjs');
const { freshWorld, tempFolder, world } = await import('./world.mjs');

const LOCAL = { signingOrigins: ['http://localhost'] };
const tokenOf = (folder) => readFileSync(join(folder, 'feed-token'), 'utf8').trim();
const PUBLIC = new Set(['kty', 'alg', 'crv', 'x', 'pub']);

/** Every member name anywhere in a JSON value. */
function members(value, out = new Set()) {
  if (Array.isArray(value)) value.forEach((v) => members(v, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) { out.add(k); members(v, out); }
  return out;
}

async function checkAnswer(port, folder, agent) {
  const reader = feedReader({ address: `http://127.0.0.1:${port}`, token: tokenOf(folder) });
  const r = await reader.get('/agent');
  assert.equal(r.code, 200);
  assert.equal(r.proved, true, 'the answer carries the recorder\'s proof');
  assert.deepEqual(Object.keys(r.body).sort(), ['agent', 'fingerprint']);
  assert.deepEqual(r.body.agent, { name: 'Claude Code', keys: agent.keys });
  assert.equal(r.body.fingerprint, await keySetFingerprint(agent.keys));
  const names = members(r.body);
  assert.ok(!names.has('d') && !names.has('priv'), 'no private member');
  for (const key of r.body.agent.keys) for (const name of Object.keys(key)) assert.ok(PUBLIC.has(name), `${name} is a public member`);
  // The agent's private keys are in the folder, and none of their private parts is in the answer.
  const file = JSON.parse(readFileSync(join(folder, 'agent-keys.jwk'), 'utf8'));
  const text = JSON.stringify(r.body);
  for (const key of file.keys) for (const secret of [key.d, key.priv].filter(Boolean)) assert.ok(!text.includes(secret));
  // The reader's own call gives the same, checked.
  assert.deepEqual(await reader.agent(), { given: true, agent: r.body.agent, fingerprint: r.body.fingerprint });
  return reader;
}

async function refusedWithoutProof(port) {
  const plain = await fetch(`http://127.0.0.1:${port}/agent`);
  const text = await plain.text();
  assert.equal(plain.status, 401);
  assert.ok(!text.includes('keys') && !text.includes('fingerprint'), text);
  // A proof made by a reader that does not hold the token is refused too.
  const stranger = feedReader({ address: `http://127.0.0.1:${port}`, token: 'S'.repeat(43) });
  await assert.rejects(stranger.get('/agent'), (e) => e.code === 'not-the-recorder');
}

test('the full recorder: GET /agent gives the public key set and its fingerprint, proved; refused without a proof', async () => {
  const w = await world();
  const service = await startService({ folder: w.folder, port: 0, ...LOCAL });
  try {
    await checkAnswer(service.port, w.folder, w.agent);
    await refusedWithoutProof(service.port);
  } finally {
    await service.close();
  }
});

test('the waiting recorder: GET /agent gives the same, proved; refused without a proof', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, ...LOCAL });
  try {
    await checkAnswer(waiting.port, w.folder, w.agent);
    await refusedWithoutProof(waiting.port);
  } finally {
    await waiting.close();
  }
});

test('GET /agent takes nothing after its name, and GET only', async () => {
  const w = await freshWorld();
  const waiting = await startWaiting({ folder: w.folder, port: 0, ...LOCAL });
  try {
    const reader = feedReader({ address: `http://127.0.0.1:${waiting.port}`, token: tokenOf(w.folder) });
    const r = await reader.get('/agent?keys=all');
    assert.equal(r.code, 400);
    assert.equal(r.proved, true);
    assert.ok(!('agent' in r.body));
    // A POST is refused before any proof is looked at, so its answer carries none.
    await assert.rejects(reader.post('/agent', {}), (e) => e.code === 'not-proved' && e.status === 405);
  } finally {
    await waiting.close();
  }
});

/** A feed on a port of its own, whose recorder gives the key set "agent" gives. */
async function feedOn(agent) {
  const folder = tempFolder('provared-cc-agent-route-');
  const token = feedToken(folder);
  const feed = createFeed({ folder, token, memory: () => [], agent });
  const server = createServer(async (req, res) => {
    if (!(await feed.handle(req, res))) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"not found"}'); }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const reader = feedReader({ address: `http://127.0.0.1:${server.address().port}`, token: token.token });
  return { reader, close: () => new Promise((r) => server.close(r)) };
}

test('a key set that holds a private member is never given: the feed refuses to answer', async () => {
  const w = await freshWorld();
  const file = JSON.parse(readFileSync(join(w.folder, 'agent-keys.jwk'), 'utf8'));
  // The private keys' text members only (the key, its private part and its kind), as a recorder that gave the file would.
  const privateKeys = file.keys.map((k) => Object.fromEntries(Object.entries(k).filter(([, v]) => typeof v === 'string')));
  assert.ok(privateKeys.every((k) => k.d || k.priv));
  const f = await feedOn(async () => ({ agent: { name: 'Claude Code', keys: privateKeys }, fingerprint: 'F'.repeat(43) }));
  try {
    const r = await f.reader.get('/agent');
    assert.equal(r.code, 500);
    assert.equal(r.proved, true);
    const text = JSON.stringify(r.body);
    for (const key of file.keys) for (const secret of [key.d, key.priv].filter(Boolean)) assert.ok(!text.includes(secret));
    assert.ok(!('agent' in r.body));
    await assert.rejects(f.reader.agent(), /key set/);
  } finally {
    await f.close();
  }
});

test('where no handler is in place yet the feed says so, proved; a feed made without a key set does not know the route', async () => {
  const starting = await feedOn(() => null);
  try {
    const r = await starting.reader.get('/agent');
    assert.equal(r.code, 503);
    assert.equal(r.proved, true);
  } finally {
    await starting.close();
  }
  // As an older recorder: the route is not the feed's, and the recorder's own 404 carries no proof.
  const older = await feedOn(undefined);
  try {
    await assert.rejects(older.reader.get('/agent'), (e) => e.code === 'not-proved' && e.status === 404);
    assert.deepEqual(await older.reader.agent(), { given: false });
    // The feed goes on answering.
    assert.equal((await older.reader.get('/books')).code, 200);
  } finally {
    await older.close();
  }
});
