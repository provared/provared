// The agent note (agent.mjs): the agent's public key set, sealed under the
// book's key with the book's id bound in, as the note of outcomes is, under
// a label of its own; put by the uploader once, and again only when it
// changes (createAgentNote, bookSide.putAgent). Against an earlier recorder,
// which does not give its key set, nothing is put, it is said once, and the
// uploader goes on uploading.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { AGENT_PURPOSE, NOT_GIVEN_WORDS, agentContext, createAgentNote, openAgent, sealAgent } from '../agent.mjs';
import { bookSide } from '../handover.mjs';
import { NAMESPACE } from '../entry.mjs';
import { openOutcomes, sealOutcomes } from '../outcomes.mjs';
import { createUploader, feedClient, handOverRound } from '../upload.mjs';
import { performance } from 'node:perf_hooks';

const cc = createCryptoCore({ namespace: NAMESPACE });
const KEYS = [{ alg: 'Ed25519', crv: 'Ed25519', kty: 'OKP', x: 'x'.repeat(43) }, { alg: 'ML-DSA-87', kty: 'AKP', pub: 'p'.repeat(3456) }];
const AGENT = { name: 'Claude Code', keys: KEYS };
const OTHER = { name: 'Claude Code', keys: [{ ...KEYS[0], x: 'y'.repeat(43) }, KEYS[1]] };
const newKey = () => cc.importSymmetricKey(cc.generateSymmetricKey());

/** A log that keeps what is said. */
function keep() {
  const k = { out: [], info: (w) => k.out.push(['info', w]), error: (w) => k.out.push(['error', w]) };
  return k;
}

test('the note\'s bound context is "<namespace>/agent/v1", a zero byte and the book\'s id', () => {
  const id = crypto.randomUUID();
  const bytes = agentContext(cc, id);
  const label = new TextEncoder().encode(`${NAMESPACE}/agent/v1`);
  assert.equal(AGENT_PURPOSE, 'agent');
  assert.deepEqual(Buffer.from(bytes), Buffer.concat([label, Buffer.from([0]), Buffer.from(cc.uuidBytes(id))]));
});

test('seal and open: the key set comes back as it was sealed, and only in its form', async () => {
  const id = crypto.randomUUID();
  const key = await newKey();
  assert.deepEqual(await openAgent(cc, key, id, await sealAgent(cc, key, id, AGENT)), AGENT);
  // A key set with a private member is never sealed.
  await assert.rejects(sealAgent(cc, key, id, { name: 'Claude Code', keys: [{ ...KEYS[0], d: 'd'.repeat(43) }] }), /not in the form/);
  // A note sealed by someone else that is not in the form opens to nothing.
  const odd = await cc.sealSymmetric(key, new TextEncoder().encode(JSON.stringify({ version: 1, agent: { name: 'x', keys: [{ kty: 'OKP', d: 'secret' }] } })), agentContext(cc, id));
  assert.equal(await openAgent(cc, key, id, odd), null);
  const otherVersion = await cc.sealSymmetric(key, new TextEncoder().encode(JSON.stringify({ version: 2, agent: AGENT })), agentContext(cc, id));
  assert.equal(await openAgent(cc, key, id, otherVersion), null);
});

test('a note for one book does not open for another, nor under an earlier key of the book', async () => {
  const id = crypto.randomUUID();
  const earlier = await newKey();
  const current = await newKey();
  const sealed = await sealAgent(cc, current, id, AGENT);
  await assert.rejects(openAgent(cc, current, crypto.randomUUID(), sealed), 'another book');
  const old = await sealAgent(cc, earlier, id, AGENT);
  await assert.rejects(openAgent(cc, current, id, old), 'sealed under an earlier key');
});

test('a note of outcomes does not open as an agent note, nor the reverse', async () => {
  const id = crypto.randomUUID();
  const key = await newKey();
  const outcomes = await sealOutcomes(cc, key, id, [{ kind: 'renewal', fingerprint: 'A'.repeat(43), outcome: 'taken', at: '2026-11-01T10:00:00.000Z' }]);
  await assert.rejects(openAgent(cc, key, id, outcomes));
  const agent = await sealAgent(cc, key, id, AGENT);
  await assert.rejects(openOutcomes(cc, key, id, agent));
});

test('the note is put once, and again only when the key set changes', async () => {
  let given = { given: true, agent: AGENT, fingerprint: 'F'.repeat(43) };
  const put = [];
  const log = keep();
  const note = createAgentNote({ feed: { agent: async () => given }, putAgent: async (a) => { put.push(a); }, log });
  assert.equal(await note.round(), 'put');
  assert.equal(await note.round(), 'same');
  assert.equal(await note.round(), 'same');
  assert.deepEqual(put, [AGENT]);
  // The same keys with their members in another order: the note keeps the order as read, so its text differs, and it is put.
  given ={ given: true, agent: { keys: KEYS.map((k) => Object.fromEntries(Object.entries(k).reverse())), name: 'Claude Code' }, fingerprint: 'F'.repeat(43) };
  assert.equal(await note.round(), 'put', 'member order is kept as read: a different text is put');
  given = { given: true, agent: OTHER, fingerprint: 'G'.repeat(43) };
  assert.equal(await note.round(), 'put');
  assert.equal(await note.round(), 'same');
  assert.equal(put.length, 3);
  assert.deepEqual(put.at(-1), OTHER);
});

test('a put that fails is tried again at the next round, and said once', async () => {
  let fail = true;
  let tries = 0;
  const log = keep();
  const note = createAgentNote({
    feed: { agent: async () => ({ given: true, agent: AGENT, fingerprint: 'F'.repeat(43) }) },
    putAgent: async () => { tries++; if (fail) throw Object.assign(new Error('the server does not know this message'), { reason: 'unknown-type' }); },
    log,
  });
  assert.equal(await note.round(), 'failed');
  assert.equal(await note.round(), 'failed');
  assert.equal(log.out.filter(([level]) => level === 'error').length, 1);
  fail = false;
  assert.equal(await note.round(), 'put');
  assert.equal(await note.round(), 'same');
  assert.equal(tries, 3);
});

test('nothing is put from what the feed client does not take, nor from a key set not in its form', async () => {
  const put = [];
  const log = keep();
  let answer = async () => { throw Object.assign(new Error('an answer does not carry the recorder\'s proof over it; it is not used'), { reason: 'feed-error' }); };
  const note = createAgentNote({ feed: { agent: () => answer() }, putAgent: async (a) => { put.push(a); }, log });
  assert.equal(await note.round(), 'failed');
  answer = async () => ({ given: true, agent: { name: 'Claude Code', keys: [{ ...KEYS[0], d: 'd'.repeat(43) }] }, fingerprint: 'F'.repeat(43) });
  assert.equal(await note.round(), 'failed');
  assert.deepEqual(put, []);
});

test('bookSide.putAgent sends the note sealed for the book, with the append capability, and nothing else', async () => {
  const objectId = crypto.randomUUID();
  const key = await newKey();
  const connection = { objectId, appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
  const sent = [];
  const listeners = new Set();
  const socket = {
    readyState: 1,
    send(text) {
      const msg = JSON.parse(text);
      sent.push(msg);
      setImmediate(() => { for (const l of listeners) l({ data: JSON.stringify({ type: 'provared-put-agent-ok', requestId: msg.requestId }) }); });
    },
    addEventListener(type, l) { if (type === 'message') listeners.add(l); },
    removeEventListener(type, l) { listeners.delete(l); },
  };
  const side = bookSide({ cc, connection, connect: async () => socket, key: async () => key });
  await side.putAgent(AGENT);
  assert.equal(sent.length, 1);
  const { requestId, ...msg } = sent[0];
  assert.deepEqual(Object.keys(msg).sort(), ['appendCapabilitySecret', 'objectId', 'sealed', 'type']);
  assert.equal(msg.type, 'provared-put-agent');
  assert.equal(msg.objectId, objectId);
  assert.equal(msg.appendCapabilitySecret, connection.appendCapabilitySecret);
  assert.deepEqual(await openAgent(cc, key, objectId, cc.fromBase64Url(msg.sealed)), AGENT);
  assert.ok(!msg.sealed.includes('Claude'), 'sealed, not in the clear');
});

test('a server that does not know the agent note answers unknown-type: the put is refused at once, not after the wait', async () => {
  const objectId = crypto.randomUUID();
  const key = await newKey();
  const listeners = new Set();
  // As the engine answers a message no handler takes: an error with the request's id, and no "-ok" or "-failed".
  const socket = {
    readyState: 1,
    send(text) {
      const { requestId } = JSON.parse(text);
      setImmediate(() => {
        for (const l of [...listeners]) l({ data: JSON.stringify({ type: 'error', reason: 'unknown-type', requestId: 'another' }) });
        for (const l of [...listeners]) l({ data: JSON.stringify({ type: 'error', reason: 'unknown-type', requestId }) });
      });
    },
    addEventListener(type, l) { if (type === 'message') listeners.add(l); },
    removeEventListener(type, l) { listeners.delete(l); },
  };
  const side = bookSide({ cc, connection: { objectId, appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) }, connect: async () => socket, key: async () => key });
  const began = performance.now();
  await assert.rejects(side.putAgent(AGENT), (e) => e.reason === 'unknown-type');
  assert.ok(performance.now() - began < 2000, `refused after ${Math.round(performance.now() - began)} ms`);
  assert.equal(listeners.size, 0, 'nothing is left listening');
});

test('a hand-over round hands the records over first, and only then puts the agent note', async () => {
  const order = [];
  let release;
  const held = new Promise((r) => { release = r; });
  const agentNote = { round: async () => { order.push('note begun'); await held; order.push('note ended'); return 'failed'; } };
  const handover = { round: async () => { order.push('records'); return []; } };
  const done = handOverRound({ handover, agentNote, log: { info() {}, error() {} } });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(order, ['records', 'note begun'], 'the records do not wait for the note');
  release();
  await done;
  assert.deepEqual(order, ['records', 'note begun', 'note ended']);
});

// --- against an earlier recorder's own feed ---

const here = dirname(fileURLToPath(import.meta.url));
const recorderFile = resolve(process.env.PROVARED_RECORDER || join(here, '..', '..', 'integrations', 'claude-code', 'recorder.mjs'));
const feedFile = join(dirname(recorderFile), 'feed.mjs');
const found = existsSync(feedFile);
const skip = !found && process.env.PROVARED_EXPECT_STACK !== '1' ? 'no recorder\'s feed' : false;

test('against an earlier recorder: nothing is put, it is said once, and the uploader goes on uploading', { skip }, async () => {
  const { createFeed, feedToken } = await import(pathToFileURL(feedFile));
  const folder = mkdtempSync(join(tmpdir(), 'provared-connect-agent-note-'));
  const token = feedToken(folder);
  let text = '{"slip":1}\n';
  // As an earlier recorder: its feed has no key set to give, and the recorder answers GET /agent itself, 404, with no proof.
  const feed = createFeed({ folder, token, memory: () => [{ key: 1, path: join(folder, 'book.jsonl'), text: () => text, inForce: true }] });
  const server = createServer(async (req, res) => {
    if (await feed.handle(req, res)) return;
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found', agent: OTHER, fingerprint: 'S'.repeat(43) }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const client = feedClient({ address: `http://127.0.0.1:${server.address().port}`, token: token.token });
    const put = [];
    const log = keep();
    const note = createAgentNote({ feed: client, putAgent: async (a) => { put.push(a); }, log });
    const dir = mkdtempSync(join(tmpdir(), 'provared-connect-agent-book-'));
    const connection = { server: 'ws://nowhere', origin: 'http://nowhere', namespace: NAMESPACE, objectId: crypto.randomUUID(), kObject: cc.toBase64Url(cc.generateSymmetricKey()), appendCapabilitySecret: cc.toBase64Url(cc.randomBytes(32)) };
    const appended = [];
    const uploader = createUploader({ connection, book: join(dir, 'book.jsonl'), log: keep(), append: async (msg) => { appended.push(msg.seq); return { type: 'provared-append-ok', part: 0, seq: msg.seq }; }, feed: client });
    for (let i = 0; i < 3; i++) {
      assert.equal(await note.round(), 'not-given');
      text += `{"line":${i}}\n`;
      feed.changed();
      await uploader.sync();
    }
    assert.deepEqual(put, [], 'nothing put');
    assert.deepEqual(log.out, [['error', NOT_GIVEN_WORDS]], 'said once');
    assert.match(NOT_GIVEN_WORDS, /update the recorder to fill in the agent's keys by itself/);
    assert.deepEqual(appended, [0, 1, 2, 3], 'every line uploaded');
    uploader.close();
  } finally {
    await new Promise((r) => server.close(r));
  }
});
