// Records handed to the agent's recorder: the renewals and cancellations
// the person signed on the signing page, which the application keeps with
// the book, sealed (the application's page). The
// uploader beside the recorder holds the book's key (from the connection
// file), so it opens what the book keeps, and hands each record to the
// recorder through the recorder's feed (POST /hand-over, proved with the
// feed's token, as every question of the feed is). Nothing is handed over
// by any other way: no file is saved or moved.
//
// THE RECORDER DECIDES. It checks each record itself (the passkey's
// signature, the agent's keys, the dates) and takes it or refuses it: a
// renewal only from a passkey that computer already trusts, never one
// admitted on the word of a record; a cancellation only of the permission
// in force, which it acknowledges in the book. What it takes is shown by
// the book, which this uploader sends as it sends every line: the new
// permission, or the cancellation and the agent's acknowledgement. What it
// refuses, or holds, is said in a sealed note of outcomes (outcomes.mjs),
// which the page reads and shows as this uploader's report.
//
// ONE FOR EACH PASSKEY. Of the new permissions from one passkey, only the
// one that starts latest is handed over in a round, of those the recorder
// has not answered for good, as the waiting recorder keeps one for each
// passkey.
//
// ONCE EACH. A record is handed over until the recorder answers that the
// book holds it ("taken", "already") or refuses it for good; a refusal the
// person can put right on that computer (a passkey it does not trust, or
// one retired there) is handed over again a minute later, and so is a
// record the recorder held or could not take for now. The recorder answers
// a record it holds already without changing the book, so handing one over
// twice is harmless; this keeps it from being asked every round.
//
// WHEN. As soon as the book's sealed content changes (the engine tells
// whoever watches the book's shelf), and once a minute besides.

import { createHash, randomUUID } from 'node:crypto';
import { createAccess, openContent } from '@microtoll/access';
import { describe } from './book.mjs';
import { COLLECTION } from './entry.mjs';
import { readOutcomes, sealOutcomes } from './outcomes.mjs';
import { sealAgent } from './agent.mjs';
import { sendAndAwait } from '@microtoll/identity';

export const HAND_OVER_AGAIN_MS = 60000;
/**
 * The allowance between clocks, 300 seconds, as the agent's recorder and the
 * application's page use it: a new permission that
 * starts less than this after a kept cancellation may have been signed
 * before it, and is not handed over.
 */
export const CANCELLATION_ALLOWANCE_MS = 300 * 1000;
/**
 * Refusals the person can put right on the agent's computer, or that may
 * pass: handed over again. "not-started": the recorder was still starting.
 * "waits-for-yes": a first permission waits there for the person's
 * thumbprint and "yes"; "nothing-in-force": a cancellation came while no
 * permission was in force yet, and is handed over again once one is.
 */
export const AGAIN = Object.freeze(['passkey-not-trusted', 'passkey-retired', 'cancellation-held', 'failed', 'not-taken', 'not-started', 'waits-for-yes', 'nothing-in-force']);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('base64url');

/** A record's fingerprint, as the library makes it: the SHA-256 of its signed content. null where it has none. */
export function recordFingerprint(record) {
  try {
    if (!record || typeof record.payload !== 'string' || !/^[A-Za-z0-9_-]+$/.test(record.payload)) return null;
    return sha256(Buffer.from(record.payload, 'base64url'));
  } catch {
    return null;
  }
}

/** What a signed record says, read from its content (not checked here: the recorder checks it); null where it cannot be read. */
function contentOf(record) {
  try {
    return JSON.parse(Buffer.from(record.payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * The records the book keeps for the agent, in the order they are handed
 * over: the person's cancellations first, then the new permissions, so that
 * a cancellation always reaches the recorder before a permission kept
 * beside it. A new permission that starts less than five minutes
 * (CANCELLATION_ALLOWANCE_MS) after one of the kept cancellations is not
 * handed over at all: it may have been signed before the person cancelled,
 * and would start the agent again (the page sets aside every unconfirmed
 * one when the person cancels, and the recorder refuses it as well). A
 * record whose content cannot be read is not handed over.
 */
export function recordsToHand(kept) {
  const out = [];
  let cancelled = -Infinity;
  for (const c of kept.cancellations) {
    const fingerprint = c && recordFingerprint(c.cancellation);
    if (!fingerprint) continue;
    const when = Date.parse(contentOf(c.cancellation)?.when);
    if (when > cancelled) cancelled = when;
    out.push({ kind: 'cancellation', fingerprint, body: { kind: 'cancellation', cancellation: c.cancellation } });
  }
  for (const r of kept.renewals) {
    const fingerprint = r && recordFingerprint(r.slip);
    if (!fingerprint) continue;
    const from = Date.parse(contentOf(r.slip)?.validFrom);
    if (!(from >= cancelled + CANCELLATION_ALLOWANCE_MS)) continue;
    out.push({ kind: 'renewal', fingerprint, body: { kind: 'renewal', slip: r.slip } });
  }
  return out;
}

/**
 * The passkey a renewal is signed with, as its content names it (not
 * checked here: the recorder checks it), as the text of its key with its
 * members in order; null where it cannot be read.
 */
function passkeyOf(record) {
  const key = contentOf(record.body.slip)?.issuer?.key;
  if (!key || typeof key !== 'object' || Array.isArray(key)) return null;
  return JSON.stringify(Object.keys(key).sort().map((n) => [n, key[n]]));
}

/** The start a renewal states, in milliseconds; -Infinity where it cannot be read. */
function startOf(record) {
  const from = Date.parse(contentOf(record.body.slip)?.validFrom);
  return Number.isNaN(from) ? -Infinity : from;
}

/**
 * createHandover({ feed, readKept, putOutcomes, log, now })
 *   feed         the recorder's feed client (upload.mjs: feedClient), with handOver
 *   readKept     () => { renewals, cancellations } that the book keeps, opened; null where it cannot be read now
 *   putOutcomes  (outcomes) => writes the note of outcomes
 *   round()      hands over what is due; resolves with the answers of this round
 */
export function createHandover({ feed, readKept, putOutcomes, log = console, now = Date.now, againMs = HAND_OVER_AGAIN_MS }) {
  // By the record's exact text: what the recorder said of it last, and when it is due again (Infinity: never).
  const handled = new Map();
  let noted = null;
  let busy = null;

  async function roundOnce() {
    const kept = await readKept();
    if (!kept) return [];
    const records = recordsToHand(kept);
    // At most one renewal for each passkey in a round: of those the recorder has not answered for good, the one
    // that starts latest (the first kept, of two that start alike), as the waiting recorder keeps one for each
    // passkey. One whose passkey cannot be read is its own. Where the one chosen gets no answer (its hand-over
    // fails), the passkey's next, by its start, is handed over in the same round: so a record that cannot be
    // handed over does not keep the others from the same passkey back.
    const groups = new Map();
    for (const r of records) {
      if (r.kind !== 'renewal' || handled.get(sha256(JSON.stringify(r.body)))?.due === Infinity) continue;
      const p = passkeyOf(r) ?? r;
      if (!groups.has(p)) groups.set(p, []);
      groups.get(p).push(r);
    }
    const heads = new Map();
    for (const group of groups.values()) {
      group.sort((a, b) => (startOf(b) > startOf(a)) - (startOf(b) < startOf(a)));
      heads.set(group[0], group);
    }
    const answers = [];
    // One record handed over: "answered", "failed" (no answer: tried again later) or "not-due".
    async function handOne(r) {
      const key = sha256(JSON.stringify(r.body));
      const last = handled.get(key);
      if (last && last.due > now()) return 'not-due';
      let answer;
      try {
        answer = await feed.handOver(r.body);
      } catch (e) {
        if (e.reason === 'too-large') {
          // Larger than the recorder's feed takes: it never can be handed over, so it is answered for good here.
          const item = { kind: r.kind, fingerprint: r.fingerprint, outcome: 'refused', code: 'too-large', at: new Date(now()).toISOString() };
          handled.set(key, { item, due: Infinity });
          answers.push({ ...item, message: e.message });
          log.error(`provared-connect: a ${r.kind} kept with the book was not handed to the recorder: ${e.message}`);
          return 'failed';
        }
        // The recorder stopped, busy, or not proving itself: tried again later, and said once.
        if (!last?.failed) log.error(`provared-connect: a ${r.kind} could not be handed to the recorder now: ${e.message}`);
        handled.set(key, { ...(last ?? {}), failed: true, due: now() + againMs });
        return 'failed';
      }
      const outcome = ['taken', 'already', 'held', 'refused'].includes(answer.outcome) ? answer.outcome : 'refused';
      const final = outcome === 'taken' || outcome === 'already' || (outcome === 'refused' && !AGAIN.includes(answer.code));
      const item = { kind: r.kind, fingerprint: r.fingerprint, outcome, at: new Date(now()).toISOString() };
      if (outcome === 'refused' || outcome === 'held') {
        if (typeof answer.code === 'string') item.code = answer.code;
        if (typeof answer.thumbprint === 'string') item.thumbprint = answer.thumbprint;
      }
      handled.set(key, { item, due: final ? Infinity : now() + againMs });
      answers.push({ ...item, message: typeof answer.message === 'string' ? answer.message.slice(0, 500) : '' });
      if (!last || last.item?.outcome !== item.outcome || last.item?.code !== item.code) {
        log.info(`provared-connect: the recorder answered ${outcome}${item.code ? ` (${item.code})` : ''} for a ${r.kind} handed over`);
      }
      return 'answered';
    }
    for (const r of records) {
      if (r.kind !== 'renewal') { await handOne(r); continue; }
      const group = heads.get(r);
      if (!group) continue;
      // The passkey's latest first; the next only where the one before got no answer.
      for (const c of group) if ((await handOne(c)) !== 'failed') break;
    }
    // The note: one outcome for each record the book keeps now, the latest the recorder gave.
    const current = new Set(records.map((r) => sha256(JSON.stringify(r.body))));
    for (const key of handled.keys()) if (!current.has(key)) handled.delete(key);
    const list = readOutcomes({ version: 1, outcomes: [...handled.values()].map((h) => h.item).filter(Boolean) });
    const text = JSON.stringify(list.map(({ at, ...rest }) => rest));
    if (text !== noted) {
      try {
        await putOutcomes(list);
        noted = text;
      } catch (e) {
        log.error(`provared-connect: the note of outcomes could not be written to the server: ${e.reason || e.code || 'error'}: ${e.message}`);
      }
    }
    return answers;
  }

  function round() {
    if (!busy) busy = roundOnce().finally(() => { busy = null; });
    return busy;
  }
  return Object.freeze({ round });
}

/** How long a message to the server waits for its answer: 20 seconds. */
export const SERVER_ANSWER_MS = 20000;

/**
 * Sends a message to the server with an id of its own, and resolves on its
 * answer okType; rejects on failType, on the server's own refusal of a
 * message it does not take ({ type: "error", reason }, with the same id:
 * "unknown-type" from a server that does not know the message yet), when
 * the connection closes, or after SERVER_ANSWER_MS.
 */
function askServer(ws, request, okType, failType, waitMs = SERVER_ANSWER_MS) {
  const requestId = `a${randomUUID()}`;
  return new Promise((resolve, reject) => {
    const end = (fn, value) => {
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
      fn(value);
    };
    const refused = (msg) => Object.assign(new Error(typeof msg.reason === 'string' ? msg.reason : 'refused'), { reason: msg.reason, code: msg.reason, serverMessage: msg });
    function onMessage(event) {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (!msg || msg.requestId !== requestId) return;
      if (msg.type === okType) end(resolve, msg);
      else if (msg.type === failType || msg.type === 'error') end(reject, refused(msg));
    }
    function onClose() { end(reject, Object.assign(new Error('the connection to the server closed before it answered'), { reason: 'closed' })); }
    const timer = setTimeout(() => end(reject, Object.assign(new Error('the server did not answer in time'), { reason: 'timeout' })), waitMs);
    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose);
    ws.send(JSON.stringify({ ...request, requestId }));
  });
}

/**
 * The book's kept records, its note of outcomes and its agent note, through the uploader's
 * own signed-in connection to the server (connect), opened with the book's
 * key from the connection file. watch(handler) asks the engine to say when
 * the book's sealed content changes (its shelf is watched; other books on
 * it are set aside).
 */
export function bookSide({ cc, connection, connect, key }) {
  const access = createAccess({ cryptoCore: cc });
  let shelf = null;
  let watchedOn = null;
  let stopLive = null;
  async function readKept() {
    const socket = await connect();
    const fetched = await access.fetchObject(socket, connection.objectId);
    if (fetched.fields && typeof fetched.fields.selector === 'string') shelf = fetched.fields.selector;
    let content;
    try {
      content = await openContent(cc, await key(), connection.objectId, fetched.keyEpoch, fetched.encryptedContent);
    } catch {
      throw Object.assign(new Error('the book\'s content does not open with the key in the connection file: the book was given a new key, and the recorder needs a new connection file'), { reason: 'rekeyed' });
    }
    const d = describe(content);
    return { renewals: d.renewals, cancellations: d.cancellations };
  }
  async function putOutcomes(list) {
    const sealed = await sealOutcomes(cc, await key(), connection.objectId, list);
    await sendAndAwait(await connect(), {
      type: 'provared-put-outcomes', objectId: connection.objectId, appendCapabilitySecret: connection.appendCapabilitySecret, sealed: cc.toBase64Url(sealed),
    }, 'provared-put-outcomes-ok', 'provared-put-outcomes-failed');
  }
  /** Writes the agent note (agent.mjs): the agent's public key set, sealed under the book's key with its id bound in. */
  async function putAgent(agent) {
    const sealed = await sealAgent(cc, await key(), connection.objectId, agent);
    // Asked with its own wait, which takes the server's refusal of a message it does not know yet at once.
    await askServer(await connect(), {
      type: 'provared-put-agent', objectId: connection.objectId, appendCapabilitySecret: connection.appendCapabilitySecret, sealed: cc.toBase64Url(sealed),
    }, 'provared-put-agent-ok', 'provared-put-agent-failed');
  }
  /** Watches the book's shelf on the connection in use; handler() once the book's content changes. Again on a new connection. */
  async function watch(handler) {
    const socket = await connect();
    if (watchedOn === socket || !shelf) return;
    if (stopLive) stopLive();
    stopLive = access.onLiveObject(socket, (e) => { if (e.objectId === connection.objectId) handler(); });
    await access.watchObjects(socket, { collection: COLLECTION, selectors: [shelf] });
    watchedOn = socket;
  }
  return { readKept, putOutcomes, putAgent, watch };
}
