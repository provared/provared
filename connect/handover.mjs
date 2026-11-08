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

import { createHash } from 'node:crypto';
import { createAccess, openContent } from '@microtoll/access';
import { describe } from './book.mjs';
import { COLLECTION } from './entry.mjs';
import { readOutcomes, sealOutcomes } from './outcomes.mjs';
import { sendAndAwait } from '@microtoll/identity';

export const HAND_OVER_AGAIN_MS = 60000;
/**
 * The allowance between clocks, 300 seconds, as the agent's recorder and the
 * application's page use it: a new permission that
 * starts less than this after a kept cancellation may have been signed
 * before it, and is not handed over.
 */
export const CANCELLATION_ALLOWANCE_MS = 300 * 1000;
/** Refusals the person can put right on the agent's computer, or that may pass: handed over again. */
export const AGAIN = Object.freeze(['passkey-not-trusted', 'passkey-retired', 'cancellation-held', 'failed', 'not-taken']);

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
    const answers = [];
    for (const r of records) {
      const key = sha256(JSON.stringify(r.body));
      const last = handled.get(key);
      if (last && last.due > now()) continue;
      let answer;
      try {
        answer = await feed.handOver(r.body);
      } catch (e) {
        // The recorder stopped, busy, or not proving itself: tried again later, and said once.
        if (!last?.failed) log.error(`provared-connect: a ${r.kind} could not be handed to the recorder now: ${e.message}`);
        handled.set(key, { ...(last ?? {}), failed: true, due: now() + againMs });
        continue;
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

/**
 * The book's kept records and its note of outcomes, through the uploader's
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
  /** Watches the book's shelf on the connection in use; handler() once the book's content changes. Again on a new connection. */
  async function watch(handler) {
    const socket = await connect();
    if (watchedOn === socket || !shelf) return;
    if (stopLive) stopLive();
    stopLive = access.onLiveObject(socket, (e) => { if (e.objectId === connection.objectId) handler(); });
    await access.watchObjects(socket, { collection: COLLECTION, selectors: [shelf] });
    watchedOn = socket;
  }
  return { readKept, putOutcomes, watch };
}
