// The waiting recorder: what answers on the recorder's port in a fresh
// folder, from "start" on, before any permission is in force. It writes no
// book and no line. Every tool call is refused; nothing is recorded, sealed
// or renewed. It is apart from startService (recorder.mjs), which assumes a
// permission in force throughout, and it answers on the same port and with
// the same feed (port.mjs), behind the same checks.

import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { entryLine, fingerprint, fromBase64url, keySetFingerprint } from 'provared';
import { portOwner, sendJson } from './port.mjs';
import {
  DEFAULT_FOLDER, DEFAULT_PORT, VERSION, addWaitingPermission, admitRequest, checkNewSlip, declineAsked, freshFolder, handOverChecks, loadAgentKeys, makeRecorderKeys,
  placeSlip, readDeclined, readRetired, readWaitingPermissions, signingOriginsFrom, startService, takeOutWaiting, untilFree, waitingByFingerprint, writeTrusted,
} from './recorder.mjs';

const MAX_BODY = 1024 * 1024;

/** Every byte of a request's body, as received; null where it is longer than MAX_BODY. */
async function bodyOf(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const NO_PERMISSION ='No permission has been signed for this agent yet: the recorder waits for the first one, so every tool call is refused, and nothing is recorded.';

/**
 * The waiting recorder's handler, for the port's owner (port.mjs).
 * @param {{folder: string, owner: ReturnType<typeof portOwner>, clock?: () => number, signingOrigins?: string|string[], faults?: (step: string) => Promise<void>|void, serviceOptions?: object}} o
 *   signingOrigins: the addresses a record handed over may have been signed at (signingOriginsFrom); the full
 *   recorder takes the same, and the same clock. For tests: faults is awaited at each step of a first permission
 *   taken ("checked": every check passed, nothing written yet); serviceOptions go to startService, and
 *   never replace its folder, port's owner, addresses or clock; unlink removes a file when a failed start
 *   is put back.
 */
export async function waitingHandler({ folder, owner, clock = Date.now, signingOrigins = process.env.PROVARED_CLAUDE_CODE_SIGNING_ORIGIN, faults = async () => {}, serviceOptions = {}, unlink = unlinkSync }) {
  const signedAt = signingOriginsFrom(signingOrigins);
  let admitting = false;
  const agent = await loadAgentKeys(folder);
  const sealer = await makeRecorderKeys(folder);
  const agentKeySet = await keySetFingerprint(agent.keys);
  const sealerKeySet = await keySetFingerprint(sealer.keys);
  const started = new Date(clock()).toISOString();
  const refusedHere = { error: NO_PERMISSION, code: 'no-permission-yet' };

  async function handle(req, res) {
    const send = (code, body) => sendJson(res, code, body);
    if (req.method === 'GET' && req.url === '/status') {
      return send(200, {
        waiting: true,
        version: VERSION,
        agentKeySet,
        sealer: sealerKeySet,
        waitingPermissions: readWaitingPermissions(folder).length,
        feed: owner.feed.status(),
        started,
        folder,
      });
    }
    if (req.method !== 'POST') return send(404, { error: 'not found' });
    if (req.url === '/before') return send(200, { allowed: false, waiting: true, breaches: [], problems: [{ code: 'no-permission-yet', message: NO_PERMISSION }] });
    if (['/record', '/seal', '/renew', '/new-book'].includes(req.url)) return send(409, refusedHere);
    if (req.url === '/admit') {
      const bytes = await bodyOf(req);
      if (bytes === null) return send(413, { error: 'too large' });
      // Only a program that holds the feed's token, from this folder, may have a passkey trusted (feed.mjs).
      const reply = owner.feed.checkQuestion(req, res, bytes);
      if (!reply) return undefined;
      let given;
      try {
        given = JSON.parse(bytes.toString('utf8'));
      } catch {
        given = null;
      }
      const asked = admitRequest(given);
      if (asked.refusal) return reply(200, { kind: 'renewal', fingerprint: null, outcome: 'refused', code: 'not-understood', message: asked.refusal });
      // One admit at a time: a second, while one runs, changes nothing.
      if (admitting) return reply(409, { error: 'Another admit-passkey is being answered on this computer now, so nothing was changed. Run the command again in a moment.', code: 'busy' });
      admitting = true;
      try {
        return reply(200, await inTurn(() => admit(asked)));
      } finally {
        admitting = false;
      }
    }
    if (req.url === '/stop') {
      const bytes = await bodyOf(req);
      if (bytes === null) return send(413, { error: 'too large' });
      let given = null;
      try {
        given = bytes.length > 0 ? JSON.parse(bytes.toString('utf8')) : null;
      } catch {
        // Not JSON: a stop as before.
      }
      // {"waiting": true}: stopped only while it still waits and takes no permission ("use"). Any other body
      // stops it, as before.
      if (given && given.waiting === true) {
        if (owner.handler !== self) return send(409, { stopped: false, code: 'not-waiting', error: 'The recorder no longer waits for a first permission: one is in force, so it was not stopped.' });
        if (admitting) return send(409, { stopped: false, code: 'busy', error: 'A permission is being taken now (admit-passkey), so the recorder was not stopped. Ask again in a moment.' });
      }
      send(200, { stopped: true });
      owner.stop();
      return undefined;
    }
    return send(404, { error: 'not found' });
  }

  // One request that reads or writes the waiting list at a time.
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const run = turn.then(work);
    turn = run.catch(() => {});
    return run;
  };
  // A permission whose start was too far ahead when it was handed over: refused for good while this recorder runs.
  const startsLater = new Set();

  // A RECORD HANDED OVER (POST /hand-over, by a reader that holds the
  // feed's token). A first permission is checked as the full recorder
  // checks a renewal, in the checks that need no permission in force
  // (handOverChecks); then it is kept in waiting-permissions.json, to wait
  // for the person's thumbprint and "yes" on this computer
  // ("admit-passkey"), and refused with "waits-for-yes". Nothing is taken
  // from the feed: no slip.json, no list of trusted passkeys, no book. A
  // cancellation is refused: no permission is in force.
  async function handOver(given) {
    const refused = (kind, fp, code, message, more = {}) => ({ kind, fingerprint: fp, outcome: 'refused', code, message, ...more });
    // One that waited its turn behind the admit that put the full recorder in
    // place: passed on to the full recorder, which answers it by its own rules
    // (a cancellation of the permission just taken is taken), and nothing is
    // kept here.
    if (owner.handler !== self) return owner.handler.handOver(given);
    if (!given || typeof given !== 'object' || Array.isArray(given)) return refused(null, null, 'not-understood', 'What was handed over is not a renewal or a cancellation.');
    const names = Object.keys(given);
    if (given.kind === 'cancellation' && names.length === 2 && names.includes('cancellation')) {
      let fp = null;
      try {
        fp = await fingerprint(fromBase64url(given.cancellation.payload));
      } catch {
        // Not a signed cancellation: refused all the same.
      }
      return refused('cancellation', fp, 'nothing-in-force', 'No permission is in force on this computer yet, so there is nothing to cancel: the recorder waits for its first permission, and every tool call is refused.');
    }
    if (!(given.kind === 'renewal' && names.length === 2 && names.includes('slip'))) {
      return refused(null, null, 'not-understood', 'What was handed over is not a renewal ({kind: "renewal", slip}) or a cancellation ({kind: "cancellation", cancellation}).');
    }
    const slip = given.slip;
    let fp;
    try {
      fp = await fingerprint(fromBase64url(slip.payload));
    } catch {
      return refused('renewal', null, 'not-sound', 'What was handed over is not a signed permission.');
    }
    const checked = await handOverChecks(slip, fp, { agentKeys: agent.keys, signedAt, trusted: null, retired: readRetired(folder), now: clock(), startsLater, declined: readDeclined(folder) });
    if (!checked.next) return refused('renewal', fp, checked.code, checked.message, checked.thumbprint ? { thumbprint: checked.thumbprint } : {});
    const T = checked.next.issuerKey;
    let kept;
    try {
      kept = addWaitingPermission(folder, slip, fp, T);
    } catch (e) {
      return refused('renewal', fp, 'failed', `The permission could not be kept to wait here (${e.message}): hand it over again, or save it from the signing window as a file and run "use <file>".`);
    }
    // Not kept: a code of its own, final, so that no program reads it as waiting.
    if (!kept) return refused('renewal', fp, 'not-kept', `A permission from the same passkey that starts no earlier waits here already, so this one is not kept: on the agent's computer, run "admit-passkey" with the thumbprint the signing window shows, ${T}, to take that one.`, { thumbprint: T });
    return refused('renewal', fp, 'waits-for-yes', `The permission waits on the agent's computer for the person's "yes": there, run "admit-passkey" with the thumbprint the signing window shows, ${T}.`, { thumbprint: T });
  }

  // TAKING A FIRST PERMISSION (POST /admit, with the feed's proof, after the
  // person typed the thumbprint and "yes" at a terminal on this computer).
  // In this order: one admit at a time (above); this handler still the one
  // in place, and the folder still fresh; the checks of a permission handed
  // over again, with that one passkey admitted, then startService's own
  // checks on the slip, all before anything is written; the list of trusted
  // passkeys written as exactly this one passkey (a list someone left is
  // replaced); slip.json; the full recorder built on the same port and feed,
  // which writes the slip as the book's first line; the full recorder put
  // in place in one step; and only then "taken" (a record handed over
  // meanwhile, which waited its turn behind this, then goes to the full
  // recorder: handOver above). Where the start fails,
  // what this attempt wrote is put back and the permission waits.
  async function admit(asked) {
    const kind = 'renewal';
    const fp = asked.fingerprint;
    const refused = (code, message) => ({ kind, fingerprint: fp, outcome: 'refused', code, message });
    if (owner.handler !== self) return refused('not-waiting', 'The recorder no longer waits for a first permission: one is in force. Nothing was changed.');
    if (asked.decline) return declineAsked(folder, asked);
    const { fresh, found } = freshFolder(folder);
    if (!fresh) return refused('not-fresh', `The folder holds ${found.join(', ')} now, so it is not the fresh folder this recorder waits in, and nothing is taken or written. Stop the recorder ("stop"), look at those files, and start it again ("ensure").`);
    const entry = await waitingByFingerprint(folder, fp);
    if (!entry) return refused('no-such-permission', 'No permission with this fingerprint waits here, so nothing is taken: a passkey is admitted only with a permission it signed that was handed over and waits on this computer.');
    const checked = await handOverChecks(entry.slip, fp, { agentKeys: agent.keys, signedAt, trusted: null, retired: readRetired(folder), admit: asked.thumbprint, now: clock(), startsLater, declined: readDeclined(folder) });
    if (!checked.next) return refused(checked.code, checked.message);
    // The checks startService makes on the slip it starts with, here too, before anything is written.
    let next;
    try {
      next = await checkNewSlip(entry.slip, { agentKeys: agent.keys, trusted: [asked.thumbprint], retired: readRetired(folder) });
    } catch (e) {
      return refused(e.code ?? 'not-taken', e.message);
    }
    if (!asked.take) return { kind, fingerprint: fp, outcome: 'would-take', thumbprint: next.issuerKey, message: 'Every check passed: it would be taken.' };
    await faults('checked');
    const written = { trusted: false, slip: false };
    let service;
    try {
      writeTrusted(folder, [asked.thumbprint], null, { replace: true });
      written.trusted = true;
      await placeSlip(folder, next);
      written.slip = true;
      // The options for tests first, so that they never change the folder, the port's owner, the addresses or the clock.
      service = await startService({ ...serviceOptions, folder, on: owner, signingOrigins, clock });
    } catch (e) {
      const left = putBack(written, next.slip);
      return refused('not-started', `The permission passed every check, but the recorder could not start with it (${e.message}), so it is not taken${left.length ? `; ${left.join('; ')}` : ', and what was written for it was put back'}. The permission waits: put right what stands in the way, then run admit-passkey again.`);
    }
    // The full recorder, in place in one step: the next request goes to it, on the same port and feed.
    owner.use(service.handler);
    try {
      takeOutWaiting(folder, fp);
    } catch {
      // Left in the list: it is the permission in force now, and admitted again it is "already".
    }
    return { kind, fingerprint: fp, outcome: 'taken', entries: service.recorder.book().split('\n').filter(Boolean).length, message: `Taken: the passkey ${asked.thumbprint} is trusted, and the agent acts under this permission from now on (in force from ${next.content.validFrom} until ${next.content.validUntil}).` };
  }

  // Put back what an admit wrote before the start failed: the folder was
  // fresh, so the list of trusted passkeys and slip.json go, and a book that
  // holds only this permission's line (no uploader has seen it: the waiting
  // recorder's feed lists no book). Each removal is tried again for up to ten
  // seconds while another program holds the file open (untilFree, as the
  // recorder writes its files). Gives back what could not be put back.
  function putBack(written, slip) {
    const left = [];
    const remove = (name) => {
      try {
        untilFree(() => unlink(join(folder, name)));
      } catch (e) {
        if (e.code !== 'ENOENT') left.push(`${join(folder, name)} could not be removed (${e.message}): remove it before you run admit-passkey again`);
      }
    };
    if (written.slip) remove('slip.json');
    if (written.trusted) remove('trusted-passkeys.json');
    const book = join(folder, 'book.jsonl');
    try {
      if (existsSync(book) && readFileSync(book, 'utf8') === `${entryLine({ slip })}\n`) remove('book.jsonl');
    } catch (e) {
      left.push(`${book} could not be read (${e.message})`);
    }
    return left;
  }

  const self = {
    handle,
    // The waiting recorder holds no book: the feed lists none.
    memory: () => [],
    handOver: (given) => inTurn(() => handOver(given)),
  };
  return self;
}

/**
 * Start the waiting recorder: the port's owner, with the waiting handler in place, listening on 127.0.0.1.
 * @param {{folder?: string, port?: number, clock?: () => number, signingOrigins?: string|string[], handOverReadMs?: number, faults?: Function, serviceOptions?: object}} [o]
 *   port 0 takes any free port; the rest as waitingHandler's
 * @returns {Promise<{port: number, owner: object, close: () => Promise<void>}>}
 */
export async function startWaiting({ folder = DEFAULT_FOLDER, port = DEFAULT_PORT, handOverReadMs, ...options } = {}) {
  // Only in a fresh folder: anywhere a permission was ever taken, the full recorder starts, or nothing does.
  const { fresh, found } = freshFolder(folder);
  if (!fresh) {
    throw new Error(found.length > 0
      ? `The folder ${folder} holds ${found.join(', ')}, so it is not fresh, and the recorder does not wait there for a first permission.`
      : `The folder ${folder} holds no agent keys, so it is not fresh, and the recorder does not wait there: run init first.`);
  }
  const owner = portOwner({ folder, handOverReadMs });
  owner.use(await waitingHandler({ folder, owner, ...options }));
  await owner.listen(port);
  return {
    get port() { return owner.port; },
    owner,
    close: () => owner.close(),
  };
}
