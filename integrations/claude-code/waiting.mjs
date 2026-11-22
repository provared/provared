// The waiting recorder: what answers on the recorder's port in a fresh
// folder, from "start" on, before any permission is in force. It writes no
// book and no line. Every tool call is refused; nothing is recorded, sealed
// or renewed. It is apart from startService (recorder.mjs), which assumes a
// permission in force throughout, and it answers on the same port and with
// the same feed (port.mjs), behind the same checks.

import { fingerprint, fromBase64url, keySetFingerprint } from 'provared';
import { portOwner, sendJson } from './port.mjs';
import { DEFAULT_FOLDER, DEFAULT_PORT, VERSION, addWaitingPermission, handOverChecks, loadAgentKeys, makeRecorderKeys, readDeclined, readRetired, readWaitingPermissions, signingOriginsFrom } from './recorder.mjs';

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
 * @param {{folder: string, owner: ReturnType<typeof portOwner>, clock?: () => number, signingOrigins?: string|string[]}} o
 *   signingOrigins: the addresses a record handed over may have been signed at (signingOriginsFrom)
 */
export async function waitingHandler({ folder, owner, clock = Date.now, signingOrigins = process.env.PROVARED_CLAUDE_CODE_SIGNING_ORIGIN }) {
  const signedAt = signingOriginsFrom(signingOrigins);
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
      return reply(409, refusedHere);
    }
    if (req.url === '/stop') {
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
    return refused('renewal', fp, 'waits-for-yes', kept
      ? `The permission waits on the agent's computer for the person's "yes": there, run "admit-passkey" with the thumbprint the signing window shows, ${T}.`
      : `A permission from the same passkey that starts no earlier waits here already, so this one is not kept: on the agent's computer, run "admit-passkey" with the thumbprint the signing window shows, ${T}.`, { thumbprint: T });
  }

  return {
    handle,
    // The waiting recorder holds no book: the feed lists none.
    memory: () => [],
    handOver: (given) => inTurn(() => handOver(given)),
  };
}

/**
 * Start the waiting recorder: the port's owner, with the waiting handler in place, listening on 127.0.0.1.
 * @param {{folder?: string, port?: number, clock?: () => number, signingOrigins?: string|string[], handOverReadMs?: number}} [o] port 0 takes any free port
 * @returns {Promise<{port: number, owner: object, close: () => Promise<void>}>}
 */
export async function startWaiting({ folder = DEFAULT_FOLDER, port = DEFAULT_PORT, handOverReadMs, ...options } = {}) {
  const owner = portOwner({ folder, handOverReadMs });
  owner.use(await waitingHandler({ folder, owner, ...options }));
  await owner.listen(port);
  return {
    get port() { return owner.port; },
    owner,
    close: () => owner.close(),
  };
}
