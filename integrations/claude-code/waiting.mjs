// The waiting recorder: what answers on the recorder's port in a fresh
// folder, from "start" on, before any permission is in force. It writes no
// book and no line. Every tool call is refused; nothing is recorded, sealed
// or renewed. It is apart from startService (recorder.mjs), which assumes a
// permission in force throughout, and it answers on the same port and with
// the same feed (port.mjs), behind the same checks.

import { keySetFingerprint } from 'provared';
import { portOwner, sendJson } from './port.mjs';
import { DEFAULT_FOLDER, DEFAULT_PORT, VERSION, loadAgentKeys, makeRecorderKeys, readWaitingPermissions } from './recorder.mjs';

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
 * @param {{folder: string, owner: ReturnType<typeof portOwner>, clock?: () => number}} o
 */
export async function waitingHandler({ folder, owner, clock = Date.now }) {
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

  return {
    handle,
    // The waiting recorder holds no book: the feed lists none.
    memory: () => [],
    handOver: async () => ({ kind: null, fingerprint: null, outcome: 'refused', code: 'no-permission-yet', message: NO_PERMISSION }),
  };
}

/**
 * Start the waiting recorder: the port's owner, with the waiting handler in place, listening on 127.0.0.1.
 * @param {{folder?: string, port?: number, clock?: () => number, handOverReadMs?: number}} [o] port 0 takes any free port
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
