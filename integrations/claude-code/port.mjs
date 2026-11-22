// The recorder's one port: one HTTP server on 127.0.0.1, which listens
// once. Its request listener refuses a web page's request (portChecks,
// below), answers the feed's own requests (feed.mjs, made here once), and
// hands every other request to the handler in place: the waiting
// recorder's (waiting.mjs) until a first permission is taken, then the full
// recorder's (startService, in recorder.mjs). The handler is swapped in one
// step ("use"): nothing closes and nothing listens again, so no other
// program can take the port in between, a request already in a handler
// finishes there, and the feed's conversations hold across the switch.

import { createServer } from 'node:http';
import { createFeed, feedToken } from './feed.mjs';

/** A Content-Type of application/json, with or without parameters such as charset. */
export const isJson = (type) => typeof type === 'string' && type.split(';')[0].trim().toLowerCase() === 'application/json';

/** An answer as JSON, unless the caller has gone or it was answered already. */
export function sendJson(res, code, body) {
  if (res.writableEnded || res.destroyed) return;
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

/**
 * The checks of 0.1.1, for every handler: every route, the feed's too,
 * answers a program on this computer, not a web page. A browser names the
 * page that sends a request (Origin, Sec-Fetch-Site), and names the website
 * it meant to reach (Host): a website's name may be made to lead to this
 * computer, but its Host is not 127.0.0.1. Refused before anything is read,
 * and nothing is written. The feed's own requests are then answered by the
 * feed, with its token. Every other POST must send its body as
 * application/json: a web page cannot send that to another website without
 * asking first, and this port never says yes. Gives back whether the
 * request was answered here.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {number} listening the port listened on
 * @param {{handle: Function}} feed
 */
export async function portChecks(req, res, listening, feed) {
  // The Host the recorder's own clients send: 127.0.0.1:<port>, or 127.0.0.1 alone on port 80, which a client leaves out.
  const ownHost = (host) => host === `127.0.0.1:${listening}` || (listening === 80 && host === '127.0.0.1');
  const refuse = (code, error) => {
    sendJson(res, code, { error });
    return true;
  };
  if (req.headers.origin !== undefined) return refuse(403, 'the recorder does not answer a web page (the request names an Origin)');
  if (req.headers['sec-fetch-site'] !== undefined && req.headers['sec-fetch-site'] !== 'none') return refuse(403, 'the recorder does not answer a web page (Sec-Fetch-Site)');
  if (!ownHost(req.headers.host)) return refuse(403, `the recorder answers at 127.0.0.1:${listening} only (Host)`);
  // The feed's own requests (GET /hello, /books and /lines, POST /hand-over), with its token.
  if (await feed.handle(req, res)) return true;
  if (req.method === 'POST' && !isJson(req.headers['content-type'])) return refuse(415, 'the recorder takes a body as application/json only (Content-Type)');
  return false;
}

/**
 * The owner of the recorder's port, and of its feed.
 *
 * A handler is {handle(req, res), memory(), handOver(given), agent?(), close?()}:
 * "handle" answers a request that passed the checks; "memory",
 * "handOver" and "agent" are the feed's (the books it reads from memory, a
 * record handed over, and the agent's public key set for GET /agent);
 * "close" is called once when the port closes.
 * @param {{folder: string, handOverReadMs?: number}} o handOverReadMs: for tests (feed.mjs)
 */
export function portOwner({ folder, handOverReadMs }) {
  let listening = null;
  let handler = null;
  let closed = false;
  const feed = createFeed({
    folder,
    token: feedToken(folder),
    // Whichever handler is in place: the feed is made once, so a reader's conversation holds across the switch.
    memory: () => (handler ? handler.memory() : []),
    handOver: (given) => (handler ? handler.handOver(given) : { kind: null, fingerprint: null, outcome: 'refused', code: 'not-started', message: 'The recorder is starting: hand it over again in a moment.' }),
    // GET /agent: the agent's public key set, from whichever handler is in place; none yet, the feed says so.
    agent: () => (handler?.agent ? handler.agent() : null),
    ...(handOverReadMs === undefined ? {} : { handOverReadMs }),
  });
  const server = createServer(async (req, res) => {
    try {
      if (await portChecks(req, res, listening, feed)) return;
      // The handler in place when the request arrives answers it, whatever is put in place meanwhile.
      const now = handler;
      if (!now) return sendJson(res, 503, { error: 'the recorder is starting: ask again in a moment' });
      await now.handle(req, res);
    } catch (e) {
      sendJson(res, 500, { error: e.message });
    }
  });
  const closeAll = () => {
    if (!closed) {
      closed = true;
      feed.close();
      try {
        handler?.close?.();
      } catch {
        // The port closes all the same.
      }
    }
  };
  return {
    feed,
    server,
    /** The port listened on, once it listens; kept after the port closes. */
    get port() { return listening; },
    get handler() { return handler; },
    /** Put a handler in place, in one step. */
    use(next) {
      handler = next;
    },
    /** Listen once, on 127.0.0.1. */
    async listen(port) {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
      });
      listening = server.address().port;
      return listening;
    },
    /** Close the port: a request that came before is still answered. */
    close() {
      closeAll();
      return new Promise((resolve) => server.close(() => resolve()));
    },
    /** POST /stop: the answer goes out first, then the port closes. */
    stop() {
      closeAll();
      setTimeout(() => server.close(), 50);
    },
  };
}
