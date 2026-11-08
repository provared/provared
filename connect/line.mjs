// The connection line: one line a person copies from a book's page on the
// application and runs on the agent's computer, and the recorder beside the
// agent is connected to that book. No file is saved or moved by the person.
//
// THE LINE IS THE SECRET. It holds the key that opens the book and the
// capability that adds to it: whoever holds the line can read the book and
// add to it, as whoever holds the connection file can. It is to be kept as
// a password is. Nothing here is new cryptography: the line is the same
// fields the connection file holds, written as text.
//
// THE FORMAT, version 1:
//
//   provared-connect:1:<base64url of the JSON>
//
// The prefix "provared-connect:" names what the line is. The number after
// it is the version of the format; a reader refuses a version it does not
// know. The rest is base64url, with no padding, of one JSON object with
// exactly these fields, every one a non-empty string:
//
//   version                1, the same as in the prefix
//   server                 the application's WebSocket address (ws:// or wss://), with no user name or password in it
//   origin                 the page's address (http:// or https://), sent when the uploader signs in
//   namespace              the engine's namespace the sealing is bound to ("provared-app")
//   objectId               the book's id, a UUID
//   kObject                the key that opens the book, base64url
//   appendCapabilitySecret the capability that adds lines to the book, base64url
//
// Written to a file, the same fields with "about" added give the connection
// file the uploader has always read, so a saved line and a saved file are
// one thing.
//
// A REFUSAL NAMES NO VALUE FROM THE LINE: not a secret, not the book's id,
// not a field name the line brought, not the version it claims. A line put
// somewhere for a person to paste could otherwise print what it liked into
// their terminal or a log. The field names in the messages are this file's
// own.

export const LINE_PREFIX = 'provared-connect:';
export const LINE_VERSION = 1;
export const FIELDS = Object.freeze(['server', 'origin', 'namespace', 'objectId', 'kObject', 'appendCapabilitySecret']);
export const ABOUT = 'A connection for the uploader beside a Provared recorder. It holds the key to one book: never share it.';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const NAMESPACE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const COPY_AGAIN = `copy the whole line from the book's page on the application, from "${LINE_PREFIX}" to its end, and run the command again.`;

function refuse(message, code = 'bad-line') {
  return Object.assign(new Error(message), { code });
}

/**
 * Checks the fields of a connection, from a line or from a file: every one a
 * non-empty string of the right shape, and no field this version does not
 * know. Gives back the connection with only these fields (and "about" and
 * "version"), or throws with code "bad-connection" and a sentence saying
 * what is wrong, naming no value from it.
 */
export function checkConnection(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw refuse('The connection is not an object.', 'bad-connection');
  if ('version' in c && c.version !== LINE_VERSION) throw refuse('The connection is of a version this package does not know.', 'bad-connection');
  for (const k of FIELDS) {
    if (typeof c[k] !== 'string' || !c[k]) throw refuse(`The connection has no "${k}".`, 'bad-connection');
  }
  for (const k of Object.keys(c)) {
    if (k !== 'about' && k !== 'version' && !FIELDS.includes(k)) throw refuse('The connection has a field this version does not know.', 'bad-connection');
  }
  let server;
  try { server = new URL(c.server); } catch { throw refuse('The connection\'s "server" is not an address.', 'bad-connection'); }
  if (server.protocol !== 'ws:' && server.protocol !== 'wss:') throw refuse('The connection\'s "server" is not a WebSocket address (ws:// or wss://).', 'bad-connection');
  if (server.username || server.password) throw refuse('The connection\'s "server" carries a user name or a password, which it must not.', 'bad-connection');
  let origin;
  try { origin = new URL(c.origin); } catch { throw refuse('The connection\'s "origin" is not an address.', 'bad-connection'); }
  if ((origin.protocol !== 'http:' && origin.protocol !== 'https:') || origin.origin !== c.origin) throw refuse('The connection\'s "origin" is not a page\'s address (http:// or https://, with nothing after the host and port).', 'bad-connection');
  if (!NAMESPACE.test(c.namespace)) throw refuse('The connection\'s "namespace" is not a name.', 'bad-connection');
  if (!UUID.test(c.objectId)) throw refuse('The connection\'s "objectId" is not a book\'s id.', 'bad-connection');
  for (const k of ['kObject', 'appendCapabilitySecret']) {
    if (!BASE64URL.test(c[k]) || c[k].length < 22 || c[k].length > 128) throw refuse(`The connection's "${k}" is not a key.`, 'bad-connection');
  }
  const out = { about: ABOUT, version: LINE_VERSION };
  for (const k of FIELDS) out[k] = c[k];
  return out;
}

/** The line for a connection (the fields above; "about" is not carried). */
export function encodeLine(connection) {
  const c = checkConnection(connection);
  const body = { version: LINE_VERSION };
  for (const k of FIELDS) body[k] = c[k];
  return `${LINE_PREFIX}${LINE_VERSION}:${Buffer.from(JSON.stringify(body), 'utf8').toString('base64url')}`;
}

/**
 * Reads a line into a connection, as checkConnection gives it. Throws with
 * code "bad-line" (not a line, or a badly copied one), "newer-line" (a
 * version this package does not know) or "bad-connection" (a field wrong),
 * each with one sentence saying what to do, naming no value from the line.
 */
export function decodeLine(text) {
  const line = typeof text === 'string' ? text.trim() : '';
  if (!line.startsWith(LINE_PREFIX)) throw refuse(`That is not a connection line: ${COPY_AGAIN}`);
  const rest = line.slice(LINE_PREFIX.length);
  const colon = rest.indexOf(':');
  if (colon < 1) throw refuse(`That is not a connection line: ${COPY_AGAIN}`);
  const version = rest.slice(0, colon);
  const body = rest.slice(colon + 1);
  if (!/^[1-9][0-9]*$/.test(version)) throw refuse(`That is not a connection line: ${COPY_AGAIN}`);
  if (version !== String(LINE_VERSION)) throw refuse('This line was made for a newer version of provared-connect: run it with "npx provared-connect@latest" instead.', 'newer-line');
  if (!body || !BASE64URL.test(body)) throw refuse(`That is not a whole connection line: ${COPY_AGAIN}`);
  let parsed;
  try { parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { throw refuse(`That is not a whole connection line: ${COPY_AGAIN}`); }
  if (!parsed || typeof parsed !== 'object' || parsed.version !== LINE_VERSION) throw refuse(`That is not a whole connection line: ${COPY_AGAIN}`);
  let c;
  try { c = checkConnection(parsed); } catch (e) {
    const detail = e.message.replace(/\.$/, '').replace(/^The/, 'the');
    throw refuse(`That is not a whole connection line (${detail}): ${COPY_AGAIN}`);
  }
  return c;
}

/** Whether two connections name the same book under the same key, at the same server. */
export function sameConnection(a, b) {
  return Boolean(a && b) && FIELDS.every((k) => a[k] === b[k]);
}
