// The wire: one JSON-RPC message to a line, as the stdio transport of the
// Model Context Protocol frames it (specification 2026-07-28, "stdio":
// "Messages are delimited by newlines, and MUST NOT contain embedded
// newlines"). This file reads lines from a stream, reads each line strictly,
// and says what kind of message it is. It sends nothing and decides nothing.

/** The longest line the executor reads, in bytes: 16 MiB. A longer one is refused, or dropped, not read. */
export const MAX_LINE_BYTES = 16 * 1024 * 1024;

/** JSON-RPC error codes the executor itself answers with. The standard ones first; then its own, outside the reserved range (-32768 to -32000), as the specification asks. */
export const CODES = Object.freeze({
  parse: -32700,
  invalidRequest: -32600,
  invalidParams: -32602,
  // The executor's own: a receipt could not be written, so the call was not taken.
  notRecorded: 1001,
  // The tool server gave no answer within the time allowed, or ended before it answered.
  noAnswer: 1002,
});

/**
 * Split a readable stream into lines. Each whole line (without its line
 * feed, and without one carriage return before it) is handed to "onLine"
 * as a Buffer. A line longer than "limit" is handed to "onTooLong" once,
 * with its length so far, and the rest of it is dropped until its end.
 * "onEnd" is called when the stream ends, with any last bytes that had no
 * line feed (handed to "onLine" first, if there are any).
 */
export function readLines(stream, { onLine, onTooLong, onEnd, limit = MAX_LINE_BYTES }) {
  let pieces = [];
  let held = 0;
  let dropping = false;
  stream.on('data', (chunk) => {
    let start = 0;
    for (;;) {
      const at = chunk.indexOf(0x0a, start);
      if (at === -1) {
        const rest = chunk.subarray(start);
        if (dropping || rest.length === 0) break;
        held += rest.length;
        if (held > limit) {
          dropping = true;
          pieces = [];
          onTooLong(held);
          held = 0;
          break;
        }
        pieces.push(rest);
        break;
      }
      const piece = chunk.subarray(start, at);
      start = at + 1;
      if (dropping) {
        dropping = false;
        continue;
      }
      held += piece.length;
      if (held > limit) {
        pieces = [];
        onTooLong(held);
        held = 0;
        continue;
      }
      pieces.push(piece);
      let line = pieces.length === 1 ? pieces[0] : Buffer.concat(pieces);
      pieces = [];
      held = 0;
      if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      onLine(line);
    }
  });
  stream.on('end', () => {
    if (!dropping && pieces.length > 0) {
      let line = Buffer.concat(pieces);
      if (line.length > 0 && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      pieces = [];
      held = 0;
      onLine(line);
    }
    onEnd();
  });
  stream.on('error', () => onEnd());
}

/**
 * Names that some readers take as one: the same once put in small letters,
 * then capitals, then small letters again (so "ID" and "id", the long s
 * and "s", the Kelvin sign and "k"), as the gateway folds them.
 */
export function foldName(name) {
  return name.toLowerCase().toUpperCase().toLowerCase().replace(/i̇/g, 'i');
}

/**
 * The first member name given twice in one object of a JSON text, or null.
 * With "fold", two names that foldName makes one count as one name. The
 * text must already be known to be JSON (JSON.parse accepted it).
 */
export function repeatedName(text, fold = false) {
  const stack = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
      expectKey = false;
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack.at(-1) instanceof Set;
    } else if (c === ':') {
      expectKey = false;
    } else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        const names = stack.at(-1);
        const seen = fold ? foldName(key) : key;
        if (names.has(seen)) return key;
        names.add(seen);
        expectKey = false;
      }
      i = j;
    }
  }
  return null;
}

/** Whether a value is a JSON-RPC id: text, or a whole number (the specification: "a string or integer ID", never null). */
export function isId(value) {
  return typeof value === 'string' || (typeof value === 'number' && Number.isInteger(value));
}

/** One key for a Map, for an id of either kind, so that 1 and "1" stay apart. */
export function idKey(id) {
  return `${typeof id}:${id}`;
}

/**
 * Read one line as a JSON-RPC message, strictly. Gives
 * {kind, message, text} or {refused: {code, message}, id}: "kind" is
 * "request" (a method and an id), "notification" (a method and no id) or
 * "response" (a result or an error and an id). Refused: text that is not
 * UTF-8 or not JSON; a list (a batch could carry a tools/call past the
 * executor to a server that still reads batches); anything but an object
 * with "jsonrpc": "2.0"; a member name given twice anywhere in the message
 * (two readers may take the first or the last, so the method the executor
 * reads could differ from the one the server acts on); an id that is not
 * text or a whole number; a message that is neither request, notification
 * nor response.
 */
export function readMessage(line) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(line);
  } catch {
    return { refused: { code: CODES.parse, message: 'The line is not text in UTF-8.' }, id: null };
  }
  let message;
  try {
    message = JSON.parse(text);
  } catch {
    return { refused: { code: CODES.parse, message: 'The line is not JSON.' }, id: null };
  }
  if (Array.isArray(message)) return { refused: { code: CODES.invalidRequest, message: 'A list of messages (a batch) is not accepted: one message to a line.' }, id: null };
  if (!message || typeof message !== 'object') return { refused: { code: CODES.invalidRequest, message: 'A message is a JSON object.' }, id: null };
  const repeated = repeatedName(text);
  if (repeated !== null) return { refused: { code: CODES.invalidRequest, message: 'A member name is given twice in one object of the message, which two readers may read differently.' }, id: null };
  const id = Object.hasOwn(message, 'id') ? message.id : undefined;
  const knownId = isId(id) ? id : null;
  if (message.jsonrpc !== '2.0') return { refused: { code: CODES.invalidRequest, message: 'The message does not say "jsonrpc": "2.0".' }, id: knownId };
  if (id !== undefined && !isId(id)) return { refused: { code: CODES.invalidRequest, message: 'The id must be text or a whole number.' }, id: null };
  const hasMethod = Object.hasOwn(message, 'method');
  const hasResult = Object.hasOwn(message, 'result');
  const hasError = Object.hasOwn(message, 'error');
  if (hasMethod) {
    if (typeof message.method !== 'string') return { refused: { code: CODES.invalidRequest, message: 'The method must be text.' }, id: knownId };
    if (hasResult || hasError) return { refused: { code: CODES.invalidRequest, message: 'A message with a method carries no result or error.' }, id: knownId };
    if (Object.hasOwn(message, 'params') && (message.params === null || typeof message.params !== 'object' || Array.isArray(message.params))) {
      return { refused: { code: CODES.invalidRequest, message: 'The params must be an object.' }, id: knownId };
    }
    return { kind: id === undefined ? 'notification' : 'request', message, text };
  }
  if (id === undefined || hasResult === hasError) return { refused: { code: CODES.invalidRequest, message: 'A message is a request, a notification or a response.' }, id: knownId };
  return { kind: 'response', message, text };
}

/** A response, as one line with its line feed, as a Buffer. */
export function responseLine(id, body) {
  return Buffer.from(`${JSON.stringify({ jsonrpc: '2.0', id, ...body })}\n`);
}

/** A notification, as one line with its line feed, as a Buffer. */
export function notificationLine(method, params) {
  return Buffer.from(`${JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) })}\n`);
}
