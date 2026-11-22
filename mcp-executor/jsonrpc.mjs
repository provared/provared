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
  methodNotFound: -32601,
  invalidParams: -32602,
  // The server's list of tools could not be read, so it was not handed on.
  internal: -32603,
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
 * and "s", the Kelvin sign and "k"), as the gateway folds them. This is
 * wider than capitals alone: it also makes one of the sharp s and "ss", of
 * the dotless i, the dotted capital I and "i", and of the ligatures (ff, fi,
 * fl, ffi, ffl, st) and their letters. It errs on the side of refusing.
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

/**
 * The first name of an object that is not one of "names" as written, yet
 * is one of them once folded (foldName): "Name" or "NAME" for "name". Null
 * where there is none. A reader that ignores capitals would take such a
 * member for the one the executor reads, and the executor would not.
 */
export function misspelt(object, names) {
  const folded = new Set(names.map(foldName));
  for (const key of Object.keys(object)) {
    if (!names.includes(key) && folded.has(foldName(key))) return key;
  }
  return null;
}

/**
 * The first member name that, once folded (foldName), is given twice in
 * one object within the value of the top-level "params" of a JSON object
 * text, or null. It walks the text as it came and calls nothing that calls
 * itself, so that no depth of nesting can overflow the stack. The text must
 * already be known to be JSON with no name given twice exactly.
 */
export function foldedInParams(text) {
  const stack = [];
  let expectKey = false;
  let inside = false;
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
        if (stack.length === 1) inside = key === 'params';
        else if (inside) {
          const names = stack.at(-1);
          const seen = foldName(key);
          if (names.has(seen)) return key;
          names.add(seen);
        }
        expectKey = false;
      }
      i = j;
    }
  }
  return null;
}

/** The members of a JSON-RPC message. A message with any other member at its top level is refused. */
const MEMBERS = new Set(['jsonrpc', 'id', 'method', 'params', 'result', 'error']);

/** The members of "params" that the executor itself reads, by method: each must be spelt exactly. */
const READ_IN_PARAMS = new Map([
  ['tools/call', ['name', 'arguments', '_meta']],
  ['notifications/cancelled', ['requestId']],
]);

/** The methods the executor itself acts on (a call it checks, a list it filters, a session it begins, a cancellation it renames). A method of the agent's that is one of them once folded (foldName), and is not written so, is refused: a server that reads a method without regard to capitals would act on it, and the executor would pass it by (X253). */
const READ_METHODS = ['tools/call', 'tools/list', 'initialize', 'notifications/cancelled'];

const SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * The first whole-number literal in a JSON text that lies outside what every
 * reader holds exactly (beyond 2^53 - 1 either way), or null. Two readers
 * would hold such a number differently (as a float, as a big integer, or
 * refused), so the executor refuses the line. The text must already be
 * known to be JSON.
 */
export function unsafeInteger(text) {
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      i = j;
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1;
      while (j < text.length && /[0-9.eE+-]/.test(text[j])) j++;
      const token = text.slice(i, j);
      if (/^-?[0-9]+$/.test(token)) {
        const magnitude = BigInt(token.startsWith('-') ? token.slice(1) : token);
        if (magnitude > SAFE) return token;
      }
      i = j - 1;
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
 * nor response; a member at the top level other than "jsonrpc", "id",
 * "method", "params", "result" and "error" (a reader that ignores capitals
 * takes "Method" for "method", so a message with both, or with "Method"
 * beside a result, is one message to the executor and another to such a
 * reader). With "strictNumbers" (the default, for the agent's lines) three
 * more are refused: a whole number beyond 2^53 - 1 anywhere in the line;
 * "params" that hold, in one object at any depth, two names that are one
 * once folded (foldName); and, in the "params" of a tools/call or of a
 * notifications/cancelled, a name that is one of those the executor reads
 * once folded but is not written as the executor reads it ("Arguments").
 * The server's lines are read without those three, and handed on as raw
 * bytes. "elements" is the most elements a message may hold (MAX_ELEMENTS
 * for the agent's lines, by default; no limit with "strictNumbers" false):
 * a message past it is refused before it is read.
 */
export function readMessage(line, options) {
  try {
    return readStrictly(line, options);
  } catch {
    // No line is known to reach this. It is here so that no line, whatever it holds, can end the executor from where its lines are read.
    return { refused: { code: CODES.invalidRequest, message: 'The message could not be read.' }, id: null };
  }
}

/**
 * The most levels of nesting, of objects and lists together, in a message
 * the executor reads: the message itself is the first. A deeper message is
 * refused where the agent sent it, and is a line the executor cannot read
 * where the server did.
 */
export const MAX_DEPTH = 256;

/**
 * The most elements, list items and member names together at every depth,
 * in one message of an agent's. A message of many small elements costs far
 * more memory once read than its bytes, so the count is taken from the
 * text, before it is read. 100,000 is well past what a tool's arguments
 * hold, and keeps what one message can cost when read to a few tens of MiB.
 * A server's message is not held to it: a list a server gives may be long.
 */
export const MAX_ELEMENTS = 100_000;

/**
 * One walk of a text: whether it is nested more than "depth" levels deep,
 * and whether it holds more than "elements" elements (each item of a list
 * and each member name of an object, at every depth), {deep, many}: it
 * stops at the first of the two limits it passes. It calls nothing
 * that calls itself, and stops at the end of the text whatever the text
 * is, so it may be given a text not yet known to be JSON; the answer is
 * then of no meaning, but it comes.
 */
export function walkText(text, { depth: maxDepth = Infinity, elements: maxElements = Infinity } = {}) {
  let depth = 0;
  let elements = 0;
  // Just after "[" or "{": the next value or name, if any, is the first of its list or object.
  let fresh = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') continue;
    if (fresh && c !== ']' && c !== '}') elements += 1;
    fresh = false;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      i = j;
    } else if (c === '{' || c === '[') {
      depth += 1;
      fresh = true;
      if (depth > maxDepth) return { deep: true, many: false };
    } else if (c === '}' || c === ']') depth -= 1;
    else if (c === ',' && depth > 0) elements += 1;
    if (elements > maxElements) return { deep: false, many: true };
  }
  return { deep: false, many: false };
}

/** Whether a JSON text is nested more than "limit" levels deep. It walks the text and calls nothing that calls itself. */
export function deeperThan(text, limit) {
  return walkText(text, { depth: limit }).deep;
}

/** The id a refusal may be answered under: the top-level "id" of the text, where it is there once, is text or a whole number, and is a number every reader holds exactly; else null. */
function answerableId(text) {
  const at = topLevelId(text);
  if (!at || !isId(at.value) || unsafeInteger(text.slice(at.start, at.end)) !== null) return null;
  return at.value;
}

function readStrictly(line, { strictNumbers = true, elements = strictNumbers ? MAX_ELEMENTS : Infinity } = {}) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(line);
  } catch {
    return { refused: { code: CODES.parse, message: 'The line is not text in UTF-8.' }, id: null };
  }
  // One walk of the text, before it is read: a message nested too deeply, or of too many elements, is refused before anything of it is built. Nothing after this point, here or in what uses the message, has to walk a value deeper than MAX_DEPTH: much that walks a value calls itself once for each level, and would overflow the stack.
  const walked = walkText(text, { depth: MAX_DEPTH, elements });
  if (walked.deep) return { refused: { code: CODES.invalidRequest, message: `The message is nested more than ${MAX_DEPTH} levels deep, which the executor does not read.` }, id: answerableId(text) };
  if (walked.many) return { refused: { code: CODES.invalidRequest, message: `The message holds more than ${elements.toLocaleString('en-GB')} elements (list items and member names together), which the executor does not read.` }, id: answerableId(text) };
  let message;
  try {
    message = JSON.parse(text);
  } catch {
    return { refused: { code: CODES.parse, message: 'The line is not JSON.' }, id: null };
  }
  if (Array.isArray(message)) return { refused: { code: CODES.invalidRequest, message: 'A list of messages (a batch) is not accepted: one message to a line.' }, id: null };
  if (!message || typeof message !== 'object') return { refused: { code: CODES.invalidRequest, message: 'A message is a JSON object.' }, id: null };
  const repeated = repeatedName(text);
  // These two refusals name the request where its id can be found, so that a client is not left waiting for an answer.
  if (repeated !== null) return { refused: { code: CODES.invalidRequest, message: 'A member name is given twice in one object of the message, which two readers may read differently.' }, id: answerableId(text) };
  if (strictNumbers && unsafeInteger(text) !== null) return { refused: { code: CODES.invalidRequest, message: 'The message holds a whole number beyond 9,007,199,254,740,991, which two readers may hold differently.' }, id: answerableId(text) };
  const id = Object.hasOwn(message, 'id') ? message.id : undefined;
  const knownId = isId(id) ? id : null;
  if (Object.keys(message).some((name) => !MEMBERS.has(name))) return { refused: { code: CODES.invalidRequest, message: 'The message has a member at its top level other than "jsonrpc", "id", "method", "params", "result" and "error", written exactly so. A reader that ignores capitals may take such a member for one of them, so the message is not read.' }, id: knownId };
  if (strictNumbers && message.params !== null && typeof message.params === 'object' && !Array.isArray(message.params)) {
    // The text is walked as it came, and not written afresh, so that no depth of nesting can overflow the stack.
    if (foldedInParams(text) !== null) return { refused: { code: CODES.invalidRequest, message: 'The params hold two member names in one object that differ only in capitals, or in letters that some readers take as the same, which two readers may read differently.' }, id: knownId };
    const read = READ_IN_PARAMS.get(message.method);
    if (read && misspelt(message.params, read) !== null) return { refused: { code: CODES.invalidRequest, message: `The params hold a member whose name differs only in capitals, or in letters that some readers take as the same, from one the executor reads (${read.join(', ')}), which two readers may read differently.` }, id: knownId };
  }
  if (message.jsonrpc !== '2.0') return { refused: { code: CODES.invalidRequest, message: 'The message does not say "jsonrpc": "2.0".' }, id: knownId };
  if (id !== undefined && !isId(id)) return { refused: { code: CODES.invalidRequest, message: 'The id must be text or a whole number.' }, id: null };
  const hasMethod = Object.hasOwn(message, 'method');
  const hasResult = Object.hasOwn(message, 'result');
  const hasError = Object.hasOwn(message, 'error');
  if (hasMethod) {
    if (typeof message.method !== 'string') return { refused: { code: CODES.invalidRequest, message: 'The method must be text.' }, id: knownId };
    if (hasResult || hasError) return { refused: { code: CODES.invalidRequest, message: 'A message with a method carries no result or error.' }, id: knownId };
    if (strictNumbers && misspelt({ [message.method]: true }, READ_METHODS) !== null) return { refused: { code: CODES.invalidRequest, message: `The method differs only in capitals, or in letters that some readers take as the same, from one the executor acts on (${READ_METHODS.join(', ')}), which two readers may read differently.` }, id: knownId };
    if (Object.hasOwn(message, 'params') && (message.params === null || typeof message.params !== 'object' || Array.isArray(message.params))) {
      return { refused: { code: CODES.invalidRequest, message: 'The params must be an object.' }, id: knownId };
    }
    return { kind: id === undefined ? 'notification' : 'request', message, text };
  }
  if (id === undefined || hasResult === hasError) return { refused: { code: CODES.invalidRequest, message: 'A message is a request, a notification or a response.' }, id: knownId };
  return { kind: 'response', message, text };
}

/**
 * Whether a text is a JSON-RPC error answer and nothing more: one object
 * whose members are "jsonrpc" ("2.0"), "id" (text, a whole number or null)
 * and "error" (an object with a whole number "code" and a text "message"),
 * each once and written exactly so, nested no deeper than MAX_DEPTH and
 * with no member name given twice at any depth. Such a text has no
 * "result", under any spelling, for any reader. readMessage refuses the
 * null id, which a server uses to refuse a request it could not read.
 */
export function errorAnswer(text) {
  try {
    if (typeof text !== 'string') return false;
    const message = JSON.parse(text);
    if (!message || typeof message !== 'object' || Array.isArray(message)) return false;
    if (deeperThan(text, MAX_DEPTH) || repeatedName(text) !== null) return false;
    const names = Object.keys(message);
    if (names.length !== 3 || !['jsonrpc', 'id', 'error'].every((name) => Object.hasOwn(message, name))) return false;
    if (message.jsonrpc !== '2.0' || !(message.id === null || isId(message.id))) return false;
    const error = message.error;
    return error !== null && typeof error === 'object' && !Array.isArray(error) && Number.isInteger(error.code) && typeof error.message === 'string';
  } catch {
    return false;
  }
}

/**
 * The span of the value of the top-level "id" member of a JSON object text:
 * {start, end, value} (value as JSON.parse reads it), or null where the text
 * does not begin with an object or has no top-level "id". It walks the text
 * once, skipping strings and nested values, so it works on a line that
 * JSON.parse would refuse elsewhere (a repeated name deeper in). A text
 * with "id" more than once at the top level gives null: two readers could
 * take either, so the executor matches it with nothing.
 */
export function topLevelId(text) {
  let i = 0;
  while (i < text.length && ' \t\r\n'.includes(text[i])) i++;
  if (text[i] !== '{') return null;
  i++;
  const skipSpace = () => {
    while (i < text.length && ' \t\r\n'.includes(text[i])) i++;
  };
  const stringEnd = (from) => {
    let j = from + 1;
    while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
    return j + 1;
  };
  const valueEnd = (from) => {
    const c = text[from];
    if (c === '"') return stringEnd(from);
    if (c === '{' || c === '[') {
      let depth = 0;
      let j = from;
      while (j < text.length) {
        const d = text[j];
        if (d === '"') j = stringEnd(j);
        else {
          if (d === '{' || d === '[') depth++;
          else if (d === '}' || d === ']') {
            depth--;
            if (depth === 0) return j + 1;
          }
          j++;
        }
      }
      return j;
    }
    let j = from;
    while (j < text.length && !',}] \t\r\n'.includes(text[j])) j++;
    return j;
  };
  let found = null;
  for (;;) {
    skipSpace();
    if (text[i] === '}' || i >= text.length) return found;
    if (text[i] !== '"') return null;
    const keyEnd = stringEnd(i);
    let key;
    try {
      key = JSON.parse(text.slice(i, keyEnd));
    } catch {
      return null;
    }
    i = keyEnd;
    skipSpace();
    if (text[i] !== ':') return null;
    i++;
    skipSpace();
    const start = i;
    const end = valueEnd(start);
    if (key === 'id') {
      if (found) return null;
      let value;
      try {
        value = JSON.parse(text.slice(start, end));
      } catch {
        return null;
      }
      found = { start, end, value };
    }
    i = end;
    skipSpace();
    if (text[i] === ',') i++;
    else if (text[i] === '}') return found;
    else return null;
  }
}

/**
 * The text with its top-level "id" value replaced by "newId", and nothing
 * else changed: numbers and spellings elsewhere survive as the sender wrote
 * them. Null where the text has no top-level "id".
 */
export function spliceId(text, newId) {
  const at = topLevelId(text);
  if (!at) return null;
  return `${text.slice(0, at.start)}${JSON.stringify(newId)}${text.slice(at.end)}`;
}

/**
 * The text of a JSON message, made one line for a reader that takes the
 * bytes as UTF-8, and still the same JSON. (A reader that takes them as
 * another encoding may still cut a line inside a character beyond ASCII:
 * inside a text, so it can spoil a message and cannot hide a call.) A line feed or a carriage return between
 * its values (in JSON they can stand nowhere else) becomes a space; U+0085,
 * U+2028 and U+2029 (in JSON they can stand only inside a text) are
 * written as the escapes \u0085, \u2028 and \u2029. The text must already
 * be known to be JSON. Why: a tool server that ends a line at more than
 * the line feed (node:readline ends one at a bare carriage return, U+2028
 * and U+2029) would cut one message into several, and read a piece of it
 * as a message of its own.
 */
export function oneLine(text) {
  if (!/[\n\r\u0085\u2028\u2029]/.test(text)) return text;
  return text.replace(/[\n\r]/g, ' ').replace(/[\u0085\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** A response, as the text of one message (no line feed). */
export function responseText(id, body) {
  return JSON.stringify({ jsonrpc: '2.0', id, ...body });
}

/** A response, as one line with its line feed, as a Buffer. */
export function responseLine(id, body) {
  return Buffer.from(`${responseText(id, body)}\n`);
}

/** A notification, as one line with its line feed, as a Buffer. */
export function notificationLine(method, params) {
  return Buffer.from(`${JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) })}\n`);
}
