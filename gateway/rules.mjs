// The rules file of the gateway: which call is which action.
//
// Everything here is plain work on text and numbers, with nothing sent
// anywhere: reading the settings, writing a call's address in the one form
// the gateway forwards, matching it to a rule, and working out its amount.
// The gateway (gateway.mjs) does the rest.
//
// Paths are matched by the WHATWG URL Pattern standard, which Node.js has
// built in (URLPattern, a global since Node.js 24). Amounts are read with
// JSON Pointer (RFC 6901).

import { actionKind } from 'provared';

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const UNIT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/;
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
/** A hash of a secret, as the settings hold it: SHA-256 in base64url, 43 characters. */
export const SECRET_HASH = /^[A-Za-z0-9_-]{43}$/;

/** The most a body may be, unless the settings say otherwise: 10 MB. */
export const BODY_LIMIT = 10 * 1024 * 1024;
/** How long an upstream is given to answer, unless the settings say otherwise: 30 seconds. */
export const TIMEOUT = 30000;

/**
 * The headers that carry a credential, removed from every call an agent
 * sends, whatever their case and however often they are given. The
 * settings may name more ("stripHeaders").
 */
export const CREDENTIAL_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'api-key', 'x-auth-token', 'x-access-token', 'private-token', 'x-goog-api-key', 'x-vault-token', 'x-amz-security-token', 'x-auth-key'];
/**
 * Headers with which some upstreams let a call say another method or
 * another address than the one it was sent with. Removed from every call, so
 * that the upstream acts on the method and the address the rule matched.
 */
export const OVERRIDE_HEADERS = ['x-http-method-override', 'x-http-method', 'x-method-override', 'x-original-url', 'x-rewrite-url'];
/** Query parameters that do the same: removed from the address of every call. */
export const OVERRIDE_PARAMETERS = ['_method'];
/**
 * Headers an agent could use to pose as another address or another client.
 * Never forwarded, with every header whose name begins "x-forwarded-".
 */
export const ADDRESS_HEADERS = ['forwarded', 'x-real-ip', 'via', 'true-client-ip', 'x-client-ip', 'x-cluster-client-ip', 'cf-connecting-ip', 'x-originating-ip'];
/** The tokens a call's own Connection header may hold. Any other is refused. */
export const CONNECTION_TOKENS = ['close', 'keep-alive'];
/** How many calls of one agent may wait at once, unless the settings say otherwise. */
export const WAITING_CALLS = 16;
/** How many bytes of bodies one agent's waiting calls may hold at once, unless the settings say otherwise: 32 MB. */
export const WAITING_BYTES = 32 * 1024 * 1024;
/**
 * The names of query parameters that carry a credential, removed from the
 * address of every call, whatever their case. The settings may name more
 * ("stripQuery").
 */
export const CREDENTIAL_PARAMETERS = ['access_token', 'api_key', 'apikey', 'api-key', 'token', 'auth', 'authorization', 'password', 'passwd', 'secret', 'client_secret'];

// Headers that belong to one connection only (RFC 9110, section 7.6.1), and
// those the gateway sets itself. Never forwarded.
export const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'expect', 'host', 'content-length'];

/** Whether a header of the agent's call is one that is never forwarded (not a credential). */
export function neverForwarded(name) {
  return HOP_BY_HOP.includes(name) || ADDRESS_HEADERS.includes(name) || name.startsWith('x-forwarded-');
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const wholeNumber = (v) => Number.isSafeInteger(v) && v >= 0;

// --- the settings ---

/**
 * Read the upstreams, the rules and the gateway-wide settings. Gives back
 * what was read, and every problem found, each in a plain sentence; nothing
 * is thrown for a problem in the settings themselves.
 * @param {object} config
 * @returns {{upstreams: Map<string, object>, rules: object[], unlisted: 'refuse'|'forward', bodyLimit: number, stripHeaders: string[], stripQuery: string[], problems: string[], warnings: string[]}}
 */
export function readRules(config) {
  const problems = [];
  const warnings = [];
  const upstreams = new Map();
  if (!isObject(config)) return { upstreams, rules: [], unlisted: 'refuse', bodyLimit: BODY_LIMIT, stripHeaders: CREDENTIAL_HEADERS, stripQuery: CREDENTIAL_PARAMETERS, problems: ['The settings are not a JSON object.'], warnings };

  const unlisted = config.unlisted ?? 'refuse';
  if (unlisted !== 'refuse' && unlisted !== 'forward') problems.push('"unlisted" must be "refuse" or "forward".');
  if (unlisted === 'forward') warnings.push('"unlisted" is "forward": a call that matches no rule is forwarded with no receipt. The record then leaves those calls out.');

  const bodyLimit = config.bodyLimit ?? BODY_LIMIT;
  if (!(Number.isSafeInteger(bodyLimit) && bodyLimit >= 0 && bodyLimit <= 100 * 1024 * 1024)) problems.push('"bodyLimit" must be a whole number of bytes from 0 to 104,857,600.');

  const names = (value, what, form, lower) => {
    if (value === undefined) return [];
    if (!Array.isArray(value) || !value.every((n) => typeof n === 'string' && form.test(n))) {
      problems.push(`"${what}" must be a list of names.`);
      return [];
    }
    return lower ? value.map((n) => n.toLowerCase()) : value;
  };
  const stripHeaders = [...new Set([...CREDENTIAL_HEADERS, ...names(config.stripHeaders, 'stripHeaders', HEADER, true)])];
  const stripQuery = [...new Set([...CREDENTIAL_PARAMETERS, ...OVERRIDE_PARAMETERS, ...names(config.stripQuery, 'stripQuery', /^[^&;=#]+$/, true)])];
  const waitingCalls = config.waitingCalls ?? WAITING_CALLS;
  if (!(Number.isSafeInteger(waitingCalls) && waitingCalls >= 1 && waitingCalls <= 1000)) problems.push('"waitingCalls" must be a whole number from 1 to 1,000.');
  const waitingBytes = config.waitingBytes ?? WAITING_BYTES;
  if (!(Number.isSafeInteger(waitingBytes) && waitingBytes >= 0 && waitingBytes <= 1024 * 1024 * 1024)) problems.push('"waitingBytes" must be a whole number of bytes from 0 to 1,073,741,824.');
  else if (waitingBytes < bodyLimit) warnings.push('"waitingBytes" is less than "bodyLimit", so a body of the largest size the gateway takes can never be held.');

  const timeout = config.timeout ?? TIMEOUT;
  if (!(Number.isSafeInteger(timeout) && timeout >= 1 && timeout <= 600000)) problems.push('"timeout" must be a whole number of milliseconds from 1 to 600,000.');

  if (!isObject(config.upstreams) || Object.keys(config.upstreams).length === 0) problems.push('"upstreams" must name at least one system behind the gateway.');
  for (const [name, u] of Object.entries(isObject(config.upstreams) ? config.upstreams : {})) {
    const at = `upstream "${name}"`;
    if (!NAME.test(name)) {
      problems.push(`${at}: its name must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.`);
      continue;
    }
    if (name === 'provared') {
      problems.push(`${at}: the name "provared" is kept for the gateway's own addresses (/provared/status).`);
      continue;
    }
    if (!isObject(u)) {
      problems.push(`${at}: must be an object.`);
      continue;
    }
    const known = ['base', 'service', 'credential', 'countersign', 'eventIdHeader', 'requestIdHeader', 'caseSensitive', 'semicolons', 'underscoreHeaders', 'timeout', 'stripHeaders', 'ca'];
    for (const k of Object.keys(u)) if (!known.includes(k)) problems.push(`${at}: "${k}" is not a setting the gateway knows.`);
    let base = null;
    try {
      base = new URL(u.base);
    } catch {
      problems.push(`${at}: "base" must be an http or https address.`);
    }
    if (base) {
      if (base.protocol !== 'http:' && base.protocol !== 'https:') problems.push(`${at}: "base" must be an http or https address.`);
      else if (base.username || base.password) problems.push(`${at}: "base" must not hold a user name or a password; name the credential in "credential".`);
      else if (base.search || base.hash) problems.push(`${at}: "base" must hold no query and no fragment.`);
      else if (base.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)) {
        warnings.push(`${at}: "base" is a plain http address, so the credential and every call cross the network unencrypted.`);
      }
    }
    if (u.service !== undefined && !(typeof u.service === 'string' && NAME.test(u.service))) problems.push(`${at}: "service" must be the id the slip gives the system (lower-case letters, digits, full stops, hyphens or underscores).`);
    let credential = null;
    if (u.credential !== undefined) {
      const c = u.credential;
      if (!isObject(c) || typeof c.header !== 'string' || !HEADER.test(c.header) || (c.file === undefined) === (c.env === undefined)) {
        problems.push(`${at}: "credential" must name a header and exactly one of "file" or "env".`);
      } else if ((c.file !== undefined && typeof c.file !== 'string') || (c.env !== undefined && typeof c.env !== 'string') || (c.prefix !== undefined && typeof c.prefix !== 'string')) {
        problems.push(`${at}: "credential": "file", "env" and "prefix" must be text.`);
      } else if (Object.keys(c).some((k) => !['header', 'file', 'env', 'prefix'].includes(k))) {
        problems.push(`${at}: "credential" holds a setting the gateway does not know.`);
      } else credential = { header: c.header.toLowerCase(), file: c.file, env: c.env, prefix: c.prefix ?? '' };
    }
    let countersign = null;
    if (u.countersign !== undefined) {
      if (typeof u.countersign !== 'string' || !u.countersign.startsWith('/') || u.countersign.startsWith('//') || /[?#\s]/.test(u.countersign)) {
        problems.push(`${at}: "countersign" must be a path on the upstream's own address, beginning "/", with no query.`);
      } else countersign = u.countersign;
    }
    for (const h of ['eventIdHeader', 'requestIdHeader']) {
      if (u[h] !== undefined && !(typeof u[h] === 'string' && HEADER.test(u[h]))) problems.push(`${at}: "${h}" must be the name of a header.`);
    }
    for (const k of ['caseSensitive', 'semicolons', 'underscoreHeaders']) if (u[k] !== undefined && typeof u[k] !== 'boolean') problems.push(`${at}: "${k}" must be true or false.`);
    if (u.semicolons === true) warnings.push(`${at}: "semicolons" is true: a ";" in a path is passed on, and the rules are matched on each segment without what follows its ";".`);
    const upTimeout = u.timeout ?? timeout;
    if (!(Number.isSafeInteger(upTimeout) && upTimeout >= 1 && upTimeout <= 600000)) problems.push(`${at}: "timeout" must be a whole number of milliseconds from 1 to 600,000.`);
    if (u.ca !== undefined && typeof u.ca !== 'string') problems.push(`${at}: "ca" must be the path of a file of certificates.`);
    upstreams.set(name, {
      name,
      base,
      basePath: base ? base.pathname.replace(/\/+$/, '') : '',
      service: u.service,
      credential,
      countersign,
      eventIdHeader: u.eventIdHeader?.toLowerCase?.(),
      requestIdHeader: u.requestIdHeader?.toLowerCase?.(),
      caseSensitive: u.caseSensitive === true,
      semicolons: u.semicolons === true,
      underscoreHeaders: u.underscoreHeaders === true,
      timeout: upTimeout,
      stripHeaders: [...new Set([...stripHeaders, ...names(u.stripHeaders, `${at}: stripHeaders`, HEADER, true)])],
      ca: u.ca,
    });
  }

  const rules = [];
  if (!Array.isArray(config.rules)) problems.push('"rules" must be a list.');
  const seen = new Set();
  for (const [i, r] of (Array.isArray(config.rules) ? config.rules : []).entries()) {
    const at = `rule ${i + 1}`;
    if (!isObject(r)) {
      problems.push(`${at}: must be an object.`);
      continue;
    }
    for (const k of Object.keys(r)) if (!['upstream', 'method', 'path', 'search', 'action', 'amount'].includes(k)) problems.push(`${at}: "${k}" is not a setting the gateway knows.`);
    const upstream = upstreams.get(r.upstream);
    if (!upstream) problems.push(`${at}: "upstream" must name one of the upstreams.`);
    if (typeof r.method !== 'string' || !TOKEN.test(r.method) || r.method !== r.method.toUpperCase()) problems.push(`${at}: "method" must be one method, in capitals, such as "GET".`);
    if (typeof r.path !== 'string' || !r.path.startsWith('/')) problems.push(`${at}: "path" must be a pattern that begins "/".`);
    if (r.search !== undefined && typeof r.search !== 'string') problems.push(`${at}: "search" must be a pattern for the query.`);
    if (typeof r.action !== 'string' || !NAME.test(r.action)) problems.push(`${at}: "action" must be an action name: 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.`);
    else if (r.action.startsWith('provared.') && actionKind(r.action) === null) problems.push(`${at}: "action": names that begin "provared." are reserved, and this one is not on the shared list.`);
    const amount = readAmount(r.amount, at, problems);
    let pattern = null;
    if (typeof r.path === 'string' && r.path.startsWith('/') && (r.search === undefined || typeof r.search === 'string')) {
      try {
        pattern = new URLPattern({ pathname: withoutTrailingSlash(r.path), ...(r.search !== undefined ? { search: r.search } : {}) }, { ignoreCase: !(upstream?.caseSensitive ?? false) });
      } catch (e) {
        problems.push(`${at}: "path" or "search" is not a URL Pattern: ${e.message}`);
      }
    }
    const key = JSON.stringify([r.upstream, r.method, r.path, r.search ?? null]);
    if (seen.has(key)) warnings.push(`${at}: the same upstream, method and pattern as an earlier rule, so it is never used: the first rule that matches wins.`);
    seen.add(key);
    rules.push({ index: i + 1, upstream: r.upstream, method: r.method, path: r.path, search: r.search, action: r.action, amount, pattern });
  }
  return { upstreams, rules, unlisted, bodyLimit, stripHeaders, stripQuery, timeout, waitingCalls, waitingBytes, problems, warnings };
}

function readAmount(a, at, problems) {
  if (a === undefined) return null;
  if (!isObject(a)) {
    problems.push(`${at}: "amount" must be an object.`);
    return null;
  }
  const forms = ['value', 'pointer', 'count'].filter((k) => Object.hasOwn(a, k));
  if (Object.keys(a).some((k) => !['unit', 'value', 'pointer', 'count'].includes(k)) || forms.length !== 1) {
    problems.push(`${at}: "amount" must hold "unit" and exactly one of "value", "pointer" or "count".`);
    return null;
  }
  if (typeof a.unit !== 'string' || !UNIT.test(a.unit)) {
    problems.push(`${at}: "amount": "unit" must be 1 to 16 letters, digits, full stops, hyphens or underscores, with no spaces.`);
    return null;
  }
  const form = forms[0];
  if (form === 'value') {
    if (!wholeNumber(a.value)) {
      problems.push(`${at}: "amount": "value" must be a whole number, 0 or more.`);
      return null;
    }
    return { unit: a.unit, value: a.value };
  }
  const tokens = pointerTokens(a[form]);
  if (!tokens) {
    problems.push(`${at}: "amount": "${form}" must be a JSON Pointer (RFC 6901), such as "/hosts".`);
    return null;
  }
  return { unit: a.unit, [form]: a[form], tokens };
}

// --- JSON Pointer (RFC 6901) ---

/** The reference tokens of a JSON Pointer, or null where it is not one. */
export function pointerTokens(pointer) {
  if (typeof pointer !== 'string') return null;
  if (pointer === '') return [];
  if (!pointer.startsWith('/')) return null;
  const tokens = [];
  for (const raw of pointer.slice(1).split('/')) {
    if (/~(?![01])/.test(raw)) return null;
    tokens.push(raw.replace(/~1/g, '/').replace(/~0/g, '~'));
  }
  return tokens;
}

/** What a JSON Pointer finds in a value: { found: true, value } or { found: false }. */
export function lookUp(value, tokens) {
  let here = value;
  for (const token of tokens) {
    if (Array.isArray(here)) {
      if (!/^(0|[1-9][0-9]*)$/.test(token) || Number(token) >= here.length) return { found: false };
      here = here[Number(token)];
    } else if (isObject(here)) {
      if (!Object.hasOwn(here, token)) return { found: false };
      here = here[token];
    } else return { found: false };
  }
  return { found: true, value: here };
}

/**
 * How a member name is compared with the others of its object: put in small
 * letters, then in capitals, then in small letters again. So two names that
 * differ only in capitals, or in letters that some readers of JSON take as
 * one (the long s and "s", the Kelvin sign and "k", the Greek final sigma and
 * sigma, the two forms of beta and of theta, the micro sign and mu, the
 * dotless i and "i", the dotted capital I and "i"), are taken as one name. This joins every pair that
 * Unicode's simple case folding joins, and some more (such as "ß" and "ss"):
 * where it joins more, it refuses more. Note that it joins names that mean
 * different things to their writer, such as "ID" and "id" in one object.
 */
export function foldName(name) {
  // The dotted capital I gives "i" and a combining dot above in small letters; the dot is dropped, so that it is "i".
  return name.toLowerCase().toUpperCase().toLowerCase().replace(/i\u0307/g, 'i');
}

/**
 * The first member name given twice in one object of a JSON text, or null.
 * Two readers may take a repeated name differently (the first, or the
 * last), and some readers take names whatever their case, so a body that
 * repeats a name, or gives two that are one name to such a reader
 * (foldName), anywhere in it, gives no amount. The text must already be
 * known to be JSON.
 */
export function repeatedName(text) {
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
        const folded = foldName(key);
        if (names.has(folded)) return key;
        names.add(folded);
        expectKey = false;
      }
      i = j;
    }
  }
  return null;
}

const JSON_TYPE = /^application\/(?:json|[!#$%&'*+\-.^_`|~0-9a-z]+\+json)$/;

/** The charset parameter of a media type, in small letters, or null where it has none. */
function charsetOf(type) {
  for (const part of type.split(';').slice(1)) {
    const at = part.indexOf('=');
    if (at === -1) continue;
    if (part.slice(0, at).trim().toLowerCase() !== 'charset') continue;
    let value = part.slice(at + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    return value.toLowerCase();
  }
  return null;
}

/**
 * The amount of a call, as its rule says: a fixed value, a whole number at a
 * JSON Pointer in the body, or the length of a list there.
 * @param {object|null} amount the rule's amount, as readRules gave it
 * @param {{body?: Uint8Array, contentType?: string[], contentEncoding?: string[]}} call
 * @returns {{amount?: {unit: string, value: number}, problem?: {code: string, message: string}}}
 */
export function amountOf(amount, call) {
  if (!amount) return {};
  if (Object.hasOwn(amount, 'value')) return { amount: { unit: amount.unit, value: amount.value } };
  const no = (message) => ({ problem: { code: 'amount-not-found', message: `${message} The rule takes the amount from the body, so the call was not taken.` } });
  if (!call.body) return no('The call has no body.');
  if (call.contentEncoding && call.contentEncoding.length > 0) return no('The body is sent with a content coding (Content-Encoding), which the gateway does not undo.');
  const types = call.contentType ?? [];
  if (types.length !== 1 || !JSON_TYPE.test(types[0].split(';')[0].trim().toLowerCase())) return no('The body is not marked as JSON: it needs exactly one Content-Type of application/json, or of a type that ends "+json".');
  const charset = charsetOf(types[0]);
  if (charset !== null && charset !== 'utf-8') return no('The body is marked as being in a character set other than UTF-8, which the gateway does not read.');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(call.body);
  } catch {
    return no('The body is not text in UTF-8.');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return no('The body is not JSON.');
  }
  if (repeatedName(text) !== null) return no('The body names one member twice in one object, or two that differ only in capitals, which two systems may read differently.');
  const at = amount.pointer ?? amount.count;
  const found = lookUp(value, amount.tokens);
  if (!found.found) return no(`Nothing is found in the body at ${JSON.stringify(at)}.`);
  if (Object.hasOwn(amount, 'count')) {
    if (!Array.isArray(found.value)) return no(`What is found at ${JSON.stringify(at)} is not a list.`);
    return { amount: { unit: amount.unit, value: found.value.length } };
  }
  if (!wholeNumber(found.value)) return no(`What is found at ${JSON.stringify(at)} is not a whole number from 0 up to 9,007,199,254,740,991.`);
  return { amount: { unit: amount.unit, value: found.value } };
}

// --- addresses ---

const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
const PATH_CHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;
const HEX2 = /^[0-9A-Fa-f]{2}$/;

function withoutTrailingSlash(path) {
  return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}

/**
 * The address of a call as the gateway reads it: which upstream, the rest
 * of the path in the one form the gateway forwards, the path the rules are
 * matched on, and the query.
 *
 * The path is written in one form so that the rule matched is the rule an
 * upstream acts on: a percent-encoded letter, digit or "-._~" is decoded,
 * and the other percent-encodings are written in capitals (RFC 3986,
 * section 6.2.2). What two systems may read in two ways is refused: an
 * encoded "/" or "\", a percent-encoding of a percent-encoding, an encoded
 * control character, encoded bytes that are not UTF-8 in its shortest form
 * (an "overlong" form), an encoded character that stands for "/", "\", ".",
 * ";" or "%" once its letters are folded (a full-width "/" or "."), "." and
 * ".." segments (written plainly or encoded), two "/" together, and any
 * character a path may not hold.
 *
 * A ";" (or %3B) is refused, unless the upstream allows it ("semicolons"):
 * many servers set aside what follows a ";" in a segment before they route
 * the call. Where it is allowed, the rules are matched on each segment
 * without what follows its first ";", and that part may not be empty, "."
 * or "..".
 * @param {string} target the request target, as the agent sent it
 * @param {(upstream: string) => boolean} [semicolons] whether that upstream allows ";"
 * @returns {{upstream?: string, rest?: string, match?: string, query?: string|null, problem?: {code: string, message: string}}}
 */
export function readTarget(target, semicolons = () => false) {
  const no = (message) => ({ problem: { code: 'address-refused', message } });
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) {
    return no('The address must be a path on the gateway, beginning with "/" and the name of an upstream.');
  }
  if (target.includes('#')) return no('The address holds a fragment ("#"), which is never sent.');
  const q = target.indexOf('?');
  const rawPath = q === -1 ? target : target.slice(0, q);
  const query = q === -1 ? null : target.slice(q + 1);
  let path = '';
  for (let i = 0; i < rawPath.length; i++) {
    const c = rawPath[i];
    if (c === '/') {
      path += c;
      continue;
    }
    if (c === '%') {
      const hex = rawPath.slice(i + 1, i + 3);
      if (!HEX2.test(hex)) return no('The path holds a "%" that is not followed by two hexadecimal digits.');
      const byte = parseInt(hex, 16);
      if (byte >= 0x80) {
        // A run of encoded bytes outside ASCII: it must be UTF-8 in its shortest form.
        const bytes = [];
        let j = i;
        while (rawPath[j] === '%' && HEX2.test(rawPath.slice(j + 1, j + 3)) && parseInt(rawPath.slice(j + 1, j + 3), 16) >= 0x80) {
          bytes.push(parseInt(rawPath.slice(j + 1, j + 3), 16));
          j += 3;
        }
        let text;
        try {
          text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(new Uint8Array(bytes));
        } catch {
          return no('The path holds encoded bytes that are not UTF-8 in its shortest form, which upstreams read in different ways.');
        }
        // A character that some systems fold into another (a full-width "/" or "_", the Kelvin sign) could reach a rule as one
        // thing and the upstream as another; so could a run that begins with a combining mark, which joins the character before it.
        if (/^\p{M}/u.test(text) || text.normalize('NFKC') !== text) return no('The path holds encoded characters that some systems read as others (a combining mark, a full-width form, or a sign such as the Kelvin sign), which upstreams read in different ways.');
        path += rawPath.slice(i, j).toUpperCase();
        i = j - 1;
        continue;
      }
      const ch = String.fromCharCode(byte);
      if (byte === 0x2f || byte === 0x5c) return no('The path holds an encoded "/" or "\\" (%2F or %5C), which upstreams read in different ways.');
      if (byte < 0x20 || byte === 0x7f) return no('The path holds an encoded control character.');
      if (byte === 0x25 && HEX2.test(rawPath.slice(i + 3, i + 5))) return no('The path holds a percent-encoding of a percent-encoding (such as %252F), which an upstream may decode twice.');
      path += UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
      i += 2;
      continue;
    }
    if (!PATH_CHAR.test(c)) return no('The path holds a character a path may not hold; write it percent-encoded.');
    path += c;
  }
  const segments = path.split('/');
  const upstream = segments[1];
  if (!upstream) return no('The address must begin with the name of an upstream, as in /name/path.');
  if (segments.some((s) => s.includes(';') || s.includes('%3B')) && !semicolons(upstream)) {
    return no('The path holds a ";" (or %3B), which many servers read as the start of parameters they set aside before routing. This upstream does not allow it ("semicolons").');
  }
  // What each segment is to a server that sets aside what follows its ";".
  const routed = segments.map((s) => s.split(/;|%3B/)[0]);
  for (let i = 1; i < segments.length; i++) {
    const s = routed[i];
    if (s === '' && (i < segments.length - 1 || segments[i] !== '')) return no('The path holds two "/" together, or a segment with nothing before its ";", which upstreams read in different ways.');
    if (s === '.' || s === '..') return no('The path holds a "." or ".." segment, which upstreams read in different ways.');
  }
  const rest = segments.length <= 2 ? '/' : `/${segments.slice(2).join('/')}`;
  const match = segments.length <= 2 ? '/' : `/${routed.slice(2).join('/')}`;
  return { upstream, rest, match, query };
}

/**
 * The query without the parameters named (those that carry a credential, and
 * those that change a call's method). A parameter is taken by its name
 * decoded ("+" as a space), without anything from its first "[" on, without
 * control characters, with no spaces at its ends, in small letters; the
 * parts of the query are told apart by "&" and by ";". Where none is
 * removed, the query is given back exactly as it was sent.
 * @returns {{query: string|null, removed: string[]}}
 */
export function stripParameters(query, names) {
  if (query === null || query === '') return { query, removed: [] };
  const pieces = query.split(/([&;])/);
  const removed = [];
  const kept = [];
  for (let i = 0; i < pieces.length; i += 2) {
    const part = pieces[i];
    const raw = part.split('=')[0].replace(/\+/g, ' ');
    let name;
    try {
      name = decodeURIComponent(raw);
    } catch {
      name = raw;
    }
    name = name.split('[')[0].replace(/[\u0000-\u001f\u007f]/g, '').trim().toLowerCase();
    if (names.includes(name)) removed.push(name);
    else kept.push(kept.length === 0 ? part : `${pieces[i - 1]}${part}`);
  }
  if (removed.length === 0) return { query, removed };
  const rebuilt = kept.join('');
  return { query: rebuilt.length ? rebuilt : null, removed: [...new Set(removed)] };
}

/**
 * The first rule that matches a call, or null.
 * @param {object[]} rules as readRules gave them
 * @param {{upstream: string, method: string, rest: string, query: string|null}} call "rest": the path the rules are matched on
 */
export function matchRule(rules, call) {
  const pathname = withoutTrailingSlash(call.rest);
  const search = call.query ?? '';
  for (const rule of rules) {
    if (!rule.pattern || rule.upstream !== call.upstream || rule.method !== call.method) continue;
    if (rule.pattern.test({ pathname, search })) return rule;
  }
  return null;
}

/** The address the gateway sends a call to. */
export function upstreamAddress(upstream, rest, query) {
  return `${upstream.base.origin}${upstream.basePath}${rest}${query === null ? '' : `?${query}`}`;
}
