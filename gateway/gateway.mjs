// provared-gateway: a reverse proxy that writes the receipts.
//
// It sits in front of the web interfaces an agent acts through. Each agent
// signs in to the gateway with a secret of its own; the gateway holds the
// agent's keys and each upstream's credential, asks the check before acting
// of the agent's stub writer, forwards the call, and writes the receipt. The
// agent holds neither the keys nor the credentials.
//
// This is the gateway's record: what the agent asked for through it, and what
// it did with the call. It proves nothing about calls that do not go through
// it.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, statSync, writeFileSync, writeSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  actionKind,
  checkBook,
  denialCodes,
  entryLine,
  httpRequestFingerprint,
  httpResponseFingerprint,
  identifierFingerprint,
  keySetFingerprint,
  openRecorder,
  randomId,
  sha256,
  toBase64url,
  utf8,
  writeSeal,
} from 'provared';
import { aboutSlip, bookFile, loadKeyFile, readIfThere, replaceFile, slipFrom, untilFree } from './files.mjs';
import { CONNECTION_TOKENS, HOP_BY_HOP, OVERRIDE_HEADERS, SECRET_HASH, amountOf, matchRule, neverForwarded, readRules, readTarget, stripParameters, upstreamAddress } from './rules.mjs';

/** The action name a denial gives a call that matched no rule. */
export const UNLISTED_ACTION = 'gateway.unlisted';
/**
 * A document a stub names, beside "provared.error", where the call is known
 * never to have reached the upstream: no connection to it was made. A label,
 * not one of the format's reserved names; its fingerprint is that of the
 * error text, as for "provared.error".
 */
export const NOT_DELIVERED = 'gateway.not-delivered';
/**
 * A document every stub of a call names: its fingerprint is that of the
 * call's own identifier, the one its line in the journal holds. So a start
 * can tell which calls of the journal the book already holds. A label, not
 * one of the format's reserved names.
 */
export const CALL_DOCUMENT = 'gateway.call';
/** The error text of a stub written for a call whose outcome the gateway never learnt, because it stopped. */
export const OUTCOME_UNKNOWN = 'The gateway stopped while this call was with the upstream, so its outcome is not known. The administrator acknowledged it after the gateway started again.';
const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const TRACEPARENT = /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/;
const ANSWER_HOP = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'trailer', 'te', 'set-cookie', 'content-length'];

/** SHA-256 of a secret, in base64url: the form the settings hold. */
export async function secretHash(secret) {
  return toBase64url(await sha256(utf8(secret)));
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function defaultLog(event) {
  process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`);
}

// --- reading what the settings point at ---

function pathFrom(root, p) {
  return isAbsolute(p) ? p : resolve(root, p);
}

/** The credential an upstream is given, read once, at start. Never logged. */
function readCredential(upstream, root) {
  const c = upstream.credential;
  if (!c) return null;
  let secret;
  if (c.file !== undefined) {
    try {
      secret = readFileSync(pathFrom(root, c.file), 'utf8');
    } catch (e) {
      throw new Error(`upstream "${upstream.name}": the credential file could not be read (${e.code ?? 'error'}).`);
    }
    // One line ending is allowed at the end of the file: a file written by a shell has one.
    secret = secret.replace(/\r?\n$/, '');
  } else {
    secret = process.env[c.env];
    // eslint-disable-next-line security/detect-possible-timing-attacks -- asks only whether the variable is set, which reveals nothing about the secret.
    if (secret === undefined) throw new Error(`upstream "${upstream.name}": the environment holds no ${c.env}.`);
  }
  if (secret === '' || /[\r\n\0]/.test(secret)) throw new Error(`upstream "${upstream.name}": the credential is empty, or holds a line break.`);
  const value = `${c.prefix}${secret}`;
  if (HOP_BY_HOP.includes(c.header)) throw new Error(`upstream "${upstream.name}": the credential cannot go in the header ${c.header}, which the gateway sets itself.`);
  try {
    http.validateHeaderName(c.header);
    http.validateHeaderValue(c.header, value);
  } catch {
    throw new Error(`upstream "${upstream.name}": the credential holds a character that cannot be sent in a header (only visible characters of ASCII, spaces and tabs can).`);
  }
  if (/[^\x20-\x7e\t]/.test(value)) throw new Error(`upstream "${upstream.name}": the credential holds a character that cannot be sent in a header (only visible characters of ASCII, spaces and tabs can).`);
  return { header: c.header, value };
}

async function signersFrom(entry, root, who) {
  if (Array.isArray(entry.privateKeys)) return entry.privateKeys;
  if (typeof entry.signers === 'string') {
    const module = await import(pathToFileURL(pathFrom(root, entry.signers)).href);
    if (typeof module.default !== 'function') throw new Error(`${who}: the module "signers" names must give a function by default.`);
    const signers = await module.default(who.startsWith('agent') ? { agent: who.slice(7, -1) } : { recorder: true });
    if (!Array.isArray(signers)) throw new Error(`${who}: the signers module gave no list of signers.`);
    return signers;
  }
  return null;
}

async function readRecorder(config, root) {
  const r = config.recorder;
  if (r === undefined) return null;
  if (!isObject(r)) throw new Error('"recorder" must be an object.');
  const name = r.name ?? 'Provared gateway';
  if (typeof name !== 'string' || name.length < 1 || name.length > 200) throw new Error('recorder: "name" must be text of 1 to 200 characters.');
  let keys;
  let privateKeys = await signersFrom(r, root, 'recorder');
  if (privateKeys) {
    keys = r.keySet ?? privateKeys.map((s) => s?.key);
  } else if (typeof r.keys === 'string') {
    ({ keys, privateKeys } = await loadKeyFile(pathFrom(root, r.keys), 'recorder'));
  } else throw new Error('recorder: name its key file ("keys") or its signers ("signers").');
  return { name, keys, privateKeys, fingerprint: await keySetFingerprint(keys) };
}

// --- the gateway ---

/**
 * Open the gateway: read the settings, the slips and the keys, and open a stub
 * writer for each agent on its book. It does not listen until asked.
 * @param {object} config the settings (gateway.json), read as JSON, or with keys and signers given in memory
 * @param {{root?: string, now?: () => number, log?: (event: object) => void, countersignWithin?: number, signWithin?: number}} [more]
 */
export async function openGateway(config, more = {}) {
  const root = more.root ?? process.cwd();
  const now = more.now ?? (() => Date.now());
  const log = more.log ?? defaultLog;
  const read = readRules(config);
  if (read.problems.length) throw new Error(`The settings are not right:\n- ${read.problems.join('\n- ')}`);
  const { upstreams, rules, unlisted, bodyLimit, stripQuery, waitingCalls, waitingBytes } = read;

  const credentials = new Map();
  for (const u of upstreams.values()) credentials.set(u.name, readCredential(u, root));
  const cas = new Map();
  for (const u of upstreams.values()) if (u.ca) cas.set(u.name, readFileSync(pathFrom(root, u.ca)));

  let admin = null;
  if (config.admin !== undefined) {
    if (!isObject(config.admin) || typeof config.admin.secretHash !== 'string' || !SECRET_HASH.test(config.admin.secretHash)) throw new Error('admin: "secretHash" must be the hash of a secret (provared-gateway secret makes one).');
    admin = Buffer.from(config.admin.secretHash);
  }
  const recorder = await readRecorder(config, root);
  const options = recorder ? { sealKeys: [recorder.fingerprint] } : {};

  if (!isObject(config.agents) || Object.keys(config.agents).length === 0) throw new Error('"agents" must name at least one agent.');
  const agents = new Map();
  const same = sameSettings(config.agents, root);
  if (same) throw new Error(same);
  for (const [name, a] of Object.entries(config.agents)) {
    const at = `agent "${name}"`;
    if (!NAME.test(name)) throw new Error(`${at}: its name must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.`);
    if (!isObject(a)) throw new Error(`${at}: must be an object.`);
    if (typeof a.secretHash !== 'string' || !SECRET_HASH.test(a.secretHash)) throw new Error(`${at}: "secretHash" must be the hash of a secret (provared-gateway secret makes one).`);
    if (!Array.isArray(a.issuerKeys) || a.issuerKeys.length === 0 || !a.issuerKeys.every((k) => typeof k === 'string' && /^[A-Za-z0-9_-]{43}$/.test(k))) {
      throw new Error(`${at}: "issuerKeys" must list the thumbprints of the passkeys whose slips it takes.`);
    }
    const slip = slipFrom(typeof a.slip === 'string' ? readIfThere(pathFrom(root, a.slip)) || '""' : a.slip, `${at}: its slip`);
    const about = await aboutSlip(slip);
    if (!a.issuerKeys.includes(about.issuerKey)) throw new Error(`${at}: its slip is signed by a passkey that "issuerKeys" does not name.`);
    let privateKeys = await signersFrom(a, root, `agent "${name}"`);
    if (!privateKeys) {
      if (typeof a.keys !== 'string') throw new Error(`${at}: name its key file ("keys") or its signers ("signers").`);
      ({ privateKeys } = await loadKeyFile(pathFrom(root, a.keys), 'agent'));
    }
    if (typeof a.book !== 'string') throw new Error(`${at}: "book" must be the path of its book file.`);
    const bookPath = pathFrom(root, a.book);
    const onDisk = readIfThere(bookPath);
    if (onDisk !== '' && !onDisk.endsWith('\n')) throw new Error(`${at}: the book file ${bookPath} does not end with a whole line.`);
    let text = onDisk;
    const checkOptions = { ...options, issuerKeys: a.issuerKeys };
    let result = text ? await checkBook(text, checkOptions) : null;
    if (result && result.summary.problemFound) throw new Error(`${at}: the book file ${bookPath} does not pass its check, so the gateway does not write to it.`);
    // The slip goes into the book first, where the book does not hold it yet: a new book, or a new slip.
    if (!result || !result.entries.some((e) => e.kind === 'slip' && e.fingerprint === about.fingerprint)) {
      text += `${entryLine({ slip })}\n`;
      result = await checkBook(text, checkOptions);
      if (result.summary.problemFound) throw new Error(`${at}: its slip does not pass its check: ${result.entries.at(-1).problems.map((p) => p.message).join(' ')}`);
    }
    const writer = await openRecorder({
      book: text,
      slip: about.fingerprint,
      privateKeys,
      issuerKeys: a.issuerKeys,
      options,
      now,
      denials: true,
      ...(more.countersignWithin !== undefined ? { countersignWithin: more.countersignWithin } : {}),
      ...(more.signWithin !== undefined ? { signWithin: more.signWithin } : {}),
    });
    const file = bookFile(bookPath, onDisk);
    file.save(writer.book());
    const journalAt = `${bookPath}.journal`;
    const keyAt = a.journalKey instanceof Uint8Array ? a.journalKey : journalKeyPath(a, root, bookPath);
    if (typeof keyAt === 'string' && !existsSync(keyAt) && readIfThere(journalAt).trim() !== '') {
      throw new Error(`${at}: its journal ${journalAt} holds lines, and its journal key ${keyAt} is missing, so no line could be checked. The gateway does not make a new key for a journal that holds lines: put the key back, or, having read the journal, move it away by hand.`);
    }
    const journalKey = loadJournalKey(keyAt);
    const asideAt = `${bookPath}.journal-set-aside`;
    const asideBefore = readSetAside(asideAt, journalKey, name);
    const journal = readJournal(journalAt, journalKey, name);
    // A journal of whole lines none of which checks was written under another key (one put back from another copy,
    // say): every honest line would only be set aside, and its call left with no receipt. So the start stops, as for
    // a missing key. Where some lines check and some do not, the gateway starts, and shows those that do not.
    if (journal.whole > 0 && journal.checked === 0) {
      throw new Error(`${at}: no line of its journal ${journalAt} checks under its journal key ${typeof keyAt === 'string' ? keyAt : '(given in memory)'}: the key is not the one the journal was written with. Put back the key the journal was written with. Setting the lines aside instead leaves the calls they stand for with no receipt; to do that, having read the journal, move it away by hand.`);
    }
    // A call whose stub the book already holds is done, whatever the journal says.
    const inBook = new Set(result.entries.filter((e) => e.kind === 'stub').flatMap((e) => (e.content?.details ?? []).filter((d) => d.name === CALL_DOCUMENT).map((d) => d.sha256)));
    // The slips the book holds, sound: a call may be acknowledged under any of them.
    const slipsInBook = new Set(result.entries.filter((e) => e.kind === 'slip' && e.problems.length === 0).map((e) => e.fingerprint));
    const pending = [];
    const startedAt = now();
    for (const p of journal.pending) {
      if (asideBefore.has(p.call)) continue;
      if (p.tag === 'valid' && inBook.has(await identifierFingerprint(p.line.sending))) {
        log({ event: 'receipt-found', agent: name, call: p.call });
        continue;
      }
      if (p.tag !== 'valid') p.problem ??= 'Its tag does not check: the gateway did not write this line, or it was changed.';
      else Object.assign(p, await unusableLine(p.line, startedAt, { slipsInBook, writer }));
      pending.push(p);
    }
    const agent = { name, hash: Buffer.from(a.secretHash), slip: about, writer, privateKeys, issuerKeys: a.issuerKeys, file, checkOptions, stopped: null, turn: Promise.resolve(), active: 0, lastCheck: null, waiting: 0, held: 0, journal: journalAt, setAsideFile: asideAt, journalKey, pending };
    if (pending.length) {
      agent.stopped = stoppedWords(pending);
      log({ event: 'receipt-missing', agent: name, calls: pending.map(shownLine) });
      for (const p of pending) if (p.tag !== 'valid') log({ event: 'journal-line-refused', agent: name, call: p.call, problem: p.problem });
    } else if (journal.lines > 0) replaceFile(agent.journal, '');
    agents.set(name, agent);
  }

  /**
   * Whether a journal line, whose tag checks, can have a stub written from it:
   * { problem: null } where it can, or a sentence saying why not; and a
   * warning where it can, but something has changed since (a rule taken out
   * of the settings). Its call must have been sent under a slip the book
   * holds, at a time not after this start, with an amount and documents of
   * the forms the gateway writes, which the library's own checks of a
   * request's fields take.
   */
  async function unusableLine(line, startedAt, { slipsInBook, writer }) {
    const no = (problem) => ({ problem, warning: null });
    const keys = ['sending', 'when', 'slip', 'action', 'amount', 'with', 'details'];
    if (!isObject(line) || Object.keys(line).some((k) => !keys.includes(k))) return no('It holds a member the gateway does not write.');
    if (typeof line.sending !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(line.sending)) return no('Its call identifier is not one the gateway makes.');
    if (typeof line.slip !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(line.slip)) return no('It does not say which slip its call was sent under.');
    if (!slipsInBook.has(line.slip)) return no('The book does not hold the slip its call was sent under, so no stub can be written under that slip. Set it aside, or put back the book that holds that slip.');
    const when = typeof line.when === 'string' ? Date.parse(line.when) : NaN;
    if (!Number.isFinite(when) || new Date(when).toISOString() !== line.when) return no('Its time is not a time written as the gateway writes it.');
    if (when > startedAt) return no("Its time is after this start of the gateway: the gateway's clock is behind the time the call was sent. Put the clock right and start the gateway again; nothing dated ahead of the clock is written.");
    if (typeof line.action !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(line.action)) return no('Its action is not an action name.');
    if (line.with !== undefined && (typeof line.with !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(line.with))) return no('Its service is not a service id.');
    let warning = null;
    const fitting = rules.filter((r) => r.action === line.action && upstreams.get(r.upstream)?.service === line.with);
    if (fitting.length === 0) {
      // The tag shows the gateway wrote this line; the rule that named the call has since been taken out of the settings.
      warning = 'No rule names this action for this service now (a rule was taken out, or changed, since the call was sent). Its tag shows the gateway wrote the line, so it can be acknowledged.';
      if (line.amount !== undefined) {
        const a = line.amount;
        if (!isObject(a) || Object.keys(a).length !== 2 || !Number.isSafeInteger(a.value) || a.value < 0 || typeof a.unit !== 'string') return no('Its amount is not a unit and a whole number from 0 up.');
      }
    } else if (line.amount === undefined) {
      if (!fitting.some((r) => !r.amount)) return no('Its rule gives an amount, and the line has none.');
    } else {
      const a = line.amount;
      if (!isObject(a) || Object.keys(a).length !== 2 || !Number.isSafeInteger(a.value) || a.value < 0 || typeof a.unit !== 'string') return no('Its amount is not a unit and a whole number from 0 up.');
      if (!fitting.some((r) => r.amount && r.amount.unit === a.unit)) return no('Its amount is not in the unit its rule gives.');
    }
    const named = ['provared.http-request', 'provared.trace-id', 'provared.request-id', CALL_DOCUMENT];
    const d = line.details;
    if (!Array.isArray(d) || d.length < 2 || d.length > 4) return no('Its documents are not the ones the gateway names.');
    for (const doc of d) {
      if (!isObject(doc) || Object.keys(doc).length !== 2 || !named.includes(doc.name) || typeof doc.sha256 !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(doc.sha256)) return no('Its documents are not the ones the gateway names.');
    }
    for (const n of named) if (d.filter((x) => x.name === n).length > 1) return no('It names one document twice.');
    if (!d.some((x) => x.name === 'provared.http-request')) return no('It names no request.');
    const call = d.find((x) => x.name === CALL_DOCUMENT);
    if (!call || call.sha256 !== (await identifierFingerprint(line.sending))) return no('Its call document does not match its call identifier.');
    // The library's own checks of a request's fields, as the stub writer will make them.
    const request = { action: line.action, ...(line.amount ? { amount: line.amount } : {}), ...(line.with !== undefined ? { with: line.with } : {}), details: [...d, { name: 'provared.error', sha256: await identifierFingerprint(OUTCOME_UNKNOWN) }] };
    let answer;
    try {
      answer = await writer.before(request, { when });
    } catch (e) {
      return no(`The library refuses it: ${e.message}`);
    }
    const field = answer.problems.find((f) => f.code === 'bad-field' || f.code === 'too-large');
    if (field) return no(`The library refuses it: ${field.message}`);
    return { problem: null, warning };
  }

  // The journal: a line before a call is sent, and one once its stub is in
  // the book file. A call with the first and not the second, found at start,
  // was sent and has no receipt.
  const note = (agent, value) => {
    const text = JSON.stringify(value);
    const fd = untilFree(() => openSync(agent.journal, 'a'));
    try {
      writeSync(fd, `${journalTag(agent.journalKey, agent.name, text)} ${text}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };

  const noteSetAside = (agent, call) => {
    const text = JSON.stringify({ setAside: call });
    const fd = untilFree(() => openSync(agent.setAsideFile, 'a'));
    try {
      writeSync(fd, `${journalTag(agent.journalKey, agent.name, text)} ${text}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };

  // One call of an agent at a time, its seals among them: the stub writer
  // takes one call at a time too, and a seal must cover the book as it is.
  const inTurn = (agent, step) => {
    const counted = async () => {
      agent.active += 1;
      try {
        return await step();
      } finally {
        agent.active -= 1;
      }
    };
    const run = agent.turn.then(counted, counted);
    agent.turn = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  };

  // Write what the book gained to its file. A file that cannot be written
  // stops the agent: no call is taken until the gateway is started again.
  const save = (agent) => {
    try {
      agent.file.save(agent.writer.book());
      return true;
    } catch (e) {
      agent.stopped ??= `the book file could not be written: ${e.message}`;
      log({ event: 'book-not-written', agent: agent.name, error: e.message });
      return false;
    }
  };

  const signedIn = async (header) => {
    const given = Buffer.from(await secretHash(header));
    for (const agent of agents.values()) if (timingSafeEqual(given, agent.hash)) return agent;
    return null;
  };
  const isAdmin = async (header) => admin !== null && timingSafeEqual(Buffer.from(await secretHash(header)), admin);

  /** The bearer secret of a call: exactly one Authorization header, "Bearer <secret>". */
  const bearer = (req) => {
    const all = req.headersDistinct?.authorization ?? [];
    if (all.length !== 1) return null;
    const m = /^Bearer ([\x21-\x7e]{1,512})$/i.exec(all[0]);
    return m ? m[1] : null;
  };

  // --- sending a call, and its answer ---

  /** Sends a call and waits for the whole answer. It never fails: what went wrong is part of the outcome. */
  function send(upstream, method, address, headers, body) {
    return new Promise((done) => {
      let finished = false;
      let timer;
      const finish = (outcome) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        done(outcome);
      };
      let connected = false;
      const fail = (status, text) => finish({ kind: 'error', status, text, delivered: connected ? undefined : false });
      const lib = address.startsWith('https:') ? https : http;
      let req;
      try {
        req = lib.request(address, { method, headers, agent: false, ...(cas.has(upstream.name) ? { ca: cas.get(upstream.name) } : {}) });
      } catch (e) {
        fail(502, `The gateway could not send the call to the upstream (${e.code ?? 'error'}).`);
        return;
      }
      timer = setTimeout(() => {
        fail(504, `The upstream gave no whole answer within ${upstream.timeout} milliseconds.`);
        req.destroy();
      }, upstream.timeout);
      // The connection itself keeps the program running; the timer alone does not.
      timer.unref();
      req.on('socket', (socket) => {
        // A connection made (and, for https, its encryption agreed): from here on, part of the call may reach the upstream.
        const ready = address.startsWith('https:') ? 'secureConnect' : 'connect';
        if (!socket.connecting && !(address.startsWith('https:') && !socket.encrypted)) connected = true;
        else socket.once(ready, () => (connected = true));
      });
      req.on('error', (e) => fail(502, `The call to the upstream failed before a whole answer came (${e.code ?? 'error'}).`));
      req.on('response', (res) => {
        const type = String(res.headers['content-type'] ?? '').toLowerCase();
        if (type.startsWith('text/event-stream')) {
          fail(502, 'The upstream answered with a stream of events (text/event-stream), which the gateway does not take.');
          req.destroy();
          return;
        }
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > bodyLimit) {
            fail(502, `The upstream's answer was larger than ${bodyLimit} bytes, the most the gateway takes.`);
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('error', () => fail(502, 'The upstream closed the connection before its answer was complete.'));
        res.on('aborted', () => fail(502, 'The upstream closed the connection before its answer was complete.'));
        res.on('end', () => {
          if (!res.complete) return fail(502, 'The upstream closed the connection before its answer was complete.');
          const hasBody = !(method === 'HEAD' || res.statusCode === 204 || res.statusCode === 304);
          finish({ kind: 'answer', status: res.statusCode, headers: res.headersDistinct, body: hasBody ? Buffer.concat(chunks) : undefined });
        });
        res.on('close', () => {
          if (!res.complete) fail(502, 'The upstream closed the connection before its answer was complete.');
        });
      });
      if (body !== undefined) req.end(body);
      else req.end();
    });
  }

  /** Asks the upstream to countersign a stub, where it says it can. Gives the countersignature, or null. */
  function askToCountersign(upstream, credential) {
    if (!upstream.countersign) return undefined;
    return async (stub) => {
      const headers = { 'content-type': 'application/jose+json', accept: 'application/json' };
      if (credential) headers[credential.header] = credential.value;
      const body = Buffer.from(JSON.stringify(stub));
      const outcome = await send(upstream, 'POST', `${upstream.base.origin}${upstream.countersign}`, headers, body);
      if (outcome.kind !== 'answer' || outcome.status !== 200 || !outcome.body) return null;
      try {
        const record = JSON.parse(outcome.body.toString('utf8'));
        return isObject(record) ? record : null;
      } catch {
        return null;
      }
    };
  }

  // --- answering the agent ---

  const json = (res, status, value, extra = {}) => {
    const body = Buffer.from(`${JSON.stringify(value)}\n`);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length, 'cache-control': 'no-store', ...extra });
    res.end(body);
  };
  const refuse = (res, status, code, message, extra = {}) => json(res, status, { taken: false, code, message, ...extra });

  const denialWords = (d) => (d ? (d.written ? { written: true, fingerprint: d.fingerprint } : { written: false, problem: d.problem }) : { written: false });

  async function denyByRule(agent, request) {
    try {
      const d = await inTurn(agent, () => agent.writer.deny(request, { source: 'rule' }));
      save(agent);
      return d;
    } catch (e) {
      return { written: false, problem: { code: 'check-failed', message: e.message } };
    }
  }

  /**
   * Reads the agent's body, up to the limit. Gives the bytes, undefined where
   * there is no body, null where it is too large, or WAITING_FULL where the
   * agent's waiting calls would hold more than they may. The bytes held are
   * counted for the agent ("held") until the call is done.
   */
  function readBody(req, agent, held) {
    const hasBody = req.headers['content-length'] !== undefined || req.headers['transfer-encoding'] !== undefined;
    if (!hasBody) return Promise.resolve(undefined);
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > bodyLimit) return Promise.resolve(null);
    const share = (more) => {
      if (!agent) return true;
      if (agent.held + more > waitingBytes) return false;
      agent.held += more;
      held.bytes += more;
      return true;
    };
    if (Number.isFinite(declared) && declared > 0 && !share(declared)) return Promise.resolve(WAITING_FULL);
    const reserved = Number.isFinite(declared) ? declared : 0;
    return new Promise((done, failed) => {
      const chunks = [];
      let size = 0;
      let over = false;
      req.on('data', (chunk) => {
        if (over) return;
        size += chunk.length;
        if (size > reserved && !share(Math.min(chunk.length, size - reserved))) {
          over = true;
          chunks.length = 0;
          done(WAITING_FULL);
          return;
        }
        if (size > bodyLimit) {
          // Answered at once; the rest is not read, and the connection is closed after the answer.
          over = true;
          chunks.length = 0;
          done(null);
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => done(over ? null : Buffer.concat(chunks)));
      req.on('error', failed);
    });
  }

  const WAITING_FULL = Symbol('the agent\'s waiting calls hold all they may');

  async function admin_(req, res, path) {
    const secret = bearer(req);
    if (admin === null) return refuse(res, 404, 'not-found', 'This gateway has no administrator secret, so its own addresses answer nothing.');
    if (!secret || !(await isAdmin(secret))) return refuse(res, 401, 'not-signed-in', 'The gateway\'s own addresses need the administrator\'s secret.');
    if (req.method === 'GET' && path === '/provared/status') return json(res, 200, await status());
    if (req.method === 'POST' && path === '/provared/acknowledge') {
      const body = await readBody(req, null, { bytes: 0 });
      let name;
      try {
        name = JSON.parse(body?.toString('utf8') ?? '').agent;
      } catch {
        name = undefined;
      }
      if (!agents.has(name)) return refuse(res, 400, 'bad-request', 'Name the agent whose calls to acknowledge: {"agent": "<name>"}.');
      let setAside;
      try {
        setAside = JSON.parse(body.toString('utf8')).setAside;
      } catch {
        setAside = undefined;
      }
      try {
        return json(res, 200, await acknowledge(name, { setAside }));
      } catch (e) {
        return refuse(res, 409, 'not-acknowledged', e.message);
      }
    }
    if (req.method === 'POST' && path === '/provared/seal') {
      const body = await readBody(req, null, { bytes: 0 });
      let name;
      try {
        name = JSON.parse(body?.toString('utf8') ?? '').agent;
      } catch {
        name = undefined;
      }
      if (!agents.has(name)) return refuse(res, 400, 'bad-request', 'Name the agent whose book to seal: {"agent": "<name>"}.');
      try {
        return json(res, 200, await seal(name));
      } catch (e) {
        return refuse(res, 409, 'not-sealed', e.message);
      }
    }
    return refuse(res, 404, 'not-found', 'The gateway\'s own addresses are GET /provared/status, POST /provared/seal and POST /provared/acknowledge.');
  }

  /**
   * Handle one call, for Node.js's own server: (request, response).
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  async function handle(req, res) {
    try {
      await handleCall(req, res);
    } catch (e) {
      log({ event: 'gateway-error', error: e.message });
      if (!res.headersSent) refuse(res, 500, 'gateway-error', 'The gateway met something it did not expect. The call was not answered by the upstream.');
      else res.destroy();
    }
  }

  async function handleCall(req, res) {
    const target = req.url ?? '';
    if (target === '/provared' || target.startsWith('/provared/') || target.startsWith('/provared?')) return admin_(req, res, target.split('?')[0]);

    // 1. Who is calling: the agent's own secret, in the one Authorization header.
    const secret = bearer(req);
    const agent = secret ? await signedIn(secret) : null;
    if (!agent) {
      log({ event: 'not-signed-in' });
      res.setHeader('www-authenticate', 'Bearer');
      return refuse(res, 401, 'not-signed-in', 'Sign in to the gateway with your own secret, in one header: Authorization: Bearer <secret>.');
    }
    if (agent.stopped) return refuse(res, 503, 'agent-stopped', `The gateway takes no call of this agent: ${agent.stopped}`);
    if (req.headers.upgrade !== undefined || req.method === 'CONNECT') {
      log({ event: 'refused', agent: agent.name, code: 'upgrade-refused' });
      return refuse(res, 400, 'upgrade-refused', 'The gateway takes no long-lived connection (an upgrade to websockets, or a tunnel).');
    }
    const tokens = (req.headersDistinct.connection ?? []).flatMap((v) => v.split(',')).map((s) => s.trim().toLowerCase()).filter(Boolean);
    if (tokens.some((tok) => !CONNECTION_TOKENS.includes(tok))) {
      log({ event: 'refused', agent: agent.name, code: 'header-refused' });
      return refuse(res, 400, 'header-refused', 'The Connection header may say only "close" or "keep-alive": a header it names would be dropped on the way, though the gateway may have relied on it.');
    }
    if (agent.waiting >= waitingCalls) {
      log({ event: 'refused', agent: agent.name, code: 'too-many-waiting' });
      res.setHeader('connection', 'close');
      return refuse(res, 503, 'too-many-waiting', `This agent already has ${waitingCalls} calls waiting at the gateway, the most it may have. Try again when one has been answered.`);
    }
    agent.waiting += 1;
    const held = { bytes: 0 };
    try {
      return await takeCall(req, res, target, agent, held);
    } finally {
      agent.waiting -= 1;
      agent.held -= held.bytes;
    }
  }

  async function takeCall(req, res, target, agent, held) {

    // 2. Where to: the upstream, and the path in the one form the gateway forwards.
    const t = readTarget(target, (name) => upstreams.get(name)?.semicolons === true);
    if (t.problem) {
      log({ event: 'refused', agent: agent.name, code: t.problem.code });
      return refuse(res, 400, t.problem.code, t.problem.message);
    }
    const upstream = upstreams.get(t.upstream);
    if (!(upstream?.underscoreHeaders ?? false) && Object.keys(req.headersDistinct).some((h) => h.includes('_'))) {
      log({ event: 'refused', agent: agent.name, code: 'header-refused' });
      return refuse(res, 400, 'header-refused', 'A header name holds "_", which some servers read as "-": the gateway could not then tell which headers it removes. This upstream does not allow it ("underscoreHeaders").');
    }
    const withService = upstream?.service !== undefined ? { with: upstream.service } : {};
    const { query, removed: removedParameters } = stripParameters(t.query, stripQuery);

    // 3. Which rule. A call to no known upstream matches no rule.
    const rule = upstream ? matchRule(rules, { upstream: t.upstream, method: req.method, rest: t.match, query }) : null;
    const action = rule ? rule.action : UNLISTED_ACTION;

    // 4. The body, up to the limit.
    let body;
    try {
      body = await readBody(req, agent, held);
    } catch {
      return refuse(res, 400, 'body-not-read', 'The body of the call could not be read.');
    }
    if (body === WAITING_FULL) {
      log({ event: 'refused', agent: agent.name, action, code: 'too-much-waiting' });
      res.setHeader('connection', 'close');
      return refuse(res, 503, 'too-much-waiting', `This agent's waiting calls already hold ${waitingBytes} bytes of bodies, the most they may. Try again when one has been answered.`);
    }
    if (body === null) {
      const denial = await denyByRule(agent, { action, ...withService });
      log({ event: 'refused', agent: agent.name, action, code: 'body-too-large' });
      // The rest of the body is not read: the connection is closed once the answer is sent.
      res.setHeader('connection', 'close');
      return refuse(res, 413, 'body-too-large', `The body is larger than ${bodyLimit} bytes, the most the gateway takes.`, { denial: denialWords(denial) });
    }

    // 5. The headers to send: the agent's, without its credentials, and with the upstream's.
    const removed = [];
    const headers = {};
    if (upstream) {
      const named = new Set(
        String(req.headers.connection ?? '')
          .toLowerCase()
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      );
      for (const [name, values] of Object.entries(req.headersDistinct)) {
        if (neverForwarded(name) || named.has(name)) continue;
        if (upstream.stripHeaders.includes(name) || OVERRIDE_HEADERS.includes(name)) {
          if (name !== 'authorization') removed.push(name);
          continue;
        }
        headers[name] = values.length === 1 ? values[0] : values;
      }
      const credential = credentials.get(upstream.name);
      if (credential) {
        delete headers[credential.header];
        headers[credential.header] = credential.value;
      }
      headers.host = upstream.base.host;
      if (body !== undefined) headers['content-length'] = String(body.length);
    }
    if (removed.length || removedParameters.length) log({ event: 'credential-removed', agent: agent.name, headers: removed, parameters: removedParameters });

    const address = upstream ? upstreamAddress(upstream, t.rest, query) : null;
    const callId = randomId();
    const details = [];
    if (address) {
      try {
        details.push({ name: 'provared.http-request', sha256: await httpRequestFingerprint({ method: req.method, url: address, body }) });
      } catch (e) {
        return refuse(res, 400, 'address-refused', `The call cannot be written down exactly: ${e.message}`);
      }
      const tp = req.headersDistinct.traceparent ?? [];
      const trace = tp.length === 1 ? TRACEPARENT.exec(tp[0]) : null;
      if (trace) details.push({ name: 'provared.trace-id', sha256: await identifierFingerprint(trace[1]) });
      if (upstream.requestIdHeader) {
        const id = randomId();
        headers[upstream.requestIdHeader] = id;
        details.push({ name: 'provared.request-id', sha256: await identifierFingerprint(id) });
      }
      details.push({ name: CALL_DOCUMENT, sha256: await identifierFingerprint(callId) });
    }

    // What a denial names: the request as it would have been sent, without the
    // gateway's own identifier, which was never sent.
    const asked = details.filter((d) => d.name !== 'provared.request-id' && d.name !== CALL_DOCUMENT);

    // 6. A call that matches no rule.
    if (!rule) {
      if (unlisted === 'forward' && upstream) {
        log({ event: 'forwarded-unlisted', agent: agent.name, upstream: upstream.name, method: req.method, path: t.rest });
        const outcome = await send(upstream, req.method, address, headers, body);
        return answer(res, outcome, req.method, null);
      }
      const denial = await denyByRule(agent, { action, ...withService, ...(asked.length ? { details: asked } : {}) });
      log({ event: 'refused', agent: agent.name, code: 'unlisted' });
      return refuse(res, 403, 'unlisted', upstream ? 'No rule of the gateway names this call, so it was not taken.' : `The gateway has no upstream named "${t.upstream}", so the call was not taken.`, { denial: denialWords(denial) });
    }

    // 7. The amount, as the rule says.
    const got = amountOf(rule.amount, { body, contentType: req.headersDistinct['content-type'], contentEncoding: req.headersDistinct['content-encoding'] });
    if (got.problem) {
      const denial = await denyByRule(agent, { action, ...withService, details: asked });
      log({ event: 'refused', agent: agent.name, action, code: got.problem.code });
      return refuse(res, 403, got.problem.code, got.problem.message, { denial: denialWords(denial) });
    }

    // 8. Ask the stub writer; its action is to send the call. Once sent, the call always gets its stub.
    const request = { action, ...(got.amount ? { amount: got.amount } : {}), ...withService, details };
    const credential = credentials.get(upstream.name);
    let sent = false;
    let outcome;
    let done;
    try {
      done = await inTurn(agent, async () => {
        if (agent.stopped) return { stopped: true };
        if (!agent.file.holds(agent.writer.book()) && !save(agent)) return { stopped: true };
        // The file must still be as the gateway left it, before anything is sent.
        let intact;
        try {
          intact = agent.file.intact();
        } catch (e) {
          intact = false;
        }
        if (!intact) {
          agent.stopped ??= 'the book file is not as the gateway left it: something else changed it.';
          log({ event: 'book-changed', agent: agent.name });
          return { stopped: true };
        }
        const result = await agent.writer.act(
          request,
          async () => {
            note(agent, { sending: callId, when: new Date(now()).toISOString(), slip: agent.slip.fingerprint, action, ...(got.amount ? { amount: got.amount } : {}), ...withService, details });
            sent = true;
            outcome = await send(upstream, req.method, address, headers, body);
            return outcome;
          },
          {
            countersign: askToCountersign(upstream, credential),
            // The denial is written below, without the identifier that was never sent.
            denial: false,
            detailsAfter: async (o) => {
              if (o.kind === 'error') {
                const error = await identifierFingerprint(o.text);
                return [{ name: 'provared.error', sha256: error }, ...(o.delivered === false ? [{ name: NOT_DELIVERED, sha256: error }] : [])];
              }
              const after = [{ name: 'provared.http-response', sha256: await httpResponseFingerprint({ status: o.status, body: o.body }) }];
              const ids = upstream.eventIdHeader ? (o.headers[upstream.eventIdHeader] ?? []) : [];
              if (ids.length === 1 && ids[0] !== '') {
                try {
                  after.push({ name: 'provared.event-id', sha256: await identifierFingerprint(ids[0]) });
                } catch {
                  // An identifier that is not well-formed text is not named.
                }
              }
              return after;
            },
          },
        );
        if (!result.done) result.denial = await agent.writer.deny({ ...request, details: asked }, { source: 'check', codes: denialCodes(result.answer) });
        if (save(agent) && result.done) {
          try {
            note(agent, { done: callId });
          } catch (e) {
            // The stub is in the book; only the journal lacks its line, so a start would ask about this call.
            log({ event: 'journal-not-written', agent: agent.name, error: e.message });
          }
        }
        return result;
      });
    } catch (e) {
      if (sent) {
        agent.stopped = `a call was sent and its receipt could not be written (${e.message}).`;
        log({ event: 'receipt-not-written', agent: agent.name, action, error: e.message });
        return answer(res, outcome ?? { kind: 'error', status: 502, text: 'The gateway could not write the receipt of this call.' }, req.method, null);
      }
      throw e;
    }
    if (done.stopped) return refuse(res, 503, 'agent-stopped', `The gateway takes no call of this agent: ${agent.stopped}`);
    if (!done.done) {
      log({ event: 'refused', agent: agent.name, action, code: 'not-allowed', codes: [...done.answer.problems, ...done.answer.breaches].map((f) => f.code) });
      return json(res, 403, {
        taken: false,
        code: 'not-allowed',
        message: 'The check before acting did not allow this call, so it was not sent.',
        problems: done.answer.problems,
        breaches: done.answer.breaches,
        denial: denialWords(done.denial),
      });
    }
    if (done.detailsAfter?.problem) log({ event: 'details-not-added', agent: agent.name, action, problem: done.detailsAfter.problem.code });
    if (done.stub.countersignature.problem) log({ event: 'countersignature-not-taken', agent: agent.name, action, problem: done.stub.countersignature.problem.code });
    log({ event: 'taken', agent: agent.name, action, status: outcome.kind === 'answer' ? outcome.status : outcome.status, stub: done.stub.fingerprint });
    return answer(res, outcome, req.method, done.stub.fingerprint);
  }

  function answer(res, outcome, method, stub) {
    const mark = stub ? { 'provared-stub': stub } : {};
    if (outcome.kind === 'error') return json(res, outcome.status, { taken: true, error: outcome.text, ...(stub ? { stub } : {}) }, mark);
    const headers = {};
    const named = new Set((outcome.headers.connection ?? []).flatMap((v) => v.split(',')).map((s) => s.trim().toLowerCase()));
    for (const [name, values] of Object.entries(outcome.headers)) {
      if (ANSWER_HOP.includes(name) || named.has(name) || name.startsWith('provared-')) continue;
      headers[name] = values.length === 1 ? values[0] : values;
    }
    if (outcome.body !== undefined) headers['content-length'] = String(outcome.body.length);
    else if (method === 'HEAD' && outcome.headers['content-length']?.length === 1) headers['content-length'] = outcome.headers['content-length'][0];
    res.writeHead(outcome.status, { ...headers, ...mark });
    res.end(outcome.body);
  }

  // --- sealing, and what the gateway says about itself ---

  /** Seal an agent's book now, with the recorder's keys. */
  async function seal(name) {
    const agent = agents.get(name);
    if (!agent) throw new Error(`The gateway has no agent named "${name}".`);
    if (!recorder) throw new Error('The settings name no recorder ("recorder"), so the gateway cannot seal.');
    return inTurn(agent, async () => {
      if (agent.stopped) throw new Error(`The agent is stopped: ${agent.stopped}`);
      const result = await agent.writer.check();
      const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0);
      const previous = seals.length ? seals[seals.length - 1].fingerprint : undefined;
      const sealed = await writeSeal(agent.writer.book(), { by: { keys: recorder.keys, name: recorder.name }, ...(previous ? { previous } : {}), when: now() }, recorder.privateKeys);
      await agent.writer.add({ seal: sealed.record });
      if (!save(agent)) throw new Error(`The seal is in the gateway's memory, and the book file could not be written: ${agent.stopped}`);
      return { agent: name, entry: result.size, fingerprint: sealed.fingerprint };
    });
  }

  /**
   * The administrator acknowledges the calls sent before the gateway last
   * stopped that have no receipt: for each, a stub is written with what the
   * journal holds of the call, dated when it was sent, naming
   * "provared.error" with the words OUTCOME_UNKNOWN; and the agent takes
   * calls again.
   */
  /**
   * The administrator acknowledges the calls sent before the gateway last
   * stopped that have no receipt, and may set aside lines of the journal
   * that no stub can be written from (or whose tag does not check). Each
   * line set aside is noted in the journal and in the log, and has no stub.
   * Each call acknowledged gets a stub, written from what its line holds,
   * dated when it was sent, naming "provared.error" with OUTCOME_UNKNOWN; it
   * leaves the list as soon as its line saying so is in the journal. The
   * agent takes calls again once the list is empty.
   * @param {string} name
   * @param {{setAside?: string[]}} [o] the calls (as the status names them) to set aside
   */
  async function acknowledge(name, o = {}) {
    const agent = agents.get(name);
    if (!agent) throw new Error(`The gateway has no agent named "${name}".`);
    const setAside = o.setAside ?? [];
    if (!Array.isArray(setAside) || !setAside.every((c) => typeof c === 'string')) throw new Error('setAside: must be a list of the calls to set aside, as the status names them.');
    return inTurn(agent, async () => {
      if (agent.pending.length === 0) throw new Error('This agent has no call without a receipt to acknowledge.');
      for (const c of setAside) if (!agent.pending.some((p) => p.call === c)) throw new Error(`No call "${c}" is waiting to be acknowledged.`);
      const asideNow = [];
      for (const c of setAside) {
        const p = agent.pending.find((x) => x.call === c);
        note(agent, { setAside: c });
        noteSetAside(agent, c);
        agent.pending = agent.pending.filter((x) => x !== p);
        asideNow.push(shownLine(p));
        log({ event: 'journal-line-set-aside', agent: name, line: shownLine(p) });
      }
      const usable = agent.pending.filter((p) => p.tag === 'valid' && p.problem === null);
      if (usable.length === 0 && asideNow.length === 0) throw new Error('No call waiting can have a stub written from its line; set aside those you have looked at (setAside).');
      const error = await identifierFingerprint(OUTCOME_UNKNOWN);
      const written = [];
      for (const p of usable.sort((x, y) => Date.parse(x.line.when) - Date.parse(y.line.when))) {
        const l = p.line;
        const request = { action: l.action, ...(l.amount ? { amount: l.amount } : {}), ...(l.with !== undefined ? { with: l.with } : {}), details: [...l.details, { name: 'provared.error', sha256: error }] };
        let stub;
        if (l.slip === agent.slip.fingerprint) {
          stub = await agent.writer.record(request, { when: Date.parse(l.when) });
        } else {
          // Sent under an earlier slip that the book holds: a stub writer for that slip, opened on the book as it
          // stands, writes the stub; the agent's own writer then takes the line into the book, only if the book
          // still passes its check with it.
          const other = await openRecorder({ book: agent.writer.book(), slip: l.slip, privateKeys: agent.privateKeys, issuerKeys: agent.issuerKeys, options, now });
          stub = await other.record(request, { when: Date.parse(l.when) });
          await agent.writer.add(JSON.parse(stub.line));
        }
        if (!save(agent)) throw new Error(`The stub is in the gateway's memory, and the book file could not be written: ${agent.stopped}`);
        note(agent, { acknowledged: p.call, stub: stub.fingerprint });
        agent.pending = agent.pending.filter((x) => x !== p);
        written.push({ when: l.when, action: l.action, slip: l.slip, stub: stub.fingerprint });
      }
      agent.stopped = agent.pending.length ? stoppedWords(agent.pending) : null;
      log({ event: 'acknowledged', agent: name, stubs: written.map((w) => w.stub), setAside: asideNow.map((l) => l.call) });
      return { agent: name, written, setAside: asideNow, remaining: agent.pending.map(shownLine) };
    });
  }

  async function status() {
    const out = {};
    for (const agent of agents.values()) {
      // The stub writer answers a check only between calls. While a call is with
      // its upstream, the answer given is that of the last check, and says so.
      let checked = null;
      if (agent.active === 0) {
        let timer;
        const late = new Promise((done) => (timer = setTimeout(() => done(null), 2000)));
        const result = await Promise.race([agent.writer.check(), late]);
        clearTimeout(timer);
        if (result) {
          const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0);
          const last = seals.at(-1);
          checked = { entries: result.size, lastSeal: last ? { entry: last.index, fingerprint: last.fingerprint } : null, sound: !result.summary.problemFound, withinSlips: result.summary.withinSlips, at: new Date(now()).toISOString() };
          agent.lastCheck = checked;
        }
      }
      const shown = checked ?? agent.lastCheck;
      out[agent.name] = {
        slip: agent.slip.fingerprint,
        entries: shown?.entries ?? null,
        bytes: Buffer.byteLength(agent.writer.book()),
        lastSeal: shown?.lastSeal ?? null,
        sound: shown?.sound ?? null,
        withinSlips: shown?.withinSlips ?? null,
        checkedAt: shown?.at ?? null,
        checkedNow: checked !== null,
        stopped: agent.stopped,
        receiptsMissing: agent.pending.map(shownLine),
        waiting: agent.waiting,
        fileHoldsBook: agent.file.holds(agent.writer.book()),
      };
    }
    return { gateway: 'provared-gateway', recorder: recorder ? recorder.fingerprint : null, agents: out };
  }

  let server = null;
  return {
    handle,
    seal,
    status,
    acknowledge,
    /** The stub writer of each agent, by name: for tests and for programs that embed the gateway. */
    writers: () => new Map([...agents].map(([n, a]) => [n, a.writer])),
    /** What a whole check of an agent's book needs to be told: the passkeys and the recorder it trusts. */
    checkOptions: (name) => agents.get(name)?.checkOptions,
    bookPath: (name) => agents.get(name)?.file.path,
    /** Listen on the settings' address (by default 127.0.0.1, port 8795), or on the one given. */
    listen(at = config.listen ?? {}) {
      const host = at.host ?? '127.0.0.1';
      const port = at.port ?? 8795;
      server = http.createServer(handle);
      // A long-lived connection is refused (websockets, server-sent tunnels).
      server.on('upgrade', (_req, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n'));
      server.on('connect', (_req, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n'));
      return new Promise((done, failed) => {
        server.once('error', failed);
        server.listen(port, host, () => done(server.address()));
      });
    },
    async close() {
      if (server) {
        const closed = new Promise((done) => server.close(() => done()));
        server.closeAllConnections();
        await closed;
      }
      for (const agent of agents.values()) await agent.turn;
    },
  };
}

// --- checking the settings ---

/**
 * Read the settings and say what each rule maps to, and what is wrong, without
 * opening any book or reading any credential's value.
 * @returns {Promise<{lines: string[], problems: string[], warnings: string[]}>}
 */
export async function checkConfig(config, { root = process.cwd() } = {}) {
  const read = readRules(config);
  const problems = [...read.problems];
  const warnings = [...read.warnings];
  const lines = [];
  for (const u of read.upstreams.values()) {
    if (!u.credential) warnings.push(`upstream "${u.name}": no credential is named, so the gateway adds none.`);
    else if (u.credential.file !== undefined) {
      try {
        const value = readFileSync(pathFrom(root, u.credential.file), 'utf8').replace(/\r?\n$/, '');
        if (value === '' || /[\r\n\0]/.test(value)) problems.push(`upstream "${u.name}": the credential file is empty, or holds a line break.`);
      } catch (e) {
        problems.push(`upstream "${u.name}": the credential file could not be read (${e.code ?? 'error'}).`);
      }
    } else if (process.env[u.credential.env] === undefined) problems.push(`upstream "${u.name}": the environment holds no ${u.credential.env}.`);
    else if (process.env[u.credential.env] === '' || /[\r\n\0]/.test(process.env[u.credential.env])) problems.push(`upstream "${u.name}": the credential in ${u.credential.env} is empty, or holds a line break.`);
  }
  if (config?.recorder === undefined) warnings.push('No recorder is named ("recorder"), so the gateway cannot seal its books.');
  else if (typeof config.recorder?.keys === 'string') {
    try {
      await loadKeyFile(pathFrom(root, config.recorder.keys), 'recorder');
    } catch (e) {
      problems.push(`recorder: ${e.message} (provared-gateway keys --recorder makes it).`);
    }
  } else if (typeof config.recorder?.signers !== 'string' && !Array.isArray(config.recorder?.privateKeys)) problems.push('recorder: name its key file ("keys") or its signers ("signers").');
  if (config?.admin === undefined) warnings.push('No administrator secret is named ("admin"), so GET /provared/status and POST /provared/seal answer nothing; "seal --offline" still works on a stopped gateway.');
  else if (typeof config.admin?.secretHash !== 'string' || !SECRET_HASH.test(config.admin.secretHash)) problems.push('admin: "secretHash" must be the hash of a secret (provared-gateway secret makes one).');
  const slips = [];
  const same = sameSettings(config?.agents, root);
  if (same) problems.push(same);
  if (!isObject(config?.agents) || Object.keys(config.agents).length === 0) problems.push('"agents" must name at least one agent.');
  for (const [name, a] of Object.entries(isObject(config?.agents) ? config.agents : {})) {
    const at = `agent "${name}"`;
    if (!NAME.test(name)) problems.push(`${at}: its name must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.`);
    if (!isObject(a)) {
      problems.push(`${at}: must be an object.`);
      continue;
    }
    if (typeof a.secretHash !== 'string' || !SECRET_HASH.test(a.secretHash)) problems.push(`${at}: "secretHash" must be the hash of a secret (provared-gateway secret makes one).`);
    if (typeof a.book !== 'string') problems.push(`${at}: "book" must be the path of its book file.`);
    if (typeof a.keys !== 'string' && typeof a.signers !== 'string' && !Array.isArray(a.privateKeys)) problems.push(`${at}: name its key file ("keys") or its signers ("signers").`);
    if (!Array.isArray(a.issuerKeys) || a.issuerKeys.length === 0) problems.push(`${at}: "issuerKeys" must list the thumbprints of the passkeys whose slips it takes.`);
    let about;
    try {
      about = await aboutSlip(slipFrom(typeof a.slip === 'string' ? readFileSync(pathFrom(root, a.slip), 'utf8') : a.slip, `${at}: its slip`));
    } catch (e) {
      problems.push(`${at}: its slip could not be read: ${e.message}`);
      continue;
    }
    const c = about.content;
    if (Array.isArray(a.issuerKeys) && !a.issuerKeys.includes(about.issuerKey)) problems.push(`${at}: its slip is signed by a passkey that "issuerKeys" does not name.`);
    if (typeof c.agent?.name === 'string' && !/through the gateway/i.test(c.agent.name)) warnings.push(`${at}: the slip names the agent "${c.agent.name}"; a name such as "…, through the gateway at <address>" says whose keys sign its receipts.`);
    if (Date.parse(c.validUntil) < Date.now()) warnings.push(`${at}: its slip ended at ${c.validUntil}.`);
    if (typeof a.keys === 'string') {
      try {
        const { keys } = await loadKeyFile(pathFrom(root, a.keys), 'agent');
        if (JSON.stringify(keys) !== JSON.stringify(c.agent?.keys)) problems.push(`${at}: the slip names other keys for the agent than its key file holds.`);
      } catch (e) {
        problems.push(`${at}: ${e.message}`);
      }
    }
    slips.push({ name, content: c });
  }
  for (const rule of read.rules) {
    const u = read.upstreams.get(rule.upstream);
    const kind = typeof rule.action === 'string' ? actionKind(rule.action) : null;
    const amount = !rule.amount ? 'no amount' : Object.hasOwn(rule.amount, 'value') ? `${rule.amount.value} ${rule.amount.unit}` : Object.hasOwn(rule.amount, 'count') ? `the length of the list at ${rule.amount.count}, in ${rule.amount.unit}` : `the number at ${rule.amount.pointer}, in ${rule.amount.unit}`;
    lines.push(`rule ${rule.index}: ${rule.method} /${rule.upstream}${rule.path}${rule.search !== undefined ? `?${rule.search}` : ''} -> ${rule.action}${kind ? ` (${kind})` : ''}; ${amount}; service ${u?.service ?? 'none'}`);
    if (!kind) warnings.push(`rule ${rule.index}: "${rule.action}" is not on the shared list, so it has no kind, and a slip's "never" kinds of action cannot apply to it.`);
    if (u && rule.method === 'DELETE' && kind && kind !== 'destroys') warnings.push(`rule ${rule.index}: a DELETE call is named "${rule.action}", whose kind is "${kind}", not "destroys". Check that the name is right.`);
    if (u && !['GET', 'HEAD'].includes(rule.method) && kind === 'reads') warnings.push(`rule ${rule.index}: a ${rule.method} call is named "${rule.action}", whose kind is "reads". Check that the call changes nothing.`);
    for (const s of slips) {
      if (!Array.isArray(s.content.actions) || !s.content.actions.includes(rule.action)) warnings.push(`rule ${rule.index}: the slip of agent "${s.name}" does not allow "${rule.action}", so such calls are refused for it.`);
      else if (u?.service !== undefined && !(s.content.with ?? []).some((w) => w.id === u.service)) warnings.push(`rule ${rule.index}: the slip of agent "${s.name}" does not name the service "${u.service}".`);
      for (const limit of s.content.limits ?? []) {
        if (limit.action === rule.action && limit.unit !== undefined && (!rule.amount || rule.amount.unit !== limit.unit)) {
          warnings.push(`rule ${rule.index}: the slip of agent "${s.name}" limits "${rule.action}" in ${limit.unit}, and the rule gives ${rule.amount ? `an amount in ${rule.amount.unit}` : 'no amount'}.`);
        }
      }
    }
  }
  return { lines, problems, warnings };
}

/** Where an agent's journal key is kept: as the settings say, beside its key file, or beside its book. */
export function journalKeyPath(a, root, bookPath) {
  if (typeof a.journalKey === 'string') return pathFrom(root, a.journalKey);
  if (typeof a.keys === 'string') return `${pathFrom(root, a.keys)}.journal-key`;
  return `${bookPath}.journal-key`;
}

/** The journal key: 32 random bytes, made the first time, kept in base64url in a file for its owner alone. */
export function loadJournalKey(where) {
  if (where instanceof Uint8Array) {
    if (where.length < 32) throw new Error('journalKey: must be at least 32 bytes.');
    return Buffer.from(where);
  }
  if (!existsSync(where)) {
    mkdirSync(dirname(where), { recursive: true });
    try {
      writeFileSync(where, `${randomBytes(32).toString('base64url')}\n`, { mode: 0o600, flag: 'wx' });
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
  }
  const key = Buffer.from(readFileSync(where, 'utf8').trim(), 'base64url');
  if (key.length !== 32) throw new Error(`The journal key ${where} is not 32 bytes in base64url.`);
  return key;
}

/** HMAC-SHA-256 (RFC 2104) of a journal line, under the agent's journal key, with the agent's name: base64url. */
function journalTag(key, agentName, text) {
  return createHmac('sha256', key).update(`${agentName}\n${text}`).digest('base64url');
}

/** A journal line as the administrator is shown it. */
function shownLine(p) {
  const l = isObject(p.line) ? p.line : {};
  return { call: p.call, tag: p.tag, usable: p.tag === 'valid' && p.problem === null, problem: p.problem ?? null, warning: p.warning ?? null, when: l.when, slip: l.slip, action: l.action, amount: l.amount, with: l.with, details: l.details };
}

function stoppedWords(pending) {
  const first = shownLine(pending[0]);
  return `${pending.length} call(s) sent before the gateway last stopped have no receipt in the book (the first: ${String(first.when).slice(0, 40)}, ${String(first.action).slice(0, 64)}). The administrator acknowledges them with POST /provared/acknowledge, or "provared-gateway acknowledge", and sets aside any line that cannot have a stub ("setAside", "--set-aside"); a stub that says the outcome is not known is written for each call acknowledged.`;
}

/**
 * The lines of a journal: the calls with a "sending" line and no line, whose
 * tag checks, that acknowledges or sets it aside. A line whose tag does not
 * check is never acted on: a "sending" line of that kind is shown, as a call
 * to set aside; any other is set aside here. A last line with no line ending
 * was cut short by a stop while it was written: its call was not sent, since
 * the line is written first.
 */
/** The calls the administrator set aside, from the file a clean start does not empty: only lines whose tag checks. */
function readSetAside(path, key, agentName) {
  const out = new Set();
  for (const raw of readIfThere(path).split('\n')) {
    const space = raw.indexOf(' ');
    if (space <= 0) continue;
    const body = raw.slice(space + 1);
    const expected = Buffer.from(journalTag(key, agentName, body));
    const given = Buffer.from(raw.slice(0, space));
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) continue;
    try {
      const value = JSON.parse(body);
      if (typeof value?.setAside === 'string') out.add(value.setAside);
    } catch {
      // Not a line the gateway wrote.
    }
  }
  return out;
}

function readJournal(path, key, agentName) {
  const text = readIfThere(path);
  const open = new Map();
  const parts = text.split('\n');
  const cut = parts.pop();
  let lines = 0;
  let checked = 0;
  parts.forEach((raw) => {
    if (!raw.trim()) return;
    lines += 1;
    const space = raw.indexOf(' ');
    const tag = space > 0 ? raw.slice(0, space) : '';
    const body = space > 0 ? raw.slice(space + 1) : raw;
    const expected = Buffer.from(journalTag(key, agentName, body));
    const given = Buffer.from(tag);
    const valid = given.length === expected.length && timingSafeEqual(given, expected);
    let value;
    try {
      value = JSON.parse(body);
    } catch {
      value = undefined;
    }
    if (!valid) {
      const call = `line-${createHash('sha256').update(raw).digest('base64url').slice(0, 16)}`;
      open.set(call, { call, tag: 'invalid', line: isObject(value) && JSON.stringify(value).length <= 16384 ? value : null, problem: value === undefined ? 'It is not JSON, and its tag does not check.' : null });
      return;
    }
    checked += 1;
    if (typeof value?.sending === 'string') open.set(value.sending, { call: value.sending, tag: 'valid', line: value, problem: null });
    else if (typeof value?.acknowledged === 'string') open.delete(value.acknowledged);
    else if (typeof value?.setAside === 'string') open.delete(value.setAside);
  });
  void cut;
  return { pending: [...open.values()], lines: lines + (cut ? 1 : 0), whole: lines, checked };
}

/**
 * The names under which a file is the same file: as the file system names it
 * (below), and, where the file exists, its device and file numbers, which a
 * hard link or a link to the file shares (a link is followed).
 */
function placeKeys(path) {
  const keys = [samePlace(path)];
  if (existsSync(path)) {
    try {
      const s = statSync(path, { bigint: true });
      keys.push(`file ${s.dev}:${s.ino}`);
    } catch {
      // Not readable: its names are compared.
    }
  }
  return [...new Set(keys)];
}

/**
 * A path as the file system names it: the real path of the deepest folder
 * that exists, with the rest after it; in small letters where that folder's
 * file system does not tell capitals from small letters.
 */
function samePlace(path) {
  let dir = dirname(path);
  const rest = [basename(path)];
  while (!existsSync(dir) && dirname(dir) !== dir) {
    rest.unshift(basename(dir));
    dir = dirname(dir);
  }
  let real;
  try {
    real = realpathSync.native(dir);
  } catch {
    real = resolve(dir);
  }
  const full = join(real, ...rest);
  const other = real.replace(/[a-zA-Z]/g, (c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()));
  let foldsCase = false;
  if (other !== real && existsSync(other)) {
    try {
      const x = statSync(real);
      const y = statSync(other);
      foldsCase = x.ino === y.ino && x.dev === y.dev;
    } catch {
      foldsCase = false;
    }
  }
  return foldsCase ? full.toLowerCase() : full;
}

/** A sentence where two agents share a secret, or a file (a book, a journal, a journal key, a key file), or null. */
function sameSettings(agents, root) {
  const hashes = new Map();
  const files = new Map();
  for (const [name, a] of Object.entries(isObject(agents) ? agents : {})) {
    if (!isObject(a)) continue;
    if (typeof a.secretHash === 'string') {
      if (hashes.has(a.secretHash)) return `agents "${hashes.get(a.secretHash)}" and "${name}" have the same secret, so the gateway could not tell their calls apart.`;
      hashes.set(a.secretHash, name);
    }
    if (typeof a.book !== 'string') continue;
    const book = pathFrom(root, a.book);
    const own = [['book file', book], ['journal', `${book}.journal`], ['list of calls set aside', `${book}.journal-set-aside`]];
    if (!(a.journalKey instanceof Uint8Array)) own.push(['journal key', journalKeyPath(a, root, book)]);
    if (typeof a.keys === 'string') own.push(['key file', pathFrom(root, a.keys)]);
    for (const [what, p] of own) {
      for (const key of placeKeys(p)) {
        if (files.has(key)) {
          const [other, otherWhat] = files.get(key);
          return `agents "${other}" and "${name}" share a file: the ${otherWhat} of one is the ${what} of the other.`;
        }
      }
    }
    for (const [what, p] of own) for (const key of placeKeys(p)) files.set(key, [name, what]);
  }
  return null;
}
