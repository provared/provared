// provared-mcp-executor: an executor, in the sense of the Internet-Draft
// draft-izmaylov-agent-permission-receipts, for tool servers that speak the
// Model Context Protocol (MCP) over the stdio transport.
//
// The agent's MCP client starts this program as if it were the tool
// server. The executor starts the real server, holds its credentials, and
// passes every message through except these:
//
//   tools/call   is checked against the person's signed permission (the
//                slip) by the check before acting of the Provared library,
//                through the agent's stub writer, which the executor holds.
//                A call the slip allows is sent on and gets a signed receipt
//                (a stub) that names the executor in "with"; the executor
//                countersigns it with keys of its own. A call the slip does
//                not allow is not sent, and a denial is written.
//   tools/list   is passed through, with the tools that have no rule taken
//                out, unless the settings say to show them.
//
// Beside the book it keeps its own copy (copy.mjs): one tagged line before
// each call is sent and one when its receipt is in the book, in a file
// apart from the book. The copy is what shows a receipt that was never
// written, held against the book (compare.mjs).
//
// Evidence, not a verdict: the record shows what went through the
// executor. A tool the agent can reach without it leaves no trace here.

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, delimiter, dirname, isAbsolute, resolve } from 'node:path';
import { argumentsFingerprint, checkBook, countersign, denialCodes, entryLine, fingerprint, fromBase64url, identifierFingerprint, openRecorder, randomId, thumbprint } from 'provared';
import { loadCopyKey, openCopy, readCopy, unfinished } from './copy.mjs';
import { aboutSlip, bookFile, loadKeyFile, readIfThere, slipFrom, untilFree } from './files.mjs';
import { CODES, MAX_LINE_BYTES, idKey, isId, notificationLine, readLines, readMessage, repeatedName, responseLine, responseText, spliceId, topLevelId, unsafeInteger } from './jsonrpc.mjs';
import { LOCK_WAIT_MS, lockFiles } from './lock.mjs';
import { RULES_DOCUMENT, RULE_DOCUMENT, RULES_ENTRY_PREFIX, TOOL_NAME, lookUp, readPointer, readRules, rulesFingerprint, statesContentRules, testCall } from './rules.mjs';
import { RECORDER_NAME } from './sealer-client.mjs';
import { SEALER_BEHIND, SEALER_MAX_UNSENT, SEALER_MAX_UNSENT_MAX, SEALER_TIMEOUT, SEALER_TIMEOUT_MAX, SEALER_TIMEOUT_MIN, centralSealer, loadRecorder, localSealer, readRecorderKeyFile } from './sealing.mjs';

/** The document, in each stub and denial, whose fingerprint is that of the executor's own identifier for the call (a label, not a reserved name). */
export const CALL_DOCUMENT = 'executor.call';
/** The document whose fingerprint is that of the tool's name, as the client called it (reserved; format description, section 27). */
export const TOOL_DOCUMENT = 'provared.tool-name';
/** The document whose fingerprint is that of the server's result, written in the one form of RFC 8785 (reserved; section 27). */
export const RESULT_DOCUMENT = 'provared.tool-result';
/** The member of a call's params._meta in which the executor sends its identifier for the call to the server. */
export const CALL_META = 'red.prova/call-id';
/** The action name a denial carries for a call to a tool that no rule names. */
export const UNLISTED_ACTION = 'executor.unlisted';

/** The error text a receipt names where the executor stopped on request (a signal, close()) with the call with the server: the receipt is written then, before the stop completes. */
export const EXECUTOR_STOPPED = 'The executor stopped while this call was with the tool server, so its outcome is not known.';
/** The same, where the executor stopped without warning and the receipt was written at the next start, from the copy. */
export const OUTCOME_UNKNOWN = `${EXECUTOR_STOPPED} The receipt was written when the executor next started, from its own copy of what it had sent.`;
export const RESULT_NOT_FINGERPRINTED = 'The tool server answered, and its result could not be written in the one form of RFC 8785 (text that is not well-formed Unicode, a number JSON cannot write, or a whole number beyond 9,007,199,254,740,991), so the receipt names no result.';
/** The error text a receipt names where the server's answer could not be read as a message; the answer went to the client as it was. */
export const UNREADABLE_ANSWER = 'The tool server answered with a line the executor could not read as a message (not JSON, a member name given twice, or not a response), so the receipt names no result. The line was handed to the agent as it was.';
/** The document a receipt written at a restart names, and the text its fingerprint is of. */
export const WRITTEN_LATE_DOCUMENT = 'executor.written-late';
export const WRITTEN_LATE = 'This receipt was written when the executor next started, from its own copy of what it had sent: the executor stopped before the receipt could be written. Its date is the time the call was sent; the countersignature is dated at the restart.';
// A receipt written when the administrator acknowledged a call names three
// fixed texts by their fingerprints. Each says only what the executor
// knows: its copy's line for a call is written before the call goes to the
// server, so the executor knows it was sending the call, not that the
// server received it; and it cannot tell a stop from any other reason for
// the receipt not being in the book. A text is never changed once a
// version that writes it is published: receipts carry its fingerprint.
/** The document only an acknowledged receipt names (a label), and the text its fingerprint is of. */
export const ACKNOWLEDGED_DOCUMENT = 'executor.acknowledged';
export const ACKNOWLEDGED = 'The administrator acknowledged this call. The permission it was made under was not the one in force when this receipt was written.';
/** The text whose fingerprint an acknowledged receipt names under "executor.written-late" (WRITTEN_LATE_DOCUMENT), where a receipt written at a restart names WRITTEN_LATE. */
export const WRITTEN_LATER = "This receipt was written later than its call, from the executor's own copy. Its date is the time the copy gives for the call.";
/** The error text an acknowledged receipt names where the copy does not hold the call's outcome. */
export const NO_RECORD_OF_OUTCOME = 'The executor recorded that it was sending this call, and has no record of its outcome.';

/** The least and the most "recorder.sealEvery" may be, in milliseconds: a second, and seven days. Below SEAL_EVERY_SHORT (a minute) the settings are warned about. */
export const SEAL_EVERY_MIN = 1000;
export const SEAL_EVERY_MAX = 7 * 86400000;
export const SEAL_EVERY_SHORT = 60000;

/** The most requests other than tool calls kept waiting for the server's answer; past it the oldest is forgotten. */
export const MAX_MAPPED = 1000;

/** The most tools/list requests whose answers wait to be filtered. */
export const MAX_LISTS = 256;

const DEFAULT_PASS_ENV = ['PATH', 'PATHEXT', 'SYSTEMROOT', 'SystemRoot', 'COMSPEC', 'ComSpec', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'TZ'];
const SHORT_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const UNIT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/;
const TRACEPARENT = /^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,255}$/;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
/** The settings "keys" does not need: the passkeys' thumbprints and, over HTTP, the agents' secret hashes. */
const NOT_FOR_KEYS = /(^|\.)(issuerKeys|secretHash)$|^recorder\.sealer(\.|$)/;

/** The error thrown where a call was never made, so that the stub writer writes nothing. */
class NotSent extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

function pathFrom(root, p) {
  return isAbsolute(p) ? p : resolve(root, p);
}

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// --- the settings ---

/**
 * Read the settings and say what is wrong with them, without opening any
 * key, slip or credential. Gives {settings, problems, warnings, partial}.
 * "settings" is complete only where there are no problems; "partial" is what
 * could be read, problems or not (checkConfig looks at its files). With
 * "keysOnly", the settings are read as the "keys" command needs them: the
 * passkeys' thumbprints (issuerKeys) are not needed yet, since they are known
 * only once the permission is signed.
 */
export function readSettings(config, root, { keysOnly = false } = {}) {
  const problems = [];
  const warnings = [];
  const s = {};
  const at = (what, text) => {
    if (!(keysOnly && NOT_FOR_KEYS.test(what))) problems.push(`${what}: ${text}`);
  };
  if (!isObject(config)) return { settings: null, problems: ['The settings must be a JSON object.'], warnings };
  readIdentity(config, s, at);

  const server = config.server;
  if (!isObject(server)) at('server', 'must be an object naming the tool server: command, args, cwd, env.');
  else {
    s.server = {};
    if (typeof server.command !== 'string' || server.command === '') at('server.command', 'must be the program to start.');
    else s.server.command = server.command;
    s.server.args = server.args ?? [];
    if (!Array.isArray(s.server.args) || !s.server.args.every((a) => typeof a === 'string')) at('server.args', 'must be a list of texts.');
    if (server.cwd !== undefined && typeof server.cwd !== 'string') at('server.cwd', 'must be a folder.');
    s.server.cwd = server.cwd === undefined ? root : pathFrom(root, server.cwd);
    if (server.path !== undefined && (!Array.isArray(server.path) || !server.path.every((d) => typeof d === 'string' && d !== ''))) at('server.path', 'must be a list of folders in which a bare command name is looked for.');
    else s.server.path = server.path === undefined ? null : server.path.map((d) => pathFrom(root, d));
    s.server.env = {};
    if (server.env !== undefined) {
      if (!isObject(server.env)) at('server.env', 'must be an object: each member a variable name, with where its value is read from ({"file": …}, {"env": …} or {"value": …}).');
      else {
        for (const [name, from] of Object.entries(server.env)) {
          if (!ENV_NAME.test(name)) at(`server.env.${name}`, 'is not a variable name.');
          if (!isObject(from) || ['file', 'env', 'value'].filter((k) => Object.hasOwn(from, k)).length !== 1) {
            at(`server.env.${name}`, 'must say where its value is read from: exactly one of "file", "env" or "value".');
            continue;
          }
          if (Object.hasOwn(from, 'file')) {
            if (typeof from.file !== 'string') at(`server.env.${name}.file`, 'must be a path.');
            else s.server.env[name] = { file: pathFrom(root, from.file) };
          } else if (Object.hasOwn(from, 'env')) {
            if (typeof from.env !== 'string' || !ENV_NAME.test(from.env)) at(`server.env.${name}.env`, "must be a variable name in the executor's own environment.");
            else {
              s.server.env[name] = { env: from.env };
              warnings.push(`server.env.${name}: its value comes from the executor's own environment, which the agent's client sets when it starts the executor. A credential is better kept in a file of its own ("file"), readable by the executor alone.`);
            }
          } else {
            if (typeof from.value !== 'string') at(`server.env.${name}.value`, 'must be text.');
            else {
              s.server.env[name] = { value: from.value };
              warnings.push(`server.env.${name}: its value is written in the settings file. A credential is better kept in a file of its own ("file"), readable by the executor alone.`);
            }
          }
        }
      }
    }
    s.server.passEnv = server.passEnv ?? DEFAULT_PASS_ENV;
    if (!Array.isArray(s.server.passEnv) || !s.server.passEnv.every((n) => typeof n === 'string' && ENV_NAME.test(n))) at('server.passEnv', "must be a list of variable names to pass from the executor's environment to the server.");
  }

  const agent = config.agent;
  if (!isObject(agent)) at('agent', 'must be an object: slip, book, keys, issuerKeys.');
  else s.agent = readAgentPaths(agent, root, at, 'agent');

  const ex = config.executor;
  if (!isObject(ex)) at('executor', 'must be an object: keys, copy, copyKey.');
  else {
    s.executor = {};
    if (typeof ex.keys !== 'string' || ex.keys === '') at('executor.keys', 'must be a path.');
    else s.executor.keys = pathFrom(root, ex.keys);
    const copy = ex.copy ?? 'copy.jsonl';
    if (typeof copy !== 'string' || copy === '') at('executor.copy', 'must be a path.');
    else s.executor.copy = pathFrom(root, copy);
    const copyKey = ex.copyKey ?? `${copy}.key`;
    if (typeof copyKey !== 'string' || copyKey === '') at('executor.copyKey', 'must be a path.');
    else s.executor.copyKey = pathFrom(root, copyKey);
    readFormerKeys(ex, s, at, root);
  }

  readToolRules(config, s, at);
  readKnobs(config, s, at, root);
  readRecorderSettings(config, s, at, root, warnings);
  s.shutdownWait = config.shutdownWait ?? 5000;
  if (!Number.isInteger(s.shutdownWait) || s.shutdownWait < 100 || s.shutdownWait > 600000) at('shutdownWait', 'must be a whole number of milliseconds from 100 to 600,000.');
  for (const k of Object.keys(config)) {
    if (![...SHARED_KEYS, 'server', 'agent', 'executor', 'shutdownWait'].includes(k)) warnings.push(`${k}: not a setting; set aside.`);
  }
  if (s.unlisted === 'forward') warnings.push(UNLISTED_FORWARD_WARNING);
  return { settings: problems.length ? null : s, problems, warnings, partial: s };
}

/** The settings both ways of running share: the name, the service id, the tool rules and the knobs of readKnobs. */
export const SHARED_KEYS = ['name', 'service', 'tools', 'unlisted', 'hideUnlisted', 'timeout', 'denialsPerHour', 'callIdInMeta', 'maxWaiting', 'contentRules', 'recorder'];
export const UNLISTED_FORWARD_WARNING = 'unlisted is "forward": a call to a tool that no rule names is sent on with no receipt and no denial. The record then leaves those calls out.';

/**
 * The recorder that seals the books, as "recorder" names it: its key file
 * ("keys"), its name (a label on each seal; the executor's name unless
 * given) and, where the books are to be sealed on a timer, "sealEvery" in
 * milliseconds. Into s.recorder; null where the settings name none, and
 * the executor then cannot seal.
 *
 * Or, in place of the key file, a central sealer that holds the recorder's
 * keys ("sealer"): its address, the name it knows this recorder by, where
 * the recorder's token is read from (a file, or a variable of the
 * environment; never the settings), the fingerprint of the key set it
 * signs with and, where wanted, how long a question to it may take and
 * how many lines may be unsent before calls are refused. The two are not
 * named together, and a central sealer's seals give its own name.
 */
export function readRecorderSettings(config, s, at, root, warnings) {
  s.recorder = null;
  const r = config.recorder;
  if (r === undefined) return;
  if (!isObject(r)) return at('recorder', 'must be an object: keys and, where wanted, name and sealEvery.');
  const out = { keys: null, sealer: null, name: r.name ?? s.name, sealEvery: r.sealEvery ?? null };
  if (r.sealer !== undefined) {
    // The recorder's keys are in one place: with a central sealer, or in a key file here, never both (X147).
    if (r.keys !== undefined) at('recorder.keys', 'must not be named together with recorder.sealer: the recorder\'s keys are held by the central sealer, or in a key file here, not both.');
    if (r.name !== undefined) at('recorder.name', 'must not be named together with recorder.sealer: a central sealer\'s seals give its own name.');
    out.name = null;
    out.sealer = readSealerSettings(r.sealer, at, root, warnings);
  } else if (typeof r.keys !== 'string' || r.keys === '') at('recorder.keys', 'must be the path of the recorder\'s key file (provared-mcp-executor keys makes it).');
  else out.keys = pathFrom(root, r.keys);
  if (r.sealer === undefined && (typeof out.name !== 'string' || out.name.length < 1 || out.name.length > 200)) at('recorder.name', 'must be text of 1 to 200 characters.');
  if (out.sealEvery !== null && (!Number.isInteger(out.sealEvery) || out.sealEvery < SEAL_EVERY_MIN || out.sealEvery > SEAL_EVERY_MAX)) at('recorder.sealEvery', 'must be a whole number of milliseconds from 1,000 to 604,800,000 (seven days): how often each book is sealed while the executor runs. Leave it out for no timer.');
  else if (out.sealEvery !== null && out.sealEvery < SEAL_EVERY_SHORT) warnings.push(`recorder.sealEvery: ${out.sealEvery} ms is less than a minute. Each seal adds about 52 KB to a book and takes a second or two to sign.`);
  for (const k of Object.keys(r)) if (!['keys', 'name', 'sealEvery', 'sealer'].includes(k)) warnings.push(`recorder.${k}: not a setting; set aside.`);
  s.recorder = out;
}

/** "recorder.sealer", read: {address, name, token: {file} or {env}, keySet, timeout, maxUnsent}; null where it has a problem. */
function readSealerSettings(c, at, root, warnings) {
  if (!isObject(c)) {
    at('recorder.sealer', 'must be an object: address, name, token and keySet.');
    return null;
  }
  let sound = true;
  const no = (what, text) => {
    sound = false;
    at(`recorder.sealer.${what}`, text);
  };
  const out = { address: c.address, name: c.name, token: null, keySet: c.keySet, timeout: c.timeout ?? SEALER_TIMEOUT, maxUnsent: c.maxUnsent ?? SEALER_MAX_UNSENT };
  if (typeof c.address !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(c.address)) no('address', 'must be http://127.0.0.1:<port>: the central sealer listens on this computer only.');
  if (typeof c.name !== 'string' || !RECORDER_NAME.test(c.name)) no('name', 'must be the name the sealer knows this recorder by ("provared-sealer add-recorder"): 1 to 63 small letters, digits and hyphens.');
  if (typeof c.keySet !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(c.keySet)) no('keySet', 'must be the fingerprint of the key set the sealer signs with, as "provared-sealer init" prints it (43 characters).');
  // The token is read from a file or from the environment, and is never written in the settings.
  const from = c.token;
  if (!isObject(from) || Object.keys(from).length !== 1 || !['file', 'env'].some((k) => typeof from[k] === 'string' && from[k] !== '')) no('token', 'must say where the recorder\'s token is read from: {"file": <path>} or {"env": <the name of a variable>}. The token itself is never written in the settings.');
  else out.token = from.file !== undefined ? { file: pathFrom(root, from.file) } : { env: from.env };
  if (!Number.isInteger(out.timeout) || out.timeout < SEALER_TIMEOUT_MIN || out.timeout > SEALER_TIMEOUT_MAX) no('timeout', `must be a whole number of milliseconds from ${SEALER_TIMEOUT_MIN} to ${SEALER_TIMEOUT_MAX}: how long one question to the sealer may take.`);
  if (!Number.isInteger(out.maxUnsent) || out.maxUnsent < 0 || out.maxUnsent > SEALER_MAX_UNSENT_MAX) no('maxUnsent', `must be a whole number from 0 to ${SEALER_MAX_UNSENT_MAX}: how many lines of a book may be unsent before calls are refused.`);
  for (const k of Object.keys(c)) if (!['address', 'name', 'token', 'keySet', 'timeout', 'maxUnsent'].includes(k)) warnings.push(`recorder.sealer.${k}: not a setting; set aside.`);
  return sound ? out : null;
}

/**
 * Key files the executor held before its present one ("executor.formerKeys",
 * a list of paths; none unless given). They are used for one thing: to
 * countersign the receipt of a call that the administrator acknowledges,
 * where the permission the call was made under names those keys for the
 * executor. Into s.executor.formerKeys.
 */
export function readFormerKeys(ex, s, at, root) {
  s.executor.formerKeys = [];
  if (ex.formerKeys === undefined) return;
  if (!Array.isArray(ex.formerKeys) || ex.formerKeys.length > 16 || !ex.formerKeys.every((p) => typeof p === 'string' && p !== '')) return at('executor.formerKeys', 'must be a list of up to 16 paths: the key files the executor held before its present one.');
  s.executor.formerKeys = ex.formerKeys.map((p) => pathFrom(root, p));
}

/** The executor's name and its service id (the id the slip gives it in "with"). Into s. */
export function readIdentity(config, s, at) {
  s.name = config.name ?? 'Provared MCP executor';
  if (typeof s.name !== 'string' || s.name.length < 1 || s.name.length > 200) at('name', 'must be text of 1 to 200 characters.');
  s.service = config.service ?? 'executor';
  if (typeof s.service !== 'string' || !SHORT_NAME.test(s.service)) at('service', 'must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores: the id the slip gives the executor in "with".');
}

/** Whether a value is a JSON object (not null, not a list). */
export { isObject, pathFrom, SHORT_NAME, NOT_FOR_KEYS };

/** An agent's paths and issuer keys, as the settings give them under "prefix" (agent, or agents.<name>). */
export function readAgentPaths(agent, root, at, prefix) {
  const a = {};
  for (const k of ['slip', 'book', 'keys']) {
    if (typeof agent[k] !== 'string' || agent[k] === '') at(`${prefix}.${k}`, 'must be a path.');
    else a[k] = pathFrom(root, agent[k]);
  }
  a.issuerKeys = agent.issuerKeys;
  if (!Array.isArray(agent.issuerKeys) || agent.issuerKeys.length === 0 || !agent.issuerKeys.every((t) => typeof t === 'string' && /^[A-Za-z0-9_-]{43}$/.test(t))) {
    at(`${prefix}.issuerKeys`, 'must list the thumbprint of each passkey the executor trusts (43 characters of base64url each); with none, nothing is allowed.');
  }
  return a;
}

/** The rules in "tools": each tool's action and, where it applies, its amount. Into s.tools. */
export function readToolRules(config, s, at) {
  s.tools = new Map();
  if (!isObject(config.tools)) at('tools', 'must be an object: each member a tool name, with the action name the slip uses for it and, where it applies, its amount.');
  else {
    for (const [tool, rule] of Object.entries(config.tools)) {
      if (!TOOL_NAME.test(tool)) {
        at(`tools.${tool}`, 'is not a tool name (1 to 128 letters, digits, underscores, hyphens or full stops).');
        continue;
      }
      if (!isObject(rule) || typeof rule.action !== 'string' || !SHORT_NAME.test(rule.action)) {
        at(`tools.${tool}.action`, 'must be an action name of the slip: 1 to 64 lower-case letters, digits, full stops, hyphens or underscores.');
        continue;
      }
      const entry = { tool, action: rule.action };
      if (rule.amount !== undefined) {
        const a = rule.amount;
        const kinds = isObject(a) ? ['value', 'pointer', 'count'].filter((k) => Object.hasOwn(a, k)) : [];
        if (!isObject(a) || typeof a.unit !== 'string' || !UNIT.test(a.unit) || kinds.length !== 1) {
          at(`tools.${tool}.amount`, 'must be {"unit", "value"}, {"unit", "pointer"} or {"unit", "count"}.');
          continue;
        }
        if (kinds[0] === 'value') {
          if (!Number.isInteger(a.value) || a.value < 0 || a.value > MAX_SAFE) {
            at(`tools.${tool}.amount.value`, 'must be a whole number from 0 up.');
            continue;
          }
          entry.amount = { unit: a.unit, value: a.value };
        } else {
          const pointer = a[kinds[0]];
          const tokens = readPointer(pointer);
          if (!tokens) {
            at(`tools.${tool}.amount.${kinds[0]}`, "must be a JSON Pointer (RFC 6901) into the call's arguments, such as \"/total\".");
            continue;
          }
          entry.amount = { unit: a.unit, [kinds[0]]: pointer, tokens };
        }
      }
      s.tools.set(tool, entry);
    }
  }
}

/** The knobs both ways of running share: unlisted, hideUnlisted, timeout, denialsPerHour, callIdInMeta, contentRules, maxWaiting. Into s. */
export function readKnobs(config, s, at, root) {
  s.unlisted = config.unlisted ?? 'refuse';
  if (!['refuse', 'forward'].includes(s.unlisted)) at('unlisted', 'must be "refuse" or "forward".');
  s.hideUnlisted = config.hideUnlisted ?? true;
  if (typeof s.hideUnlisted !== 'boolean') at('hideUnlisted', 'must be true or false.');
  s.timeout = config.timeout ?? 300000;
  if (!Number.isInteger(s.timeout) || s.timeout < 1000 || s.timeout > 86400000) at('timeout', 'must be a whole number of milliseconds from 1,000 to 86,400,000.');
  s.denialsPerHour = config.denialsPerHour ?? 600;
  if (!Number.isInteger(s.denialsPerHour) || s.denialsPerHour < 1 || s.denialsPerHour > 100000) at('denialsPerHour', 'must be a whole number from 1 to 100,000.');
  s.callIdInMeta = config.callIdInMeta ?? true;
  if (typeof s.callIdInMeta !== 'boolean') at('callIdInMeta', 'must be true or false.');
  s.contentRules = null;
  if (config.contentRules !== undefined) {
    if (typeof config.contentRules !== 'string' || config.contentRules === '') at('contentRules', 'must be the path of the rules file (rules on the content of a change).');
    else s.contentRules = pathFrom(root, config.contentRules);
  }
  s.maxWaiting = config.maxWaiting ?? 16;
  if (!Number.isInteger(s.maxWaiting) || s.maxWaiting < 1 || s.maxWaiting > 1000) at('maxWaiting', 'must be a whole number from 1 to 1,000: the most tool calls in progress or waiting their turn at once.');
}

/**
 * The amount of a call, as its rule says: a fixed value, the whole number at
 * a pointer in the arguments, or the length of the list there. Gives
 * {amount} or {problem}. Where the amount is read from the arguments, an
 * argument object that names one member twice once folded (foldName) gives
 * no amount: a server may read the other one. (With a fixed value, or no
 * amount, the arguments are not read, and such names pass.)
 */
export function amountOf(rule, args, argsText) {
  if (!rule.amount) return {};
  if (Object.hasOwn(rule.amount, 'value')) return { amount: { unit: rule.amount.unit, value: rule.amount.value } };
  const no = (message) => ({ problem: { code: 'amount-not-found', message: `${message} The rule takes the amount from the arguments, so the call was not taken.` } });
  if (args === undefined) return no('The call has no arguments.');
  if (repeatedName(argsText, true) !== null) return no('The arguments name one member twice in one object, or two that differ only in capitals, which two readers may read differently.');
  const where = rule.amount.pointer ?? rule.amount.count;
  const found = lookUp(args, rule.amount.tokens);
  if (!found.found) return no(`Nothing is found in the arguments at ${JSON.stringify(where)}.`);
  if (Object.hasOwn(rule.amount, 'count')) {
    if (!Array.isArray(found.value)) return no(`What is found at ${JSON.stringify(where)} is not a list.`);
    return { amount: { unit: rule.amount.unit, value: found.value.length } };
  }
  if (!Number.isInteger(found.value) || found.value < 0 || found.value > MAX_SAFE) return no(`What is found at ${JSON.stringify(where)} is not a whole number from 0 up to 9,007,199,254,740,991.`);
  return { amount: { unit: rule.amount.unit, value: found.value } };
}

// --- the program, the keys, the slip and the credentials ---

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * The program to start, as an absolute path. A name with a folder in it is
 * read from the settings file's folder; a bare name is looked for in the
 * folders of "server.path" or, failing that, of the executor's own PATH,
 * which the agent's client set. Gives {path, warning}; throws where the
 * program is not found. On Windows a bare name is tried with .exe and .com,
 * which a program started without a shell can run (not .cmd or .bat).
 */
export function resolveCommand(command, { root, path, env = process.env, platform = process.platform }) {
  const named = /[\\/]/.test(command);
  if (named) {
    const full = pathFrom(root, command);
    if (!isFile(full)) throw new Error(`server.command: ${full} was not found.`);
    return { path: full, warning: null };
  }
  const windows = platform === 'win32';
  const dirs = path ?? (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean);
  const exts = windows ? ['', '.exe', '.com'] : [''];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = resolve(dir, command + ext);
      if (isFile(candidate)) {
        return { path: candidate, warning: path ? null : `server.command: the bare name "${command}" was found through the executor's own PATH, which the agent's client sets, as ${candidate}. Name the program by its path, or give "server.path", so that the client cannot choose which program is given the credential.` };
      }
    }
  }
  throw new Error(`server.command: no program named "${command}" was found in ${path ? '"server.path"' : "the executor's PATH"}. Name it by its path.`);
}

function sameKeys(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Read a credential's value from where the settings say. Its value is returned, never logged. */
function credentialValue(name, from) {
  if (from.value !== undefined) return from.value;
  if (from.env !== undefined) {
    const v = process.env[from.env];
    if (v === undefined) throw new Error(`server.env.${name}: the variable ${from.env} is not set in the executor's environment.`);
    return v;
  }
  return readCredentialFile(from.file, `server.env.${name}`);
}

/** Read a credential from a file, as the gateway does: one line ending at the end is dropped. Its value is returned, never logged. */
export function readCredentialFile(path, what) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new Error(`${what}: the file could not be read (${e.code ?? e.message}).`);
  }
  return text.replace(/\r?\n$/, '');
}

/** The entry for the permission's agent.software that states a rules file. */
export function softwareEntry(name, sha256) {
  return { name: `${RULES_ENTRY_PREFIX}${name}`, sha256 };
}

/** Read the rules file strictly and fingerprint it: {rules, fingerprint, names}. Throws where it is missing or has problems. */
export async function loadRules(path) {
  let bytes;
  try {
    bytes = untilFree(() => readFileSync(path));
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    bytes = Buffer.alloc(0);
  }
  if (bytes.length === 0) throw new Error(`The rules file ${path} (contentRules) is missing or empty.`);
  // The bytes, not text: readRules decodes them as strict UTF-8.
  const { rules, parsed, problems } = readRules(bytes);
  if (problems.length) throw new Error(`The rules file ${path} has problems:\n- ${problems.join('\n- ')}`);
  return { rules, fingerprint: await rulesFingerprint(parsed), names: rules.map((r) => r.name) };
}

/**
 * Open what every agent shares: the executor's own keys, and the rules on
 * content where the settings name a rules file. Gives
 * {executorKeys, content, warnings}; throws where a rule names a tool that
 * "forward" would send on untested.
 */
export async function prepareShared(settings) {
  const warnings = [];
  const executorKeys = await loadKeyFile(settings.executor.keys, 'agent');
  let content = null;
  if (settings.contentRules) {
    content = await loadRules(settings.contentRules);
    for (const rule of content.rules) {
      for (const tool of rule.tools) {
        if (settings.tools.has(tool)) continue;
        // With "forward", a call to a tool that no rule in "tools" names is sent on before any content rule is reached, so the content rule would never be tested.
        if (settings.unlisted === 'forward') throw new Error(`contentRules: the rule ${JSON.stringify(rule.name)} names the tool "${tool}", which no rule in "tools" names, and "unlisted" is "forward": a call to that tool would be sent on with no content rule tested. Add "${tool}" to "tools", or set "unlisted" to "refuse".`);
        warnings.push(`contentRules: the rule ${JSON.stringify(rule.name)} names the tool "${tool}", which no rule in "tools" names, so the executor never sends a call to it and the content rule is never tested.`);
      }
    }
  }
  // The recorder that seals, where the settings name one: its key file is read through sealing.mjs.
  // Or a central sealer that holds the keys elsewhere: the executor then holds the recorder's token, and no key of the recorder's.
  const sealer = !settings.recorder ? null : settings.recorder.sealer ? centralSealer(settings.recorder.sealer) : localSealer(await loadRecorder(settings.recorder));
  // The key files the executor held before: used only to countersign a receipt the administrator acknowledges.
  const formerKeys = [];
  for (const path of settings.executor.formerKeys ?? []) formerKeys.push(await loadKeyFile(path, 'agent'));
  return { executorKeys, content, warnings, sealer, formerKeys };
}

/**
 * Open one agent: its keys, its slip (held against the executor's keys, the
 * tool rules and the rules on content), its book, its copy and its stub
 * writer. "paths": slip, book, keys, issuerKeys, copy, copyKey. Says what
 * is wrong in one error. With "readOnly" nothing is written: no slip line to
 * the book file, no copy key made (checkConfig). "lockWait": how long to ask
 * again for the lock while another program holds it (0: once).
 */
export async function prepareAgent(paths, settings, shared, { now = Date.now, readOnly = false, lockWait = 0 } = {}) {
  // One program writes a book and its copy at a time: the lock is taken before anything is read (lock.mjs).
  const lock = readOnly ? null : await lockFiles(paths.book, { wait: lockWait });
  try {
    return { ...(await readAgentFiles(paths, settings, shared, { now, readOnly })), release: () => (lock ? lock.release() : Promise.resolve()) };
  } catch (e) {
    if (lock) await lock.release();
    throw e;
  }
}

async function readAgentFiles(paths, settings, shared, { now, readOnly }) {
  const warnings = [];
  const { executorKeys, content } = shared;
  const agentKeys = await loadKeyFile(paths.keys, 'agent');
  const slipText = readIfThere(paths.slip);
  if (slipText === '') throw new Error(`The slip ${paths.slip} is missing. Sign the permission (at https://sign.prova.red) and save it there.`);
  const about = await aboutSlip(slipFrom(slipText, paths.slip));
  const c = about.content;
  if (!sameKeys(c.agent?.keys, agentKeys.keys)) throw new Error(`The slip ${paths.slip} names other agent keys than ${paths.keys} holds. The executor writes receipts only under a permission for the keys it holds.`);
  const named = Array.isArray(c.with) ? c.with.find((w) => w?.id === settings.service) : undefined;
  if (!named) throw new Error(`The slip does not name the executor in "with" as "${settings.service}". Add {"id": "${settings.service}", "name": …, "keys": <the executor's keys>} to the permission's "with" (provared-mcp-executor keys prints the entry).`);
  if (!sameKeys(named.keys, executorKeys.keys)) throw new Error(`The slip names "${settings.service}" in "with" with other keys than ${settings.executor.keys} holds, so the executor's countersignatures would not check.`);
  if (!paths.issuerKeys.includes(about.issuerKey)) {
    throw new Error(`The slip was signed by a passkey (thumbprint ${about.issuerKey}) that agent.issuerKeys does not list, so nothing would be allowed.`);
  }
  const requires = Array.isArray(c.requires) ? c.requires : [];
  const all = requires.some((r) => r?.need === 'countersignature' && r.action === undefined && r.above === undefined);
  if (!all) warnings.push('The slip does not require a countersignature for every action ("requires": [{"need": "countersignature"}]). The executor countersigns anyway, but a receipt without its countersignature is then not a finding, so the record cannot show by itself that a call went round the executor.');
  const others = (Array.isArray(c.with) ? c.with : []).filter((w) => w?.id !== settings.service).map((w) => w?.id);
  if (others.length) warnings.push(`The slip names other services beside the executor in "with" (${others.join(', ')}). A receipt that names one of them, written by whoever holds the agent's keys, would not be a finding; name only the executor, so that every receipt must carry its countersignature.`);
  const actions = new Set(Array.isArray(c.actions) ? c.actions : []);
  for (const rule of settings.tools.values()) {
    if (!actions.has(rule.action)) warnings.push(`tools.${rule.tool}: its action "${rule.action}" is not among the slip's actions, so every call to it will be refused (action-not-allowed).`);
  }
  // The rules on content, held against what the slip states of the agent's
  // software: nothing where it states nothing (a warning says how to add
  // it); a stop where it states software and not these rules, since the
  // person approved other rules; and a stop where the slip states rules on
  // content and the settings name no rules file, since the person approved
  // rules and none would run.
  if (!settings.contentRules && statesContentRules(c.agent?.software)) {
    throw new Error(`The slip ${paths.slip} states rules on content in the agent's software (agent.software holds an entry whose name begins "${RULES_ENTRY_PREFIX}"), and the settings name no rules file (contentRules): the executor would run without the rules the person approved. Set "contentRules" to the approved rules file, or sign a permission that states no rules on content.`);
  }
  if (content) {
    const software = Array.isArray(c.agent?.software) ? c.agent.software : null;
    const entry = JSON.stringify(softwareEntry(settings.name, content.fingerprint));
    if (software && !software.some((x) => x?.sha256 === content.fingerprint)) {
      throw new Error(`The slip ${paths.slip} states the agent's software (agent.software), and the rules on content in force (${settings.contentRules}, fingerprint ${content.fingerprint}) are not among what it states: the person approved other rules than these. Put the approved rules file back, or sign a permission whose agent.software holds ${entry}.`);
    }
    if (!software) warnings.push(`The slip states nothing of the agent's software (agent.software), so a reader cannot see that the rules on content in force are the ones the person approved. Add ${entry} to the permission's agent.software and sign it again (provared-mcp-executor keys prints the entry).`);
  }

  // The book and the stub writer. The slip goes into the book first,
  // where the book does not hold it yet: a new book, or a new slip.
  const onDisk = readIfThere(paths.book);
  let text = onDisk;
  // Where the settings name a recorder, a seal in the book must be that recorder's: one signed with other keys is a problem (sealer-not-expected).
  const options = shared.sealer ? { sealKeys: [shared.sealer.fingerprint] } : {};
  const checkOptions = { ...options, issuerKeys: paths.issuerKeys };
  let result = text ? await checkBook(text, checkOptions) : null;
  if (result && result.summary.problemFound) throw new Error(`The book file ${paths.book} does not pass its check, so the executor does not write to it.`);
  if (!result || !result.entries.some((e) => e.kind === 'slip' && e.fingerprint === about.fingerprint)) {
    text += `${entryLine({ slip: about.slip })}\n`;
    result = await checkBook(text, checkOptions);
    if (result.summary.problemFound) throw new Error(`The slip does not pass its check: ${result.entries.at(-1).problems.map((q) => q.message).join(' ')}`);
  }
  const file = bookFile(paths.book, onDisk);
  const writer = await openRecorder({
    book: text,
    slip: about.fingerprint,
    privateKeys: agentKeys.privateKeys,
    issuerKeys: paths.issuerKeys,
    options,
    now,
    denials: true,
    denialsPerHour: settings.denialsPerHour,
  });
  // The slip's line, where it is new, is in the writer's book and not yet in the file: openAgent's save() writes it, as it writes every line.
  const copyKey = loadCopyKey(paths.copyKey, { create: !readOnly });
  const read = copyKey ? readCopy(paths.copy, copyKey, settings.name) : { lines: [], checked: 0, refused: 0, cut: null, next: 0, sequence: { ok: true, problem: null } };
  if (!copyKey && existsSync(paths.copy)) throw new Error(`The copy ${paths.copy} holds lines, and its key ${paths.copyKey} is missing, so no line could be checked. Put the key back.`);
  if (read.cut !== null) throw new Error(`The copy ${paths.copy} ends part-way through a line (a stop while it was written). Look at it, and take off the part line by hand before the executor starts.`);
  if (read.lines.length > 0 && read.checked === 0) throw new Error(`No line of the copy ${paths.copy} checks under the copy key ${paths.copyKey}: the key is not the one the copy was written with. Put back the key the copy was written with.`);
  if (!read.sequence.ok) throw new Error(`The copy ${paths.copy} is not whole: ${read.sequence.problem} The executor does not start on a copy with a line missing, moved or put twice; look at it, and keep what it shows.`);
  const copy = copyKey ? openCopy(paths.copy, copyKey, settings.name, read.next) : null;
  // For a central sealer: the book file's text as it was found, and the seals the book holds, each at its entry.
  const seals = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0).map((e) => ({ index: e.index, fingerprint: e.fingerprint }));
  return { paths, warnings, agentKeys, about, file, writer, copy, read, options, checkOptions, onDisk, seals };
}

/**
 * Open everything the stdio executor needs but the server: the keys, the
 * slip, the book, the copy, the stub writer and the credentials. Says what
 * is wrong in one error. With "readOnly" nothing is written (checkConfig).
 * With "offline" (the commands that work on the files of an executor that
 * is not running) the server's program and its credentials are not read:
 * no server is started.
 */
async function prepare(config, root, { now = Date.now, readOnly = false, offline = false, lockWait } = {}) {
  const { settings, problems, warnings } = readSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const env = {};
  const credentialNames = [];
  if (!offline) {
    const program = resolveCommand(settings.server.command, { root, path: settings.server.path });
    if (program.warning) warnings.push(program.warning);
    settings.server.resolved = program.path;
  }
  const shared = await prepareShared(settings);
  warnings.push(...shared.warnings);
  if (!offline) {
    // The credentials: read now, so that a missing one stops the start, and
    // kept in memory for the server's environment alone.
    for (const name of settings.server.passEnv) {
      const v = process.env[name];
      if (v !== undefined) env[name] = v;
    }
    for (const [name, from] of Object.entries(settings.server.env)) {
      env[name] = credentialValue(name, from);
      credentialNames.push(name);
    }
  }
  // A start asks again for the lock while the executor before it may still be ending: for as long as its server is given to end, and 5 seconds more (10 seconds at least). A command asks once.
  const wait = offline || readOnly ? 0 : (lockWait ?? Math.max(LOCK_WAIT_MS, settings.shutdownWait + 5000));
  const agent = await prepareAgent({ ...settings.agent, copy: settings.executor.copy, copyKey: settings.executor.copyKey }, settings, shared, { now, readOnly, lockWait: wait });
  warnings.push(...agent.warnings);
  return { settings, warnings, agent, agentKeys: agent.agentKeys, executorKeys: shared.executorKeys, about: agent.about, env, credentialNames, read: agent.read, content: shared.content, sealer: shared.sealer, formerKeys: shared.formerKeys };
}

/** What "check" says where the settings name no recorder. */
export const NO_RECORDER_WARNING = 'recorder: none is named, so the executor cannot seal its books. To seal, name its key file ("recorder": {"keys": "keys/recorder.jwk"}) and run "provared-mcp-executor keys".';

/** The recorder, as "check" and "status" show it: its name, the fingerprint of its key set (what a person checking names as the recorder they expect) and the timer. Null where the settings name none. */
export function describeRecorder(settings, sealer) {
  if (!sealer) return null;
  // A central sealer: the key set it signs with as the settings name it, its address, and the name it knows this recorder by. Its seals give its own name.
  if (sealer.central) return { fingerprint: sealer.fingerprint, sealEvery: settings.recorder.sealEvery, sealer: { address: sealer.address, recorder: sealer.name, maxUnsent: settings.recorder.sealer.maxUnsent } };
  return { name: sealer.name, fingerprint: sealer.fingerprint, sealEvery: settings.recorder.sealEvery };
}

/**
 * Check the settings, the keys, the slip and the credentials, as a start
 * would, without starting the server and without writing anything. Gives
 * {problems, warnings, tools, slip}. Every problem that can be found on its
 * own is listed in one run: the settings, a placeholder of the example
 * still in place, the server's program and folder, each credential, the
 * rules file, each key file and the slip (missingFiles). Only where none is
 * found are the slip, the keys and the rules held against each other, as a
 * start does; that part stops at the first difference, since a start stops
 * there too.
 */
export async function checkConfig(config, root) {
  const { settings, problems: found, warnings, partial } = readSettings(config, root);
  const tools = settings ? describeTools(settings) : [];
  const problems = placeholderProblems(config, found);
  if (partial) {
    const s = partial;
    if (s.server?.command && s.server.path !== undefined && !isPlaceholder(s.server.command)) {
      try {
        resolveCommand(s.server.command, { root, path: s.server.path });
      } catch (e) {
        problems.push(e.message);
      }
    }
    if (typeof config.server?.cwd === 'string' && !isPlaceholder(config.server.cwd) && !isFolder(s.server.cwd)) problems.push(`server.cwd: the folder ${s.server.cwd} does not exist.`);
    for (const [name, from] of Object.entries(s.server?.env ?? {})) {
      if (from.file !== undefined && isPlaceholder(config.server.env[name].file)) continue;
      try {
        credentialValue(name, from);
      } catch (e) {
        problems.push(e.message);
      }
    }
    problems.push(...(await missingFiles(s, s.agent ? [['agent', s.agent]] : [])));
  }
  if (problems.length) return { problems, warnings, tools };
  try {
    const p = await prepare(config, root, { readOnly: true });
    if (!p.sealer) p.warnings.push(NO_RECORDER_WARNING);
    return { problems: [], warnings: p.warnings, tools, program: p.settings.server.resolved, slip: describeSlip(p.about, p.content), credentials: p.credentialNames, contentRules: describeContentRules(p.settings, p.content, p.about), unfinished: unfinished(p.read).length, recorder: describeRecorder(p.settings, p.sealer) };
  } catch (e) {
    return { problems: [e.message], warnings, tools };
  }
}

/**
 * The placeholders of the two example settings files, word for word: what
 * a person must put in before the settings can pass. Only these texts are
 * taken for placeholders, so that no value of a person's own is.
 */
export const PLACEHOLDERS = Object.freeze([
  "<path of your MCP tool server's program>",
  '<folder your tool server runs in>',
  "<file that holds your tool server's credential>",
  "<thumbprint of the person's passkey>",
  "<file that holds the upstream's bearer token>",
  '<hash that provared-mcp-executor secret prints>',
]);

/** A text that is still one of the example's placeholders (PLACEHOLDERS). */
export function isPlaceholder(text) {
  return PLACEHOLDERS.includes(text);
}

function isFolder(path) {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Each placeholder of the example still in the settings, as a problem of
 * its own, and the problems the settings gave, less those about a setting
 * that holds a placeholder (the placeholder says it better).
 */
export function placeholderProblems(config, problems) {
  const out = [];
  const fields = new Set();
  const walk = (v, path) => {
    if (isPlaceholder(v)) {
      out.push(`${path}: still holds the example's placeholder ${JSON.stringify(v)}. Put in the ${v.slice(1, -1)}.`);
      fields.add(path.replace(/\[\d+\]$/, ''));
    } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${path}[${i}]`));
    else if (isObject(v)) for (const [k, x] of Object.entries(v)) walk(x, path ? `${path}.${k}` : k);
  };
  walk(config, '');
  return [...out, ...problems.filter((p) => ![...fields].some((f) => p.startsWith(`${f}: `)))];
}

/**
 * The problems with the files the settings name that can be found each on
 * its own: the rules file, the executor's key file and, for each agent
 * ([prefix of its settings, paths]), its key file and its slip. A missing key file is named
 * with the command that makes it. Paths that hold a placeholder are left to
 * placeholderProblems.
 */
export async function missingFiles(s, agents) {
  const problems = [];
  const keyFile = async (path, what, kind = 'agent') => {
    if (!path || isPlaceholder(basename(path))) return;
    if (!existsSync(path)) problems.push(`${what}: the key file ${path} does not exist yet. Make it with "provared-mcp-executor keys --config <this settings file>".`);
    else {
      try {
        if (kind === 'recorder') await readRecorderKeyFile(path);
        else await loadKeyFile(path, kind);
      } catch (e) {
        problems.push(`${what}: ${e.message}`);
      }
    }
  };
  if (s.contentRules && !isPlaceholder(basename(s.contentRules))) {
    try {
      await loadRules(s.contentRules);
    } catch (e) {
      problems.push(e.message);
    }
  }
  await keyFile(s.executor?.keys, 'executor.keys');
  await keyFile(s.recorder?.keys, 'recorder.keys', 'recorder');
  for (const [i, path] of (s.executor?.formerKeys ?? []).entries()) {
    if (!existsSync(path)) problems.push(`executor.formerKeys[${i}]: the key file ${path} does not exist. Name only key files the executor held before, or take it out.`);
    else await keyFile(path, `executor.formerKeys[${i}]`);
  }
  for (const [prefix, paths] of agents) {
    await keyFile(paths.keys, `${prefix}.keys`);
    if (paths.slip && !isPlaceholder(basename(paths.slip)) && readIfThere(paths.slip) === '') problems.push(`${prefix}.slip: the slip ${paths.slip} is missing. Sign the permission (at https://sign.prova.red) and save it there${isFolder(dirname(paths.slip)) ? '' : `, in the folder ${dirname(paths.slip)}, which does not exist yet: make it first`}.`);
  }
  return problems;
}

/** The tool rules, as "check" shows them. */
export function describeTools(settings) {
  return [...settings.tools.values()].map((t) => {
    const shown = { tool: t.tool, action: t.action };
    if (t.amount) {
      shown.amount = { unit: t.amount.unit };
      if (t.amount.value !== undefined) shown.amount.value = t.amount.value;
      else if (t.amount.pointer !== undefined) shown.amount.pointer = t.amount.pointer;
      else shown.amount.count = t.amount.count;
    }
    return shown;
  });
}

/** A slip, as "check" shows it. */
export function describeSlip(about) {
  return { fingerprint: about.fingerprint, issuerKey: about.issuerKey, agent: about.content.agent?.name, validUntil: about.content.validUntil };
}

/** The rules on content in force, as "check" shows them, with whether this slip states them. */
export function describeContentRules(settings, content, about) {
  if (!content) return null;
  const software = Array.isArray(about.content.agent?.software) ? about.content.agent.software : null;
  return { path: settings.contentRules, fingerprint: content.fingerprint, rules: content.names, statedInSlip: software ? software.some((x) => x?.sha256 === content.fingerprint) : null };
}

// --- one agent, running ---

/**
 * One agent as the executor runs it: its writer, book file and copy; one
 * call at a time through its writer; whether it has stopped; and the calls
 * it has in progress. A call its copy shows as sent and never given its
 * receipt (the executor stopped meanwhile) is given one now, under the slip
 * it was sent under: with what the executor knew of the outcome where the
 * copy holds that, or naming "provared.error" with OUTCOME_UNKNOWN. Where
 * that slip is not the one in force, the call waits for the administrator
 * ("pending"): the agent takes no call until each such call has been
 * acknowledged or set aside ("acknowledge"). With "name" (several agents)
 * every log event names the agent. With "sealer" (sealing.mjs) the agent's
 * book can be sealed ("seal"). With "late" false (a command at work on the
 * files of an executor that is not running) no receipt is written by
 * itself: the calls that a start would give a late receipt are left for
 * the start, and the book is not sealed while there are any. "formerKeys"
 * are the key files the executor held before (prepareShared).
 */
export async function openAgent(prepared, { settings, executorKeys, now, log, name = null, sealer = null, late = true, formerKeys = [] }) {
  const { about, file, writer, copy, paths, options } = prepared;
  const agentLog = name === null ? log : (event) => log({ agent: name, ...event });
  for (const l of prepared.read.lines) if (!l.valid) agentLog({ event: 'copy-line-refused', line: l.raw.slice(0, 80) });

  let stopped = null;
  const stop = (why, event) => {
    stopped ??= why;
    agentLog({ event, reason: why });
  };
  /** The calls sent under a permission no longer in force that have no receipt: while there are any, the agent takes no call. */
  let pending = [];
  /** The book's link to a central sealer, where the settings name one (sealing.mjs): every line the file gains is sent to it. */
  let link = null;
  /** Why the agent takes no call: something it could not write, a seal of the central sealer's that must be added first, or calls that wait for the administrator. Null where it takes calls. */
  const stoppedNow = () => stopped ?? link?.doubt() ?? (pending.length ? waitingWords(pending) : null);

  /** Append what the book gained to its file, and send the new lines' leaf fingerprints to the central sealer, where there is one. False, and the agent stopped, where the file could not be written. */
  function save() {
    try {
      file.save(writer.book());
    } catch (e) {
      stop(`the book could not be written (${e.message}).`, 'book-not-written');
      return false;
    }
    // Only what is in the file is sent.
    link?.wrote(writer.book());
    return true;
  }

  /**
   * Add a seal the central sealer signed, through the stub writer's "add",
   * which takes it only if the whole book still passes its check with it.
   * A seal the book refuses was signed over other lines than the book
   * holds: the two do not agree, and the agent is stopped. Gives {entry,
   * fingerprint} as the book's own check has them.
   */
  async function addCentralSeal(entry) {
    // At a start, a permission new to the book is in the writer and not yet in the file: the seal covers the file, and would come after it.
    if (!started && !file.holds(writer.book())) throw Object.assign(new Error('The central sealer signed a seal over the book as its file stands, which the book never took, and the permission in force is new to the book: its line would come before the seal. Start the executor once with the permission the book last held, so that the seal is added; then with the new one.'), { notTaken: true });
    try {
      await writer.add(entry);
    } catch (e) {
      link.fail(`the central sealer signed a seal that the book does not take (${e.message}), so the book and what the sealer holds of it do not agree.`);
      throw new Error(`The agent is stopped: ${stopped}`);
    }
    if (!save()) throw new Error(`The seal is in the executor's memory, and the book file could not be written: ${stopped}`);
    const added = (await writer.check()).entries.at(-1);
    link.sealed(added.index, added.fingerprint);
    agentLog({ event: 'sealed', entry: added.index, seal: added.fingerprint, by: 'central-sealer' });
    return { entry: added.index, fingerprint: added.fingerprint };
  }

  let started = false;
  if (sealer?.central) {
    const book = writer.book();
    link = sealer.open({
      first: book.slice(0, book.indexOf('\n')),
      seals: prepared.seals,
      now,
      log: agentLog,
      disagree: (why) => stop(why, 'sealer-disagrees'),
      // A seal the sealer signed and the book never took: at a start it is added at once; later, in the agent's turn.
      takeBack: (entry) => (started ? inTurn(() => addCentralSeal(entry)) : addCentralSeal(entry)),
    });
    // Before anything is written: the sealer must answer, and what it holds must agree with the book file.
    await link.start(prepared.onDisk);
  }
  // The slip's line, where the book did not hold it yet, reaches the file here, as every line does.
  if (!save()) throw new Error(`The book file ${paths.book} could not be written: ${stopped}`);
  // And the sealer must take it, with every line before it, before the agent takes a call.
  if (link) await link.level();

  /** How many calls a start will give a late receipt, left alone because this is not a start. */
  let lateWaiting = 0;
  // Calls the copy shows as sent and not finished.
  const open = unfinished(prepared.read);
  if (open.length) {
    const sorted = await sortUnfinished(open, await writer.check(), { settings, about, agentKeys: prepared.agentKeys.keys, executorKeys: executorKeys.keys, formerKeys: formerKeys.map((k) => k.keys), startedAt: now() });
    for (const f of sorted.found) copy.note({ kind: 'done', call: f.call, when: new Date(now()).toISOString(), outcome: 'found-in-book', stub: f.stub });
    // Sent under a permission that is no longer the one in force: these wait for the administrator.
    pending = sorted.pending;
    if (pending.length) agentLog({ event: 'receipt-missing', calls: pending.map(shownCall) });
    if (!late) lateWaiting = sorted.late.length;
    for (const { sending: s, done: d } of late ? sorted.late : []) {
      // What the copy knows of the outcome, where the receipt was made and could not be written; else the fixed text.
      const known = Array.isArray(d?.documents) && d.documents.length ? d.documents : null;
      const details = [...(Array.isArray(s.details) ? s.details : []), ...(known ?? [{ name: 'provared.error', sha256: await identifierFingerprint(OUTCOME_UNKNOWN) }]), { name: WRITTEN_LATE_DOCUMENT, sha256: await identifierFingerprint(WRITTEN_LATE) }];
      let made;
      try {
        made = await writer.record({ action: s.action, ...(s.amount ? { amount: s.amount } : {}), with: settings.service, details }, { when: Date.parse(s.when), countersign: (stub) => countersign(stub, executorKeys.privateKeys, now()) });
      } catch (e) {
        throw new Error(`The copy shows call ${s.call} sent and never given its receipt, and the receipt could not be written now (${e.message}). The executor does not start until it is.`);
      }
      if (!save()) throw new Error(`The receipt of call ${s.call} could not be written to the book file: ${stopped}`);
      copy.note({ kind: 'done', call: s.call, when: new Date(now()).toISOString(), outcome: known ? 'written-late' : 'outcome-unknown', stub: made.fingerprint, countersigned: made.countersignature.accepted });
      agentLog({ event: 'receipt-written-late', call: s.call, stub: made.fingerprint, outcome: known ? 'as the copy knew it' : 'not known' });
    }
  }

  // One tool call at a time goes through the writer; this is its queue. A
  // seal and an acknowledgement take their turn in it too: a seal must
  // cover the book as it is.
  let turn = Promise.resolve();
  let busy = 0;
  const inTurn = (work) => {
    const counted = async () => {
      busy += 1;
      try {
        return await work();
      } finally {
        busy -= 1;
      }
    };
    const mine = turn.then(counted, counted);
    turn = mine.then(
      () => {},
      () => {},
    );
    return mine;
  };

  /** Before a seal or an acknowledged receipt is written: the book file must hold the book, as the executor left it. Throws, and stops the agent, where it does not. */
  const fileAsLeft = () => {
    if (!file.holds(writer.book()) && !save()) throw new Error(`The book file could not be written: ${stopped}`);
    let intact;
    try {
      intact = file.intact();
    } catch {
      intact = false;
    }
    if (!intact) {
      stop('the book file is not as the executor left it: something else changed it.', 'book-changed');
      throw new Error(`The agent is stopped: ${stopped}`);
    }
  };

  /**
   * Seal the book now, with the recorder's keys. The seal goes into the
   * book only if the whole book still passes its check with it (the stub
   * writer's "add"). With "onlyIfNew", nothing is sealed where the book's
   * last entry is its last seal; with "olderThan" (milliseconds), nothing
   * where its last seal is younger than that. Gives {sealed: true, entry,
   * fingerprint}, or {sealed: false, reason}.
   */
  function seal({ onlyIfNew = false, olderThan = null } = {}) {
    if (!sealer) throw new Error('The settings name no recorder ("recorder"), so the executor cannot seal.');
    return inTurn(async () => {
      // A seal of the central sealer's that waits to be added does not hold up a seal: asking for one is how it is added.
      const why = stopped ?? (pending.length ? waitingWords(pending) : null);
      if (why) throw new Error(`The agent is stopped: ${why}`);
      if (lateWaiting) throw new Error(`The copy shows ${lateWaiting} call(s) with no receipt in the book, which the executor's next start will give one. The book is not sealed before that: start the executor, and seal then.`);
      fileAsLeft();
      const result = await writer.check();
      const last = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0).at(-1);
      if (onlyIfNew && last && last.index === result.size - 1) return { sealed: false, reason: 'nothing-new' };
      if (olderThan !== null && last && now() - Date.parse(last.content.when) < olderThan) return { sealed: false, reason: 'not-due' };
      if (link) {
        // The central sealer signs over the lines it was sent, and only once it holds every one; its seal's entry is added as it is.
        const { entry } = await link.seal(last?.fingerprint, now());
        return { sealed: true, ...(await addCentralSeal(entry)) };
      }
      const sealed = await sealer.seal(writer.book(), { previous: last?.fingerprint, when: now() });
      await writer.add({ seal: sealed.record });
      if (!save()) throw new Error(`The seal is in the executor's memory, and the book file could not be written: ${stopped}`);
      agentLog({ event: 'sealed', entry: result.size, seal: sealed.fingerprint });
      return { sealed: true, entry: result.size, fingerprint: sealed.fingerprint };
    });
  }

  /**
   * The administrator acknowledges the calls sent under a permission no
   * longer in force that have no receipt, and may set aside calls (by the
   * "call" the status gives them). A call set aside is noted in the copy
   * and in the log, and gets no receipt. Each call acknowledged gets a
   * receipt, written from its line in the copy by a stub writer opened for
   * the permission it was sent under, on the book as it stands, dated
   * when it was sent, countersigned now; the agent's own writer takes the
   * line into the book only if the book still passes its check with it. It
   * names what the copy holds of the outcome, or "provared.error" with
   * NO_RECORD_OF_OUTCOME; "executor.written-late" with WRITTEN_LATER; and
   * "executor.acknowledged" with ACKNOWLEDGED. Where the permission names
   * for the executor the keys of a key file it held before, that file's
   * keys countersign. A call leaves the list once the line saying so is in
   * the copy; a call whose receipt the book already holds gets no second
   * one. The agent takes calls again once none is waiting. Gives {written,
   * setAside, failed, remaining}: "failed" names each call that was to get
   * a receipt or be set aside and did not, with why; the others are tried
   * all the same, unless the book file or the copy can no longer be
   * written.
   * @param {{setAside?: string[]}} [o]
   */
  function acknowledge(o = {}) {
    const setAside = o.setAside ?? [];
    if (!Array.isArray(setAside) || !setAside.every((c) => typeof c === 'string')) throw new Error('setAside: must be a list of the calls to set aside, as the status names them.');
    return inTurn(async () => {
      if (pending.length === 0) throw new Error('This agent has no call without a receipt to acknowledge.');
      for (const c of setAside) if (!pending.some((p) => p.call === c)) throw new Error(`No call "${c}" is waiting to be acknowledged.`);
      fileAsLeft();
      const at = () => new Date(now()).toISOString();
      // What was done is always given back, with what was not and why: a call set aside cannot be taken back.
      const asideNow = [];
      const written = [];
      const failed = [];
      const result = () => ({ written, setAside: asideNow, failed, remaining: pending.map(shownCall) });
      const notDone = (p, e) => {
        failed.push({ call: p.call, when: p.sending.when, tool: p.sending.tool, problem: e.message });
        agentLog({ event: 'not-acknowledged', call: p.call, reason: e.message });
      };
      // Once the copy cannot be written, nothing more is tried: a receipt would reach the book with no line to say so.
      let copyFailed = false;
      const note = (line) => {
        try {
          copy.note(line);
        } catch (e) {
          copyFailed = true;
          throw e;
        }
      };
      for (const c of new Set(setAside)) {
        const p = pending.find((x) => x.call === c);
        try {
          note({ kind: 'set-aside', call: c, when: at() });
        } catch (e) {
          notDone(p, e);
          return result();
        }
        pending = pending.filter((x) => x !== p);
        asideNow.push(shownCall(p));
        agentLog({ event: 'call-set-aside', call: shownCall(p) });
      }
      const usable = pending.filter((p) => p.problem === null).sort((x, y) => Date.parse(x.sending.when) - Date.parse(y.sending.when));
      if (usable.length === 0 && asideNow.length === 0) throw new Error('No call waiting can have a receipt written from its line; set aside those you have looked at (setAside).');
      for (const p of usable) {
        const s = p.sending;
        try {
          // Never two receipts for one call: the book is looked at again before each is written.
          const inBook = stubsByCall(await writer.check()).get(await identifierFingerprint(p.call));
          if (inBook) {
            note({ kind: 'done', call: p.call, when: at(), outcome: 'found-in-book', stub: inBook });
            pending = pending.filter((x) => x !== p);
            written.push({ call: p.call, when: s.when, tool: s.tool, action: s.action, slip: s.slip, stub: inBook, found: true });
            continue;
          }
          const details = [...s.details, ...(p.known ?? [{ name: 'provared.error', sha256: await identifierFingerprint(NO_RECORD_OF_OUTCOME) }]), { name: WRITTEN_LATE_DOCUMENT, sha256: await identifierFingerprint(WRITTEN_LATER) }, { name: ACKNOWLEDGED_DOCUMENT, sha256: await identifierFingerprint(ACKNOWLEDGED) }];
          // The keys the permission names for the executor: its present ones, or those of a key file it held before.
          const countersignWith = p.former === null ? executorKeys.privateKeys : formerKeys[p.former].privateKeys;
          const other = await openRecorder({ book: writer.book(), slip: s.slip, privateKeys: prepared.agentKeys.privateKeys, issuerKeys: paths.issuerKeys, options, now });
          const made = await other.record({ action: s.action, ...(s.amount ? { amount: s.amount } : {}), with: settings.service, details }, { when: Date.parse(s.when), countersign: (stub) => countersign(stub, countersignWith, now()) });
          await writer.add(JSON.parse(made.line));
          if (!save()) throw new Error(`The receipt is in the executor's memory, and the book file could not be written: ${stopped}`);
          const former = p.former === null ? {} : { formerKeys: true };
          note({ kind: 'done', call: p.call, when: at(), outcome: p.known ? 'acknowledged' : 'acknowledged-outcome-unknown', stub: made.fingerprint, countersigned: made.countersignature.accepted, ...former });
          pending = pending.filter((x) => x !== p);
          written.push({ call: p.call, when: s.when, tool: s.tool, action: s.action, slip: s.slip, stub: made.fingerprint, ...former });
          agentLog({ event: 'acknowledged', call: p.call, stub: made.fingerprint, outcome: p.known ? 'as the copy knew it' : 'not known', ...former });
        } catch (e) {
          notDone(p, e);
          if (stopped || copyFailed) break;
        }
      }
      return result();
    });
  }

  let lastCheck = null;
  /**
   * What the agent's record shows now: the slip in force, the entries and
   * bytes of the book, its last seal, whether the book as it stands passes
   * its check, why the agent takes no call (or null), and the calls
   * waiting to be acknowledged. The stub writer answers a check only
   * between calls: while a call is with the server, the check shown is the
   * last one, with "checkedNow" false and its time in "checkedAt".
   */
  async function report() {
    let checked = null;
    if (busy === 0) {
      let timer;
      const late = new Promise((done) => (timer = setTimeout(() => done(null), 2000)));
      const result = await Promise.race([writer.check(), late]);
      clearTimeout(timer);
      if (result) {
        checked = { ...bookSummary(result), at: new Date(now()).toISOString() };
        lastCheck = checked;
      }
    }
    const shown = checked ?? lastCheck;
    return {
      slip: about.fingerprint,
      entries: shown?.entries ?? null,
      bytes: Buffer.byteLength(writer.book()),
      lastSeal: shown?.lastSeal ?? null,
      sound: shown?.sound ?? null,
      withinSlips: shown?.withinSlips ?? null,
      checkedAt: shown?.at ?? null,
      checkedNow: checked !== null,
      stopped: stoppedNow(),
      receiptsMissing: pending.map(shownCall),
      waiting: calls.size,
      fileHoldsBook: file.holds(writer.book()),
      receiptsAtNextStart: lateWaiting,
      // With a central sealer: how many lines it has not answered for and since when, when it last answered, and what is wrong.
      ...(link ? { sealer: link.status() } : {}),
    };
  }

  /** The tool calls in progress or waiting their turn, by the client's id. @type {Map<string, object>} */
  const calls = new Map();
  started = true;
  return {
    name,
    paths,
    about,
    file,
    writer,
    copy,
    agentKeys: prepared.agentKeys,
    log: agentLog,
    stop,
    stopped: stoppedNow,
    save,
    inTurn,
    /** With a central sealer, for a call about to be sent: null, or {unsent, since, problem} where more lines are unsent than the settings allow (sealing.mjs). */
    sealerBehind: async () => (link ? link.behind() : null),
    /** With a central sealer: why no line may be written to the book now, or null. */
    sealInDoubt: () => link?.doubt() ?? null,
    seal,
    acknowledge,
    report,
    /** The calls that wait for the administrator, as the status shows them. */
    pending: () => pending.map(shownCall),
    /** Give up the lock on the book and its copy, once nothing more is to be written (lock.mjs). With a central sealer, first one last try to send it what it lacks; nothing more is sent after. */
    release: async () => {
      if (link) await link.end();
      await prepared.release();
    },
    calls,
  };
}

// --- calls that wait for the administrator ---

const FINGERPRINT = /^[A-Za-z0-9_-]{43}$/;
const CALL_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** The members of a "sending" line of the copy, and the documents it may name: what the executor writes before a call is sent. */
const SENDING_MEMBERS = ['seq', 'kind', 'call', 'when', 'slip', 'tool', 'action', 'amount', 'with', 'details'];
const SENT_DOCUMENTS = ['provared.arguments', TOOL_DOCUMENT, CALL_DOCUMENT, RULES_DOCUMENT, 'provared.trace-id', 'provared.request-id'];
const OUTCOME_DOCUMENTS = [RESULT_DOCUMENT, 'provared.error'];
const isDocument = (d, names) => isObject(d) && Object.keys(d).length === 2 && names.includes(d.name) && typeof d.sha256 === 'string' && FINGERPRINT.test(d.sha256);

/** The book's stubs that name a call of the executor's: the fingerprint of each "executor.call" document, with its stub's. */
function stubsByCall(checked) {
  const held = new Map();
  for (const e of checked.entries) {
    if (e.kind !== 'stub' || !Array.isArray(e.content?.details)) continue;
    for (const d of e.content.details) if (d.name === CALL_DOCUMENT) held.set(d.sha256, e.fingerprint);
  }
  return held;
}

/** What a whole check of a book shows of it, for the status: its entries, its last seal, and whether it passes. */
function bookSummary(result) {
  const last = result.entries.filter((e) => e.kind === 'seal' && e.problems.length === 0).at(-1);
  return { entries: result.size, lastSeal: last ? { entry: last.index, fingerprint: last.fingerprint, when: last.content.when } : null, sound: !result.summary.problemFound, withinSlips: result.summary.withinSlips };
}

/**
 * The calls a copy shows as sent and not finished (unfinished), held
 * against a check of the book: "found", those whose receipt the book
 * already holds ({call, stub}); "late", those sent under the slip in force,
 * which the next start gives a receipt; and "pending", those sent under
 * another slip, which wait for the administrator, each with whether a
 * receipt can be written from its line (lineProblem).
 */
export async function sortUnfinished(open, checked, { settings, about, agentKeys, executorKeys, formerKeys = [], startedAt }) {
  const held = stubsByCall(checked);
  // The slips the book holds, sound: a call may be acknowledged under any of them.
  const slips = new Map(checked.entries.filter((e) => e.kind === 'slip' && e.problems.length === 0).map((e) => [e.fingerprint, e.content]));
  const out = { found: [], late: [], pending: [] };
  for (const { sending, done } of open) {
    const stub = held.get(await identifierFingerprint(sending.call));
    if (stub) out.found.push({ call: sending.call, stub });
    else if (sending.slip === about.fingerprint) out.late.push({ sending, done });
    else out.pending.push({ call: sending.call, sending, done, ...(await lineProblem(sending, done, { settings, slips, agentKeys, executorKeys, formerKeys, startedAt })) });
  }
  return out;
}

/**
 * Whether a receipt can be written from a "sending" line of the copy
 * (whose tag checked) for a call sent under another slip than the one in
 * force: {problem: null, warning, known} where it can, or a sentence
 * saying why not. The line must hold only what the executor writes; name a
 * slip the book holds, which names the agent's and the executor's keys as
 * the executor holds them now; give a time not after this start; and give
 * an amount and documents of the forms the executor writes. (The library
 * makes its own checks when the receipt is written: a receipt the book
 * would not pass its check with is not written, and the call stays
 * waiting.) "known" is what a later line of the copy holds of the outcome
 * (one document), or null. "warning" says where a rule has changed since:
 * the line can still be acknowledged.
 */
async function lineProblem(s, done, { settings, slips, agentKeys, executorKeys, formerKeys, startedAt }) {
  const no = (problem) => ({ problem, warning: null, known: null, former: null });
  if (Object.keys(s).some((k) => !SENDING_MEMBERS.includes(k))) return no('It holds a member the executor does not write.');
  if (!CALL_ID.test(s.call)) return no('Its call identifier is not one the executor makes.');
  if (typeof s.slip !== 'string' || !FINGERPRINT.test(s.slip)) return no('It does not say which permission its call was sent under.');
  const slip = slips.get(s.slip);
  if (!slip) return no('The book does not hold the permission its call was sent under, so no receipt can be written under that permission. Set it aside, or put back the book that holds that permission.');
  if (!sameKeys(slip.agent?.keys, agentKeys)) return no('The permission its call was sent under names other agent keys than the executor now holds, so the executor cannot sign a receipt under it.');
  const named = Array.isArray(slip.with) ? slip.with.find((w) => w?.id === settings.service) : undefined;
  // The keys that permission names for the executor: its present ones, or those of a key file it held before ("executor.formerKeys"), which then countersign.
  let former = null;
  if (named && !sameKeys(named.keys, executorKeys)) {
    const at = formerKeys.findIndex((k) => sameKeys(named.keys, k));
    former = at === -1 ? undefined : at;
  }
  if (!named || former === undefined) return no(`The permission its call was sent under does not name the executor in "with" as "${settings.service}" with the keys the executor now holds, so its countersignature would not check. Where the executor's keys were changed and the key file it held then is still to hand, name that file in "executor.formerKeys", and the call can be acknowledged.`);
  const when = typeof s.when === 'string' ? Date.parse(s.when) : NaN;
  if (!Number.isFinite(when) || new Date(when).toISOString() !== s.when) return no('Its time is not a time written as the executor writes it.');
  if (when > startedAt) return no("Its time is after this start of the executor: the executor's clock is behind the time the call was sent. Put the clock right and start the executor again; nothing dated ahead of the clock is written.");
  if (typeof s.action !== 'string' || !SHORT_NAME.test(s.action)) return no('Its action is not an action name.');
  if (s.with !== settings.service) return no(`It names another service id than the settings now give the executor ("${settings.service}").`);
  if (typeof s.tool !== 'string' || !TOOL_NAME.test(s.tool)) return no('Its tool name is not a tool name.');
  const amountForm = (a) => isObject(a) && Object.keys(a).length === 2 && Number.isSafeInteger(a.value) && a.value >= 0 && typeof a.unit === 'string' && UNIT.test(a.unit);
  let warning = null;
  const rule = settings.tools.get(s.tool);
  if (!rule || rule.action !== s.action) {
    // The tag shows the executor wrote this line; the rule that named the call has since been taken out of the settings, or changed.
    warning = 'No rule names this tool with this action now (a rule was taken out, or changed, since the call was sent). Its tag shows the executor wrote the line, so it can be acknowledged.';
    if (s.amount !== undefined && !amountForm(s.amount)) return no('Its amount is not a unit and a whole number from 0 up.');
  } else if (s.amount === undefined) {
    if (rule.amount) return no('Its rule gives an amount, and the line has none.');
  } else {
    if (!amountForm(s.amount)) return no('Its amount is not a unit and a whole number from 0 up.');
    if (!rule.amount || rule.amount.unit !== s.amount.unit) return no('Its amount is not in the unit its rule gives.');
  }
  const d = s.details;
  if (!Array.isArray(d) || d.length < 3 || d.length > SENT_DOCUMENTS.length || !d.every((x) => isDocument(x, SENT_DOCUMENTS))) return no('Its documents are not the ones the executor names.');
  for (const n of SENT_DOCUMENTS) if (d.filter((x) => x.name === n).length > 1) return no('It names one document twice.');
  const of = (n) => d.find((x) => x.name === n)?.sha256;
  if (!of('provared.arguments')) return no('It names no arguments.');
  if (of(TOOL_DOCUMENT) !== (await identifierFingerprint(s.tool))) return no('Its tool document does not match its tool name.');
  if (of(CALL_DOCUMENT) !== (await identifierFingerprint(s.call))) return no('Its call document does not match its call identifier.');
  if (of('provared.request-id') !== undefined && of('provared.request-id') !== of(CALL_DOCUMENT)) return no('Its request identifier does not match its call identifier.');
  // What a later line holds of the outcome, where the receipt was made and the book could not be written: one document.
  let known = null;
  if (done && done.documents !== undefined && !(Array.isArray(done.documents) && done.documents.length === 0)) {
    if (!Array.isArray(done.documents) || done.documents.length !== 1 || !isDocument(done.documents[0], OUTCOME_DOCUMENTS)) return no('What the copy holds of its outcome is not of the form the executor writes.');
    known = [done.documents[0]];
  }
  return { problem: null, warning, known, former };
}

/** A waiting call as the administrator is shown it: names, times and fingerprints from its line of the copy. */
function shownCall(p) {
  const s = p.sending;
  return { call: p.call, usable: p.problem === null, problem: p.problem, warning: p.warning, when: s.when, slip: s.slip, tool: s.tool, action: s.action, ...(s.amount !== undefined ? { amount: s.amount } : {}), outcomeKnown: p.known !== null, ...(p.former === null ? {} : { formerKeys: true }) };
}

function waitingWords(pending) {
  const first = pending[0].sending;
  return `${pending.length} call(s) sent before the executor last stopped, under a permission that is not the one in force, have no receipt in the book (the first: ${String(first.when).slice(0, 40)}, ${String(first.tool).slice(0, 128)}). The administrator acknowledges them with "provared-mcp-executor acknowledge" (over HTTP, also POST /provared/acknowledge), and sets aside any that cannot have a receipt ("--set-aside", "setAside"); a receipt is written for each call acknowledged, under the permission it was sent under.`;
}

/**
 * What one agent's files show, read without writing anything: for the
 * "status" command where there is no running executor to ask (over stdio
 * there is no address to ask at). Gives the slip in force and whether the
 * book holds it yet, the entries and bytes of the book file, its last
 * seal, whether it passes its check, the calls that wait for the
 * administrator ("receiptsMissing") and how many calls the next start will
 * give a late receipt ("receiptsAtNextStart"); or {problem} where the
 * files cannot be opened as a start would open them. What a running
 * executor holds in memory (whether it has stopped, calls in progress) is
 * not in the files.
 */
export async function reportFromFiles(paths, settings, shared, { now = Date.now } = {}) {
  let prepared;
  try {
    prepared = await prepareAgent(paths, settings, shared, { now, readOnly: true });
  } catch (e) {
    // The book by itself, where it can be read: whether it passes its check.
    let sound = null;
    try {
      const text = readIfThere(paths.book);
      if (text) sound = !(await checkBook(text, { ...(shared.sealer ? { sealKeys: [shared.sealer.fingerprint] } : {}), issuerKeys: paths.issuerKeys })).summary.problemFound;
    } catch {
      sound = null;
    }
    return { problem: e.message, sound };
  }
  const onDisk = readIfThere(paths.book);
  const checked = onDisk ? await checkBook(onDisk, prepared.checkOptions) : null;
  const shown = checked ? bookSummary(checked) : { entries: 0, lastSeal: null, sound: null, withinSlips: null };
  const sorted = await sortUnfinished(unfinished(prepared.read), await prepared.writer.check(), { settings, about: prepared.about, agentKeys: prepared.agentKeys.keys, executorKeys: shared.executorKeys.keys, formerKeys: shared.formerKeys.map((k) => k.keys), startedAt: now() });
  return {
    slip: prepared.about.fingerprint,
    slipInBook: checked ? checked.entries.some((e) => e.kind === 'slip' && e.fingerprint === prepared.about.fingerprint) : false,
    entries: shown.entries,
    bytes: Buffer.byteLength(onDisk),
    lastSeal: shown.lastSeal,
    sound: shown.sound,
    withinSlips: shown.withinSlips,
    checkedAt: new Date(now()).toISOString(),
    receiptsMissing: sorted.pending.map(shownCall),
    receiptsAtNextStart: sorted.late.length,
    // With a central sealer: it is asked, once, how many lines of this book it holds. Nothing is sent of the book but its first line's leaf fingerprint.
    ...(shared.sealer?.central ? { sealer: await shared.sealer.look(onDisk) } : {}),
  };
}

/** The "status" of a stdio executor, from its files (reportFromFiles): {executor, from: 'files', recorder, agent}. */
export async function statusFromFiles(config, root, { now = Date.now } = {}) {
  const { settings, problems } = readSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const shared = await prepareShared(settings);
  return { executor: 'provared-mcp-executor', from: 'files', recorder: describeRecorder(settings, shared.sealer), agent: await reportFromFiles({ ...settings.agent, copy: settings.executor.copy, copyKey: settings.executor.copyKey }, settings, shared, { now }) };
}

// --- sealing on a timer ---

/**
 * Seal each agent's book on a timer, where the settings give
 * "recorder.sealEvery". At "start": a book that holds an entry after its
 * last seal is sealed where that seal is at least "every" old, or there is
 * none. Then every "every" milliseconds: a book that holds an entry after
 * its last seal is sealed. A book whose last entry is its last seal is
 * left as it is, so an idle executor writes no seal over a seal. Each
 * agent's book has its round to itself: a seal waits its turn behind that
 * agent's own calls, and holds up no other agent's seal. A seal that
 * cannot be written is logged ("not-sealed"), once for as long as the
 * reason stays the same, and tried again "every" milliseconds later. After
 * "stop" no seal is asked for; one asked for before is written when its
 * turn comes. The timer does not keep the program running.
 * @param {object[]} agents as openAgent gives them
 * @param {number} every milliseconds
 */
export function sealTimer(agents, every) {
  let ended = false;
  const timers = new Map();
  const said = new Map();
  const round = async (agent, first) => {
    try {
      await agent.seal({ onlyIfNew: true, ...(first ? { olderThan: every } : {}) });
      said.delete(agent);
    } catch (e) {
      if (said.get(agent) !== e.message) agent.log({ event: 'not-sealed', reason: e.message });
      said.set(agent, e.message);
    }
    if (ended) return;
    const timer = setTimeout(() => round(agent, false), every);
    timer.unref();
    timers.set(agent, timer);
  };
  return {
    start() {
      for (const agent of agents) round(agent, true);
    },
    stop() {
      ended = true;
      for (const timer of timers.values()) clearTimeout(timer);
    },
  };
}

// --- the handling of one tools/call, shared by both transports ---

/** A maker of ids of the executor's own for requests sent to the server: unique for the session and not guessable (a number from 1 and a random part). */
export function serverIds() {
  let next = 1;
  return () => `provared-${next++}-${randomId()}`;
}

/**
 * The text of a tools/list answer for the client, with the tools that have
 * no rule taken out and every number kept as the server wrote it, under the
 * client's id. Gives {text, hidden}, or null where the text is not such an
 * answer. "m" is the message as readMessage read it.
 */
export function filteredList(text, m, clientId, settings) {
  if (!Object.hasOwn(m, 'result') || !isObject(m.result) || !Array.isArray(m.result.tools)) return null;
  // Read again with every number kept as the server wrote it, so that filtering changes nothing else.
  let exact;
  try {
    exact = JSON.parse(text, (k, v, context) => (typeof v === 'number' ? JSON.rawJSON(context.source) : v));
  } catch {
    exact = m;
  }
  const shown = exact.result.tools.filter((t) => isObject(t) && typeof t.name === 'string' && settings.tools.has(t.name));
  return { text: JSON.stringify({ ...exact, id: clientId, result: { ...exact.result, tools: shown } }), hidden: exact.result.tools.length - shown.length };
}

/**
 * The handling of one tools/call (DESIGN.md, section 5), the same on stdio
 * and over HTTP: the rule, the amount, the rules on content, the check
 * before acting, the copy's line, the sending, the receipt and the answer.
 * The transport gives a "link" to the client and the server:
 *   newServerId()                an id of the executor's own for the call (serverIds)
 *   answer(text)                 one message for the client, as text without a line feed
 *   unavailable()                why the server can take no call now, or null
 *   send(call, forwarded)        forward the call (the message under the executor's id, with its _meta); false where it could not be sent
 *   cancel(call, reason)         on the executor's timeout: tell the server, or close the stream
 *   forward(id, serverId, text)  an unlisted call sent on unchecked ("unlisted": "forward")
 *   track(call), untrack(call)   hold a call while it is in flight
 * The transport settles the outcome with call.settle(outcome), once:
 * {kind: 'answer', text, result, unsafe}, {kind: 'server-error', text,
 * errorText}, {kind: 'unreadable', text, errorText} or {kind: 'error',
 * text, code}. "text" is the server's message as it wrote it, which goes to
 * the client under the client's id.
 */
export function callCore({ settings, content, executorKeys, now }) {
  // The rules file in force, named in every receipt and denial by its fingerprint.
  const rulesDocument = content ? { name: RULES_DOCUMENT, sha256: content.fingerprint } : null;
  const countersignWith = (stub) => countersign(stub, executorKeys.privateKeys, now());

  async function handleCall(agent, link, id, message, text) {
    const { log, copy, writer, file, about, calls } = agent;
    const answerError = (code, words, data) => link.answer(responseText(id, { error: { code, message: words, ...(data === undefined ? {} : { data }) } }));
    const key = idKey(id);
    if (calls.has(key)) return answerError(CODES.invalidRequest, 'A request with this id is already in progress.');
    if (calls.size >= settings.maxWaiting) {
      log({ event: 'refused', code: 'too-many-waiting', waiting: calls.size });
      return answerError(CODES.notRecorded, `The executor already has ${calls.size} tool calls in progress or waiting their turn, the most it takes at once (maxWaiting). This call was not taken and nothing was written; ask again when one has ended.`);
    }
    const params = message.params ?? {};
    const name = params.name;
    if (typeof name !== 'string' || !TOOL_NAME.test(name)) return answerError(CODES.invalidParams, 'The tool name must be 1 to 128 letters, digits, underscores, hyphens or full stops.');
    if (Object.hasOwn(params, 'arguments') && !isObject(params.arguments)) return answerError(CODES.invalidParams, 'The arguments must be an object.');
    if (Object.hasOwn(params, '_meta') && !isObject(params._meta)) return answerError(CODES.invalidParams, 'The _meta member must be an object.');
    const serverId = link.newServerId();
    const call = { id, serverId, state: 'queued', cancelled: false, settle: null, timer: null };
    const callId = randomId();
    try {
      const rule = settings.tools.get(name);
      if (!rule && settings.unlisted === 'forward') {
        log({ event: 'forwarded-unlisted', tool: name, call: callId });
        link.forward(id, serverId, text);
        return;
      }
      calls.set(key, call);
      link.track(call);
      const argsText = Object.hasOwn(params, 'arguments') ? JSON.stringify(params.arguments) : undefined;
      const args = params.arguments;
      const details = [
        { name: 'provared.arguments', sha256: await argumentsFingerprint(args ?? {}) },
        { name: TOOL_DOCUMENT, sha256: await identifierFingerprint(name) },
        { name: CALL_DOCUMENT, sha256: await identifierFingerprint(callId) },
        ...(rulesDocument ? [rulesDocument] : []),
      ];
      const trace = typeof params._meta?.traceparent === 'string' ? TRACEPARENT.exec(params._meta.traceparent) : null;
      if (trace) details.push({ name: 'provared.trace-id', sha256: await identifierFingerprint(trace[1]) });
      // What a denial names: what was asked for, without the identifier that was never sent.
      const asked = details.filter((d) => d.name !== CALL_DOCUMENT);
      const refuse = async (reason, request, source, codes, ruleName) => {
        let denial = null;
        try {
          // No line is written while a seal of the central sealer's waits to be added: a seal sits after exactly the entries it covers.
          const d = await agent.inTurn(() => (agent.sealInDoubt() ? { written: false } : writer.deny(request, { source, ...(codes ? { codes } : {}) })));
          if (d.written) denial = d.fingerprint;
          agent.save();
        } catch (e) {
          log({ event: 'denial-not-written', call: callId, error: e.message });
        }
        copy.note({ kind: 'refused', call: callId, when: new Date(now()).toISOString(), slip: about.fingerprint, tool: name, action: request.action, ...(request.amount ? { amount: request.amount } : {}), reason: reason.code, ...(codes ? { codes } : {}), ...(ruleName ? { rule: ruleName } : {}), ...(denial ? { denial } : {}) });
        log({ event: 'refused', call: callId, tool: name, code: reason.code, ...(codes ? { codes } : {}), ...(ruleName ? { rule: ruleName } : {}) });
        // A tool execution error, so that the model is told and can choose another call.
        link.answer(responseText(id, { result: { content: [{ type: 'text', text: `Not taken by the Provared executor: ${reason.message}` }], isError: true, _meta: { 'red.prova/refused': reason.code, ...(codes ? { 'red.prova/codes': codes } : {}), ...(ruleName ? { 'red.prova/rule': ruleName } : {}), ...(denial ? { 'red.prova/denial': denial } : {}) } } }));
      };
      if (!rule) return refuse({ code: 'unlisted', message: `No rule of the executor names the tool "${name}", so the call was not sent.` }, { action: UNLISTED_ACTION, with: settings.service, details: asked }, 'rule');
      if (agent.stopped()) {
        log({ event: 'refused', call: callId, tool: name, code: 'executor-stopped' });
        return answerError(CODES.notRecorded, `The executor takes no call: ${agent.stopped()}`);
      }
      const got = amountOf(rule, args, argsText);
      if (got.problem) return refuse(got.problem, { action: rule.action, with: settings.service, details: asked }, 'rule');
      if (content) {
        // The rules on content: a call a rule refuses, or whose content a rule cannot read exactly, is not sent.
        const refused = testCall(content.rules, name, args, argsText);
        if (refused) {
          return refuse(refused.reason, { action: rule.action, ...(got.amount ? { amount: got.amount } : {}), with: settings.service, details: [...asked, { name: RULE_DOCUMENT, sha256: await identifierFingerprint(refused.rule) }] }, 'rule', undefined, refused.rule);
        }
      }
      const request = { action: rule.action, ...(got.amount ? { amount: got.amount } : {}), with: settings.service, details };
      if (settings.callIdInMeta) details.push({ name: 'provared.request-id', sha256: details.find((d) => d.name === CALL_DOCUMENT).sha256 });

      // The message sent to the server: the client's call under the executor's id, with the executor's identifier in _meta where the settings say.
      const forwarded = { ...message, id: serverId, ...(settings.callIdInMeta ? { params: { ...params, _meta: { ...(params._meta ?? {}), [CALL_META]: callId } } } : {}) };

      let sent = false;
      let outcome;
      let afterDocuments = [];
      let done;
      try {
        done = await agent.inTurn(async () => {
          if (agent.stopped()) return { stopped: true };
          if (call.cancelled) return { withdrawn: true };
          // With a central sealer: no call is sent while more lines are unsent than the settings allow. One try to send them is waited for, within the time a question may take.
          const behind = await agent.sealerBehind();
          if (agent.stopped()) return { stopped: true };
          if (behind) return { behind };
          if (!file.holds(writer.book()) && !agent.save()) return { stopped: true };
          let intact;
          try {
            intact = file.intact();
          } catch {
            intact = false;
          }
          if (!intact) {
            agent.stop('the book file is not as the executor left it: something else changed it.', 'book-changed');
            return { stopped: true };
          }
          const result = await writer.act(
            request,
            async () => {
              // The agent may have withdrawn the call while the stub was being made and checked.
              if (call.cancelled) throw new NotSent('withdrawn');
              const away = link.unavailable();
              if (away) throw new NotSent(away, CODES.noAnswer);
              // Before anything goes to the server: the copy's line, on the disk.
              try {
                copy.note({ kind: 'sending', call: callId, when: new Date(now()).toISOString(), slip: about.fingerprint, tool: name, action: rule.action, ...(got.amount ? { amount: got.amount } : {}), with: settings.service, details });
              } catch (e) {
                agent.stop(`its own copy could not be written (${e.message}).`, 'copy-not-written');
                throw new NotSent(`The executor could not write its own copy of this call, so the call was not sent: ${e.message}`, CODES.notRecorded);
              }
              call.state = 'sent';
              sent = true;
              outcome = await new Promise((settle) => {
                // Settled once: by the server's answer, the timeout, the agent's cancellation or the server's end.
                call.settle = (o) => {
                  if (!call.settle) return;
                  call.settle = null;
                  clearTimeout(call.timer);
                  call.timer = null;
                  settle(o);
                };
                call.timer = setTimeout(() => {
                  if (!call.settle) return;
                  link.cancel(call, `The Provared executor gave this call ${settings.timeout} ms and got no answer.`);
                  call.settle({ kind: 'error', text: `The tool server gave no answer within ${settings.timeout} ms, so the executor cancelled the call (call ${callId}). Its outcome is not known.`, code: CODES.noAnswer });
                }, settings.timeout);
                if (!link.send(call, forwarded)) call.settle({ kind: 'error', text: 'The tool server has ended, so the call could not be sent. Whether any of it reached the server is not known.', code: CODES.noAnswer });
              });
              return outcome;
            },
            {
              denial: false,
              countersign: countersignWith,
              detailsAfter: async (o) => {
                if (o.kind === 'error') afterDocuments = [{ name: 'provared.error', sha256: await identifierFingerprint(o.text) }];
                else if (o.kind === 'server-error') afterDocuments = [{ name: 'provared.error', sha256: await identifierFingerprint(o.errorText) }];
                else if (o.kind === 'unreadable') afterDocuments = [{ name: 'provared.error', sha256: await identifierFingerprint(UNREADABLE_ANSWER) }];
                else if (o.unsafe) {
                  log({ event: 'result-not-fingerprinted', call: callId, error: 'The result holds a whole number beyond 9,007,199,254,740,991.' });
                  afterDocuments = [{ name: 'provared.error', sha256: await identifierFingerprint(RESULT_NOT_FINGERPRINTED) }];
                } else {
                  try {
                    afterDocuments = [{ name: RESULT_DOCUMENT, sha256: await argumentsFingerprint(o.result) }];
                  } catch (e) {
                    log({ event: 'result-not-fingerprinted', call: callId, error: e.message });
                    afterDocuments = [{ name: 'provared.error', sha256: await identifierFingerprint(RESULT_NOT_FINGERPRINTED) }];
                  }
                }
                return afterDocuments;
              },
            },
          );
          if (!result.done) result.denial = await writer.deny({ ...request, details: asked }, { source: 'check', codes: denialCodes(result.answer) });
          const saved = agent.save();
          if (result.done) {
            const cs = result.stub.countersignature;
            let csFingerprint = null;
            if (cs.accepted) {
              try {
                const entry = JSON.parse(result.stub.line);
                csFingerprint = await fingerprint(fromBase64url(entry.countersignature.payload));
              } catch {
                csFingerprint = null;
              }
            }
            // The "done" line names the stub only once it is on the disk. Where the
            // book could not be written, the line holds what the executor knew of the
            // outcome and no stub, and the call stays unfinished: the next start
            // writes the receipt from the "sending" line and these documents.
            // The kind of outcome is named only beside its documents: a line with
            // none holds no record of the outcome, as a receipt from it then says
            // (NO_RECORD_OF_OUTCOME), and names no kind of one either.
            const added = result.detailsAfter?.added ? afterDocuments : [];
            try {
              copy.note({ kind: 'done', call: callId, when: new Date(now()).toISOString(), ...(added.length ? { outcome: outcome.kind } : {}), ...(saved ? { stub: result.stub.fingerprint } : {}), countersigned: cs.accepted, ...(csFingerprint ? { countersignature: csFingerprint } : {}), documents: added });
            } catch (e) {
              agent.stop(`its own copy could not be written (${e.message}).`, 'copy-not-written');
            }
          }
          return result;
        });
      } catch (e) {
        if (e instanceof NotSent) {
          if (e.message === 'withdrawn') {
            copy.note({ kind: 'withdrawn', call: callId, when: new Date(now()).toISOString(), tool: name, action: rule.action });
            log({ event: 'withdrawn', call: callId, tool: name });
            return;
          }
          return answerError(e.code ?? CODES.notRecorded, e.message);
        }
        if (sent) {
          agent.stop(`a call was sent and its receipt could not be written (${e.message}).`, 'receipt-not-written');
          if (outcome && outcome.kind !== 'error') link.answer(spliceId(outcome.text, id) ?? outcome.text);
          else answerError(CODES.notRecorded, 'The executor could not write the receipt of this call.');
          return;
        }
        log({ event: 'call-failed', call: callId, error: e.message });
        return answerError(CODES.notRecorded, `The executor could not handle this call: ${e.message}`);
      }
      if (done.withdrawn) {
        copy.note({ kind: 'withdrawn', call: callId, when: new Date(now()).toISOString(), tool: name, action: rule.action });
        log({ event: 'withdrawn', call: callId, tool: name });
        return;
      }
      if (done.stopped) {
        log({ event: 'refused', call: callId, tool: name, code: 'executor-stopped' });
        return answerError(CODES.notRecorded, `The executor takes no call: ${agent.stopped()}`);
      }
      if (done.behind) {
        // Refused as a rule of the executor's refuses: a denial in the book, a line in the copy, and a tool error for the model.
        const b = done.behind;
        return refuse({ code: SEALER_BEHIND, message: `The central sealer has not taken ${b.unsent} line(s) of the book${b.since ? `, the oldest written at ${b.since}` : ''}, more than the settings allow to be unsent (recorder.sealer.maxUnsent), so the call was not sent. It can be made again once the sealer has caught up.` }, { action: rule.action, ...(got.amount ? { amount: got.amount } : {}), with: settings.service, details: asked }, 'rule');
      }
      if (!done.done) {
        const codes = denialCodes(done.answer);
        const words = [...done.answer.problems, ...done.answer.breaches].map((f) => f.message).join(' ');
        const denial = done.denial?.written ? done.denial.fingerprint : null;
        copy.note({ kind: 'refused', call: callId, when: new Date(now()).toISOString(), slip: about.fingerprint, tool: name, action: rule.action, ...(got.amount ? { amount: got.amount } : {}), reason: 'not-allowed', codes, ...(denial ? { denial } : {}) });
        log({ event: 'refused', call: callId, tool: name, code: 'not-allowed', codes });
        return link.answer(responseText(id, { result: { content: [{ type: 'text', text: `Not taken by the Provared executor: the permission does not allow this call. ${words}` }], isError: true, _meta: { 'red.prova/refused': 'not-allowed', 'red.prova/codes': codes, ...(denial ? { 'red.prova/denial': denial } : {}) } } }));
      }
      if (done.stub.countersignature.problem) log({ event: 'countersignature-not-taken', call: callId, problem: done.stub.countersignature.problem.code });
      if (done.detailsAfter?.problem) log({ event: 'details-not-added', call: callId, problem: done.detailsAfter.problem.code });
      log({ event: 'taken', call: callId, tool: name, action: rule.action, outcome: outcome.kind, stub: done.stub.fingerprint, countersigned: done.stub.countersignature.accepted, saved: !agent.stopped() });
      if (outcome.kind === 'error') answerError(outcome.code ?? CODES.noAnswer, outcome.text, { 'red.prova/stub': done.stub.fingerprint });
      else link.answer(spliceId(outcome.text, id) ?? outcome.text);
    } finally {
      if (call.timer) clearTimeout(call.timer);
      calls.delete(key);
      link.untrack(call);
    }
  }

  return { handleCall, rulesDocument };
}

// --- the executor, over stdio ---

/**
 * Open the executor on its settings: keys, slip, book, copy and stub writer
 * are read now; the tool server is started by "attach". A call the copy
 * shows as sent and never given its receipt (the executor stopped
 * meanwhile) is given one now (openAgent).
 *
 * A call sent under a permission that is no longer the one in force, with
 * no receipt in the book, waits for the administrator: the executor then
 * does not open, and says so, unless it is opened with "offline", as the
 * commands "acknowledge", "seal" and "status" open it to work on the files
 * of an executor that is not running. Opened so, it reads no credential
 * and cannot be attached.
 *
 * @param {object} config the settings, as in executor.example.json
 * @param {{root?: string, now?: () => number, log?: (event: object) => void, serverStderr?: NodeJS.WritableStream|null, offline?: boolean, lockWait?: number}} [more] "lockWait": how long a start asks again for a lock that is held, in place of the rule (for tests)
 */
export async function openExecutor(config, more = {}) {
  const root = more.root ?? process.cwd();
  const now = more.now ?? Date.now;
  const log = more.log ?? ((event) => process.stderr.write(`${JSON.stringify({ provared: 'mcp-executor', ...event })}\n`));
  const offline = more.offline === true;
  const p = await prepare(config, root, { now, offline, lockWait: more.lockWait });
  const { settings, about, content } = p;
  for (const w of p.warnings) log({ event: 'warning', message: w });
  let agent;
  try {
    // A command at work on the files (offline) is not a start: it writes no late receipt by itself.
    agent = await openAgent(p.agent, { settings, executorKeys: p.executorKeys, now, log, sealer: p.sealer, late: !offline, formerKeys: p.formerKeys });
  } catch (e) {
    await p.agent.release();
    throw e;
  }
  if (!offline && agent.pending().length) {
    // Over stdio there is no address at which a running executor could be asked to acknowledge, so it does not start with a call waiting.
    const waiting = agent.pending();
    await agent.release();
    throw new Error(`The copy ${p.agent.paths.copy} shows ${waiting.length} call(s) sent under a permission that is not the one in force (${about.fingerprint}), with no receipt in the book (the first: call ${waiting[0].call}, sent at ${waiting[0].when} under permission ${waiting[0].slip}). The executor does not start until each has been acknowledged or set aside: run "provared-mcp-executor acknowledge --config <settings> --offline", which writes each receipt under the permission its call was sent under (README, "A call sent under a permission no longer in force").`);
  }
  const core = callCore({ settings, content, executorKeys: p.executorKeys, now });
  const timer = settings.recorder?.sealEvery ? sealTimer([agent], settings.recorder.sealEvery) : null;

  let attached = null;
  // How many requests the executor holds for the server's answer: tool calls, and all others (for status and for tests).
  const stats = { requests: 0 };

  /**
   * Start the tool server, and carry messages between the agent's client
   * (input, output) and it. Gives a promise of {code}: the server's exit
   * code, once the server has ended and everything in flight is settled.
   */
  function attach(input, output, { serverStderr = more.serverStderr === undefined ? process.stderr : more.serverStderr } = {}) {
    if (attached) throw new Error('The executor is already attached.');
    if (offline) throw new Error('The executor was opened to work on its files (offline), and starts no server.');
    const child = spawn(settings.server.resolved, settings.server.args, { cwd: settings.server.cwd, env: p.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
    log({ event: 'server-started', command: settings.server.resolved, credentials: p.credentialNames });
    if (serverStderr) child.stderr.pipe(serverStderr, { end: false });
    else child.stderr.resume();

    let serverGone = false;
    let outputOpen = true;
    const toClient = (buffer) => {
      if (!outputOpen) return;
      try {
        output.write(buffer);
      } catch {
        outputOpen = false;
      }
    };
    const toServer = (buffer) => {
      if (serverGone) return false;
      try {
        child.stdin.write(buffer);
        return true;
      } catch {
        return false;
      }
    };
    child.stdin.on('error', (e) => log({ event: 'server-stdin-error', error: e.message }));

    // Every request from the client goes to the server under an id of the
    // executor's own, unique for the session and not guessable (a number
    // and a random part), and the answer comes back under the client's id,
    // spliced into the server's raw bytes. So nothing the client sends can
    // collide with a call in flight, and an answer that comes late (after
    // a timeout or a cancellation) can never be taken for the answer to a
    // later request. "mapped" holds every request in flight by its server
    // id: tool calls ("call"), tools/list requests to be filtered ("list"),
    // unlisted calls sent on ("forwarded") and all others ("request"). Tool
    // calls are also held by the client's id (agent.calls), for a repeated
    // id and for cancellation.
    /** @type {Map<string, {id: any, kind: string, call?: object}>} */
    const mapped = new Map();
    const calls = agent.calls;
    // Requests that are not tool calls are forgotten after MAX_MAPPED of them wait unanswered, the oldest first (a server that never answers).
    const waitingOrder = [];
    const remember = (serverId, entry) => {
      mapped.set(serverId, entry);
      stats.requests = mapped.size;
      if (entry.kind === 'call') return;
      waitingOrder.push(serverId);
      while (waitingOrder.length > MAX_MAPPED) {
        const old = waitingOrder.shift();
        if (mapped.get(old)?.kind !== 'call') mapped.delete(old);
      }
      stats.requests = mapped.size;
    };
    const forget = (serverId) => {
      mapped.delete(serverId);
      stats.requests = mapped.size;
    };
    // The server ids of calls that were settled before the server answered; a late answer under one is dropped.
    const settled = new Set();
    const MAX_SETTLED = 10000;
    const markSettled = (serverId) => {
      settled.add(serverId);
      if (settled.size > MAX_SETTLED) settled.delete(settled.values().next().value);
    };

    const answerError = (id, code, message, data) => toClient(responseLine(id, { error: { code, message, ...(data === undefined ? {} : { data }) } }));

    /** The server's raw line for the client, with the client's id spliced in place of the executor's and nothing else changed. */
    const forClient = (text, id) => {
      const spliced = spliceId(text, id);
      return Buffer.from(`${spliced ?? text}\n`);
    };

    // The link the shared call handling uses: one line per message each way.
    const newServerId = serverIds();
    const link = {
      newServerId,
      answer: (text) => toClient(Buffer.from(`${text}\n`)),
      unavailable: () => (serverGone ? 'The tool server has ended.' : null),
      send: (call, forwarded) => toServer(Buffer.from(`${JSON.stringify(forwarded)}\n`)),
      cancel: (call, reason) => {
        markSettled(call.serverId);
        toServer(notificationLine('notifications/cancelled', { requestId: call.serverId, reason }));
      },
      forward: (id, serverId, text) => {
        remember(serverId, { id, kind: 'forwarded' });
        toServer(Buffer.from(`${spliceId(text, serverId)}\n`));
      },
      track: (call) => remember(call.serverId, { id: call.id, kind: 'call', call }),
      untrack: (call) => {
        if (mapped.get(call.serverId)?.kind === 'call') forget(call.serverId);
      },
    };

    // --- from the client ---
    const clientEnded = new Promise((done) => {
      readLines(input, {
        onLine: (line) => {
          const read = readMessage(line);
          if (read.refused) {
            log({ event: 'client-line-refused', code: read.refused.code });
            return answerError(read.id, read.refused.code, read.refused.message);
          }
          const m = read.message;
          if (read.kind === 'request') {
            if (m.method === 'tools/call') {
              core.handleCall(agent, link, m.id, m, read.text).catch((e) => {
                log({ event: 'call-failed', error: e.message });
                answerError(m.id, CODES.notRecorded, `The executor could not handle this call: ${e.message}`);
              });
              return;
            }
            // Every other request goes under an id of the executor's own too.
            const list = m.method === 'tools/list' && settings.hideUnlisted;
            if (list && [...mapped.values()].filter((e) => e.kind === 'list').length >= MAX_LISTS) {
              log({ event: 'refused', code: 'too-many-lists' });
              return answerError(m.id, CODES.notRecorded, `The executor already has ${MAX_LISTS} tools/list requests waiting for the server, the most it keeps; ask again when one has been answered.`);
            }
            const serverId = newServerId();
            remember(serverId, { id: m.id, kind: list ? 'list' : 'request' });
            return toServer(Buffer.from(`${spliceId(read.text, serverId) ?? JSON.stringify({ ...m, id: serverId })}\n`));
          }
          if (read.kind === 'notification') {
            // A notification is one-way, so a request's method sent without an id
            // ("tools/call" with no id) would reach the server unchecked and give
            // the executor nothing to answer. Only the protocol's own notifications pass.
            if (!m.method.startsWith('notifications/')) {
              log({ event: 'notification-dropped', method: m.method });
              return;
            }
            if (m.method === 'notifications/cancelled' && isId(m.params?.requestId)) {
              const call = calls.get(idKey(m.params.requestId));
              if (call && !call.cancelled) {
                call.cancelled = true;
                // The server knows the call by the executor's id.
                const renamed = Buffer.from(`${JSON.stringify({ ...m, params: { ...m.params, requestId: call.serverId } })}\n`);
                if (call.state === 'sent' && call.settle) {
                  // Forwarded; the server then sends nothing more for it, so the outcome is settled here.
                  toServer(renamed);
                  markSettled(call.serverId);
                  call.settle({ kind: 'error', text: 'The agent cancelled this call while it was with the tool server, so its outcome is not known.', code: CODES.noAnswer });
                  return;
                }
                if (call.state === 'queued') return; // never sent: nothing for the server to cancel
              }
              // Another request in flight under the client's id: renamed for the server.
              const other = [...mapped.entries()].find(([, e]) => e.kind !== 'call' && idKey(e.id) === idKey(m.params.requestId));
              if (other) return void toServer(Buffer.from(`${JSON.stringify({ ...m, params: { ...m.params, requestId: other[0] } })}\n`));
            }
          }
          toServer(Buffer.from(`${read.text}\n`));
        },
        onTooLong: (length) => {
          log({ event: 'client-line-refused', code: 'too-long', length });
          answerError(null, CODES.invalidRequest, `A line longer than ${MAX_LINE_BYTES} bytes is not read.`);
        },
        onEnd: () => done(),
      });
    });

    // --- from the server ---
    /** The entry for a server id, or undefined. */
    const entryFor = (id) => (typeof id === 'string' ? mapped.get(id) : undefined);
    readLines(child.stdout, {
      onLine: (line) => {
        const read = readMessage(line, { strictNumbers: false });
        if (read.refused) {
          // Not a message the executor can read strictly. Where its top-level id can
          // still be found and names a request in flight, the raw bytes go to the
          // client under the client's id; a tool call then gets a receipt that says
          // the answer could not be read. Otherwise the line is handed on as it is.
          let text = null;
          try {
            text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(line);
          } catch {
            text = null;
          }
          const found = text === null ? null : topLevelId(text);
          const entry = found ? entryFor(found.value) : undefined;
          log({ event: 'server-line-not-read', code: read.refused.code, ...(entry ? { matched: entry.kind } : {}) });
          if (entry?.kind === 'call' && entry.call.state === 'sent' && entry.call.settle) return entry.call.settle({ kind: 'unreadable', text, errorText: UNREADABLE_ANSWER });
          if (entry && entry.kind !== 'call') {
            forget(found.value);
            return toClient(forClient(text, entry.id));
          }
          return toClient(Buffer.concat([line, Buffer.from('\n')]));
        }
        const m = read.message;
        if (read.kind === 'response') {
          const entry = entryFor(m.id);
          if (entry?.kind === 'call') {
            const call = entry.call;
            if (call.state === 'sent' && call.settle) {
              const unsafe = unsafeInteger(read.text) !== null;
              if (Object.hasOwn(m, 'result')) call.settle({ kind: 'answer', text: read.text, result: m.result, unsafe });
              else call.settle({ kind: 'server-error', text: read.text, errorText: `The tool server answered with an error: ${JSON.stringify(m.error)}` });
              return;
            }
            log({ event: 'late-answer-dropped', id: m.id });
            return;
          }
          if (typeof m.id === 'string' && settled.has(m.id)) {
            log({ event: 'late-answer-dropped', id: m.id });
            return;
          }
          if (entry?.kind === 'list') {
            const filtered = filteredList(read.text, m, entry.id, settings);
            if (filtered) {
              forget(m.id);
              if (filtered.hidden) log({ event: 'tools-hidden', hidden: filtered.hidden });
              return toClient(Buffer.from(`${filtered.text}\n`));
            }
          }
          if (entry) {
            forget(m.id);
            return toClient(forClient(read.text, entry.id));
          }
        }
        toClient(Buffer.concat([line, Buffer.from('\n')]));
      },
      onTooLong: (length) => log({ event: 'server-line-dropped', code: 'too-long', length }),
      onEnd: () => {},
    });

    // --- the end ---
    const serverEnded = new Promise((done) => {
      child.on('exit', (code, signal) => {
        serverGone = true;
        for (const call of calls.values()) {
          if (call.state === 'sent' && call.settle) call.settle({ kind: 'error', text: 'The tool server ended before it answered this call, so its outcome is not known.', code: CODES.noAnswer });
        }
        log({ event: 'server-ended', code, signal });
        done({ code: code ?? 1, signal });
      });
      child.on('error', (e) => {
        serverGone = true;
        log({ event: 'server-failed', error: e.message });
        done({ code: 1, error: e.message });
      });
    });

    let killTimer = null;
    clientEnded.then(() => {
      log({ event: 'client-ended' });
      try {
        child.stdin.end();
      } catch {
        // Already gone.
      }
      killTimer = setTimeout(() => {
        if (!serverGone) {
          log({ event: 'server-killed' });
          child.kill();
        }
      }, settings.shutdownWait);
    });

    const closed = serverEnded.then(async (ended) => {
      if (killTimer) clearTimeout(killTimer);
      timer?.stop();
      // Every call that was sent has settled; let the writer finish writing their stubs (and a seal that was asked for before the end).
      await agent.inTurn(() => {});
      // Nothing more is written: another program may now open the files.
      await agent.release();
      outputOpen = false;
      return ended;
    });
    attached = { child, closed };
    // The book is sealed on a timer while the executor runs, where the settings say so.
    timer?.start();
    return closed;
  }

  return {
    settings,
    slip: { fingerprint: about.fingerprint, issuerKey: about.issuerKey },
    executorKeys: p.executorKeys.keys,
    /** The recorder that seals: its name, the fingerprint of its key set and the timer; null where the settings name none. */
    recorder: describeRecorder(settings, p.sealer),
    attach,
    /** Seal the book now, with the recorder's keys: {entry, fingerprint}. */
    async seal() {
      const { entry, fingerprint: seal } = await agent.seal();
      return { entry, fingerprint: seal };
    },
    /** The administrator acknowledges the calls sent under a permission no longer in force, and may set some aside: {written, setAside, remaining}. */
    acknowledge: (o) => agent.acknowledge(o),
    /** What the executor says about itself: the recorder, and the agent's book, last seal and waiting calls (openAgent's "report"). */
    report: async () => ({ executor: 'provared-mcp-executor', recorder: describeRecorder(settings, p.sealer), agent: await agent.report() }),
    /** The stub writer: its "check()" is the book as the executor holds it. */
    writer: agent.writer,
    /** Why the executor takes no more calls, or null. */
    stopped: () => agent.stopped(),
    /** How many tool calls, and how many requests of every kind, wait for the server's answer. */
    status: () => ({ calls: agent.calls.size, requests: stats.requests }),
    /** Thumbprints of the executor's own keys, for the person who writes the permission. */
    async thumbprints() {
      return Promise.all(p.executorKeys.keys.map((k) => thumbprint(k)));
    },
    /** End the server now, if attached, and give up the lock on the files. */
    async close() {
      if (!attached) {
        await agent.inTurn(() => {});
        await agent.release();
        return;
      }
      try {
        attached.child.stdin.end();
      } catch {
        // Already gone.
      }
      const t = setTimeout(() => attached.child.kill(), settings.shutdownWait);
      await attached.closed;
      clearTimeout(t);
    },
  };
}

export { untilFree, RULES_DOCUMENT, RULE_DOCUMENT };
