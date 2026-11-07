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
import { delimiter, isAbsolute, resolve } from 'node:path';
import { argumentsFingerprint, checkBook, countersign, denialCodes, entryLine, fingerprint, fromBase64url, identifierFingerprint, openRecorder, randomId, thumbprint } from 'provared';
import { loadCopyKey, openCopy, readCopy, unfinished } from './copy.mjs';
import { aboutSlip, bookFile, loadKeyFile, readIfThere, slipFrom, untilFree } from './files.mjs';
import { CODES, MAX_LINE_BYTES, idKey, isId, notificationLine, readLines, readMessage, repeatedName, responseLine, responseText, spliceId, topLevelId, unsafeInteger } from './jsonrpc.mjs';
import { RULES_DOCUMENT, RULE_DOCUMENT, RULES_ENTRY_PREFIX, TOOL_NAME, lookUp, readPointer, readRules, rulesFingerprint, statesContentRules, testCall } from './rules.mjs';

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

export const OUTCOME_UNKNOWN = 'The executor stopped while this call was with the tool server, so its outcome is not known. The receipt was written when the executor next started, from its own copy of what it had sent.';
export const RESULT_NOT_FINGERPRINTED = 'The tool server answered, and its result could not be written in the one form of RFC 8785 (text that is not well-formed Unicode, a number JSON cannot write, or a whole number beyond 9,007,199,254,740,991), so the receipt names no result.';
/** The error text a receipt names where the server's answer could not be read as a message; the answer went to the client as it was. */
export const UNREADABLE_ANSWER = 'The tool server answered with a line the executor could not read as a message (not JSON, a member name given twice, or not a response), so the receipt names no result. The line was handed to the agent as it was.';
/** The document a receipt written at a restart names, and the text its fingerprint is of. */
export const WRITTEN_LATE_DOCUMENT = 'executor.written-late';
export const WRITTEN_LATE = 'This receipt was written when the executor next started, from its own copy of what it had sent: the executor stopped before the receipt could be written. Its date is the time the call was sent; the countersignature is dated at the restart.';

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
 * key, slip or credential. Gives {settings, problems, warnings}. "settings"
 * is complete only where there are no problems.
 */
export function readSettings(config, root) {
  const problems = [];
  const warnings = [];
  const s = {};
  const at = (what, text) => problems.push(`${what}: ${text}`);
  if (!isObject(config)) return { settings: null, problems: ['The settings must be a JSON object.'], warnings };
  s.name = config.name ?? 'Provared MCP executor';
  if (typeof s.name !== 'string' || s.name.length < 1 || s.name.length > 200) at('name', 'must be text of 1 to 200 characters.');
  s.service = config.service ?? 'executor';
  if (typeof s.service !== 'string' || !SHORT_NAME.test(s.service)) at('service', 'must be 1 to 64 lower-case letters, digits, full stops, hyphens or underscores: the id the slip gives the executor in "with".');

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
  }

  readToolRules(config, s, at);
  readKnobs(config, s, at, root);
  s.shutdownWait = config.shutdownWait ?? 5000;
  if (!Number.isInteger(s.shutdownWait) || s.shutdownWait < 100 || s.shutdownWait > 600000) at('shutdownWait', 'must be a whole number of milliseconds from 100 to 600,000.');
  for (const k of Object.keys(config)) {
    if (![...SHARED_KEYS, 'server', 'agent', 'executor', 'shutdownWait'].includes(k)) warnings.push(`${k}: not a setting; set aside.`);
  }
  if (s.unlisted === 'forward') warnings.push(UNLISTED_FORWARD_WARNING);
  return { settings: problems.length ? null : s, problems, warnings };
}

/** The settings both ways of running share: the name, the service id, the tool rules and the knobs of readKnobs. */
export const SHARED_KEYS = ['name', 'service', 'tools', 'unlisted', 'hideUnlisted', 'timeout', 'denialsPerHour', 'callIdInMeta', 'maxWaiting', 'contentRules'];
export const UNLISTED_FORWARD_WARNING = 'unlisted is "forward": a call to a tool that no rule names is sent on with no receipt and no denial. The record then leaves those calls out.';

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
  return { executorKeys, content, warnings };
}

/**
 * Open one agent: its keys, its slip (held against the executor's keys, the
 * tool rules and the rules on content), its book, its copy and its stub
 * writer. "paths": slip, book, keys, issuerKeys, copy, copyKey. Says what
 * is wrong in one error. With "readOnly" nothing is written: no slip line to
 * the book file, no copy key made (checkConfig).
 */
export async function prepareAgent(paths, settings, shared, { now = Date.now, readOnly = false } = {}) {
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
  const checkOptions = { issuerKeys: paths.issuerKeys };
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
    now,
    denials: true,
    denialsPerHour: settings.denialsPerHour,
  });
  if (!readOnly) file.save(writer.book());
  const copyKey = loadCopyKey(paths.copyKey, { create: !readOnly });
  const read = copyKey ? readCopy(paths.copy, copyKey, settings.name) : { lines: [], checked: 0, refused: 0, cut: null, next: 0, sequence: { ok: true, problem: null } };
  if (!copyKey && existsSync(paths.copy)) throw new Error(`The copy ${paths.copy} holds lines, and its key ${paths.copyKey} is missing, so no line could be checked. Put the key back.`);
  if (read.cut !== null) throw new Error(`The copy ${paths.copy} ends part-way through a line (a stop while it was written). Look at it, and take off the part line by hand before the executor starts.`);
  if (read.lines.length > 0 && read.checked === 0) throw new Error(`No line of the copy ${paths.copy} checks under the copy key ${paths.copyKey}: the key is not the one the copy was written with. Put back the key the copy was written with.`);
  if (!read.sequence.ok) throw new Error(`The copy ${paths.copy} is not whole: ${read.sequence.problem} The executor does not start on a copy with a line missing, moved or put twice; look at it, and keep what it shows.`);
  const copy = copyKey ? openCopy(paths.copy, copyKey, settings.name, read.next) : null;
  return { paths, warnings, agentKeys, about, file, writer, copy, read };
}

/**
 * Open everything the stdio executor needs but the server: the keys, the
 * slip, the book, the copy, the stub writer and the credentials. Says what
 * is wrong in one error. With "readOnly" nothing is written (checkConfig).
 */
async function prepare(config, root, { now = Date.now, readOnly = false } = {}) {
  const { settings, problems, warnings } = readSettings(config, root);
  if (problems.length) throw new Error(`The settings have problems:\n- ${problems.join('\n- ')}`);
  const program = resolveCommand(settings.server.command, { root, path: settings.server.path });
  if (program.warning) warnings.push(program.warning);
  settings.server.resolved = program.path;
  const shared = await prepareShared(settings);
  warnings.push(...shared.warnings);
  // The credentials: read now, so that a missing one stops the start, and
  // kept in memory for the server's environment alone.
  const env = {};
  for (const name of settings.server.passEnv) {
    const v = process.env[name];
    if (v !== undefined) env[name] = v;
  }
  const credentialNames = [];
  for (const [name, from] of Object.entries(settings.server.env)) {
    env[name] = credentialValue(name, from);
    credentialNames.push(name);
  }
  const agent = await prepareAgent({ ...settings.agent, copy: settings.executor.copy, copyKey: settings.executor.copyKey }, settings, shared, { now, readOnly });
  warnings.push(...agent.warnings);
  return { settings, warnings, agent, agentKeys: agent.agentKeys, executorKeys: shared.executorKeys, about: agent.about, env, credentialNames, read: agent.read, content: shared.content };
}

/**
 * Check the settings, the keys, the slip and the credentials, as a start
 * would, without starting the server and without writing anything. Gives
 * {problems, warnings, tools, slip}: "problems" holds the one error a start
 * would stop with, if any.
 */
export async function checkConfig(config, root) {
  const { settings, problems, warnings } = readSettings(config, root);
  const tools = settings ? describeTools(settings) : [];
  if (problems.length) return { problems, warnings, tools };
  try {
    const p = await prepare(config, root, { readOnly: true });
    return { problems: [], warnings: p.warnings, tools, program: p.settings.server.resolved, slip: describeSlip(p.about, p.content), credentials: p.credentialNames, contentRules: describeContentRules(p.settings, p.content, p.about), unfinished: unfinished(p.read).length };
  } catch (e) {
    return { problems: [e.message], warnings, tools };
  }
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
 * that slip is not the one in force, this throws and the executor does not
 * open. With "name" (several agents) every log event names the agent.
 */
export async function openAgent(prepared, { settings, executorKeys, now, log, name = null }) {
  const { about, file, writer, copy, paths } = prepared;
  const agentLog = name === null ? log : (event) => log({ agent: name, ...event });
  for (const l of prepared.read.lines) if (!l.valid) agentLog({ event: 'copy-line-refused', line: l.raw.slice(0, 80) });

  let stopped = null;
  const stop = (why, event) => {
    stopped ??= why;
    agentLog({ event, reason: why });
  };

  /** Append what the book gained to its file. False, and the agent stopped, where that failed. */
  function save() {
    try {
      file.save(writer.book());
      return true;
    } catch (e) {
      stop(`the book could not be written (${e.message}).`, 'book-not-written');
      return false;
    }
  }

  // Calls the copy shows as sent and not finished.
  const stubsByCall = async () => {
    const held = new Map();
    for (const e of (await writer.check()).entries) {
      if (e.kind !== 'stub' || !Array.isArray(e.content?.details)) continue;
      for (const d of e.content.details) if (d.name === CALL_DOCUMENT) held.set(d.sha256, e.fingerprint);
    }
    return held;
  };
  const open = unfinished(prepared.read);
  if (open.length) {
    const held = await stubsByCall();
    for (const { sending: s, done: d } of open) {
      const inBook = held.get(await identifierFingerprint(s.call));
      if (inBook) {
        copy.note({ kind: 'done', call: s.call, when: new Date(now()).toISOString(), outcome: 'found-in-book', stub: inBook });
        continue;
      }
      if (s.slip !== about.fingerprint) {
        throw new Error(`The copy ${paths.copy} shows call ${s.call} sent under permission ${s.slip}, which is not the one in force (${about.fingerprint}), and the book holds no receipt for it. The executor cannot write that receipt under the permission in force. Put back the permission it was sent under and start again, so that the receipt is written; then put the new permission in place.`);
      }
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

  // One tool call at a time goes through the writer; this is its queue.
  let turn = Promise.resolve();
  const inTurn = (work) => {
    const mine = turn.then(work, work);
    turn = mine.then(
      () => {},
      () => {},
    );
    return mine;
  };

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
    stopped: () => stopped,
    save,
    inTurn,
    /** The tool calls in progress or waiting their turn, by the client's id. @type {Map<string, object>} */
    calls: new Map(),
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
          const d = await agent.inTurn(() => writer.deny(request, { source, ...(codes ? { codes } : {}) }));
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
            const added = result.detailsAfter?.added ? afterDocuments : [];
            try {
              copy.note({ kind: 'done', call: callId, when: new Date(now()).toISOString(), outcome: outcome.kind, ...(saved ? { stub: result.stub.fingerprint } : {}), countersigned: cs.accepted, ...(csFingerprint ? { countersignature: csFingerprint } : {}), documents: added });
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
 * @param {object} config the settings, as in executor.example.json
 * @param {{root?: string, now?: () => number, log?: (event: object) => void, serverStderr?: NodeJS.WritableStream|null}} [more]
 */
export async function openExecutor(config, more = {}) {
  const root = more.root ?? process.cwd();
  const now = more.now ?? Date.now;
  const log = more.log ?? ((event) => process.stderr.write(`${JSON.stringify({ provared: 'mcp-executor', ...event })}\n`));
  const p = await prepare(config, root, { now });
  const { settings, about, content } = p;
  for (const w of p.warnings) log({ event: 'warning', message: w });
  const agent = await openAgent(p.agent, { settings, executorKeys: p.executorKeys, now, log });
  const core = callCore({ settings, content, executorKeys: p.executorKeys, now });

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
      // Every call that was sent has settled; let the writer finish writing their stubs.
      await agent.inTurn(() => {});
      outputOpen = false;
      return ended;
    });
    attached = { child, closed };
    return closed;
  }

  return {
    settings,
    slip: { fingerprint: about.fingerprint, issuerKey: about.issuerKey },
    executorKeys: p.executorKeys.keys,
    attach,
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
    /** End the server now, if attached. */
    async close() {
      if (!attached) return;
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
