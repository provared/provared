// Rules on the content of a change (F-157, F-158): tested before a call is
// let through to the tool server.
//
// A permission allows kinds of action. Being allowed to change a file is
// not being allowed to change everything the file controls: a call that
// changes a label in a settings file, and with the same edit switches on a
// "scan" setting, is one call of one kind. The person who runs the agent
// writes rules on content in a file of the executor's own (the settings'
// "contentRules"); the executor tests each proposed change against them
// and refuses, with a denial, a call that would break one.
//
// A rule names a tool, says which of its calls it applies to ("when": a
// condition on the arguments), where the proposed content is in the
// arguments and how to read it ("content": a pointer, and "json" or
// "value"), and what must hold in it ("test": conditions). A rule with no
// "test" refuses every call it applies to: that is how a person closes a
// route the executor cannot judge, such as a tool that carries only a
// partial edit, whose resulting file the executor cannot know.
//
// The executor reads no file and keeps no content: it tests only what the
// call carries. Where it cannot read the content exactly (not JSON, a
// member named twice, a number two readers hold differently, nothing at
// the pointer), it refuses the call: a rule that let through what it
// could not read would be a rule any comment in a file evades.
//
// The rules file is fingerprinted (the SHA-256 of its parsed content in
// the one form of RFC 8785) into every receipt and denial as the label
// document "executor.rules", and the person puts the same fingerprint into
// the permission's "agent.software", so a reader sees that the rules in
// force were the ones the person approved, with no change to the format.
// A denial by a rule also names the rule, by the fingerprint of its name,
// as "executor.rule".

import { argumentsFingerprint } from 'provared';
import { repeatedName, unsafeInteger } from './jsonrpc.mjs';

/** The document, in every receipt and denial, whose fingerprint is that of the rules file in force (a label). */
export const RULES_DOCUMENT = 'executor.rules';
/** The document, in a denial by a content rule, whose fingerprint is that of the refusing rule's name (a label). */
export const RULE_DOCUMENT = 'executor.rule';
/** The most rules in a file. */
export const MAX_RULES = 1000;
/** The most bytes a rules file may have. */
export const MAX_RULES_BYTES = 1048576;
/** The longest text a pattern is matched against; a longer one cannot be read exactly and refuses the call. */
export const MAX_MATCH_TEXT = 4096;

/** The form of a tool's name (the MCP specification: 1 to 128 letters, digits, underscores, hyphens and full stops). */
export const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** The tokens of a JSON Pointer (RFC 6901), or null where the text is not one. */
export function readPointer(pointer) {
  if (typeof pointer !== 'string' || (pointer !== '' && !pointer.startsWith('/'))) return null;
  if (pointer === '') return [];
  return pointer.slice(1).split('/').map((t) => t.replaceAll('~1', '/').replaceAll('~0', '~'));
}

/** The value at a pointer's tokens in plain data: {found, value}. */
export function lookUp(value, tokens) {
  let v = value;
  for (const t of tokens) {
    if (Array.isArray(v)) {
      if (!/^(0|[1-9][0-9]*)$/.test(t)) return { found: false };
      v = v[Number(t)];
    } else if (isObject(v)) {
      if (!Object.hasOwn(v, t)) return { found: false };
      v = v[t];
    } else return { found: false };
    if (v === undefined) return { found: false };
  }
  return { found: true, value: v };
}

/** Whether two plain JSON values are the same (the same text in the one form of RFC 8785). */
export function sameJson(a, b) {
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((v, i) => sameJson(v, b[i]));
  if (isObject(a)) {
    if (!isObject(b)) return false;
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return ka.length === kb.length && ka.every((k, i) => k === kb[i] && sameJson(a[k], b[k]));
  }
  return a === b;
}

/**
 * Whether a text matches a pattern. "*" matches any run of characters
 * other than "/" and "\" (possibly none); "**" (any run of two or more
 * stars) matches any run of any characters; "?" matches exactly one
 * character other than "/" and "\"; every other character matches itself.
 * Characters are Unicode code points. Nothing else is special: a pattern
 * cannot escape a star.
 */
export function globMatch(pattern, text) {
  const p = Array.from(pattern);
  const t = Array.from(text);
  const tokens = [];
  for (let i = 0; i < p.length; i++) {
    if (p[i] === '*') {
      let j = i;
      while (p[j + 1] === '*') j++;
      tokens.push(j > i ? '**' : '*');
      i = j;
    } else if (p[i] === '?') tokens.push('?');
    else tokens.push({ c: p[i] });
  }
  const sep = (c) => c === '/' || c === '\\';
  // prev[j]: whether the tokens read so far match the first j characters.
  let prev = new Uint8Array(t.length + 1);
  prev[0] = 1;
  for (const tok of tokens) {
    const cur = new Uint8Array(t.length + 1);
    if (tok === '**') {
      let any = 0;
      for (let j = 0; j <= t.length; j++) {
        any = any || prev[j];
        cur[j] = any;
      }
    } else if (tok === '*') {
      // A run of non-separators that began where the earlier tokens matched.
      let run = 0;
      for (let j = 0; j <= t.length; j++) {
        if (prev[j]) run = 1;
        else if (j === 0 || sep(t[j - 1])) run = 0;
        cur[j] = run;
      }
    } else if (tok === '?') {
      for (let j = 1; j <= t.length; j++) cur[j] = prev[j - 1] && !sep(t[j - 1]) ? 1 : 0;
    } else {
      for (let j = 1; j <= t.length; j++) cur[j] = prev[j - 1] && t[j - 1] === tok.c ? 1 : 0;
    }
    prev = cur;
  }
  return prev[t.length] === 1;
}

// --- reading the rules file ---

const CONDITION_KINDS = ['equals', 'oneOf', 'absent', 'matches'];

/** Read one condition ({pointer, and exactly one of equals, oneOf, absent, matches; orAbsent}); gives the condition or adds problems. */
function readCondition(c, where, at) {
  if (!isObject(c)) return void at(where, 'must be an object: a "pointer", and exactly one of "equals", "oneOf", "absent" or "matches".');
  for (const k of Object.keys(c)) if (!['pointer', 'orAbsent', ...CONDITION_KINDS].includes(k)) at(`${where}.${k}`, 'is not part of a condition.');
  const tokens = readPointer(c.pointer);
  if (!tokens) at(`${where}.pointer`, 'must be a JSON Pointer (RFC 6901), such as "/scan" ("" is the whole value).');
  const kinds = CONDITION_KINDS.filter((k) => Object.hasOwn(c, k));
  if (kinds.length !== 1) return void at(where, 'must hold exactly one of "equals", "oneOf", "absent" or "matches".');
  const kind = kinds[0];
  const out = { pointer: c.pointer, tokens: tokens ?? [], kind, orAbsent: false };
  if (kind === 'equals') out.value = c.equals;
  else if (kind === 'oneOf') {
    if (!Array.isArray(c.oneOf) || c.oneOf.length < 1 || c.oneOf.length > 64) return void at(`${where}.oneOf`, 'must be a list of 1 to 64 values.');
    out.values = c.oneOf;
  } else if (kind === 'absent') {
    if (c.absent !== true) return void at(`${where}.absent`, 'must be true.');
  } else {
    if (typeof c.matches !== 'string' || c.matches.length < 1 || c.matches.length > 1000) return void at(`${where}.matches`, 'must be a pattern of 1 to 1,000 characters ("*" within one path part, "**" across parts, "?" one character).');
    out.pattern = c.matches;
  }
  if (Object.hasOwn(c, 'orAbsent')) {
    if (typeof c.orAbsent !== 'boolean') return void at(`${where}.orAbsent`, 'must be true or false.');
    if (kind === 'absent' && c.orAbsent) return void at(`${where}.orAbsent`, 'has no meaning with "absent".');
    out.orAbsent = c.orAbsent;
  }
  return out;
}

/** Read one condition or a list of 1 to "most" conditions. */
function readConditions(v, where, most, at) {
  const list = Array.isArray(v) ? v : [v];
  if (list.length < 1 || list.length > most) return void at(where, `must be a condition, or a list of 1 to ${most} conditions.`);
  const out = list.map((c, i) => readCondition(c, list.length === 1 && !Array.isArray(v) ? where : `${where}[${i}]`, at));
  return out.every(Boolean) ? out : undefined;
}

/**
 * Read the rules file's text. Gives {rules, parsed, problems}: "rules" is
 * complete only where there are no problems; "parsed" is the file as plain
 * data, which the fingerprint is of. The text is read strictly: UTF-8 (a
 * byte-order mark at the start is dropped, as for the settings), JSON, no
 * member name given twice, no whole number beyond 9,007,199,254,740,991,
 * no member that is not part of a rule.
 */
export function readRules(text) {
  const problems = [];
  const at = (what, message) => problems.push(`${what}: ${message}`);
  if (typeof text !== 'string') return { rules: null, parsed: null, problems: ['The rules file could not be read as text.'] };
  if (Buffer.byteLength(text) > MAX_RULES_BYTES) return { rules: null, parsed: null, problems: [`The rules file is longer than ${MAX_RULES_BYTES} bytes.`] };
  const clean = text.replace(/^﻿/, '');
  let parsed;
  try {
    parsed = JSON.parse(clean);
  } catch (e) {
    return { rules: null, parsed: null, problems: [`The rules file is not JSON (${e.message}).`] };
  }
  const twice = repeatedName(clean);
  if (twice !== null) return { rules: null, parsed: null, problems: [`The rules file names the member ${JSON.stringify(twice)} twice in one object.`] };
  if (unsafeInteger(clean) !== null) return { rules: null, parsed: null, problems: ['The rules file holds a whole number beyond 9,007,199,254,740,991, which two readers would hold differently.'] };
  if (!isObject(parsed)) return { rules: null, parsed, problems: ['The rules file must be a JSON object: {"version": 1, "rules": [...]}.'] };
  for (const k of Object.keys(parsed)) if (!['version', 'rules'].includes(k)) at(k, 'is not part of a rules file.');
  if (parsed.version !== 1) at('version', 'must be 1.');
  if (!Array.isArray(parsed.rules) || parsed.rules.length > MAX_RULES) at('rules', `must be a list of up to ${MAX_RULES} rules.`);
  const rules = [];
  const names = new Set();
  for (const [i, r] of (Array.isArray(parsed.rules) ? parsed.rules : []).entries()) {
    const where = `rules[${i}]`;
    if (!isObject(r)) {
      at(where, 'must be an object: name, tool, and optionally when, content and test.');
      continue;
    }
    for (const k of Object.keys(r)) if (!['name', 'tool', 'when', 'content', 'test'].includes(k)) at(`${where}.${k}`, 'is not part of a rule.');
    const rule = { name: r.name, tools: [], when: [], content: null, tests: null };
    if (typeof r.name !== 'string' || r.name.length < 1 || r.name.length > 200) at(`${where}.name`, 'must be text of 1 to 200 characters.');
    else if (names.has(r.name)) at(`${where}.name`, 'is the name of another rule; names must differ.');
    else names.add(r.name);
    const tools = Array.isArray(r.tool) ? r.tool : [r.tool];
    if (tools.length < 1 || tools.length > 64 || !tools.every((t) => typeof t === 'string' && TOOL_NAME.test(t))) at(`${where}.tool`, 'must be a tool name (1 to 128 letters, digits, underscores, hyphens or full stops), or a list of 1 to 64 of them.');
    else if (new Set(tools).size !== tools.length) at(`${where}.tool`, 'names one tool twice.');
    else rule.tools = tools;
    if (Object.hasOwn(r, 'when')) rule.when = readConditions(r.when, `${where}.when`, 16, at) ?? [];
    if (Object.hasOwn(r, 'content')) {
      const c = r.content;
      if (!isObject(c) || Object.keys(c).some((k) => !['pointer', 'as'].includes(k))) at(`${where}.content`, 'must be {"pointer": <a JSON Pointer into the arguments>, "as": "json" or "value"}.');
      else {
        const tokens = readPointer(c.pointer);
        if (!tokens) at(`${where}.content.pointer`, 'must be a JSON Pointer (RFC 6901) into the arguments, such as "/content".');
        if (!['json', 'value'].includes(c.as)) at(`${where}.content.as`, 'must be "json" (the argument is text holding JSON) or "value" (the argument is the content itself, as plain data).');
        rule.content = { pointer: c.pointer, tokens: tokens ?? [], as: c.as };
      }
      if (!Object.hasOwn(r, 'test')) at(`${where}.content`, 'is given with no "test": a rule with no test refuses every call it applies to, and reads no content.');
    }
    if (Object.hasOwn(r, 'test')) rule.tests = readConditions(r.test, `${where}.test`, 64, at) ?? [];
    rules.push(rule);
  }
  return { rules: problems.length ? null : rules, parsed, problems };
}

/** The fingerprint of a rules file: the SHA-256 of its parsed content in the one form of RFC 8785, in base64url. */
export function rulesFingerprint(parsed) {
  return argumentsFingerprint(parsed);
}

// --- testing a call ---

const TOO_LONG = `is text longer than ${MAX_MATCH_TEXT} characters, which is not matched against a pattern`;

/** A value from a rule, shown in a message, cut short where long. The value is the person's own, from the rules file. */
function shown(v) {
  const text = JSON.stringify(v) ?? 'undefined';
  return text.length > 120 ? `${text.slice(0, 117)}...` : text;
}

/** What a condition asks for, in words. */
function wants(c) {
  let w;
  if (c.kind === 'equals') w = `must equal ${shown(c.value)}`;
  else if (c.kind === 'oneOf') w = `must be one of ${shown(c.values)}`;
  else if (c.kind === 'absent') w = 'must not be present';
  else w = `must match the pattern ${shown(c.pattern)}`;
  return c.orAbsent ? `${w}, or be absent` : w;
}

/**
 * Whether a condition holds for a value. Gives {holds} or {problem}: a
 * problem is a value the condition cannot judge exactly (text too long to
 * match).
 */
function holds(c, subject) {
  const found = lookUp(subject, c.tokens);
  if (c.kind === 'absent') return { holds: !found.found };
  if (!found.found) return { holds: c.orAbsent };
  const v = found.value;
  if (c.kind === 'equals') return { holds: sameJson(v, c.value) };
  if (c.kind === 'oneOf') return { holds: c.values.some((x) => sameJson(v, x)) };
  if (typeof v !== 'string') return { holds: false };
  if (v.length > MAX_MATCH_TEXT) return { problem: `what is found at ${JSON.stringify(c.pointer)} ${TOO_LONG}` };
  return { holds: globMatch(c.pattern, v) };
}

/**
 * Read the content a rule tests, from the arguments: the arguments
 * themselves where the rule names no "content"; else what is at the
 * content pointer, read as JSON text or taken as it is. Gives {subject,
 * where} or {problem}.
 */
function contentOf(rule, args) {
  if (!rule.content) return { subject: args, where: 'in the arguments' };
  const where = `in the content at ${JSON.stringify(rule.content.pointer)}`;
  const found = lookUp(args, rule.content.tokens);
  if (!found.found) return { problem: `nothing is found at ${JSON.stringify(rule.content.pointer)} in the arguments, where the rule reads the content` };
  if (rule.content.as === 'value') return { subject: found.value, where };
  const text = found.value;
  if (typeof text !== 'string') return { problem: `what is found at ${JSON.stringify(rule.content.pointer)} in the arguments is not text, and the rule reads it as JSON text` };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { problem: `the content at ${JSON.stringify(rule.content.pointer)} is not JSON, and the rule reads it as JSON` };
  }
  if (repeatedName(text, true) !== null) return { problem: `the content at ${JSON.stringify(rule.content.pointer)} names one member twice in one object, or two that differ only in capitals, which two readers may read differently` };
  if (unsafeInteger(text) !== null) return { problem: `the content at ${JSON.stringify(rule.content.pointer)} holds a whole number beyond 9,007,199,254,740,991, which two readers would hold differently` };
  return { subject: parsed, where };
}

/**
 * Test a call against the rules. Gives null where no rule refuses it, or
 * {reason: {code, message}, rule} where one does: the code is
 * "content-rule" (a rule's test did not hold, or a rule with no test
 * applies) or "content-unreadable" (the rule could not read exactly what
 * it tests). The first refusing rule, in the file's order, is the one
 * named. The message names the rule and what it asks for, never a value
 * from the arguments.
 *
 * @param {object[]} rules from readRules
 * @param {string} tool the tool's name
 * @param {object|undefined} args the call's arguments
 * @param {string|undefined} argsText their JSON text, for the check of names given twice
 */
export function testCall(rules, tool, args, argsText) {
  const relevant = rules.filter((r) => r.tools.includes(tool));
  if (relevant.length === 0) return null;
  const unreadable = (rule, what) => ({ reason: { code: 'content-unreadable', message: `Content rule ${JSON.stringify(rule.name)} could not read what it tests: ${what}. The call was not taken.` }, rule: rule.name });
  const subjectArgs = args ?? {};
  if (argsText !== undefined && repeatedName(argsText, true) !== null) return unreadable(relevant[0], 'the arguments name one member twice in one object, or two that differ only in capitals, which two readers may read differently');
  for (const rule of relevant) {
    let applies = true;
    for (const c of rule.when) {
      const h = holds(c, subjectArgs);
      if (h.problem) return unreadable(rule, `in its "when", ${h.problem}`);
      if (!h.holds) {
        applies = false;
        break;
      }
    }
    if (!applies) continue;
    if (!rule.tests) return { reason: { code: 'content-rule', message: `Content rule ${JSON.stringify(rule.name)} does not allow this call to ${JSON.stringify(tool)}. The call was not taken.` }, rule: rule.name };
    const content = contentOf(rule, subjectArgs);
    if (content.problem) return unreadable(rule, content.problem);
    for (const c of rule.tests) {
      const h = holds(c, content.subject);
      if (h.problem) return unreadable(rule, h.problem);
      if (!h.holds) return { reason: { code: 'content-rule', message: `Content rule ${JSON.stringify(rule.name)}: the value at ${JSON.stringify(c.pointer)} ${content.where} ${wants(c)}. The call was not taken.` }, rule: rule.name };
    }
  }
  return null;
}
