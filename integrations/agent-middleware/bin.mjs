#!/usr/bin/env node
// The command: "provared-agent-middleware verify" checks one AMW record's
// signature; "provared-agent-middleware judge" judges AMW receipts against
// a Provared slip. Everything is read from files named on the command
// line; nothing is sent anywhere.
//
// Exit codes, as the Provared checker's: 0 where every receipt verified,
// every one was compared and found within the slip (and within the AMW
// permits where handed over), no condition of the slip that applies to a
// receipt was left unjudged, and the judgement rests on a passkey you
// named; 1 where it is intact as far as it goes but not that; 2 where
// nothing could be judged, or the command was not understood.
//
// "verify" needs Node.js alone; "judge" needs the library "provared", and
// loads it only when it is asked for.

import { readFileSync } from 'node:fs';
import { verifyRecord } from './verify.mjs';

// Anything from a record or a key list is untrusted text. As the Provared
// checker shows it (bin/provared-check.mjs): control characters, characters
// that cannot be seen, characters that change the direction of text and
// the blank Braille pattern are shown as a visible mark; more than three
// marks drawn on one character are shown as three and one mark; every run
// of spaces as one space.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cs}\p{DI}\u2800]/gu;
const STACKED = /(?<=\p{M}{3})\p{M}+/gu;
const safe = (text) => String(text).replace(UNSAFE, '\ufffd').replace(STACKED, '\ufffd').replace(/\p{Zs}+/gu, ' ');

// In JSON the same characters are written as escapes, which keeps the JSON
// exact and the terminal safe.
const UNSAFE_IN_JSON = /(?![\n])[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{DI}\u2800]|(?<=\p{M}{3})\p{M}/gu;
function escaped(character) {
  let out = '';
  for (let i = 0; i < character.length; i++) out += '\\u' + character.charCodeAt(i).toString(16).padStart(4, '0');
  return out;
}
const safeJson = (value) => JSON.stringify(value, null, 2).replace(UNSAFE_IN_JSON, escaped);

const USAGE = `provared-agent-middleware: reads the records of Agent Middleware (AMW) and judges them against a Provared slip.

  provared-agent-middleware verify --keys <keys.json> (--receipt <file> | --permit <file>) [--json]
  provared-agent-middleware judge --slip <slip.json> --keys <keys.json> --receipts <file> --service <id>
      [--issuer-key <thumbprint>]... [--issuer-origin <address>]... [--permits <file>]
      [--tool <amw-tool>=<action>]... [--credits <unit>:<decimals>] [--json]

  --keys          AMW's published key list ({"keys": [...]})
  --receipts      a JSON list of AMW receipt envelopes, or one envelope
  --permits       a JSON list of AMW permit envelopes, or one, if you hold them
  --service       the id, in the slip's "with", of the service that is the AMW gateway
  --issuer-key    the thumbprint of a passkey you trust; without one, the judgement rests on no key you named
  --issuer-origin a page address the slip may have been signed at
  --tool          an AMW tool name and the slip's action name for it; a tool not named is taken as the action of the same name
  --credits       how AMW's credits are read: the slip's unit and the decimal places, such as credits:2 (needed where the slip limits an amount)
  --json          print the whole answer as JSON
`;

const REPEATED = new Set(['--issuer-key', '--issuer-origin', '--tool']);
const SINGLE = new Set(['--keys', '--receipt', '--permit', '--slip', '--receipts', '--permits', '--service', '--credits']);

function usage(message) {
  process.stderr.write(`${message}\n\n${USAGE}`);
  return 2;
}

function parseArgs(args) {
  const out = { json: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') {
      out.json = true;
    } else if (REPEATED.has(a) || SINGLE.has(a)) {
      const value = args[i + 1];
      if (value === undefined || value.startsWith('--')) throw new Error(`${a} needs a value.`);
      i += 1;
      if (REPEATED.has(a)) (out[a] ??= []).push(value);
      else if (Object.hasOwn(out, a)) throw new Error(`${a} may be given once.`);
      else out[a] = value;
    } else {
      throw new Error(`Not an option: ${a.replace(/[^\x20-\x7e]/g, '?').slice(0, 64)}`);
    }
  }
  return out;
}

function readJson(path, what) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`The ${what} file could not be read.`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`The ${what} file is not JSON.`);
  }
}

// A list of envelopes, or one envelope.
function envelopes(value) {
  if (Array.isArray(value)) return value;
  if (value !== null && typeof value === 'object') return [value];
  return [];
}

const yes = (v) => (v ? 'yes' : 'NO');

function verifyCommand(o) {
  if (!o['--keys']) return usage('verify: --keys is needed.');
  const which = o['--receipt'] ? 'receipt' : o['--permit'] ? 'permit' : null;
  if (!which || (o['--receipt'] && o['--permit'])) return usage('verify: give --receipt or --permit, one of them.');
  const keys = readJson(o['--keys'], 'keys');
  const record = readJson(o[`--${which}`], which);
  const answer = verifyRecord(record, keys, which);
  if (o.json) {
    process.stdout.write(`${safeJson(answer)}\n`);
  } else {
    // The id is shown only for a record that verified (verifyRecord gives no other).
    process.stdout.write(`AMW ${which} ${answer.id === null ? '(identifier not shown: the record did not verify)' : safe(answer.id)}: ${answer.status}. ${answer.reason}\n`);
    if (answer.key) process.stdout.write(`Key: ${safe(answer.key.kid)} (${answer.key.alg === null ? 'method not stated' : safe(answer.key.alg)}, ${answer.key.status === null ? 'status not stated' : safe(answer.key.status)})\n`);
    process.stdout.write('This shows only that the key named signed this text. Evidence, not a verdict.\n');
  }
  return answer.status === 'verified' ? 0 : answer.status === 'malformed' ? 2 : 1;
}

async function judgeCommand(o) {
  for (const needed of ['--slip', '--keys', '--receipts', '--service']) if (!o[needed]) return usage(`judge: ${needed} is needed.`);
  const options = {
    slip: readJson(o['--slip'], 'slip'),
    keys: readJson(o['--keys'], 'keys'),
    receipts: envelopes(readJson(o['--receipts'], 'receipts')),
    service: o['--service'],
  };
  if (o['--permits']) options.permits = envelopes(readJson(o['--permits'], 'permits'));
  if (o['--issuer-key']) options.issuerKeys = o['--issuer-key'];
  if (o['--issuer-origin']) options.issuerOrigins = o['--issuer-origin'];
  if (o['--tool']) {
    options.tools = {};
    for (const pair of o['--tool']) {
      const eq = pair.indexOf('=');
      if (eq < 1 || eq === pair.length - 1) return usage('--tool takes <amw-tool>=<action>.');
      options.tools[pair.slice(0, eq)] = pair.slice(eq + 1);
    }
  }
  if (o['--credits']) {
    const m = /^([^:]+):(\d{1,2})$/.exec(o['--credits']);
    if (!m) return usage('--credits takes <unit>:<decimals>, such as credits:2.');
    options.credits = { unit: m[1], decimals: Number(m[2]) };
  }

  let judgeReceipts;
  try {
    ({ judgeReceipts } = await import('./judge.mjs'));
  } catch {
    throw new Error('judge needs the library "provared" (a version after 0.6.0), which could not be loaded. From a copy of the repository, run the command as its README shows.');
  }
  const r = await judgeReceipts(options);
  if (o.json) {
    process.stdout.write(`${safeJson(r)}\n`);
  } else {
    print(r);
  }
  return exitCode(r);
}

// 0 only where every receipt verified and was compared, none falls under a
// condition of the slip that was not judged, all are within the slip (and
// the AMW permits, where handed over), and the slip rests on a passkey you named.
function exitCode(r) {
  if (!r.judged) return 2;
  const s = r.summary;
  const allVerified = s.byStatus.verified === s.handed;
  const ok = s.withinSlip === true && s.notJudged === 0 && s.withinPermits !== false && allVerified && s.notCompared === 0 && s.trusted;
  return ok ? 0 : 1;
}

function print(r) {
  const out = (line = '') => process.stdout.write(`${line}\n`);
  if (r.slip) {
    out(`Slip ${r.slip.fingerprint ?? '(not read)'}${r.slip.issuerKey ? `, passkey ${r.slip.issuerKey}` : ''}`);
    for (const p of r.slip.problems) out(`  problem ${p.code}: ${p.message}`);
    for (const n of r.slip.notes) out(`  note: ${n}`);
  }
  for (const p of r.problems) out(`Problem ${p.code}: ${p.message}`);
  if (!r.judged) {
    out('Nothing was judged.');
    return;
  }
  out(`AMW gateway: the service "${r.service}" in the slip.`);
  out();
  out(`AMW receipts handed over: ${r.summary.handed} (${Object.entries(r.summary.byStatus).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'})`);
  r.receipts.forEach((item, i) => {
    const head = [`${i + 1}. ${item.id === null ? '(identifier not shown)' : safe(item.id)}: ${item.status}`];
    if (item.status !== 'verified') head.push(item.reason);
    else if (item.kind === 'denied') head.push(`${item.tool === null ? '(no tool)' : safe(item.tool)}, refused by the gateway`);
    else if (item.compared) {
      head.push(`${item.action ?? '(not an action name)'} at ${item.when}`);
      if (item.amount) head.push(`${item.amount.value} ${item.amount.unit}`);
      if (item.permit) head.push(`permit ${safe(item.permit)}`);
      head.push(item.findings.length > 0 ? 'OUTSIDE the slip' : item.notJudged.length > 0 ? `NOT KNOWN whether within the slip: ${item.notJudged.join(' and ')} not judged` : 'within the slip');
    }
    out(`  ${head.join('; ')}`);
    for (const f of item.findings) out(`     - ${f.code}: ${f.message}`);
    for (const f of item.permitFindings) out(`     - ${f.code}: ${f.message}`);
    for (const n of item.notes) out(`     note: ${n}`);
  });
  if (r.permits.length > 0) {
    out();
    out(`AMW permits handed over: ${r.permits.length}`);
    r.permits.forEach((p, i) => {
      const bits = [`${i + 1}. ${p.id === null ? '(identifier not shown)' : safe(p.id)}: ${p.status}`];
      if (p.status === 'verified') bits.push(p.active ? 'active' : 'NOT active', `tools ${p.allowedTools.map(safe).join(', ') || '(none)'}`);
      else bits.push(p.reason);
      out(`  ${bits.join('; ')}`);
      for (const n of p.notes ?? []) out(`     note: ${n}`);
    });
  }
  if (r.notJudged.length > 0) {
    out();
    out(`Conditions of the slip this reader cannot judge: ${r.notJudged.join(', ')}. A receipt they apply to is never said to be within the slip (see below).`);
  }
  out();
  out('What this judgement cannot show:');
  for (const line of r.cannotShow) out(`  - ${line}`);
  out();
  const s = r.summary;
  out(`Every AMW receipt verified? ${yes(s.byStatus.verified === s.handed)}`);
  out(`Every AMW receipt compared with the slip? ${s.notCompared === 0 ? 'yes' : `NO: ${s.notCompared} not compared (${s.denied} refused by the gateway, ${s.duplicates} handed over more than once)`}`);
  out(`Within the slip, as far as these receipts show? ${s.withinSlip === false ? 'NO' : s.withinSlip === true ? 'yes' : s.compared === 0 ? 'nothing was compared' : `NOT KNOWN: ${s.notJudged} compared receipt(s) fall under a condition of the slip this reader cannot judge`}`);
  if (s.withinPermits !== null) out(`Within the AMW permits handed over? ${yes(s.withinPermits)}`);
  out(`Rests on a passkey you named? ${s.trusted ? 'yes' : 'NO: name one with --issuer-key'}`);
  out('Evidence, not a verdict.');
}

async function main(args) {
  const [command, ...rest] = args;
  if (command === '--help' || command === '-h' || command === undefined) {
    process.stdout.write(USAGE);
    return command === undefined ? 2 : 0;
  }
  let o;
  try {
    o = parseArgs(rest);
  } catch (e) {
    return usage(e.message);
  }
  try {
    if (command === 'verify') return verifyCommand(o);
    if (command === 'judge') return await judgeCommand(o);
  } catch (e) {
    process.stderr.write(`${e.message}\n`);
    return 2;
  }
  return usage(`Not a command: ${String(command).replace(/[^\x20-\x7e]/g, '?').slice(0, 64)}`);
}

process.exitCode = await main(process.argv.slice(2));
