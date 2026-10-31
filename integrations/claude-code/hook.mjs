#!/usr/bin/env node
// The hook Claude Code runs before and after each tool call. It reads the
// call from standard input (as Claude Code hands it to a hook), names the
// action (actions.mjs), and asks the recorder service (recorder.mjs):
//
//   PreToolUse          "is this action within the slip?" A call outside it
//                       is refused, and Claude Code is told why. If the
//                       recorder is not running, the call is refused too: no
//                       record, no action.
//   PostToolUse         "write the stub for this action." If the stub cannot
//                       be written, Claude Code is told, so that the gap is
//                       known.
//   PostToolUseFailure  the same, for a call that started and then failed:
//                       it may have done part of its work, so it is recorded,
//                       with the tool named as failed.
//
// The stub always names the tool, and the SHA-256 fingerprint of the
// call's arguments, written in the one form of RFC 8785 (or, where that
// form cannot be made, as JavaScript writes them, which the document's name
// then says): never the arguments themselves, and never a file's contents.
// For a failed call it also names the fingerprint of the error text Claude
// Code reported, as UTF-8, never the text. Nothing in either can keep the
// stub from being written.
//
// It fails closed. Claude Code lets a call go ahead when its hook fails in
// any way but one (exit code 2), so everything here runs under one guard:
// whatever goes wrong (input that cannot be read, a library that cannot be
// loaded, a fault in this file), a call is refused before it is taken, and
// Claude Code is told after it. Where the hook cannot even start, only
// Claude Code's own setting "onFailure": "block" refuses the call.
//
// Run by the Claude Code plugin (hooks/hooks.json), it also looks, before
// each call, for the recorder's hooks in a settings file of the project or
// of the person (settings-hooks.mjs): where they are there too, each call
// would be asked about and recorded twice, so the call is refused and the
// person is told how to take one of the two out.

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.env.PROVARED_CLAUDE_CODE_PORT || 8794);
// The command that starts the recorder beside this hook, by its path, which works however it was installed.
const RECORDER = fileURLToPath(new URL('./recorder.mjs', import.meta.url));
const START = `node "${RECORDER}" start`;
const RUN = `node ${RECORDER.includes(' ') ? `"${RECORDER}"` : RECORDER}`;
// The recorder's folder, as recorder.mjs names it: whether a permission was ever put in place there.
const FOLDER = process.env.PROVARED_CLAUDE_CODE_DIR || join(homedir(), '.provared', 'claude-code');
const AFTER = ['PostToolUse', 'PostToolUseFailure'];
// How long the hook waits for the recorder: a call waits its turn while the
// recorder seals the book or takes a new permission. It is less than the
// hooks' own time-out (30 seconds, as "init" writes them), so that the hook
// always answers before Claude Code gives up on it.
const WAIT_MS = 25000;

// The input as Claude Code wrote it, and as JSON reads it.
let given = '';
async function readInput() {
  for await (const chunk of process.stdin) given += chunk;
  return given ? JSON.parse(given) : {};
}

// The arguments in the fallback form: as JavaScript's JSON.stringify writes
// them, except that a number too large to hold, which JSON reads as
// Infinity, is written as it was sent (1e400, -1e400), so that two such
// numbers are not written alike. Such a number stands bare in the text,
// where no value in JSON could stand, so it cannot be taken for another
// value. A mark made for this one writing stands in for it meanwhile.
function fallbackForm() {
  const mark = `@${crypto.randomUUID()}@`;
  const args = JSON.parse(given, (key, value, context) => (typeof value === 'number' && !Number.isFinite(value) && context?.source ? mark + context.source : value)).tool_input ?? {};
  // eslint-disable-next-line security/detect-non-literal-regexp -- built from a random UUID made here, which holds only hexadecimal digits and hyphens.
  return (JSON.stringify(args) ?? 'null').replaceAll(new RegExp(`"${mark}([^"]*)"`, 'g'), '$1');
}

// The recorder's answer; "refused" says the recorder answered and refused,
// so that its word, and only its word, is taken as certain.
async function ask(path, body) {
  const response = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(WAIT_MS),
  });
  const answer = await response.json();
  if (!response.ok) throw Object.assign(new Error(answer.error || `the recorder answered ${response.status}`), { refused: true, code: answer.code });
  return answer;
}

function deny(reason) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }));
}

// Nothing answers on the port: the recorder is not running, and nothing was sent to it.
const notRunning = (e) => e?.cause?.code === 'ECONNREFUSED';

let event = null;
try {
  const input = await readInput();
  event = input.hook_event_name;
  const { actionFor } = await import('./actions.mjs');
  const action = actionFor(input.tool_name, input.tool_input);
  if (!action || (event !== 'PreToolUse' && !AFTER.includes(event))) process.exit(0);
  // The library is loaded only for a call that is recorded.
  const { argumentsFingerprint, sha256, toBase64url, utf8 } = await import('provared');
  // The SHA-256 of a text as UTF-8, a broken character written as U+FFFD: it can be made of any text.
  const textFingerprint = async (text) => toBase64url(await sha256(utf8(text)));

  // The stub always names the tool, in at most 120 characters.
  let tool = String(input.tool_name ?? '').toWellFormed() || '(no name)';
  if ([...tool].length > 120) tool = `${[...tool].slice(0, 119).join('')}…`;
  const failed = event === 'PostToolUseFailure';
  // The fingerprint of the arguments in the one form of RFC 8785. Where
  // that form cannot be made (a number out of range, a broken character),
  // the fingerprint of the arguments as JavaScript's JSON.stringify writes
  // them, as UTF-8, and the document's name says so.
  const said = [];
  if (failed) said.push('failed');
  let sha;
  try {
    sha = await argumentsFingerprint(input.tool_input ?? {});
  } catch {
    sha = await textFingerprint(fallbackForm());
    said.push('arguments in the fallback form');
  }
  const request = { action, details: [{ name: said.length ? `${tool} (${said.join('; ')})` : tool, sha256: sha }] };
  // A failed call: the fingerprint of the error text Claude Code reported, never the text.
  if (failed && typeof input.error === 'string') request.details.push({ name: 'error', sha256: await textFingerprint(input.error) });
  // Claude Code's identifier of the call, so that the call is recorded under the permission it was asked under.
  const call = { ...request, ...(typeof input.tool_use_id === 'string' ? { toolUseId: input.tool_use_id } : {}) };

  if (event === 'PreToolUse') {
    // Run as the plugin: the recorder's hooks also in a settings file would ask about, and record, each call twice.
    const settingsHooks = process.env.CLAUDE_PLUGIN_ROOT ? await import('./settings-hooks.mjs') : null;
    if (settingsHooks?.runAsPlugin(dirname(RECORDER))) {
      const project = process.env.CLAUDE_PROJECT_DIR || (typeof input.cwd === 'string' ? input.cwd : process.cwd());
      const found = settingsHooks.recorderHooksInSettings(project);
      if (found.length > 0) {
        deny(settingsHooks.doubledWords(found, RUN, project));
        process.exit(0);
      }
    }
    let answer;
    try {
      answer = await ask('/before', call);
    } catch (e) {
      deny(notRunning(e) && !existsSync(join(FOLDER, 'slip.json'))
        ? `Provared: no permission has been signed for this agent yet, so the recorder beside Claude Code is not running, and this call is not recorded and is not taken. Ask the person to set it up, in a terminal: ${RUN} init (it makes the agent's keys and prints a link to https://sign.prova.red/, where they sign the permission with their own passkey), then ${RUN} use <the saved file>. Nothing signs for them.`
        : notRunning(e)
        ? `Provared: the recorder beside Claude Code is not running, so this call is not recorded and is not taken. Ask the person to start it: ${START}`
        : `Provared: the recorder beside Claude Code did not answer (${e.message}), so this call is not recorded and is not taken.`);
      process.exit(0);
    }
    if (!answer.allowed) {
      const reasons = [...answer.breaches, ...answer.problems].map((f) => `[${f.code}] ${f.message}`).join(' ');
      deny(`Provared: this call (${action}) is outside the permission the person signed, so it is not taken. ${reasons}`);
    }
    process.exit(0);
  }

  try {
    await ask('/record', call);
  } catch (e) {
    const which = `${action}${failed ? ', which failed' : ''}`;
    // Only where the recorder refused, or was not there, is the stub known not to be written;
    // where it signed the stub and could not write the file yet, it says so, and that is told.
    console.error(e.code === 'held-not-saved'
      ? `Provared: the stub for this call (${which}) is not yet in the book file: ${e.message}. The action was taken.`
      : e.refused || notRunning(e)
        ? `Provared: the stub for this call (${which}) was not written: ${e.message}. The action was taken and is not in the record.`
        : `Provared: the recorder did not confirm the stub for this call (${which}) within ${WAIT_MS / 1000} seconds (${e.message}). The action was taken and is not shown to be in the record.`);
    process.exit(2);
  }
} catch (e) {
  // Anything not foreseen above. Before a call: refused. After it, or where
  // the event is not known: exit code 2, which refuses a call not yet taken
  // and tells Claude Code about one that was.
  const said = `Provared: the hook beside Claude Code failed (${e && e.message ? e.message : e}).`;
  if (event === 'PreToolUse') {
    deny(`${said} This call is not checked or recorded, so it is not taken.`);
    process.exit(0);
  }
  console.error(`${said} ${AFTER.includes(event) ? 'The stub was not sent to the recorder: the call was taken and is not in the record.' : 'The call is not checked or recorded.'}`);
  process.exit(2);
}
