#!/usr/bin/env node
// The hook Claude Code runs before and after each tool call. It reads the
// call from standard input (as Claude Code hands it to a hook), names the
// action (actions.mjs), and asks the recorder service (recorder.mjs):
//
//   PreToolUse   "is this action within the slip?" A call outside it is
//                refused, and Claude Code is told why. If the recorder is
//                not running, the call is refused too: no record, no action.
//   PostToolUse  "write the stub for this action." If the stub cannot be
//                written, Claude Code is told, so that the gap is known.
//
// The stub names the tool and the SHA-256 fingerprint of the call's
// arguments, written in the one form of RFC 8785: never the arguments
// themselves, and never a file's contents.

import { argumentsFingerprint } from '../../src/index.js';
import { actionFor } from './actions.mjs';

const PORT = Number(process.env.PROVARED_CLAUDE_CODE_PORT || 8794);
const START = 'node integrations/claude-code/recorder.mjs start';

async function readInput() {
  let text = '';
  for await (const chunk of process.stdin) text += chunk;
  return text ? JSON.parse(text) : {};
}

async function ask(path, body) {
  const response = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const answer = await response.json();
  if (!response.ok) throw new Error(answer.error || `the recorder answered ${response.status}`);
  return answer;
}

function deny(reason) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason } }));
}

const input = await readInput();
const event = input.hook_event_name;
const action = actionFor(input.tool_name, input.tool_input);
if (!action || (event !== 'PreToolUse' && event !== 'PostToolUse')) process.exit(0);

let request;
try {
  request = { action, details: [{ name: String(input.tool_name), sha256: await argumentsFingerprint(input.tool_input ?? {}) }] };
} catch (e) {
  // Arguments that are not plain data cannot be fingerprinted: the call is still named, with no document.
  request = { action };
}

if (event === 'PreToolUse') {
  let answer;
  try {
    answer = await ask('/before', request);
  } catch (e) {
    deny(`Provared: the recorder beside Claude Code is not running, so this call is not recorded and is not taken. Ask the person to start it: ${START}`);
    process.exit(0);
  }
  if (!answer.allowed) {
    const reasons = [...answer.breaches, ...answer.problems].map((f) => `[${f.code}] ${f.message}`).join(' ');
    deny(`Provared: this call (${action}) is outside the permission the person signed, so it is not taken. ${reasons}`);
  }
  process.exit(0);
}

try {
  await ask('/record', request);
} catch (e) {
  console.error(`Provared: the stub for this call (${action}) was not written: ${e.message}. The action was taken and is not in the record.`);
  process.exit(2);
}
