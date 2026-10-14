// What the tests share: a folder with the agent's keys and a slip signed
// with the library's development stand-in for a passkey; the hook run as
// Claude Code runs it; and the commands run as a person runs them. Every
// test works in a temporary folder and on a port of its own, never in the
// recorder's own folder or on its own port.
//
// Imported with import(), after local-library.mjs (see that file).

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleSlip, formatTime, prepareSlip } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { makeAgentKeys } from '../recorder.mjs';

export const here = fileURLToPath(new URL('.', import.meta.url));
const hook = join(here, '..', 'hook.mjs');
export const recorderFile = join(here, '..', 'recorder.mjs');
const LIVE_PORT = 8794;
const temporary = resolve(tmpdir());

// A temporary folder for a test file, removed when that file's tests end,
// so that test runs leave nothing behind in the computer's temporary
// folder (as the library's own tests do: test/helpers/temp.mjs). A folder
// still in use then (a recorder started in the background that has not
// yet ended) is left as it is.
const made = [];
process.on('exit', () => {
  for (const dir of made) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // Still in use: left for the computer's own clearing of its temporary folder.
    }
  }
});
export function tempFolder(prefix = 'provared-cc-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}

export const ACTIONS = ['provared.code.read', 'provared.code.change', 'provared.code.run', 'provared.code.release', 'provared.web.read', 'provared.agent.instruct'];

/**
 * A slip signed with the development stand-in for a passkey.
 * @param {{agentKeys: object[], passkey?: object, limits?: object[], actions?: string[], never?: string[], from?: number, until?: number, purpose?: string, sign?: (challenge: Uint8Array) => Promise<object>}} o
 */
export async function signSlip({ agentKeys, passkey, limits = [], actions = ACTIONS, never = ['destroys'], from = Date.now() - 60000, until = Date.now() + 3600000, purpose = 'Test the recorder beside a coding agent.', sign, id }) {
  passkey ??= await developmentPasskey();
  const prepared = await prepareSlip({
    issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'A coding agent', keys: agentKeys },
    actions,
    limits,
    never,
    with: [],
    validFrom: formatTime(from),
    validUntil: formatTime(until),
    purpose,
    ...(id ? { id } : {}),
  });
  return assembleSlip(prepared, sign ? await sign(prepared.challenge) : await passkey.sign(prepared.challenge));
}

/** A folder with the agent's keys and a signed slip in place as slip.json. */
export async function world(limits = [{ action: 'provared.code.run', count: 2 }]) {
  const folder = tempFolder();
  const agent = await makeAgentKeys(folder);
  const passkey = await developmentPasskey();
  const slip = await signSlip({ agentKeys: agent.keys, passkey, limits });
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(slip));
  return { folder, passkey, agent, slip };
}

function run(args, { env = {}, cwd, input } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', ...args], { cwd, env: { ...process.env, ...env } });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => resolve({ code, out: out.trim(), err: err.trim() }));
    child.stdin.end(input ?? '');
  });
}

let calls = 0;

/**
 * Run the hook as Claude Code runs it, as a separate process with its JSON
 * on standard input. It is awaited, not waited for, so that a service in
 * this process can answer it.
 * @param {{file?: string, env?: object, input?: string, more?: object}} [o] another copy of the hook, other
 *   surroundings, input written as it is, or more members of the input (such as a failed call's "error")
 */
export async function runHook(port, event, toolName, toolInput, { file = hook, env = {}, input, more = {} } = {}) {
  // Each call has an identifier of its own, as in Claude Code, unless the test gives one (in more).
  const text = input ?? JSON.stringify({ session_id: 'test', hook_event_name: event, tool_name: toolName, tool_input: toolInput, tool_use_id: `toolu_${++calls}`, cwd: here, ...more });
  const r = await run([file], { env: { PROVARED_CLAUDE_CODE_PORT: String(port), ...env }, input: text });
  return { ...r, decision: r.out ? JSON.parse(r.out).hookSpecificOutput : null };
}

/** A command of the recorder, run as a person runs it, on a temporary folder and a port of the test's own. */
export function runCommand(args, { folder, port, cwd = folder }) {
  if (!resolve(folder).startsWith(temporary + sep) || !resolve(cwd).startsWith(temporary + sep)) throw new Error('A test runs the commands in a temporary folder only.');
  if (!Number.isInteger(port) || port === LIVE_PORT) throw new Error('A test runs the commands on a port of its own only.');
  return run([recorderFile, ...args], { cwd, env: { PROVARED_CLAUDE_CODE_DIR: folder, PROVARED_CLAUDE_CODE_PORT: String(port) } });
}

/** A port that nothing listens on, at the moment it is asked for. */
export function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export const status = async (port) => (await fetch(`http://127.0.0.1:${port}/status`)).json();

/** Stop a service started in the background, if one answers on the port. */
export async function stopService(port) {
  if (port === LIVE_PORT) return;
  try {
    await fetch(`http://127.0.0.1:${port}/stop`, { method: 'POST', body: '{}', signal: AbortSignal.timeout(5000) });
  } catch {
    // Nothing was running.
  }
}
