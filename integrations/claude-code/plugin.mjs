#!/usr/bin/env node
// The Claude Code plugin's entry: what its hooks run (hooks/hooks.json), and
// what the person runs in a terminal, from the plugin's folder:
//
//   node plugin.mjs hook               the hook before and after each tool call (hook.mjs)
//   node plugin.mjs session-start      at the start of a session: the library, then the recorder
//   node plugin.mjs install-library    install the library into the plugin's data folder now
//   node plugin.mjs <command>          any of the recorder's commands (init, use, check, ...)
//
// It finds the library "provared" by an exact path, installing it into the
// plugin's data folder where Claude Code did not install it beside the
// plugin, and loads it from there alone (plugin-library.mjs). The recorder's
// and the hook's own files are the same as everywhere else.

import { join } from 'node:path';
import { findLibrary, installLibrary, ROOT, useLibrary } from './plugin-library.mjs';

const [command] = process.argv.slice(2);
const self = join(ROOT, 'plugin.mjs');
// How the person runs the plugin's commands, said in every message: the recorder and the hook read it.
const run = `node ${self.includes(' ') ? `"${self}"` : self}`;
process.env.PROVARED_CLAUDE_CODE_RUN = run;
process.env.PROVARED_CLAUDE_CODE_PLUGIN = '1';

const remedy = `Run in a terminal: ${run} install-library`;
let library = findLibrary();
let problem = null;
// The library is installed at a session's start and at the person's own commands, never before a tool call, which must answer at once.
if (!library && command !== 'hook') {
  try {
    library = installLibrary({ timeoutMs: command === 'session-start' ? 20000 : 120000 });
  } catch (e) {
    problem = e.message;
  }
}
useLibrary(library, `Provared's library is not installed for the plugin${problem ? ` (${problem})` : ''}. ${remedy}`);

if (command === 'hook') {
  await import('./hook.mjs');
} else if (!library) {
  const words = `Provared: the recorder beside Claude Code cannot run, because its library is not installed for the plugin (${problem}). Until it is, every tool call is refused: no record, no action. ${remedy}`;
  if (command === 'session-start') {
    console.log(JSON.stringify({ systemMessage: words, hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: words } }));
  } else {
    console.error(words);
    process.exitCode = 1;
  }
} else if (command === 'install-library') {
  console.log(`Provared's library is installed for the plugin, in ${library}.`);
} else {
  const { main } = await import('./recorder.mjs');
  process.removeAllListeners('warning');
  main(process.argv.slice(2)).then((code) => {
    if (code !== null) process.exitCode = code;
  }, (e) => {
    console.error(e.message);
    process.exitCode = 1;
  });
}
