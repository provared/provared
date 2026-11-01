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
//
// It fails closed, as hook.mjs does: everything, from loading
// plugin-library.mjs on, runs under one guard, with no import that could
// fail before it. Claude Code lets a call go ahead when its hook ends in any
// way but one (exit code 2), unless it reads "onFailure": "block" (version
// 2.1.295 and later); so whatever goes wrong here, a call is refused before
// it is taken, and Claude Code is told after it.

const [command] = process.argv.slice(2);

// What a hook says where the plugin itself cannot run, as hook.mjs's own guard says it.
async function hookFailed(e) {
  let event = null;
  try {
    let given = '';
    for await (const chunk of process.stdin) given += chunk;
    event = given ? JSON.parse(given).hook_event_name : null;
  } catch {
    // The input could not be read: the call is refused all the same.
  }
  const said = `Provared: the plugin's hook could not run (${e && e.message ? e.message : e}).`;
  if (event === 'PreToolUse') {
    console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `${said} This call is not checked or recorded, so it is not taken.` } }));
    process.exit(0);
  }
  console.error(`${said} ${event === 'PostToolUse' || event === 'PostToolUseFailure' ? 'The call was taken and is not in the record.' : 'The call is not checked or recorded.'}`);
  process.exit(2);
}

try {
  const { join } = await import('node:path');
  const { findLibrary, installLibrary, ROOT, useLibrary } = await import('./plugin-library.mjs');
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
    // From here hook.mjs reads the input, and its own guard answers for whatever goes wrong in it.
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
} catch (e) {
  if (command === 'hook') {
    // A hook.mjs that could not even load has not read the input; one that read it answers for itself, so this is a last resort.
    if (!process.stdin.readableEnded) await hookFailed(e);
    console.error(`Provared: the plugin's hook failed (${e && e.message ? e.message : e}). The call is not checked or recorded.`);
    process.exit(2);
  } else if (command === 'session-start') {
    const words = `Provared: the plugin could not run (${e && e.message ? e.message : e}), so every tool call is refused: no record, no action. If its files are damaged, install it again (/plugin).`;
    console.log(JSON.stringify({ systemMessage: words, hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: words } }));
  } else {
    console.error(`Provared: the plugin could not run (${e && e.message ? e.message : e}).`);
    process.exitCode = 1;
  }
}
