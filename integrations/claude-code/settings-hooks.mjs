// The recorder's hooks in Claude Code's settings files, read without the
// library, so that the hook can look before every call at little cost.
//
// The recorder's hooks reach Claude Code in one of two ways: "init" writes
// them into a project's .claude/settings.local.json, or the Claude Code
// plugin (hooks/hooks.json, beside this file) brings them. Where both are
// in force, Claude Code runs both, since it keeps a plugin's hook apart
// from the same hook in a settings file, and each tool call would be asked
// about, and recorded, twice. The plugin's hook looks for the other kind
// here, and refuses the call where it finds one (hook.mjs); the start of a
// session says so (recorder.mjs, "session-start"); "remove-hooks" takes
// out the ones "init" wrote.
//
// A hook counts as the recorder's where one word of its command names a
// file "hook.mjs" with "recorder.mjs" and "actions.mjs" beside it: any copy
// of this recorder, installed from npm, from a copy of the repository or as
// the plugin, written by "init" or by hand.

import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

// The events in which a call is asked about and recorded.
export const CALL_EVENTS = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'];

// Claude Code's folder for the person's own settings and plugins.
export const claudeFolder = () => process.env.CLAUDE_CONFIG_DIR || join(homedir(), '.claude');

/**
 * The settings files Claude Code reads hooks from for a project, apart from
 * an organisation's managed settings: the person's own, the project's
 * shared one, and the project's local one (the one "init" writes).
 * @param {string} [project] the project's folder
 */
export function settingsFiles(project) {
  const list = [join(claudeFolder(), 'settings.json')];
  if (project) list.push(join(project, '.claude', 'settings.json'), join(project, '.claude', 'settings.local.json'));
  return list;
}

/** Whether two paths name one file, with either slash, and in any letter case on Windows. */
export function samePath(a, b) {
  const plain = (p) => resolve(p).split('\\').join('/');
  return process.platform === 'win32' ? plain(a).toLowerCase() === plain(b).toLowerCase() : plain(a) === plain(b);
}

/** Whether a path is a folder, or anything inside it. */
export function within(path, folder) {
  const plain = (p) => {
    const s = resolve(p).split('\\').join('/');
    return process.platform === 'win32' ? s.toLowerCase() : s;
  };
  const f = plain(folder).replace(/\/$/, '');
  return plain(path) === f || plain(path).startsWith(`${f}/`);
}

// The words of one command line: a word in quotation marks is one word.
const lineWords = (line) => [...line.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);

/** The words of a command hook: its program and arguments, as Claude Code is handed them. */
export function hookWords(h) {
  if (h === null || typeof h !== 'object' || h.type !== 'command' || typeof h.command !== 'string') return [];
  if (Array.isArray(h.args)) return [h.command, ...h.args.filter((a) => typeof a === 'string')];
  return lineWords(h.command.trim());
}

// A word with the project's folder put in, as Claude Code puts it in.
const expand = (word, project) => word.replace(/\$\{CLAUDE_PROJECT_DIR\}|\$CLAUDE_PROJECT_DIR|%CLAUDE_PROJECT_DIR%/g, () => project ?? '');

/**
 * Whether a word names one of the recorder's own scripts ("hook.mjs" or
 * "recorder.mjs"), in a folder that holds this recorder's files.
 * @param {string} word
 * @param {string} name "hook.mjs" or "recorder.mjs"
 * @param {string} [project] the folder a relative path is read from
 */
export function namesScript(word, name, project) {
  const path = expand(word, project);
  const parts = path.split(/[\\/]/);
  if (parts.at(-1) !== name) return false;
  const folder = dirname(resolve(project ?? '.', path));
  return ['hook.mjs', 'recorder.mjs', 'actions.mjs'].every((f) => existsSync(join(folder, f)));
}

function readSettings(file) {
  try {
    const text = readFileSync(file, 'utf8');
    return { settings: JSON.parse(text.replace(/^\uFEFF/, '')), mark: text.startsWith('\uFEFF') ? '\uFEFF' : '' };
  } catch {
    return null;
  }
}

/**
 * The recorder's hooks in the settings files Claude Code reads for a
 * project: each hook, in the events that ask about a call, whose command
 * names a recorder's "hook.mjs".
 * @param {string} [project]
 * @param {string[]} [files]
 * @returns {{file: string, event: string, command: string}[]}
 */
export function recorderHooksInSettings(project, files = settingsFiles(project)) {
  const found = [];
  for (const file of files) {
    const read = readSettings(file);
    const hooks = read?.settings?.hooks;
    if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) continue;
    for (const event of CALL_EVENTS) {
      if (!Array.isArray(hooks[event])) continue;
      for (const group of hooks[event]) {
        for (const h of group && Array.isArray(group.hooks) ? group.hooks : []) {
          const words = hookWords(h);
          if (words.some((w) => namesScript(w, 'hook.mjs', project))) found.push({ file, event, command: words.join(' ') });
        }
      }
    }
  }
  return found;
}

/** The files that hold the hooks found, each once. */
export const filesOf = (found) => [...new Set(found.map((f) => f.file))];

/**
 * What the plugin's hook, and the start of a session, say where the
 * recorder's hooks are also in a settings file.
 * @param {{file: string}[]} found
 * @param {string} run how the person runs this recorder's commands
 * @param {string} [project]
 */
export function doubledWords(found, run, project) {
  const local = project ? join(project, '.claude', 'settings.local.json') : null;
  const fixes = [];
  if (local && filesOf(found).some((f) => samePath(f, local))) fixes.push(`in the project's folder (${resolve(project)}), run: ${run} remove-hooks (it takes the recorder's hooks out of .claude/settings.local.json, and changes nothing else there)`);
  const others = filesOf(found).filter((f) => !local || !samePath(f, local));
  if (others.length > 0) fixes.push(`take the hooks that run a recorder's hook.mjs out of ${others.join(' and ')} by hand`);
  fixes.push('or turn the plugin off (/plugin, or "claude plugin disable provared-recorder@provared")');
  return `Provared: the recorder's hooks are in force twice, from the plugin provared-recorder and from ${filesOf(found).join(' and ')}, so each tool call would be asked about and recorded twice. Until one of the two is taken out, every tool call is refused. To take one out: ${fixes.join('; ')}. Then start Claude Code again, since it reads hooks when a session starts.`;
}

/**
 * The kind of a hook exactly as some copy of "init" writes it: "node",
 * perhaps the warning switch, the script's path and, for the start of a
 * session, "ensure"; nothing more. "hook", "ensure", or null.
 */
export function initKind(h, project) {
  let words = hookWords(h);
  if (words[0] !== 'node') return null;
  words = words.slice(1);
  if (words[0] === '--disable-warning=ExperimentalWarning') words = words.slice(1);
  if (words.length === 1 && namesScript(words[0], 'hook.mjs', project)) return 'hook';
  if (words.length === 2 && words[1] === 'ensure' && namesScript(words[0], 'recorder.mjs', project)) return 'ensure';
  return null;
}

/**
 * Take the hooks that "init" writes, from any copy of this recorder, out of
 * a project's .claude/settings.local.json, and nothing else: a group left
 * with no hook goes, and so does an event left with no group. The file is
 * written only where something was taken out, with a byte-order mark if it
 * had one.
 * @returns {{path: string, removed: number, problem?: string}}
 */
export function removeInitHooks(project, write) {
  const path = join(project, '.claude', 'settings.local.json');
  if (!existsSync(path)) return { path, removed: 0 };
  const read = readSettings(path);
  if (!read) return { path, removed: 0, problem: `${path} is not JSON, so it was left as it is.` };
  const hooks = read.settings?.hooks;
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return { path, removed: 0 };
  let removed = 0;
  for (const event of ['SessionStart', ...CALL_EVENTS]) {
    if (!Array.isArray(hooks[event])) continue;
    const groups = [];
    for (const group of hooks[event]) {
      if (!group || !Array.isArray(group.hooks)) {
        groups.push(group);
        continue;
      }
      const kept = group.hooks.filter((h) => initKind(h, project) === null);
      removed += group.hooks.length - kept.length;
      if (kept.length === group.hooks.length) groups.push(group);
      else if (kept.length > 0) groups.push({ ...group, hooks: kept });
    }
    if (groups.length > 0) hooks[event] = groups;
    else delete hooks[event];
  }
  if (removed > 0) write(path, read.mark + JSON.stringify(read.settings, null, 2) + '\n');
  return { path, removed };
}

/** Whether this process is a hook the plugin runs from this folder: Claude Code names the plugin's folder to its hooks. */
export function runAsPlugin(folder) {
  const root = process.env.CLAUDE_PLUGIN_ROOT;
  if (!root) return false;
  try {
    return samePath(realpathSync(root), realpathSync(folder));
  } catch {
    return false;
  }
}
