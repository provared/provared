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

import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
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

// The words of one command line, as a shell splits it: blanks part words;
// text in double or single quotation marks is part of the word it stands
// in, blanks and all, so that "$CLAUDE_PROJECT_DIR"/hooks/hook.mjs is one
// word. A backslash is kept as it is (a Windows path), not read as an escape.
export function lineWords(line) {
  const words = [];
  let word = null;
  let quote = null;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = null;
      else word += ch;
    } else if (ch === '"' || ch === '\'') {
      quote = ch;
      word ??= '';
    } else if (/\s/.test(ch)) {
      if (word !== null) words.push(word);
      word = null;
    } else {
      word = (word ?? '') + ch;
    }
  }
  if (word !== null) words.push(word);
  return words;
}

/** The words of a command hook: its program and arguments, as Claude Code is handed them. */
export function hookWords(h) {
  if (h === null || typeof h !== 'object' || h.type !== 'command' || typeof h.command !== 'string') return [];
  if (Array.isArray(h.args)) return [h.command, ...h.args.filter((a) => typeof a === 'string')];
  return lineWords(h.command.trim());
}

/**
 * A word with the folders a hook's command may name put in: the project's
 * (${CLAUDE_PROJECT_DIR}, $CLAUDE_PROJECT_DIR, %CLAUDE_PROJECT_DIR%,
 * $env:CLAUDE_PROJECT_DIR) and the person's home folder (~ at the start,
 * ${HOME}, $HOME, %USERPROFILE%, $env:USERPROFILE).
 */
export function expand(word, project) {
  const home = homedir();
  return word
    .replace(/\$\{CLAUDE_PROJECT_DIR\}|\$env:CLAUDE_PROJECT_DIR|\$CLAUDE_PROJECT_DIR|%CLAUDE_PROJECT_DIR%/g, () => project ?? '')
    .replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])|%USERPROFILE%|\$env:USERPROFILE(?![A-Za-z0-9_])/g, () => home)
    .replace(/^~(?=$|[\\/])/, () => home);
}

/**
 * Whether a word names one of the recorder's own scripts ("hook.mjs" or
 * "recorder.mjs"): in a folder that holds this recorder's files, or, where
 * the file is no longer there, on a path that names Provared (a copy since
 * deleted or moved, whose hook still runs, and fails, at every call).
 * @param {string} word
 * @param {string} name "hook.mjs" or "recorder.mjs"
 * @param {string} [project] the folder a relative path is read from
 */
export function namesScript(word, name, project) {
  const path = expand(word, project);
  const parts = path.split(/[\\/]/);
  if (parts.at(-1) !== name) return false;
  const file = resolve(project ?? '.', path);
  if (!existsSync(file)) return /provared/i.test(path);
  return ['hook.mjs', 'recorder.mjs', 'actions.mjs'].every((f) => existsSync(join(dirname(file), f)));
}

// What the plugin's hook looks through before each call, at most, so that it always answers in time:
// a settings file larger than this is not read, at most this many words are looked at, for at most this long.
export const SCAN_LIMITS = { bytes: 1024 * 1024, words: 20000, ms: 2000 };

/**
 * A JSON text with its comments (two slashes to the end of a line, and a
 * slash and star to a star and slash)
 * and its commas before a closing bracket taken out, outside strings: what
 * a reader of "JSON with comments" would read. Claude Code itself is not
 * documented to accept comments in a settings file; a file that holds them
 * is looked through all the same, so that hooks in it are not missed.
 */
export function withoutComments(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 2;
    } else if (ch === ',' && ']}'.includes(text[nextSignificant(text, i + 1)])) {
      i++;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
}

// Where the next character that is neither a blank nor in a comment stands, read forwards once.
function nextSignificant(text, from) {
  let i = from;
  while (i < text.length) {
    if (/\s/.test(text[i])) i++;
    else if (text[i] === '/' && text[i + 1] === '/') {
      const end = text.indexOf('\n', i);
      i = end < 0 ? text.length : end;
    } else if (text[i] === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 2;
    } else return i;
  }
  return i;
}

function readSettings(file, maxBytes = Infinity, { comments = false } = {}) {
  try {
    if (statSync(file).size > maxBytes) return { tooLarge: true };
    const text = readFileSync(file, 'utf8');
    const body = text.replace(/^\uFEFF/, '');
    let settings;
    try {
      settings = JSON.parse(body);
    } catch (e) {
      if (!comments) throw e;
      settings = JSON.parse(withoutComments(body));
    }
    return { settings, mark: text.startsWith('\uFEFF') ? '\uFEFF' : '', text };
  } catch {
    return null;
  }
}

/**
 * The recorder's hooks in the settings files Claude Code reads for a
 * project: each hook, in the events that ask about a call, whose command
 * names a recorder's "hook.mjs". Where a file is larger than the limit, or
 * there are more words than the limit, or looking takes longer than the
 * limit, it stops and says why ("problem"), so that the caller can refuse
 * rather than answer late.
 * @param {string} [project]
 * @param {string[]} [files]
 * @param {{bytes: number, words: number, ms: number}} [limits]
 * @returns {{found: {file: string, event: string, command: string}[], problem: string|null}}
 */
export function recorderHooksInSettings(project, files = settingsFiles(project), limits = SCAN_LIMITS) {
  const found = [];
  const until = Date.now() + limits.ms;
  let words = 0;
  for (const file of files) {
    const read = readSettings(file, limits.bytes, { comments: true });
    if (read?.tooLarge) return { found, problem: `the settings file ${file} is larger than ${Math.round(limits.bytes / 1024)} KB, so it was not looked through for the recorder's hooks` };
    const hooks = read?.settings?.hooks;
    if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) continue;
    for (const event of CALL_EVENTS) {
      if (!Array.isArray(hooks[event])) continue;
      for (const group of hooks[event]) {
        for (const h of group && Array.isArray(group.hooks) ? group.hooks : []) {
          const these = hookWords(h);
          words += these.length;
          if (words > limits.words || Date.now() > until) return { found, problem: `the hooks in ${file} hold too much to be looked through in time for the recorder's own` };
          if (these.some((w) => namesScript(w, 'hook.mjs', project))) found.push({ file, event, command: these.join(' ') });
        }
      }
    }
  }
  return { found, problem: null };
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
 * had one, as JSON indented by two spaces: other formatting is not kept.
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
  // The text read is handed on, so that the writer can refuse where the file changed since.
  if (removed > 0) write(path, read.mark + JSON.stringify(read.settings, null, 2) + '\n', read.text);
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
