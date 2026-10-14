// How a Claude Code tool call is named in a record. The names are from the
// format's shared list (spec/provared-format.md, section 16), so that any
// checker knows what they mean. The naming is done here, by the hook, which
// the agent cannot change: an agent names its action honestly or not at all,
// and this file is the "honestly".
//
// Every tool is recorded, those of MCP servers and those not known here
// included, except a short list of tools that only talk to the person or to
// the model itself (a question, a plan, a list of tasks): they read and
// change nothing outside the conversation. A tool not known here is named
// as running a program, the widest of the names, so that a new tool is
// checked and recorded rather than let through.

/**
 * The tools that are not recorded: each only asks the person something, or
 * changes what the model itself holds (its plan, its list of tasks, the
 * instructions or tool descriptions it has loaded).
 */
export const NOT_RECORDED = ['AskUserQuestion', 'TodoWrite', 'TodoRead', 'ExitPlanMode', 'EnterPlanMode', 'Skill', 'ToolSearch', 'EndConversation'];

/**
 * The action name for a tool call, or null where the call is not recorded.
 * @param {string} toolName
 * @param {any} toolInput
 * @returns {string|null}
 */
export function actionFor(toolName, toolInput) {
  const name = String(toolName ?? '');
  if (/^mcp__/.test(name)) return 'provared.code.run';
  if (NOT_RECORDED.includes(name)) return null;
  switch (name) {
    case 'Read':
    case 'Grep':
    case 'Glob':
    case 'LS':
    case 'NotebookRead':
      return 'provared.code.read';
    case 'Edit':
    case 'Write':
    case 'MultiEdit':
    case 'NotebookEdit':
      return 'provared.code.change';
    case 'WebFetch':
    case 'WebSearch':
      return 'provared.web.read';
    // Starting another agent, or handing a message to one.
    case 'Agent':
    case 'Task':
    case 'Workflow':
    case 'SendMessage':
      return 'provared.agent.instruct';
    // Publishing a page on a server for others to open, as a push or a package release does.
    case 'Artifact':
      return 'provared.code.release';
    case 'Bash':
    case 'PowerShell':
      return commandAction(toolInput && typeof toolInput === 'object' ? toolInput.command : undefined);
    default:
      return 'provared.code.run';
  }
}

// --- commands ---
//
// A command is named as a deletion where it removes something (a deletion
// wins over a release), as a release where it publishes something to
// others, and otherwise as running a program. Three readings are made, and
// the strictest name any of them finds counts, so that a later reading can
// only add to what an earlier one found:
//
//  - The command line read roughly as a shell reads it: quotation marks
//    taken off (a quotation mark after \ or ` is a plain character),
//    comments left out, and ; & | ( ) { } ` $( and line breaks starting a
//    new command. A program is known by its name in any letter case,
//    without its folder or its ending (.exe, .cmd, .ps1, …), after any
//    "NAME=value" settings, redirections (2>/dev/null) and wrappers such as
//    sudo, env or timeout with their own options; a shell handed a command
//    line (bash -c or -lc, cmd /c, powershell -Command) has that line read
//    in the same way.
//  - Every word that names a known program is read as the start of a
//    command, whatever stands before it (ssh host rm, docker exec c rm,
//    python -m twine upload, npx npm publish).
//  - The patterns of the first version of this file, kept as they were.
//
// So a word that names a deletion counts even where a shell would not run
// it (echo rm): the hook errs towards the stricter name. This is a reading
// of the command's text, and it can always be got round: a script that
// deletes, a program renamed, a name built in a variable. That is why the
// checker's words say that the kind of action is the hook's reading of the
// call.

// Programs that remove what they are given, in the shells Claude Code uses
// (with PowerShell's names for Remove-Item: rm, del, erase, rd, rmdir, ri).
const DELETES = new Set(['rm', 'rmdir', 'rd', 'del', 'erase', 'ri', 'remove-item', 'clear-content', 'clc', 'unlink', 'truncate', 'shred']);
// Programs that run the command after them, and those of their options that take the next word as their value.
const WRAPPERS = new Map([
  ['sudo', ['-u', '-g', '-h', '-p', '-C', '-D', '-r', '-t', '-U', '-T', '--user', '--group', '--host', '--prompt', '--chdir']],
  ['doas', ['-u', '-C']],
  ['env', ['-u', '-C', '-S', '--unset', '--chdir', '--split-string']],
  ['timeout', ['-s', '-k', '--signal', '--kill-after']],
  ['nice', ['-n', '--adjustment']],
  ['xargs', ['-I', '-i', '-n', '-L', '-l', '-P', '-d', '-s', '-E', '-e', '-a', '--arg-file', '--delimiter', '--max-args', '--max-procs']],
  ['time', []], ['nohup', []], ['command', []], ['exec', []], ['builtin', []],
  ['then', []], ['do', []], ['else', []], ['if', []], ['while', []], ['until', []], ['!', []],
]);
// Shells that run a command line handed to them.
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'cmd', 'powershell', 'pwsh']);
// Commands that run their words as a command line: eval (the Unix shells), iex and Invoke-Expression (PowerShell).
const EVALS = new Set(['eval', 'iex', 'invoke-expression']);
// The option that hands a shell its command line: -c, or a cluster with c (-lc, -ec) for the Unix shells; /c or /k for cmd; -Command or a shortening of it for PowerShell.
const handsLine = (shell, word) => (shell === 'cmd' ? /^\/[ck]$/i.test(word) : shell === 'powershell' || shell === 'pwsh' ? /^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(word) : /^-[a-z]*c[a-z]*$/i.test(word));
// git's own options before the command that take the next word as their value.
const GIT_VALUED = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);
// The programs whose words the second reading starts from.
const KNOWN = new Set([...DELETES, 'find', 'git', 'npm', 'pnpm', 'yarn', 'bun', 'gh', 'twine', 'uv', 'poetry', 'cargo', 'docker', 'podman']);

/**
 * The simple commands in a command line, each as its list of words.
 * @param {string} text
 * @param {boolean} [endMark] whether a word that is exactly \; is a plain word, as in the Unix shells (find -exec … \;); in PowerShell and cmd it is a break
 */
export function simpleCommands(text, endMark = true) {
  const out = [];
  let words = [];
  let word = '';
  let inWord = false;
  const endWord = () => {
    if (inWord) words.push(word);
    word = '';
    inWord = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length) out.push(words);
    words = [];
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if ((c === '\\' || c === '`') && (text[i + 1] === '"' || text[i + 1] === "'")) {
      // An escaped quotation mark (\" in bash, `" in PowerShell) is a plain character.
      word += text[i + 1];
      inWord = true;
      i++;
    } else if (endMark && c === '\\' && text[i + 1] === ';' && !inWord && (i + 2 >= text.length || /[\s;&|]/.test(text[i + 2]))) {
      // A word that is exactly \; is find's own end mark in the Unix shells (find -exec … \;), not a break between commands.
      words.push(';');
      i++;
    } else if (c === '{' && text[i + 1] === '}' && !inWord) {
      // {} is a plain word (find's place for each file's name), not a block.
      word += '{}';
      inWord = true;
      i++;
    } else if (c === "'" || c === '"') {
      const close = text.indexOf(c, i + 1);
      const end = close < 0 ? text.length : close;
      word += text.slice(i + 1, end);
      inWord = true;
      i = end;
    } else if (c === '\n' || ';&|(){}`'.includes(c) || (c === '$' && text[i + 1] === '(')) {
      endCommand();
    } else if (/\s/.test(c)) {
      endWord();
    } else if (c === '<' && text[i + 1] === '#') {
      // PowerShell's comment <# … #>, which may stand inside a line.
      endWord();
      const close = text.indexOf('#>', i + 2);
      i = close < 0 ? text.length : close + 1;
    } else if (c === '#' && !inWord && (i === 0 || /\s/.test(text[i - 1]))) {
      // A comment, to the end of the line.
      const next = text.indexOf('\n', i);
      i = next < 0 ? text.length : next - 1;
    } else {
      word += c;
      inWord = true;
    }
  }
  endCommand();
  return out;
}

// A program's name as it is compared: in small letters, without its folder or its ending.
const programName = (word) => word.split(/[\\/]/).pop().toLowerCase().replace(/\.(exe|cmd|bat|com|ps1)$/, '');
const setting = (word) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
// A redirection: 2>/dev/null, >log.txt, <in.txt, 2>&1, or the sign alone, whose target is the next word.
const redirection = (word) => /^\d*(>>?|<|&>|>&)/.test(word);

// The program a simple command runs, and the words handed to it.
function program(words) {
  let i = 0;
  while (i < words.length) {
    const name = programName(words[i]);
    if (setting(words[i])) {
      i++;
    } else if (redirection(words[i])) {
      i += /^\d*(>>?|<|&>|>&)$/.test(words[i]) ? 2 : 1;
    } else if (WRAPPERS.has(name)) {
      const valued = WRAPPERS.get(name);
      i++;
      // A wrapper's own options (with their values), settings, and a number it takes (timeout 10, nice -n 5).
      while (i < words.length) {
        if (valued.includes(words[i])) i += 2;
        else if (words[i].startsWith('-') || /^\d+[a-z]?$/i.test(words[i]) || setting(words[i])) i++;
        else break;
      }
    } else {
      return { name, args: words.slice(i + 1) };
    }
  }
  return null;
}

// "delete", "release" or null: the strictest of several.
const strictest = (kinds) => (kinds.includes('delete') ? 'delete' : kinds.includes('release') ? 'release' : null);

// The first reading, for a command line.
// A line that holds \; is read both as the Unix shells read it (find's end mark) and as PowerShell and cmd do (a
// break), and the stricter name counts: the hook cannot always tell which shell runs a line (bash -c inside PowerShell).
function kindOfText(text, depth) {
  const commands = simpleCommands(text);
  if (text.includes('\\;')) commands.push(...simpleCommands(text, false));
  return strictest([...commands.map((words) => kindOf(words, depth)), /\bDROP\s+(TABLE|DATABASE)\b/i.test(text) ? 'delete' : null]);
}

// "delete", "release" or null, for one simple command.
function kindOf(words, depth) {
  const p = program(words);
  if (!p) return null;
  const { name, args } = p;
  const lower = args.map((a) => a.toLowerCase());
  if (DELETES.has(name)) return 'delete';
  if (SHELLS.has(name)) {
    const at = args.findIndex((a) => handsLine(name, a));
    if (at >= 0) return depth < 4 ? kindOfText(args.slice(at + 1).join(' '), depth + 1) : null;
    // cmd's /c or /k with the command line written straight after it: cmd /c"del x".
    const glued = name === 'cmd' ? args.findIndex((a) => /^\/[ck]./i.test(a)) : -1;
    return glued >= 0 && depth < 4 ? kindOfText([args[glued].slice(2), ...args.slice(glued + 1)].join(' '), depth + 1) : null;
  }
  if (EVALS.has(name)) {
    // PowerShell's -Command (or a shortening of it) names the line; eval takes none.
    const line = name === 'eval' ? args : args.filter((a) => !/^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(a));
    return depth < 4 ? kindOfText(line.join(' '), depth + 1) : null;
  }
  if (name === 'find') {
    if (lower.includes('-delete')) return 'delete';
    const EXECS = ['-exec', '-execdir', '-ok', '-okdir'];
    const kinds = [];
    for (let i = 0; i < args.length - 1; i++) {
      if (!EXECS.includes(lower[i])) continue;
      if (DELETES.has(programName(args[i + 1]))) return 'delete';
      // The command find runs, up to its closing ";" or "+", or the next -exec, so that each word is read in one part
      // only and the time grows with the length of the line: read as a command of its own (find -exec sh -c 'rm …').
      let end = i + 1;
      while (end < args.length && ![';', '\\;', '+'].includes(args[end]) && !EXECS.includes(lower[end])) end++;
      if (depth < 4) kinds.push(kindOf(args.slice(i + 1, end), depth + 1));
      i = end - 1;
    }
    return strictest(kinds);
  }
  if (name === 'git') return gitKind(args);
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(name)) {
    if (lower.includes('unpublish')) return 'delete';
    return lower.includes('publish') ? 'release' : null;
  }
  if (name === 'gh') {
    const [what, how] = lower;
    if ((what === 'repo' || what === 'release') && how === 'delete') return 'delete';
    if (what === 'api' && lower.some((a, i) => ((a === '-x' || a === '--method') && lower[i + 1] === 'delete') || a === '--method=delete' || a === '-xdelete')) return 'delete';
    if (what === 'release' && ['create', 'upload', 'edit'].includes(how)) return 'release';
    if (what === 'repo' && how === 'edit') return 'release';
    if (what === 'pr' && ['create', 'merge'].includes(how)) return 'release';
    return null;
  }
  if (name === 'twine' && lower[0] === 'upload') return 'release';
  if (['uv', 'poetry', 'cargo'].includes(name) && lower[0] === 'publish') return 'release';
  if (['docker', 'podman'].includes(name) && lower[0] === 'push') return 'release';
  return null;
}

// git: the command is the first word that is not one of git's own options.
function gitKind(args) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) i += GIT_VALUED.has(args[i]) ? 2 : 1;
  const sub = (args[i] ?? '').toLowerCase();
  const rest = args.slice(i + 1);
  const has = (...flags) => rest.some((a) => flags.includes(a));
  // A cluster of one-letter options, such as -fu, holds each of its letters.
  const short = (letter) => rest.some((a) => /^-[A-Za-z]+$/.test(a) && a.includes(letter));
  if (sub === 'push') {
    // A push that can take history or branches away: forced, deleting, or with a refspec that forces (+) or deletes (:).
    const forced = has('--force', '--delete', '--mirror', '--prune') || rest.some((a) => a.startsWith('--force-with-lease') || a.startsWith('--force-if-includes')) || short('f') || short('d');
    const refspec = rest.some((a) => !a.startsWith('-') && (a.startsWith('+') || a.startsWith(':')));
    return forced || refspec ? 'delete' : 'release';
  }
  // git rm removes the working files, unless it only stops tracking them (--cached).
  if (sub === 'rm' && !has('--cached')) return 'delete';
  if (sub === 'reset' && has('--hard')) return 'delete';
  if (sub === 'clean' && !has('-n', '--dry-run')) return 'delete';
  if ((sub === 'branch' || sub === 'tag') && (has('--delete') || short('d') || short('D'))) return 'delete';
  if (sub === 'stash' && ['drop', 'clear'].includes((rest[0] ?? '').toLowerCase())) return 'delete';
  // Changes in the working files thrown away.
  const paths = rest.indexOf('--');
  if (sub === 'checkout' && (has('--force') || short('f') || (paths >= 0 && paths < rest.length - 1))) return 'delete';
  if (sub === 'restore' && !(has('--staged', '-S') && !has('--worktree', '-W'))) return 'delete';
  return null;
}

// The second reading: every word that names a known program, read as the
// start of a command, with at most 64 words after it. The words are split
// at spaces, shell signs and redirections; a word wholly in quotation marks
// is taken out of them, and one that only begins or ends with a quotation
// mark is not a program's name.
function kindOfWords(text) {
  const words = text.split(/[\s;&|(){}`<>]+/).filter(Boolean).map((w) => (/^(["']).+\1$/.test(w) ? w.slice(1, -1) : w));
  const kinds = [];
  for (let i = 0; i < words.length; i++) {
    if (KNOWN.has(programName(words[i]))) kinds.push(kindOf(words.slice(i, i + 65), 4));
    if (kinds.includes('delete')) break;
  }
  return strictest(kinds);
}

// The third reading: the patterns of the first version of this file, as they were.
const FIRST_DELETES = [
  /(^|[\s;&|(])rm\s/,
  /(^|[\s;&|(])rmdir\s/,
  /(^|[\s;&|(])del\s/i,
  /\bRemove-Item\b/i,
  /\bgit\s+(reset\s+--hard|clean\b|branch\s+-D\b|push\b.*(--force|-f\b)|tag\s+-d\b)/,
  /\bDROP\s+(TABLE|DATABASE)\b/i,
  /\bunlink\s/,
  /\btruncate\s/,
];
const FIRST_RELEASES = [
  /\bgit\s+push\b/,
  /\bnpm(\.cmd)?\s+publish\b/,
  /\btwine\s+upload\b/,
  /\bgh\s+release\s+(create|upload|edit)\b/,
  /\bgh\s+repo\s+edit\b/,
  /\bgh\s+pr\s+(create|merge)\b/,
];
const kindOfFirst = (text) => (FIRST_DELETES.some((re) => re.test(text)) ? 'delete' : FIRST_RELEASES.some((re) => re.test(text)) ? 'release' : null);

/** The action name for a shell command: a deletion, a release, or a run. */
export function commandAction(command) {
  const text = typeof command === 'string' ? command : '';
  const kind = strictest([kindOfText(text, 0), kindOfWords(text), kindOfFirst(text)]);
  if (kind === 'delete') return 'provared.data.delete';
  if (kind === 'release') return 'provared.code.release';
  return 'provared.code.run';
}
