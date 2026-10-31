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

/// --- commands ---
//
// A command is named as a deletion where it removes something (a deletion
// wins over a release), as a release where it publishes something to
// others, and otherwise as running a program. Three readings are made, and
// the strictest name any of them finds counts, so that a later reading can
// only add to what an earlier one found. A recorder written in Python,
// elsewhere in this repository, makes the same three by the same rules, and
// its tests hold the rows marked as shared in this package's tests:
//
//  1. The command line read roughly as a shell reads it: quotation marks
//     taken off (a quotation mark after \ or ` is a plain character, and so
//     is one inside "…" after an odd number of `, as PowerShell reads it),
//     comments left out, and ; & | ( ) { } ` $( and line breaks starting a
//     new command; >&, N>&M and &> are a redirection, not a break; a word
//     that is exactly \; is find's end mark, and a line that holds one is
//     read the other way too, as PowerShell and cmd read it; a line that
//     holds ` before a quotation mark is read the other way too, as bash
//     reads it (` starts a command), at the last level only; {} is a plain
//     word. A program is known by its name in any letter case, without its
//     folder or its ending (.exe, .cmd, .ps1, …), after any "NAME=value"
//     settings, redirections (2>/dev/null) and wrappers such as sudo, env or
//     timeout with their own options. A command line handed on is read in
//     the same way: to a shell (bash -c or -lc, cmd /c, also written
//     cmd /c"…", powershell -Command), to eval, iex or Invoke-Expression, to
//     ssh (the words after its destination), to watch and parallel (the
//     words after them), and each command find -exec runs, up to its ; or +
//     or the next -exec; and a value written in quotation marks after -c, a
//     cluster of small letters ending in c, --command, -Command or
//     -ArgumentList (su -c "…", script -qc "…", Start-Process cmd
//     -ArgumentList '/c …', the list read after the name of the program it
//     is for) or after env -S; except, for all but -ArgumentList, where it
//     is handed to a shell (read as above), to a program that only reads or
//     shows text, to git, to ssh or to an interpreter (an -ArgumentList written as a list, "/c","del x", is read
//     as one line). So is each $( … ) and `…` inside "…" (not inside '…'), which a shell runs there, to any
//     depth (a quotation mark inside a $( … ) does not close the "…", nor does the ) of a case pattern or one in a
//     # comment close the $( … ); a \$ or \` written in "…" is plain); what the
//     command before a single | writes, where a shell given nothing but options reads it (echo "rm x" | sh); and a
//     here-string (bash <<< "…"). Four things a program's name alone does
//     not show are read too, in a command line that runs an interpreter
//     (python, node, ruby, perl, php, deno, bun, PowerShell), a script
//     written into the line after it (python - <<EOF) included: a script's
//     own calls that delete (shutil.rmtree, os.remove, fs.rmSync,
//     Path(…).unlink(), File.Delete and the like); and a script's call that
//     hands a command line to the system (subprocess, os.system,
//     child_process and the like), after which the line is read again with
//     its quotation marks, brackets and commas taken as spaces, one level
//     down. Also a move to the null device (mv x /dev/null); and a file
//     emptied by a redirection alone (: > file, > file).
//  2. In each simple command, every later word that names a known program
//     or an interpreter is read as the start of a command, whatever stands
//     before it (ssh host rm, docker exec c rm, python -m twine upload, npx
//     npm publish), with at most 64 words after it; and a later word that
//     names a shell, eval, ssh, watch or parallel starts a command whose
//     line is read one level down, as the first word of a line is (docker
//     exec c sh -c "…"), up to the next such word. A word written as a
//     program's path counts (/bin/rm, ./node_modules/.bin/npm,
//     C:\Tools\rm.exe, \rm), but not a word with / or \ inside it (a path to
//     a file, a web address, a sed expression). A word written in quotation
//     marks counts only after a program that runs another program (docker
//     exec c "rm", npx "npm", python -m "twine"), and not once a program
//     that only reads or shows text, a known program, a shell, an
//     interpreter or a program whose -m takes a message stands after that
//     one (sudo grep -w "rm"). The value of -m counts unless the
//     program before it takes a message there (git commit -m, hg, svn,
//     docker commit -m, npm version -m); the value of --message never does.
//  3. The patterns of the first version of this file, kept as they were,
//     applied to the text with everything in quotation marks taken out.
//
// So a word that names a deletion counts even where a shell would not run
// it (echo rm): the hook errs towards the stricter name, though not inside
// a quoted message, a path or a web address. Each part of a line is handed
// one level down at most once at each level (a line read twice in the same
// way is read once), so that the time grows in step with the length of the
// line, well within the hook's limit. This is a reading of the command's
// text, and it can always be got round: a script that deletes in a way not
// listed here or from a file, a program renamed or copied, a name built in
// a variable, an upload with curl or scp. That is why the checker's words
// say that the kind of action is the hook's reading of the call.

// Programs that remove what they are given, in the shells Claude Code uses
// (with PowerShell's names for Remove-Item: rm, del, erase, rd, rmdir, ri).
const DELETES = new Set(['rm', 'rmdir', 'rd', 'del', 'erase', 'ri', 'remove-item', 'clear-content', 'clc', 'unlink', 'truncate', 'shred']);
// Programs that run the command after them, and those of their options that take the next word as their value
// (sudo's -h, and xargs's -i, -l and -e, take one only when it is written straight after them: -hhost, -i{}).
const WRAPPERS = new Map([
  ['sudo', ['-u', '-g', '-p', '-a', '-c', '-C', '-D', '-R', '-r', '-t', '-U', '-T', '--user', '--group', '--host', '--prompt', '--chdir', '--chroot', '--close-from', '--login-class', '--auth-type', '--role', '--type', '--other-user', '--command-timeout']],
  ['doas', ['-u', '-C']],
  ['env', ['-u', '-C', '-S', '-a', '--unset', '--chdir', '--split-string', '--argv0']],
  ['timeout', ['-s', '-k', '--signal', '--kill-after']],
  ['nice', ['-n', '--adjustment']],
  ['xargs', ['-I', '-n', '-L', '-P', '-d', '-s', '-E', '-a', '--arg-file', '--delimiter', '--max-args', '--max-procs', '--max-chars', '--process-slot-var']],
  ['time', []], ['nohup', []], ['command', []], ['exec', []], ['builtin', []],
  ['then', []], ['do', []], ['else', []], ['if', []], ['while', []], ['until', []], ['!', []],
]);
// Shells that run a command line handed to them.
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish', 'csh', 'tcsh', 'cmd', 'powershell', 'pwsh']);
// Commands that run their words as a command line: eval (the Unix shells), iex and Invoke-Expression (PowerShell).
const EVALS = new Set(['eval', 'iex', 'invoke-expression']);
// Programs that run the words after them as a command line, again and again or once for each input.
const REPEATERS = new Set(['watch', 'parallel']);
// The option that hands a shell its command line: -c, or a cluster with c (-lc, -ec) for the Unix shells; /c or /k for cmd; -Command or a shortening of it for PowerShell.
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (only optional letters, each at most once), so matching takes time in proportion to the input.
const handsLine = (shell, word) => (shell === 'cmd' ? /^\/[ck]$/i.test(word) : shell === 'powershell' || shell === 'pwsh' ? /^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(word) : /^-[a-z]*c[a-z]*$/i.test(word));
// The options of any other program whose value, written in quotation marks, is a command line: -c, or a cluster of
// small letters ending in c (su -c, script -qc, flock -c); --command; PowerShell's -Command or a shortening of it of two
// letters or more; Start-Process's -ArgumentList or -Args; and env's -S or --split-string.
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (only optional letters, each at most once), so matching takes time in proportion to the input.
const linesOption = (owner, word) => /^-[a-z]*c$/.test(word) || /^(?:--command|-co(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?|-argumentlist|-args)$/i.test(word)
  || (owner === 'env' && (word === '-S' || word === '--split-string'));
// git's own options before the command that take the next word as their value.
const GIT_VALUED = new Set(['-c', '-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env']);
// ssh's own options that take the next word as their value.
const SSH_VALUED = new Set(['-B', '-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-P', '-p', '-Q', '-R', '-S', '-W', '-w']);
// Programs that move what they are given, and the names of the null device: a move there throws away what is moved.
const MOVES = new Set(['mv', 'move', 'move-item', 'mi']);
const NULL_DEVICES = new Set(['/dev/null', 'nul', '$null', 'nul:']);
// Interpreters, which may run a script written in the command line; and Python's launchers, whose -m names a module.
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (digits split by a full stop the digits cannot match), so matching takes time in proportion to the input.
const INTERPRETERS = /^(python(\d+(\.\d+)?)?|pythonw|py|node|nodejs|deno|bun|ruby|perl|php|pwsh|powershell)$/;
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (digits split by a full stop the digits cannot match), so matching takes time in proportion to the input.
const PYTHONS = /^(python(\d+(\.\d+)?)?|pythonw|py)$/;
// A script's own calls that delete.
const SCRIPT_DELETES = /(?:\b(?:shutil\.rmtree|rmtree|os\.(?:remove|unlink|rmdir|removedirs)|(?:unlink|rm|rmdir)Sync|fs(?:\.promises)?\.(?:rm|rmdir|unlink)|FileUtils\.(?:rm_rf|rm_r|rm_f|rm|remove_dir|remove_entry|remove)|Deno\.remove(?:Sync)?|(?:File|Directory)\]?(?:\.|::)Delete)|\.(?:unlink|rmdir)\b)\s*[("']|\bunlink\b/i;
// A script's calls that hand a command line to the system.
const SCRIPT_RUNS = /\b(?:subprocess|pty\.spawn|child_process|shell_exec|passthru|proc_open|Process\.Start|Open3|IO\.popen|Deno\.(?:run|Command)|Bun\.(?:spawn|\$)|os\.(?:system|popen|exec|spawn)|(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen)\s*\()/;
// The programs whose words the second reading starts from, and those whose command line it reads one level down.
// Programs that publish where their first word is "publish" (and take back with "unpublish" or "yank"), and those that
// publish with "push" (and take back with "yank").
const PUBLISHERS = new Set(['uv', 'poetry', 'cargo', 'hatch', 'flit', 'pdm', 'vsce', 'ovsx']);
const PUSHERS = new Set(['gem', 'helm']);
// Programs that copy (cp /dev/null x empties x), clients of a database (whose DELETE FROM deletes), and what rsync is
// told that deletes.
const COPIES = new Set(['cp', 'copy', 'copy-item', 'cpi']);
const SQL_CLIENTS = new Set(['psql', 'mysql', 'mariadb', 'sqlite3', 'sqlcmd', 'duckdb', 'clickhouse-client', 'cockroach']);
const SQL_DELETE = /\bDELETE\s+FROM\b/i;
const rsyncDeletes = (word) => word.startsWith('--delete') || word === '--del' || word === '--remove-source-files';
const KNOWN = new Set([...DELETES, ...MOVES, 'find', 'git', 'hub', 'npm', 'pnpm', 'yarn', 'bun', 'gh', 'twine', ...PUBLISHERS, ...PUSHERS, 'dotnet',
  'docker', 'podman', 'rsync', ...COPIES, ...SQL_CLIENTS, 'redis-cli']);
const LINE_STARTS = new Set([...SHELLS, ...EVALS, 'ssh', ...REPEATERS]);
// Programs that run a program named in a later word (docker exec c rm, npx npm, strace rm, chroot /mnt rm): after one,
// a word in quotation marks counts as a program's name. Python's launchers count too (python -m "twine").
const RUNNERS = new Set([...WRAPPERS.keys(), 'docker', 'podman', 'nerdctl', 'kubectl', 'oc', 'lxc', 'incus', 'wsl', 'strace', 'ltrace',
  'chroot', 'nsenter', 'unshare', 'setsid', 'busybox', 'runuser', 'su', 'sg', 'npx', 'pnpx', 'bunx', 'uvx', 'pipx', 'uv', 'poetry', 'pdm',
  'hatch', 'pipenv', 'conda', 'mamba', 'npm', 'pnpm', 'yarn', 'bun', 'stdbuf', 'ionice', 'taskset', 'chrt', 'firejail', 'bwrap',
  'systemd-run', 'flatpak-spawn', 'toolbox', 'distrobox', 'schroot', 'proot', 'fakeroot', 'valgrind', 'gosu', 'su-exec', 'setpriv',
  'prlimit', 'numactl', 'eatmydata', 'torsocks', 'proxychains', 'proxychains4', 'flock', 'script', 'cross-env', 'dotenv', 'watch',
  'parallel', 'start-process', 'saps', 'start']);
// Programs that only read, search or show text, and two whose -c is not a command line (git -c name=value, ssh -c
// cipher): a value after -c handed to one of them is not a command line, and after one of them a word in quotation
// marks is not a program's name.
const TEXT_PROGRAMS = new Set(['echo', 'printf', 'grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'ag', 'ack', 'sed', 'awk', 'gawk', 'cat', 'head',
  'tail', 'less', 'more', 'wc', 'sort', 'uniq', 'cut', 'tr', 'tee', 'ls', 'jq', 'yq', 'diff', 'test', 'write-output', 'write-host',
  'select-string', 'sls', 'findstr', 'get-content', 'gc', 'git', 'ssh']);
// Programs whose -m takes a message (git commit -m), which is never a program's name.
const MESSAGES = new Set(['git', 'hg', 'svn', 'bzr', 'fossil', 'cvs', 'jj', 'sl', 'docker', 'podman', 'npm', 'pnpm', 'yarn']);
// A word written as a program's path: from the root, from here or above, from home, from a drive, or with a backslash first (\rm).
const PROGRAM_PATH = /^(?:\/|\.{1,2}[\\/]|~[\\/]|\\|[A-Za-z]:[\\/])/;

/**
 * The simple commands in a command line, each as its list of words, each
 * word with whether any part of it was written in quotation marks.
 * @param {string} text
 * @param {boolean} [endMark] whether a word that is exactly \; is a plain word, as in the Unix shells (find -exec … \;); in PowerShell and cmd it is a break
 * @param {boolean} [backtickEscapes] whether ` before a quotation mark makes it a plain character, as in PowerShell; in bash ` starts a command
 * @param {string[]|null} [subs] where the command lines inside each part in "…" ($( … ) and `…`) are put
 * @returns {{text: string, quoted: boolean}[][]} each command marked "piped" where a single | stands before it
 */
function parse(text, endMark = true, backtickEscapes = true, subs = null) {
  const out = [];
  let words = [];
  let piped = false;
  let word = '';
  let last = ''; // the last character of the word, kept apart so that a long word is not read again for it
  let inWord = false;
  let quoted = false;
  const endWord = () => {
    if (inWord) words.push({ text: word, quoted });
    word = '';
    last = '';
    inWord = false;
    quoted = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length) {
      if (piped) words.piped = true;
      out.push(words);
    }
    words = [];
    piped = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if ((c === '\\' || (c === '`' && backtickEscapes)) && (text[i + 1] === '"' || text[i + 1] === "'")) {
      // An escaped quotation mark (\" in bash, `" in PowerShell) is a plain character.
      word += text[i + 1];
      last = text[i + 1];
      inWord = true;
      i++;
    } else if (endMark && c === '\\' && text[i + 1] === ';' && !inWord && (i + 2 >= text.length || /[\s;&|]/.test(text[i + 2]))) {
      // A word that is exactly \; is find's own end mark in the Unix shells (find -exec … \;), not a break between commands.
      words.push({ text: ';', quoted: false });
      i++;
    } else if (c === '{' && text[i + 1] === '}' && !inWord) {
      // {} is a plain word (find's place for each file's name), not a block.
      word += '{}';
      last = '}';
      inWord = true;
      i++;
    } else if (c === "'") {
      const close = text.indexOf(c, i + 1);
      const end = close < 0 ? text.length : close;
      if (end > i + 1) {
        word += text.slice(i + 1, end);
        last = text[end - 1];
      }
      inWord = true;
      quoted = true;
      i = end;
    } else if (c === '"') {
      // A part in "…", to its closing mark, which a $( … ) or `…` inside it does not close; its command lines go in subs.
      const end = closingQuote(text, i + 1, backtickEscapes, subs);
      if (end > i + 1) {
        // As PowerShell reads it, `" is a plain quotation mark: the ` is taken off.
        const part = backtickEscapes ? text.slice(i + 1, end).replaceAll('`"', '"') : text.slice(i + 1, end);
        word += part;
        last = part[part.length - 1];
      }
      inWord = true;
      quoted = true;
      i = end;
    } else if (c === '&' && text[i + 1] === '>') {
      // bash's &> (both outputs to a file): a redirection that starts a word of its own, not a break between commands.
      endWord();
      word = '&';
      last = '&';
      inWord = true;
    } else if (c === '&' && inWord && last === '>') {
      // >& and N>&M (>&2, 2>&1): a redirection, one word.
      word += c;
      last = c;
    } else if (c === '\n' || ';&|(){}`'.includes(c) || (c === '$' && text[i + 1] === '(')) {
      endCommand();
      // The next command takes what this one writes, as its input: a single | (not ||).
      piped = c === '|' && text[i + 1] !== '|' && text[i - 1] !== '|';
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
      last = c;
      inWord = true;
    }
  }
  endCommand();
  return out;
}

// Where a part in "…" that starts at "from" closes (or the length of the text, where it does not close), and the command
// lines that a shell runs inside it and puts its output in their place, put in "into" (where it is not null): each
// $( … ), to its matching bracket, and each `…`. A $( … ) starts a new quotation of its own, so a quotation mark inside
// it (echo "$(cd "/tmp"; rm x)") does not close the part. Inside "…", \$, \` and \\ are plain characters (but \" is
// not, so that a Windows folder written "C:\x\" ends where cmd ends it); as PowerShell reads it, so are `" and ``.
// The parts still open are kept on a list, not by calling this again, so that no depth of nesting can overflow.
function closingQuote(text, from, backtickEscapes, into) {
  const n = text.length;
  const open = []; // { kind: 'sub' | 'tick' | 'quote', level, from }
  for (let i = from; i < n; i++) {
    const c = text[i];
    if (backtickEscapes && c === '`' && (text[i + 1] === '"' || text[i + 1] === '`')) {
      i++;
      continue;
    }
    const top = open.length === 0 ? null : open[open.length - 1];
    if (top === null || top.kind === 'quote') {
      if (c === '"') {
        if (top === null) return i;
        open.pop();
      } else if (c === '\\' && (text[i + 1] === '$' || text[i + 1] === '`' || text[i + 1] === '\\')) {
        i++;
      } else if (c === '$' && text[i + 1] === '(') {
        open.push({ kind: 'sub', level: 1, from: i + 2 });
        i++;
      } else if (c === '`') {
        open.push({ kind: 'tick', from: i + 1 });
      }
    } else if (top.kind === 'sub') {
      if (c === '(') {
        top.level++;
      } else if (c === ')') {
        const cases = top.cases;
        if (cases !== undefined && cases.length > 0 && top.level <= cases[cases.length - 1]) {
          // The end of a pattern of a case (case x in a) …): it closes nothing.
        } else {
          top.level--;
          if (top.level === 0) {
            open.pop();
            if (open.length === 0 && into !== null) into.push(text.slice(top.from, i));
          }
        }
      } else if (backtickEscapes && c === '<' && text[i + 1] === '#') {
        // As PowerShell reads it, a block comment, to its #> (or the end): a ) or a quotation mark in it is plain text.
        const end = text.indexOf('#>', i + 2);
        i = end < 0 ? n : end + 1;
      } else if (c === '#' && COMMENT_AFTER.includes(text[i - 1])) {
        // A comment, to the end of its line: a ) or a quotation mark in it is plain text.
        const end = text.indexOf('\n', i + 1);
        i = end < 0 ? n : end;
      } else if ((c === 'c' || c === 'e') && COMMAND_AFTER.includes(text[i - 1])) {
        const word = reservedWord(text, i, top.from);
        if (word === 'case') {
          (top.cases ??= []).push(top.level);
          i += 3;
        } else if (word === 'esac') {
          if (top.cases !== undefined && top.cases.length > 0) top.cases.pop();
          i += 3;
        }
      } else if (c === '"') {
        open.push({ kind: 'quote' });
      } else if (c === "'") {
        const close = text.indexOf("'", i + 1);
        i = close < 0 ? n : close;
      } else if (c === '\\') {
        i++;
      } else if (c === '`') {
        open.push({ kind: 'tick', from: i + 1 });
      }
    } else if (c === '`') {
      open.pop();
      if (open.length === 0 && into !== null) into.push(text.slice(top.from, i));
    } else if (c === '\\') {
      i++;
    }
  }
  // The text ends inside: a $( … ) or `…` still open in the part itself is read to the end.
  if (into !== null && open.length > 0) into.push(text.slice(open[0].from));
  return n;
}

// Inside a $( … ): what may come just before a # that starts a comment, and before a word a shell takes as a command.
const COMMENT_AFTER = ' \t\r\n;&|()';
const COMMAND_AFTER = ' \t\r\n;&|(){!';
const SPACES = ' \t\r';
const COMMAND_STARTS = ';&|(){!\n';
const COMMAND_WORDS = ['then', 'do', 'else', 'elif', 'if', 'while', 'until'];

// The word case or esac at i, inside a $( … ) whose text starts at from, where a shell takes it as one: a word of its
// own, at the start of a command (after the start of the $( … ), ; & | ( ) { ! a line break, or then, do, else, elif,
// if, while or until), and for case with a word after it. Otherwise null.
function reservedWord(text, i, from) {
  const word = text.startsWith('case', i) ? 'case' : text.startsWith('esac', i) ? 'esac' : null;
  if (word === null) return null;
  const next = text[i + 4];
  if (word === 'case' ? !(next !== undefined && ' \t\r\n'.includes(next)) : !(next === undefined || ' \t\r\n;&|)'.includes(next))) return null;
  let k = i - 1;
  while (k >= from && SPACES.includes(text[k])) k--;
  if (k < from || COMMAND_STARTS.includes(text[k])) return word;
  let s = k;
  while (s >= from && text[s] >= 'a' && text[s] <= 'z') s--;
  if (s === k) return null;
  if (s >= from && !(SPACES.includes(text[s]) || COMMAND_STARTS.includes(text[s]))) return null;
  return COMMAND_WORDS.includes(text.slice(s + 1, k + 1)) ? word : null;
}

/**
 * The simple commands in a command line, each as its list of words.
 * @param {string} text
 * @param {boolean} [endMark] as for the reading above
 */
export function simpleCommands(text, endMark = true) {
  return parse(text, endMark).map((words) => words.map((w) => w.text));
}

// A program's name as it is compared: in small letters, without its folder or its ending.
const programName = (word) => word.split(/[\\/]/).pop().toLowerCase().replace(/\.(exe|cmd|bat|com|ps1)$/, '');
const setting = (word) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(word);
// A redirection: 2>/dev/null, >log.txt, <in.txt, 2>&1, >&2, &>log.txt, or the sign alone, whose target is the next word.
const redirection = (word) => /^\d*(>>?|<|&>|>&)/.test(word);
// A redirection that empties its file: >file, 2>file, &>file, or the sign alone, whose target is the next word (not >>, which adds to its file, nor >&2).
// eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (one repeated part on each side of the sign >), so matching takes time in proportion to the input.
const EMPTIES = /^(?:\d*|&)>([^>&][\s\S]*)?$/;

// The program a simple command runs, the words handed to it, and its place among the words.
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
      return { name, args: words.slice(i + 1), at: i };
    }
  }
  return null;
}

// "delete", "release" or null: the strictest of several.
const strictest = (kinds) => (kinds.includes('delete') ? 'delete' : kinds.includes('release') ? 'release' : null);

// The places of the later words of a simple command that the second reading
// reads as the start of a command: not a word with / or \ inside it unless it
// is written as a program's path; not written in quotation marks unless a
// program that runs another one stands before it, and no program that only
// reads or shows text, known program, shell, interpreter or program whose -m
// takes a message after that one; not the value of -m after a program whose
// -m takes a message, nor of --message.
function laterWords(command, names) {
  const places = [];
  const first = names[0];
  let runner = RUNNERS.has(first) || PYTHONS.test(first);
  let message = MESSAGES.has(first) && !PYTHONS.test(first);
  for (let i = 1; i < command.length; i++) {
    const { text: word, quoted } = command[i];
    const before = command[i - 1].text;
    if ((quoted && !runner) || (/[\\/]/.test(word) && !PROGRAM_PATH.test(word)) || (before === '-m' && message) || before === '--message') continue;
    places.push(i);
    // The program named last decides what follows: whether a word in quotation marks may be a program's name, and
    // whether -m takes a message.
    const name = names[i];
    if (PYTHONS.test(name)) {
      runner = true;
      message = false;
    } else if (RUNNERS.has(name)) {
      runner = true;
      message = MESSAGES.has(name);
    } else if (TEXT_PROGRAMS.has(name) || KNOWN.has(name) || SHELLS.has(name) || MESSAGES.has(name) || INTERPRETERS.test(name)) {
      runner = false;
      message = MESSAGES.has(name);
    }
  }
  return places;
}

// Where the command line that a program hands on starts among the words handed to it, or -1 where it hands on none;
// undefined for a program that hands none on. cmd's /c written together with its line (cmd /c"del x"), and a here-string
// written together with its line (<<<"…"), are marked by a place written as -2 - its index.
function lineStart(name, args) {
  if (SHELLS.has(name)) {
    const at = args.findIndex((a) => handsLine(name, a));
    if (at >= 0) return at + 1;
    // cmd's /c or /k with the command line written straight after it: cmd /c"del x".
    if (name === 'cmd') {
      const glued = args.findIndex((a) => /^\/[ck][\s\S]/i.test(a));
      return glued >= 0 ? -2 - glued : -1;
    }
    // A command line handed on standard input as a here-string: bash <<< "…", also written <<<"…".
    const here = args.indexOf('<<<');
    if (here >= 0) return here + 1 < args.length ? here + 1 : -1;
    const glued = args.findIndex((a) => a.startsWith('<<<') && a.length > 3);
    return glued >= 0 ? -2 - glued : -1;
  }
  if (EVALS.has(name) || REPEATERS.has(name)) return 0;
  if (name === 'ssh') {
    // The words after ssh's own options and its destination are the command line it runs there.
    let i = 0;
    while (i < args.length && args[i].startsWith('-')) i += SSH_VALUED.has(args[i]) ? 2 : 1;
    return i + 1 < args.length ? i + 1 : -1;
  }
  return undefined;
}

// The command line a program hands on, or null where it hands on none; undefined for a program that hands none on.
function lineOf(name, args) {
  const start = lineStart(name, args);
  if (start === undefined) return undefined;
  if (start === -1) return null;
  if (start <= -2) return [args[-2 - start].slice(name === 'cmd' ? 2 : 3), ...args.slice(-1 - start)].join(' ');
  // PowerShell's -Command (or a shortening of it) names the line given to iex or Invoke-Expression; eval takes none.
  // eslint-disable-next-line security/detect-unsafe-regex -- no repetition inside repetition can match the same text two ways (only optional letters, each at most once), so matching takes time in proportion to the input.
  const line = name === 'iex' || name === 'invoke-expression' ? args.filter((a) => !/^-c(o(m(m(a(n(d)?)?)?)?)?)?$/i.test(a)) : args.slice(start);
  return line.join(' ');
}

// Whether the first reading of a command hands the rest of it on, read one level down: a shell, eval, ssh, watch or
// parallel that hands on a line, or find with -exec. Then nothing after its program is handed on again from here.
function handsRestOn(p, depth) {
  if (p === null || depth >= 4) return false;
  if (p.name === 'find') return p.args.some((a) => ['-exec', '-execdir', '-ok', '-okdir'].includes(a.toLowerCase()));
  const start = lineStart(p.name, p.args);
  return start !== undefined && start !== -1;
}

// The first and the second reading, for a command line, at any depth. "read" holds what has been read already: a
// command line read twice in the same way (the two readings of a line that holds \;) is read once.
// A line that holds \; is read both as the Unix shells read it (find's end mark) and as PowerShell and cmd do (a
// break), and the stricter name counts: the hook cannot always tell which shell runs a line (bash -c inside PowerShell).
function kindOfText(text, depth, read = new Map()) {
  const key = `${depth}:${text}`;
  if (read.has(key)) return read.get(key);
  const kind = readText(text, depth, read);
  read.set(key, kind);
  return kind;
}

function readText(text, depth, read) {
  if (/\bDROP\s+(TABLE|DATABASE)\b/i.test(text)) return 'delete';
  const subs = [];
  const commands = parse(text, true, true, subs);
  if (text.includes('\\;')) for (const command of parse(text, false, true, subs)) commands.push(command);
  // A line that holds ` before a quotation mark, read as bash reads it, at the last level only.
  const others = /`["']/.test(text) ? parse(text, true, false, subs) : [];
  const prepared = (list) => list.map((command) => {
    const words = command.map((w) => w.text);
    const names = words.map(programName);
    return { command, words, names, places: laterWords(command, names), p: program(words) };
  });
  const mine = prepared(commands);
  const theirs = prepared(others);
  // A script's own calls that delete, in a line that runs an interpreter, as a command's program or as a later word.
  const runsScript = [...mine, ...theirs].some(({ names, places, p }) => (p !== null && INTERPRETERS.test(p.name)) || places.some((i) => INTERPRETERS.test(names[i])));
  if (runsScript && SCRIPT_DELETES.test(text)) return 'delete';
  let release = false;
  // A script's call that hands a command line to the system: the line read again with its quotation marks, brackets
  // and commas as spaces, so that the strings handed on are read as command lines (subprocess.run(['git', 'push'])).
  if (runsScript && depth < 4 && /["'`]/.test(text) && SCRIPT_RUNS.test(text)) {
    const kind = kindOfText(text.replace(/["'`[\],]/g, ' '), depth + 1, read);
    if (kind === 'delete') return 'delete';
    if (kind === 'release') release = true;
  }
  // Each command line inside a part in "…" that a shell runs there ($( … ), `…`), read one level down. At the last
  // level, it is read flat, with its quotation marks as spaces, so that one nested deeper still is not left unread.
  for (const sub of new Set(subs)) {
    const kind = depth < 4 ? kindOfText(sub, depth + 1, read) : kindOfText(sub.replace(/["']/g, ' '), 4, read);
    if (kind === 'delete') return 'delete';
    if (kind === 'release') release = true;
  }
  for (let k = 0; k < mine.length; k++) {
    const kind = kindOfCommand(mine[k], depth, read);
    if (kind === 'delete') return 'delete';
    if (kind === 'release') release = true;
    // A shell given nothing but options, after a single |, runs what the command before it writes (echo "rm -rf x" | sh):
    // the words handed to that command, read one level down as its command line.
    const { command, p } = mine[k];
    if (depth < 4 && command.piped && k > 0 && p !== null && SHELLS.has(p.name) && p.args.every((a) => a.startsWith('-')) && mine[k - 1].p !== null) {
      const before = kindOfText(mine[k - 1].p.args.join(' '), depth + 1, read);
      if (before === 'delete') return 'delete';
      if (before === 'release') release = true;
    }
  }
  for (const command of theirs) {
    const kind = kindOfCommand(command, 4, read);
    if (kind === 'delete') return 'delete';
    if (kind === 'release') release = true;
  }
  return release ? 'release' : null;
}

// The first and the second reading of one simple command.
function kindOfCommand(info, depth, read) {
  const { command, words, names, places, p } = info;
  let release = false;
  const found = (kind) => {
    if (kind === 'release') release = true;
    return kind === 'delete';
  };
  if (found(kindOf(words, depth, read))) return 'delete';
  // Below, each part of the command is handed one level down once at most: after the part that "next" stands at.
  let next = handsRestOn(p, depth) ? words.length : 1;
  const isPlace = new Set(places);
  // The program the nearest word that is not an option names, before the word read: the one an option belongs to.
  let owner = 0;
  for (let i = 1, k = 0; i < words.length; i++) {
    if (k < places.length && places[k] === i) {
      k++;
      const name = names[i];
      // The second reading: a known program, read as the start of a command, with at most 64 words after it.
      if (KNOWN.has(name) && found(knownKind(info, i, Math.min(i + 65, words.length)))) return 'delete';
      // A shell, eval, ssh, watch or parallel: its command line read one level down, up to the next such word.
      if (LINE_STARTS.has(name) && depth < 4 && i >= next && (p === null || i !== p.at)) {
        let end = i + 1;
        let list = false;
        while (end < words.length && end < i + 65 && !(isPlace.has(end) && LINE_STARTS.has(names[end]))) {
          if (/^-(?:argumentlist|args)$/i.test(words[end])) list = true;
          end++;
        }
        // A shell named to Start-Process, with -ArgumentList after it: the list is read below, after the shell's name.
        const line = list ? null : lineOf(name, words.slice(i + 1, end));
        if (typeof line === 'string') {
          if (found(kindOfText(line, depth + 1, read))) return 'delete';
          next = end;
        }
      }
    }
    // A value written in quotation marks after an option that hands a command line on (su -c "…"), read one level down;
    // the value of -ArgumentList or -Args whatever program it is for.
    if (command[i].quoted && depth < 4 && i >= next) {
      const ownerName = names[owner];
      const handedTo = !SHELLS.has(ownerName) && !TEXT_PROGRAMS.has(ownerName) && !INTERPRETERS.test(ownerName);
      const glued = /^--command=/i.test(words[i]);
      const list = /^-(?:argumentlist|args)$/i.test(words[i - 1]);
      if (list || (handedTo && (glued || linesOption(ownerName, words[i - 1])))) {
        // A list of arguments is read after the name of the program it is for (Start-Process powershell -ArgumentList
        // "-Command …"), where that name is a short one.
        // Written as a list ("/c","del x"), its items are read as words of one line.
        const value = list ? words[i].replaceAll(',', ' ') : words[i];
        const line = glued ? words[i].slice(10) : list && ownerName.length <= 64 && !/\s/.test(ownerName) ? `${ownerName} ${value}` : value;
        if (found(kindOfText(line, depth + 1, read))) return 'delete';
        next = i + 1;
      }
    }
    if (!words[i].startsWith('-')) owner = i;
  }
  return release ? 'release' : null;
}

// What kindOf gives at the last level for the words of a command from a known program at "at" up to "end" (not
// included), in a time that does not grow with the number of words: whether a word of some kind stands among them is
// looked up in a table made once for the command (the place of the next such word from each place). A known program's
// name is never a setting, a redirection or a wrapper, so it is the program of those words.
function knownKind(info, at, end) {
  const { words, names } = info;
  const name = names[at];
  const has = (kind, from, to = end) => from < to && nextOf(info, kind)[from] < to;
  if (DELETES.has(name)) return 'delete';
  if (MOVES.has(name)) return has('nullDevice', at + 1) ? 'delete' : null;
  if (name === 'find') return has('-delete', at + 1) || has('execDelete', at + 1, end - 1) ? 'delete' : null;
  const lower = lowerOf(info);
  if (name === 'git' || name === 'hub') {
    // git's command: the first word after git's own options (and their values), where it stands before "end".
    const s = nextOf(info, 'gitCommand')[at + 1];
    const sub = s < end ? lower[s] : '';
    if (sub === 'push') return has('pushForce', s + 1) ? 'delete' : 'release';
    if (sub === 'rm') return has('cached', s + 1) ? null : 'delete';
    if (sub === 'reset') return has('hard', s + 1) ? 'delete' : null;
    if (sub === 'clean') return has('dryRun', s + 1) ? null : 'delete';
    if (sub === 'branch' || sub === 'tag') return has('branchDelete', s + 1) ? 'delete' : null;
    if (sub === 'stash') return s + 1 < end && ['drop', 'clear'].includes(lower[s + 1]) ? 'delete' : null;
    if (sub === 'checkout') return has('checkoutForce', s + 1) || has('--', s + 1, end - 1) ? 'delete' : null;
    if (sub === 'restore') return has('staged', s + 1) && !has('worktree', s + 1) ? null : 'delete';
    return null;
  }
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(name)) return has('unpublish', at + 1) ? 'delete' : has('publish', at + 1) ? 'release' : null;
  const what = at + 1 < end ? lower[at + 1] : undefined;
  const how = at + 2 < end ? lower[at + 2] : undefined;
  if (name === 'gh') {
    if ((what === 'repo' || what === 'release') && how === 'delete') return 'delete';
    if (what === 'api' && (has('methodDelete', at + 1) || has('methodThenDelete', at + 1, end - 1))) return 'delete';
    if (what === 'release' && ['create', 'upload', 'edit'].includes(how)) return 'release';
    if (what === 'repo' && how === 'edit') return 'release';
    if (what === 'pr' && ['create', 'merge'].includes(how)) return 'release';
    return null;
  }
  if (name === 'twine' && what === 'upload') return 'release';
  if (PUBLISHERS.has(name)) return what === 'unpublish' || what === 'yank' ? 'delete' : what === 'publish' ? 'release' : null;
  if (PUSHERS.has(name)) return what === 'yank' ? 'delete' : what === 'push' ? 'release' : null;
  if (name === 'dotnet') return what === 'nuget' && how === 'delete' ? 'delete' : what === 'nuget' && how === 'push' ? 'release' : null;
  if (['docker', 'podman'].includes(name)) return what === 'push' || ((what === 'build' || what === 'buildx') && has('--push', at + 1)) ? 'release' : null;
  if (name === 'rsync') return has('rsyncDelete', at + 1) ? 'delete' : null;
  if (COPIES.has(name)) return has('nullDevice', at + 1, end - 1) ? 'delete' : null;
  if (SQL_CLIENTS.has(name)) return has('sqlDelete', at + 1) || has('deleteThenFrom', at + 1, end - 1) ? 'delete' : null;
  if (name === 'redis-cli') return has('flush', at + 1) ? 'delete' : null;
  return null;
}

// The words of a command in small letters, made once.
function lowerOf(info) {
  info.lower ??= info.words.map((w) => w.toLowerCase());
  return info.lower;
}

// A cluster of one-letter options, such as -fu, that holds the letter.
const holds = (word, letter) => /^-[A-Za-z]+$/.test(word) && word.includes(letter);
// The kinds of word that knownKind looks for, each as a test of the word at a place.
const WORD_KINDS = {
  nullDevice: (w, l) => NULL_DEVICES.has(l[w]),
  '-delete': (w, l) => l[w] === '-delete',
  execDelete: (w, l, words, names) => ['-exec', '-execdir', '-ok', '-okdir'].includes(l[w]) && w + 1 < words.length && DELETES.has(names[w + 1]),
  unpublish: (w, l) => l[w] === 'unpublish',
  publish: (w, l) => l[w] === 'publish',
  methodDelete: (w, l) => l[w] === '--method=delete' || l[w] === '-xdelete',
  methodThenDelete: (w, l) => (l[w] === '-x' || l[w] === '--method') && l[w + 1] === 'delete',
  // A push that can take history or branches away: forced, deleting, or with a refspec that forces (+) or deletes (:).
  pushForce: (w, l, words) => {
    const a = words[w];
    return ['--force', '--delete', '--mirror', '--prune'].includes(a) || a.startsWith('--force-with-lease') || a.startsWith('--force-if-includes')
      || holds(a, 'f') || holds(a, 'd') || (!a.startsWith('-') && (a.startsWith('+') || a.startsWith(':')));
  },
  cached: (w, l, words) => words[w] === '--cached',
  hard: (w, l, words) => words[w] === '--hard',
  dryRun: (w, l, words) => words[w] === '-n' || words[w] === '--dry-run',
  branchDelete: (w, l, words) => words[w] === '--delete' || holds(words[w], 'd') || holds(words[w], 'D'),
  checkoutForce: (w, l, words) => words[w] === '--force' || holds(words[w], 'f'),
  '--': (w, l, words) => words[w] === '--',
  staged: (w, l, words) => words[w] === '--staged' || words[w] === '-S',
  worktree: (w, l, words) => words[w] === '--worktree' || words[w] === '-W',
  '--push': (w, l) => l[w] === '--push',
  rsyncDelete: (w, l) => rsyncDeletes(l[w]),
  sqlDelete: (w, l, words) => SQL_DELETE.test(words[w]),
  deleteThenFrom: (w, l) => l[w] === 'delete' && l[w + 1] === 'from',
  flush: (w, l) => l[w] === 'flushall' || l[w] === 'flushdb',
};

// For each place of a command, the place of the next word of the kind (or the number of words where there is none),
// made once for the command. "gitCommand": where git's command stands when git's own options start at the place.
function nextOf(info, kind) {
  info.next ??= new Map();
  if (info.next.has(kind)) return info.next.get(kind);
  const { words, names } = info;
  const n = words.length;
  const next = new Int32Array(n + 2).fill(n);
  if (kind === 'gitCommand') {
    for (let w = n - 1; w >= 0; w--) next[w] = words[w].startsWith('-') ? next[Math.min(n, w + (GIT_VALUED.has(words[w]) ? 2 : 1))] : w;
  } else {
    const lower = lowerOf(info);
    const test = WORD_KINDS[kind];
    for (let w = n - 1; w >= 0; w--) next[w] = test(w, lower, words, names) ? w : next[w + 1];
  }
  info.next.set(kind, next);
  return next;
}

// "delete", "release" or null, for one simple command.
function kindOf(words, depth, read) {
  const p = program(words);
  // A file emptied by a redirection alone ("> file", ": > file", "true > file"), not one sent to the null device.
  if (p === null || [':', 'true', ''].includes(p.name)) {
    for (let i = 0; i < words.length; i++) {
      const m = EMPTIES.exec(words[i]);
      const target = m === null ? undefined : (m[1] ?? words[i + 1]);
      if (target !== undefined && !NULL_DEVICES.has(target.toLowerCase())) return 'delete';
    }
  }
  if (!p) return null;
  const { name, args } = p;
  if (DELETES.has(name)) return 'delete';
  if (MOVES.has(name) && args.some((a) => NULL_DEVICES.has(a.toLowerCase()))) return 'delete';
  // A shell, eval, ssh, watch or parallel: the command line it hands on, read one level down.
  const line = lineOf(name, args);
  if (line !== undefined) return line !== null && depth < 4 ? kindOfText(line, depth + 1, read) : null;
  const lower = args.map((a) => a.toLowerCase());
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
      if (depth < 4) {
        const kind = kindOf(args.slice(i + 1, end), depth + 1, read);
        if (kind === 'delete') return 'delete';
        kinds.push(kind);
      }
      i = end - 1;
    }
    return strictest(kinds);
  }
  if (name === 'git' || name === 'hub') return gitKind(args);
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
  if (PUBLISHERS.has(name)) return lower[0] === 'unpublish' || lower[0] === 'yank' ? 'delete' : lower[0] === 'publish' ? 'release' : null;
  if (PUSHERS.has(name)) return lower[0] === 'yank' ? 'delete' : lower[0] === 'push' ? 'release' : null;
  if (name === 'dotnet') return lower[0] === 'nuget' && lower[1] === 'delete' ? 'delete' : lower[0] === 'nuget' && lower[1] === 'push' ? 'release' : null;
  if (['docker', 'podman'].includes(name)) return lower[0] === 'push' || (['build', 'buildx'].includes(lower[0]) && lower.includes('--push')) ? 'release' : null;
  if (name === 'rsync') return lower.some(rsyncDeletes) ? 'delete' : null;
  // cp /dev/null x empties x: a null device that is not the last word.
  if (COPIES.has(name)) return lower.slice(0, -1).some((a) => NULL_DEVICES.has(a)) ? 'delete' : null;
  if (SQL_CLIENTS.has(name)) return args.some((a) => SQL_DELETE.test(a)) || lower.some((a, i) => a === 'delete' && lower[i + 1] === 'from') ? 'delete' : null;
  if (name === 'redis-cli') return lower.some((a) => a === 'flushall' || a === 'flushdb') ? 'delete' : null;
  return null;
}

// git: the command is the first word that is not one of git's own options.
function gitKind(args) {
  let i = 0;
  while (i < args.length && args[i].startsWith('-')) i += GIT_VALUED.has(args[i]) ? 2 : 1;
  const sub = (args[i] ?? '').toLowerCase();
  if (!['push', 'rm', 'reset', 'clean', 'branch', 'tag', 'stash', 'checkout', 'restore'].includes(sub)) return null;
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

// The text with every part in quotation marks taken out, each such part as
// one space (a quotation mark after \ or ` is a plain character, as in the
// first reading).
function withoutQuoted(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if ((c === '\\' || c === '`') && (text[i + 1] === '"' || text[i + 1] === "'")) {
      out += c + text[i + 1];
      i++;
    } else if (c === "'" || c === '"') {
      const close = text.indexOf(c, i + 1);
      i = close < 0 ? text.length : close;
      out += ' ';
    } else {
      out += c;
    }
  }
  return out;
}

// The third reading: the patterns of the first version of this file, as they were, outside quotation marks. Its
// pattern git\s+push\b.*(--force|-f\b) is found by forcedPush below, in a time in step with the length of the text.
const FIRST_DELETES = [
  /(^|[\s;&|(])rm\s/,
  /(^|[\s;&|(])rmdir\s/,
  /(^|[\s;&|(])del\s/i,
  /\bRemove-Item\b/i,
  /\bgit\s+(reset\s+--hard|clean\b|branch\s+-D\b|tag\s+-d\b)/,
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
// Whether the text holds git push and, later on the same line, --force or -f: what /\bgit\s+push\b.*(--force|-f\b)/
// finds (. stops at a line break), without trying the rest of the line again from each push.
function forcedPush(text) {
  const forces = [...text.matchAll(/--force|-f\b/g)].map((m) => m.index);
  if (forces.length === 0) return false;
  const breaks = /[\n\r\u2028\u2029]/g;
  let k = 0;
  let lineEnd = -1;
  for (const push of text.matchAll(/\bgit\s+push\b/g)) {
    const end = push.index + push[0].length;
    while (k < forces.length && forces[k] < end) k++;
    if (k === forces.length) return false;
    if (end > lineEnd) {
      breaks.lastIndex = end;
      lineEnd = breaks.exec(text)?.index ?? text.length;
    }
    if (forces[k] < lineEnd) return true;
  }
  return false;
}
const kindOfFirst = (text) => (FIRST_DELETES.some((re) => re.test(text)) || forcedPush(text) ? 'delete' : FIRST_RELEASES.some((re) => re.test(text)) ? 'release' : null);

/** The action name for a shell command: a deletion, a release, or a run. */
export function commandAction(command) {
  const text = typeof command === 'string' ? command : '';
  const kind = strictest([kindOfText(text, 0), kindOfFirst(withoutQuoted(text))]);
  if (kind === 'delete') return 'provared.data.delete';
  if (kind === 'release') return 'provared.code.release';
  return 'provared.code.run';
}
