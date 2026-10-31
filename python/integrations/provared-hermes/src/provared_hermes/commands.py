# How a terminal command is named in a record: a deletion, a release, or
# running a program.
#
# The readings are those of the recorder beside Claude Code (actions.mjs in
# integrations/claude-code of the repository), the same rules in the same
# order, so that the two name a command alike; the tests of both hold the
# same rows. A command is named as a deletion where it removes something (a
# deletion wins over a release), as a release where it publishes something
# to others, and otherwise as running a program. Three readings are made,
# and the strictest name any of them finds counts, so that a later reading
# can only add to what an earlier one found:
#
#  1. The command line read roughly as a shell reads it: quotation marks
#     taken off (a quotation mark after \ or ` is a plain character, and so
#     is one inside "..." after an odd number of `, as PowerShell reads it),
#     comments left out, and ; & | ( ) { } ` $( and line breaks starting a
#     new command; >&, N>&M and &> are a redirection, not a break; a word
#     that is exactly \; is find's end mark, and a line that holds one is
#     read the other way too, as PowerShell and cmd read it; a line that
#     holds ` before a quotation mark is read the other way too, as bash
#     reads it (` starts a command), at the last level only; {} is a plain
#     word. A program is known by its name in any letter case, without its
#     folder or its ending (.exe, .cmd, .ps1, ...), after any "NAME=value"
#     settings, redirections (2>/dev/null) and wrappers such as sudo, env or
#     timeout with their own options. A command line handed on is read in
#     the same way: to a shell (bash -c or -lc, cmd /c, also written
#     cmd /c"...", powershell -Command), to eval, iex or Invoke-Expression,
#     to ssh (the words after its destination), to watch and parallel (the
#     words after them), and each command find -exec runs, up to its ; or +
#     or the next -exec; and a value written in quotation marks after -c, a
#     cluster of small letters ending in c, --command, -Command or
#     -ArgumentList (su -c "...", script -qc "...", Start-Process cmd
#     -ArgumentList '/c ...', the list read after the name of the program it
#     is for) or after env -S; except, for all but -ArgumentList, where it
#     is handed to a shell (read as above), to a program that only reads or
#     shows text, to git, to ssh or to an interpreter (an -ArgumentList
#     written as a list, "/c","del x", is read as one line). So is each
#     $( ... ) and `...` inside "..." (not inside '...'), which a shell runs
#     there, to any depth (a quotation mark inside a $( ... ) does not close
#     the "...", nor does the ) of a case pattern or one in a # comment close
#     the $( ... ); a \$ or \` written in "..." is plain); what the command
#     before a single | writes, where a shell given
#     nothing but options reads it (echo "rm x" | sh); and a here-string
#     (bash <<< "..."). Four things a
#     program's name alone does not show are read too, in a command line
#     that runs an interpreter (python, node, ruby, perl, php, deno, bun,
#     PowerShell), a script written into the line after it (python - <<EOF)
#     included: a script's own calls that delete (shutil.rmtree, os.remove,
#     fs.rmSync, Path(...).unlink(), File.Delete and the like); and a
#     script's call that hands a command line to the system (subprocess,
#     os.system, child_process and the like), after which the line is read
#     again with its quotation marks, brackets and commas taken as spaces,
#     one level down. Also a move to the null device (mv x /dev/null); and a
#     file emptied by a redirection alone (: > file, > file).
#  2. In each simple command, every later word that names a known program
#     or an interpreter is read as the start of a command, whatever stands
#     before it (ssh host rm, docker exec c rm, python -m twine upload, npx
#     npm publish), with at most 64 words after it; and a later word that
#     names a shell, eval, ssh, watch or parallel starts a command whose
#     line is read one level down, as the first word of a line is (docker
#     exec c sh -c "..."), up to the next such word. A word written as a
#     program's path counts (/bin/rm, ./node_modules/.bin/npm,
#     C:\Tools\rm.exe, \rm), but not a word with / or \ inside it (a path to
#     a file, a web address, a sed expression). A word written in quotation
#     marks counts only after a program that runs another program (docker
#     exec c "rm", npx "npm", python -m "twine"), and not once a program
#     that only reads or shows text, a known program, a shell, an
#     interpreter or a program whose -m takes a message stands after that
#     one (sudo grep -w "rm"). The value of -m counts unless the
#     program before it takes a message there (git commit -m, hg, svn,
#     docker commit -m, npm version -m); the value of --message never does.
#  3. The patterns of the first version of that file, kept as they were,
#     applied to the text with everything in quotation marks taken out.
#
# So a word that names a deletion counts even where a shell would not run it
# (echo rm): the plugin errs towards the stricter name, though not inside a
# quoted message, a path or a web address. Each part of a line is handed one
# level down at most once at each level (a line read twice in the same way
# is read once), so that the time grows in step with the length of the line.
# This is a reading of the command's text, and it can always be got round: a
# script that deletes in a way not listed here or from a file, a program
# renamed or copied, a name built in a variable, an upload with curl or scp.
# That is why the record's kind of action is the plugin's reading of the
# call, not a fact about it.

import bisect
import functools
import re

__all__ = ['command_action', 'simple_commands']

# Programs that remove what they are given (with PowerShell's names for
# Remove-Item: rm, del, erase, rd, rmdir, ri).
DELETES = frozenset({'rm', 'rmdir', 'rd', 'del', 'erase', 'ri', 'remove-item', 'clear-content', 'clc', 'unlink', 'truncate', 'shred'})
# Programs that run the command after them, and those of their options that take the next word as their value
# (sudo's -h, and xargs's -i, -l and -e, take one only when it is written straight after them: -hhost, -i{}).
WRAPPERS = {
    'sudo': ['-u', '-g', '-p', '-a', '-c', '-C', '-D', '-R', '-r', '-t', '-U', '-T', '--user', '--group', '--host', '--prompt', '--chdir', '--chroot',
             '--close-from', '--login-class', '--auth-type', '--role', '--type', '--other-user', '--command-timeout'],
    'doas': ['-u', '-C'],
    'env': ['-u', '-C', '-S', '-a', '--unset', '--chdir', '--split-string', '--argv0'],
    'timeout': ['-s', '-k', '--signal', '--kill-after'],
    'nice': ['-n', '--adjustment'],
    'xargs': ['-I', '-n', '-L', '-P', '-d', '-s', '-E', '-a', '--arg-file', '--delimiter', '--max-args', '--max-procs', '--max-chars', '--process-slot-var'],
    'time': [], 'nohup': [], 'command': [], 'exec': [], 'builtin': [],
    'then': [], 'do': [], 'else': [], 'if': [], 'while': [], 'until': [], '!': [],
}
# Shells that run a command line handed to them.
SHELLS = frozenset({'bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish', 'csh', 'tcsh', 'cmd', 'powershell', 'pwsh'})
# Commands that run their words as a command line: eval (the Unix shells), iex and Invoke-Expression (PowerShell).
EVALS = frozenset({'eval', 'iex', 'invoke-expression'})
# Programs that run the words after them as a command line, again and again or once for each input.
REPEATERS = frozenset({'watch', 'parallel'})
# git's own options before the command that take the next word as their value.
GIT_VALUED = frozenset({'-c', '-C', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env'})
# ssh's own options that take the next word as their value.
SSH_VALUED = frozenset({'-B', '-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-P', '-p', '-Q', '-R', '-S', '-W', '-w'})
# Programs that move what they are given, and the names of the null device: a move there throws away what is moved.
MOVES = frozenset({'mv', 'move', 'move-item', 'mi'})
NULL_DEVICES = frozenset({'/dev/null', 'nul', '$null', 'nul:'})
# Interpreters, which may run a script written in the command line; and Python's launchers, whose -m names a module.
INTERPRETERS = re.compile(r'(python([0-9]+(\.[0-9]+)?)?|pythonw|py|node|nodejs|deno|bun|ruby|perl|php|pwsh|powershell)')
PYTHONS = re.compile(r'(python([0-9]+(\.[0-9]+)?)?|pythonw|py)')
# JavaScript's \s, so that both readers read spaces alike.
_S = '[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]'
# A script's own calls that delete.
SCRIPT_DELETES = re.compile(
    r'(?:\b(?:shutil\.rmtree|rmtree|os\.(?:remove|unlink|rmdir|removedirs)|(?:unlink|rm|rmdir)Sync|fs(?:\.promises)?\.(?:rm|rmdir|unlink)'
    r'|FileUtils\.(?:rm_rf|rm_r|rm_f|rm|remove_dir|remove_entry|remove)|Deno\.remove(?:Sync)?|(?:File|Directory)\]?(?:\.|::)Delete)'
    r'|\.(?:unlink|rmdir)\b)' + _S + r'*[("\']|\bunlink\b', re.I | re.A)
# A script's calls that hand a command line to the system.
SCRIPT_RUNS = re.compile(
    r'\b(?:subprocess|pty\.spawn|child_process|shell_exec|passthru|proc_open|Process\.Start|Open3|IO\.popen|Deno\.(?:run|Command)'
    r'|Bun\.(?:spawn|\$)|os\.(?:system|popen|exec|spawn)|(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|system|popen)' + _S + r'*\()', re.A)
# The programs whose words the second reading starts from, and those whose command line it reads one level down.
# Programs that publish where their first word is "publish" (and take back with "unpublish" or "yank"), and those that
# publish with "push" (and take back with "yank").
PUBLISHERS = frozenset({'uv', 'poetry', 'cargo', 'hatch', 'flit', 'pdm', 'vsce', 'ovsx'})
PUSHERS = frozenset({'gem', 'helm'})
# Programs that copy (cp /dev/null x empties x), clients of a database (whose DELETE FROM deletes), and what rsync is
# told that deletes.
COPIES = frozenset({'cp', 'copy', 'copy-item', 'cpi'})
SQL_CLIENTS = frozenset({'psql', 'mysql', 'mariadb', 'sqlite3', 'sqlcmd', 'duckdb', 'clickhouse-client', 'cockroach'})
SQL_DELETE = re.compile(r'\bDELETE' + '[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]' + r'+FROM\b', re.I | re.A)


def _rsync_deletes(word):
    return word.startswith('--delete') or word in ('--del', '--remove-source-files')


KNOWN = DELETES | MOVES | {'find', 'git', 'hub', 'npm', 'pnpm', 'yarn', 'bun', 'gh', 'twine', 'dotnet', 'docker', 'podman', 'rsync', 'redis-cli'} \
    | PUBLISHERS | PUSHERS | COPIES | SQL_CLIENTS
LINE_STARTS = SHELLS | EVALS | {'ssh'} | REPEATERS
# Programs that run a program named in a later word (docker exec c rm, npx npm, strace rm, chroot /mnt rm): after one,
# a word in quotation marks counts as a program's name. Python's launchers count too (python -m "twine").
RUNNERS = frozenset(WRAPPERS) | {
    'docker', 'podman', 'nerdctl', 'kubectl', 'oc', 'lxc', 'incus', 'wsl', 'strace', 'ltrace', 'chroot', 'nsenter', 'unshare', 'setsid',
    'busybox', 'runuser', 'su', 'sg', 'npx', 'pnpx', 'bunx', 'uvx', 'pipx', 'uv', 'poetry', 'pdm', 'hatch', 'pipenv', 'conda', 'mamba', 'npm',
    'pnpm', 'yarn', 'bun', 'stdbuf', 'ionice', 'taskset', 'chrt', 'firejail', 'bwrap', 'systemd-run', 'flatpak-spawn', 'toolbox', 'distrobox',
    'schroot', 'proot', 'fakeroot', 'valgrind', 'gosu', 'su-exec', 'setpriv', 'prlimit', 'numactl', 'eatmydata', 'torsocks', 'proxychains',
    'proxychains4', 'flock', 'script', 'cross-env', 'dotenv', 'watch', 'parallel', 'start-process', 'saps', 'start'}
# Programs that only read, search or show text, and two whose -c is not a command line (git -c name=value, ssh -c
# cipher): a value after -c handed to one of them is not a command line, and after one of them a word in quotation
# marks is not a program's name.
TEXT_PROGRAMS = frozenset({
    'echo', 'printf', 'grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'ag', 'ack', 'sed', 'awk', 'gawk', 'cat', 'head', 'tail', 'less', 'more', 'wc',
    'sort', 'uniq', 'cut', 'tr', 'tee', 'ls', 'jq', 'yq', 'diff', 'test', 'write-output', 'write-host', 'select-string', 'sls', 'findstr',
    'get-content', 'gc', 'git', 'ssh'})
# Programs whose -m takes a message (git commit -m), which is never a program's name.
MESSAGES = frozenset({'git', 'hg', 'svn', 'bzr', 'fossil', 'cvs', 'jj', 'sl', 'docker', 'podman', 'npm', 'pnpm', 'yarn'})
# The names the readings look at, or that change how the words after them are read (with every name of an interpreter
# that begins "python").
_LOOKED_AT = RUNNERS | TEXT_PROGRAMS | KNOWN | SHELLS | MESSAGES | EVALS | REPEATERS | {
    'ssh', 'pythonw', 'py', 'node', 'nodejs', 'deno', 'bun', 'ruby', 'perl', 'php', 'pwsh', 'powershell'}
# A word written as a program's path: from the root, from here or above, from home, from a drive, or with a backslash first (\rm).
PROGRAM_PATH = re.compile(r'(?:/|\.{1,2}[\\/]|~[\\/]|\\|[A-Za-z]:[\\/])', re.A)
# A redirection that empties its file: >file, 2>file, &>file, or the sign alone, whose target is the next word (not >>, which adds to its file, nor >&2).
EMPTIES = re.compile(r'(?:[0-9]*|&)>([^>&][\s\S]*)?')
_EXECS = ('-exec', '-execdir', '-ok', '-okdir')
# Spaces other than a plain space and a line break: each ends a word.
_OTHER_SPACES = '\t\v\f\r\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'
# A run of characters that the first reading adds to a word as they are, whatever stands around them, and plain
# spaces between them.
_PLAIN_RUN = '[^\\\\`{\'"&;|()}$<#\n' + _OTHER_SPACES + ']+'


def _token(end_mark, backtick_escapes):
    """The steps the first reading takes more than one character at a time: a
    run of characters that go into a word as they are (a backslash too,
    unless a quotation mark follows it, or with find's end mark a ;), with
    plain spaces between them; a run of other spaces, not a line break; and a
    part in '...', to its closing mark or the end. A part in "..." is found by
    _closing_quote."""
    backslash = '\\\\(?![;"\'])' if end_mark else '\\\\(?!["\'])'
    return re.compile(f'((?:{_PLAIN_RUN}|{backslash})+)|([{_OTHER_SPACES}]+)|\'([^\']*)\'?')


_TOKENS = {(e, b): _token(e, b) for e in (True, False) for b in (True, False)}
# A text made only of characters that go into a word as they are, with plain spaces between them.
_SIMPLE = re.compile('[^\\\\`{\'"&;|()}$<#\t\n\v\f\r\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]*')
_COMMAND_SHORTENING = re.compile(r'-c(o(m(m(a(n(d)?)?)?)?)?)?', re.I | re.A)
_ARGUMENT_LIST = re.compile(r'-(?:argumentlist|args)', re.I | re.A)
_LINES_OPTION_UNIX = re.compile(r'-[a-z]*c', re.A)
_LINES_OPTION_OTHER = re.compile(r'(?:--command|-co(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?|-argumentlist|-args)', re.I | re.A)
_CLUSTER = re.compile(r'-[A-Za-z]+', re.A)


def _space(c):
    # The characters JavaScript's \s matches, so that both readers split words alike.
    return c in ' \t\n\v\f\r\u00a0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff' or '\u2000' <= c <= '\u200a'


def _js_length(text):
    """A text's length as JavaScript counts it: in UTF-16 code units."""
    return len(text.encode('utf-16-le')) // 2


def _hands_line(shell, word):
    """The option that hands a shell its command line: -c, or a cluster with c
    (-lc, -ec) for the Unix shells; /c or /k for cmd; -Command or a
    shortening of it for PowerShell."""
    if shell == 'cmd':
        return re.fullmatch(r'/[ck]', word, re.I | re.A) is not None
    if shell in ('powershell', 'pwsh'):
        return _COMMAND_SHORTENING.fullmatch(word) is not None
    return re.fullmatch(r'-[a-z]*c[a-z]*', word, re.I | re.A) is not None


def _lines_option(owner, word):
    """The options of any other program whose value, written in quotation
    marks, is a command line: -c, or a cluster of small letters ending in c
    (su -c, script -qc, flock -c); --command; PowerShell's -Command or a
    shortening of it of two letters or more; Start-Process's -ArgumentList or
    -Args; and env's -S or --split-string."""
    return (_LINES_OPTION_UNIX.fullmatch(word) is not None or _LINES_OPTION_OTHER.fullmatch(word) is not None
            or (owner == 'env' and word in ('-S', '--split-string')))


class _Piped(list):
    """The words of a simple command that a single | stands before: it takes what the command before it writes."""

    __slots__ = ()


# The characters that may matter, in each kind of part still open: inside "..." itself (or a "..." inside a $( ... )),
# inside a $( ... ), and inside a `...`.
_IN_QUOTE = re.compile('["\\\\$`]')
_IN_SUB = re.compile('[()"\'\\\\`#<]|(?<=[ \\t\\r\\n;&|(){!])(?:case|esac)')
_IN_TICK = re.compile('[`\\\\]')
# Inside a $( ... ): what may come just before a # that starts a comment, and before a word a shell takes as a command.
_COMMENT_AFTER = ' \t\r\n;&|()'
_SPACES = ' \t\r'
_COMMAND_STARTS = ';&|(){!\n'
_COMMAND_WORDS = ('then', 'do', 'else', 'elif', 'if', 'while', 'until')


def _reserved_word(text, i, start):
    """The word case or esac at i, inside a $( ... ) whose text starts at
    start, where a shell takes it as one: a word of its own, at the start of a
    command (after the start of the $( ... ), ; & | ( ) { ! a line break, or
    then, do, else, elif, if, while or until), and for case with a word after
    it. Otherwise None."""
    word = 'case' if text.startswith('case', i) else 'esac' if text.startswith('esac', i) else None
    if word is None:
        return None
    nxt = text[i + 4] if i + 4 < len(text) else ''
    if word == 'case' and not (nxt != '' and nxt in ' \t\r\n'):
        return None
    if word == 'esac' and not (nxt == '' or nxt in ' \t\r\n;&|)'):
        return None
    k = i - 1
    while k >= start and text[k] in _SPACES:
        k -= 1
    if k < start or text[k] in _COMMAND_STARTS:
        return word
    s = k
    while s >= start and 'a' <= text[s] <= 'z':
        s -= 1
    if s == k:
        return None
    if s >= start and not (text[s] in _SPACES or text[s] in _COMMAND_STARTS):
        return None
    return word if text[s + 1:k + 1] in _COMMAND_WORDS else None


def _closing_quote(text, start, backtick_escapes, into):
    """Where a part in "..." that starts at start closes (or the length of the
    text, where it does not close), and the command lines that a shell runs
    inside it and puts its output in their place, put in into (where it is not
    None): each $( ... ), to its matching bracket, and each `...`. A $( ... )
    starts a new quotation of its own, so a quotation mark inside it
    (echo "$(cd "/tmp"; rm x)") does not close the part. Inside "...", \\$, \\`
    and \\\\ are plain characters (but \\" is not, so that a Windows folder
    written "C:\\x\\" ends where cmd ends it); as PowerShell reads it, so are `"
    and ``. The parts still open are kept on a list, not by calling this
    again, so that no depth of nesting can overflow. As the recorder beside
    Claude Code reads it, one character at a time; here only the characters
    that may matter are looked at."""
    n = len(text)
    open_ = []  # [kind ('sub', 'tick' or 'quote'), level, from]
    i = start
    while True:
        top = open_[-1] if open_ else None
        kind = 'quote' if top is None else top[0]
        m = (_IN_QUOTE if kind == 'quote' else _IN_SUB if kind == 'sub' else _IN_TICK).search(text, i)
        if m is None:
            break
        i = m.start()
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if backtick_escapes and c == '`' and nxt in ('"', '`'):
            i += 2
            continue
        if kind == 'quote':
            if c == '"':
                if top is None:
                    return i
                open_.pop()
            elif c == '\\' and nxt in ('$', '`', '\\'):
                i += 1
            elif c == '$' and nxt == '(':
                open_.append(['sub', 1, i + 2, []])
                i += 1
            elif c == '`':
                open_.append(['tick', 0, i + 1])
        elif kind == 'sub':
            if c == '(':
                top[1] += 1
            elif c == ')':
                cases = top[3]
                if cases and top[1] <= cases[-1]:
                    pass  # The end of a pattern of a case (case x in a) ...): it closes nothing.
                else:
                    top[1] -= 1
                    if top[1] == 0:
                        open_.pop()
                        if not open_ and into is not None:
                            into.append(text[top[2]:i])
            elif c == '<':
                if backtick_escapes and nxt == '#':
                    # As PowerShell reads it, a block comment, to its #> (or the end): a ) or a quotation mark in it is
                    # plain text.
                    end = text.find('#>', i + 2)
                    i = n if end < 0 else end + 1
            elif c == '#':
                if text[i - 1] in _COMMENT_AFTER:
                    # A comment, to the end of its line: a ) or a quotation mark in it is plain text.
                    end = text.find('\n', i + 1)
                    i = n if end < 0 else end
            elif c in 'ce':
                word = _reserved_word(text, i, top[2])
                if word == 'case':
                    top[3].append(top[1])
                    i += 3
                elif word == 'esac':
                    if top[3]:
                        top[3].pop()
                    i += 3
            elif c == '"':
                open_.append(['quote', 0, 0])
            elif c == "'":
                close = text.find("'", i + 1)
                i = n if close < 0 else close
            elif c == '\\':
                i += 1
            elif c == '`':
                open_.append(['tick', 0, i + 1])
        elif c == '`':
            open_.pop()
            if not open_ and into is not None:
                into.append(text[top[2]:i])
        elif c == '\\':
            i += 1
        i += 1
    # The text ends inside: a $( ... ) or `...` still open in the part itself is read to the end.
    if into is not None and open_:
        into.append(text[open_[0][2]:])
    return n


def _parse(text, end_mark=True, backtick_escapes=True, subs=None):
    """The simple commands in a command line, each as its list of words, each
    word as (text, whether any part of it was written in quotation marks).
    end_mark: whether a word that is exactly \\; is a plain word, as in the
    Unix shells (find -exec ... \\;); in PowerShell and cmd it is a break.
    backtick_escapes: whether ` before a quotation mark makes it a plain
    character, as in PowerShell; in bash ` starts a command.
    subs: where the command lines inside each part in "..." ($( ... ) and `...`)
    are put. A command that a single | stands before is a _Piped list.

    It reads as the recorder beside Claude Code reads, one character at a
    time; here a run of characters that go into a word as they are, a run of
    spaces and a part in quotation marks are each taken in one step."""
    if _SIMPLE.fullmatch(text):
        # Only characters that go into a word as they are, and spaces between words.
        words = [(w, False) for w in text.split(' ') if w]
        return [words] if words else []
    out = []
    words = []
    parts = []  # the word so far, in pieces
    last = ''  # the word's last character
    in_word = False
    quoted = False
    n = len(text)
    i = 0
    token = _TOKENS[end_mark, backtick_escapes].match
    while i < n:
        run = token(text, i)
        if run is not None:
            i = run.end()
            which = run.lastindex
            if which == 1:
                stretch = run.group(1)
                if ' ' not in stretch:
                    # Characters that only ever go into the word, taken together.
                    parts.append(stretch)
                    last = stretch[-1]
                    in_word = True
                    continue
                # Such characters with spaces between them: the word so far ends at the first space, the words between
                # spaces are whole, and the characters after the last space start a word.
                pieces = stretch.split(' ')
                if pieces[0]:
                    parts.append(pieces[0])
                    in_word = True
                if in_word:
                    words.append((''.join(parts), quoted))
                words.extend([(w, False) for w in pieces[1:-1] if w])
                quoted = False
                if pieces[-1]:
                    parts = [pieces[-1]]
                    last = pieces[-1][-1]
                    in_word = True
                else:
                    parts = []
                    last = ''
                    in_word = False
            elif which == 2:
                # Spaces (not a line break): the end of a word.
                if in_word:
                    words.append((''.join(parts), quoted))
                parts = []
                last = ''
                in_word = False
                quoted = False
            else:
                # A part in '...', to its closing mark or the end.
                part = run.group(which)
                if part:
                    parts.append(part)
                    last = part[-1]
                in_word = True
                quoted = True
            continue
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if (c == '\\' or (c == '`' and backtick_escapes)) and nxt in ('"', "'"):
            # An escaped quotation mark (\" in bash, `" in PowerShell) is a plain character.
            parts.append(nxt)
            last = nxt
            in_word = True
            i += 1
        elif end_mark and c == '\\' and nxt == ';' and not in_word and (i + 2 >= n or _space(text[i + 2]) or text[i + 2] in ';&|'):
            # A word that is exactly \; is find's own end mark in the Unix shells (find -exec ... \;), not a break between commands.
            words.append((';', False))
            i += 1
        elif c == '{' and nxt == '}' and not in_word:
            # {} is a plain word (find's place for each file's name), not a block.
            parts.append('{}')
            last = '}'
            in_word = True
            i += 1
        elif c == '"':
            # A part in "...", to its closing mark, which a $( ... ) or `...` inside it does not close; its command lines go
            # in subs. As PowerShell reads it, `" is a plain quotation mark: the ` is taken off.
            end = _closing_quote(text, i + 1, backtick_escapes, subs)
            if end > i + 1:
                part = text[i + 1:end].replace('`"', '"') if backtick_escapes else text[i + 1:end]
                parts.append(part)
                last = part[-1]
            in_word = True
            quoted = True
            i = end
        elif c == '&' and nxt == '>':
            # bash's &> (both outputs to a file): a redirection that starts a word of its own, not a break between commands.
            if in_word:
                words.append((''.join(parts), quoted))
            parts = ['&']
            last = '&'
            in_word = True
            quoted = False
        elif c == '&' and in_word and last == '>':
            # >& and N>&M (>&2, 2>&1): a redirection, one word.
            parts.append(c)
            last = c
        elif c == '\n' or c in ';&|(){}`' or (c == '$' and nxt == '('):
            if in_word:
                words.append((''.join(parts), quoted))
            parts = []
            last = ''
            in_word = False
            quoted = False
            if words:
                out.append(words)
            # The next command takes what this one writes, as its input: a single | (not ||).
            words = _Piped() if c == '|' and nxt != '|' and (i == 0 or text[i - 1] != '|') else []
        elif c == '<' and nxt == '#':
            # PowerShell's comment <# ... #>, which may stand inside a line.
            if in_word:
                words.append((''.join(parts), quoted))
            parts = []
            last = ''
            in_word = False
            quoted = False
            close = text.find('#>', i + 2)
            i = n if close < 0 else close + 1
        elif c == '#' and not in_word and (i == 0 or _space(text[i - 1])):
            # A comment, to the end of the line.
            nl = text.find('\n', i)
            i = n if nl < 0 else nl - 1
        else:
            parts.append(c)
            last = c
            in_word = True
        i += 1
    if in_word:
        words.append((''.join(parts), quoted))
    if words:
        out.append(words)
    return out


def simple_commands(text, end_mark=True):
    """The simple commands in a command line, each as its list of words."""
    return [[w for w, _ in words] for words in _parse(text, end_mark)]


_ENDING = re.compile(r'\.(exe|cmd|bat|com|ps1)\Z')


def _program_name(word):
    """A program's name as it is compared: in small letters, without its folder or its ending."""
    return _short_program_name(word) if len(word) <= 64 else _long_program_name(word)


def _long_program_name(word):
    cut = max(word.rfind('/'), word.rfind('\\'))
    name = (word[cut + 1:] if cut >= 0 else word).lower()
    return _ENDING.sub('', name) if '.' in name else name


# Short words are many and repeat: their names are kept, a few thousand at most.
_short_program_name = functools.lru_cache(maxsize=4096)(_long_program_name)


def _setting(word):
    return re.match(r'[A-Za-z_][A-Za-z0-9_]*=', word) is not None


def _redirection(word):
    """2>/dev/null, >log.txt, <in.txt, 2>&1, >&2, &>log.txt, or the sign alone, whose target is the next word."""
    return re.match(r'[0-9]*(>>?|<|&>|>&)', word) is not None


def _program(words):
    """The program a simple command runs, the words handed to it, and its place among the words; or None."""
    i = 0
    while i < len(words):
        name = _program_name(words[i])
        if _setting(words[i]):
            i += 1
        elif _redirection(words[i]):
            i += 2 if re.fullmatch(r'[0-9]*(>>?|<|&>|>&)', words[i]) else 1
        elif name in WRAPPERS:
            valued = WRAPPERS[name]
            i += 1
            # A wrapper's own options (with their values), settings, and a number it takes (timeout 10, nice -n 5).
            while i < len(words):
                if words[i] in valued:
                    i += 2
                elif words[i].startswith('-') or re.fullmatch(r'[0-9]+[a-z]?', words[i], re.I | re.A) or _setting(words[i]):
                    i += 1
                else:
                    break
        else:
            return name, words[i + 1:], i
    return None


def _strictest(kinds):
    """"delete", "release" or None: the strictest of several."""
    if 'delete' in kinds:
        return 'delete'
    if 'release' in kinds:
        return 'release'
    return None


def _kind_of_name(name):
    """What a later word that names this program changes for the words after
    it: 1 for Python's launchers, 2 for another program that runs another
    one, 3 for a program that only reads or shows text, a known program, a
    shell, an interpreter or a program whose -m takes a message, 0 for any
    other word."""
    return _short_kind_of_name(name) if len(name) <= 64 else _long_kind_of_name(name)


def _long_kind_of_name(name):
    if PYTHONS.fullmatch(name):
        return 1
    if name in RUNNERS:
        return 2
    if name in TEXT_PROGRAMS or name in KNOWN or name in SHELLS or name in MESSAGES or INTERPRETERS.fullmatch(name):
        return 3
    return 0


_short_kind_of_name = functools.lru_cache(maxsize=4096)(_long_kind_of_name)


def _later_words(command, names):
    """The places of the later words of a simple command that name a program
    the readings look at, and that the second reading reads as the start of a
    command: not a word with / or \\ inside it unless it is written as a
    program's path; not written in quotation marks unless a program that
    runs another one stands before it, and no program that only reads or
    shows text, known program, shell, interpreter or program whose -m takes
    a message after that one; not the value of -m after a program whose -m
    takes a message, nor of --message. (Only the words that name a program
    the readings look at are given: no other word is ever read as a program,
    nor changes how the words after it are read.)"""
    places = []
    first = names[0]
    runner = first in RUNNERS or PYTHONS.fullmatch(first) is not None
    message = first in MESSAGES and PYTHONS.fullmatch(first) is None
    # Only a word that names a program the readings look at, or one that changes how the words after it are read,
    # is looked at: no other word is ever read as a program here, nor changes anything.
    looked_at = _LOOKED_AT
    for i in [i for i in range(1, len(names)) if names[i] in looked_at or names[i][:6] == 'python']:
        word, quoted = command[i]
        before = command[i - 1][0]
        if ((quoted and not runner) or (('/' in word or '\\' in word) and PROGRAM_PATH.match(word) is None)
                or (before == '-m' and message) or before == '--message'):
            continue
        places.append(i)
        # The program named last decides what follows: whether a word in quotation marks may be a program's name, and
        # whether -m takes a message.
        name = names[i]
        kind = _kind_of_name(name)
        if kind == 1:
            runner = True
            message = False
        elif kind == 2:
            runner = True
            message = name in MESSAGES
        elif kind == 3:
            runner = False
            message = name in MESSAGES
    return places


def _line_start(name, args):
    """Where the command line that a program hands on starts among the words
    handed to it, or -1 where it hands on none; None for a program that hands
    none on. cmd's /c written together with its line (cmd /c"del x"), and a
    here-string written together with its line (<<<"..."), are marked by a
    place written as -2 - its index."""
    if name in SHELLS:
        at = next((k for k, a in enumerate(args) if _hands_line(name, a)), -1)
        if at >= 0:
            return at + 1
        # cmd's /c or /k with the command line written straight after it: cmd /c"del x".
        if name == 'cmd':
            glued = next((k for k, a in enumerate(args) if re.match(r'/[ck][\s\S]', a, re.I | re.A)), -1)
            return -2 - glued if glued >= 0 else -1
        # A command line handed on standard input as a here-string: bash <<< "...", also written <<<"...".
        if '<<<' in args:
            here = args.index('<<<')
            return here + 1 if here + 1 < len(args) else -1
        glued = next((k for k, a in enumerate(args) if a.startswith('<<<') and len(a) > 3), -1)
        return -2 - glued if glued >= 0 else -1
    if name in EVALS or name in REPEATERS:
        return 0
    if name == 'ssh':
        # The words after ssh's own options and its destination are the command line it runs there.
        i = 0
        while i < len(args) and args[i].startswith('-'):
            i += 2 if args[i] in SSH_VALUED else 1
        return i + 1 if i + 1 < len(args) else -1
    return None


def _line_of(name, args):
    """The command line a program hands on, or False where it hands on none;
    None for a program that hands none on."""
    start = _line_start(name, args)
    if start is None:
        return None
    if start == -1:
        return False
    if start <= -2:
        return ' '.join([args[-2 - start][2 if name == 'cmd' else 3:], *args[-1 - start:]])
    # PowerShell's -Command (or a shortening of it) names the line given to iex or Invoke-Expression; eval takes none.
    if name in ('iex', 'invoke-expression'):
        return ' '.join(a for a in args if not _COMMAND_SHORTENING.fullmatch(a))
    return ' '.join(args[start:])


def _hands_rest_on(p, depth):
    """Whether the first reading of a command hands the rest of it on, read
    one level down: a shell, eval, ssh, watch or parallel that hands on a
    line, or find with -exec. Then nothing after its program is handed on
    again from here."""
    if p is None or depth >= 4:
        return False
    name, args, _ = p
    if name == 'find':
        return any(a.lower() in _EXECS for a in args)
    start = _line_start(name, args)
    return start is not None and start != -1


class _Command:
    """A simple command, read once: its words, whether each was quoted, the
    program each names, its program, which kinds of program its later words
    name; and, made when first needed, the places of the second reading and
    the tables of _known_kind."""

    __slots__ = ('command', 'words', 'names', 'p', 'known', 'interpreter', '_places', 'lower', 'next', 'key')

    def __init__(self, command, known_names):
        self.command = command
        self.words = [w for w, _ in command]
        # The names of words met before in the same command line are not worked out again.
        get = known_names.get
        self.names = [name if (name := get(w)) is not None else known_names.setdefault(w, _program_name(w)) for w in self.words]
        self.p = _program(self.words)
        later = set(self.names[1:])
        self.known = not KNOWN.isdisjoint(later)
        self.interpreter = any(INTERPRETERS.fullmatch(name) for name in later if name in _INTERPRETER_NAMES or name[:6] == 'python')
        self._places = None
        self.lower = None
        self.next = {}
        self.key = None

    @property
    def places(self):
        if self._places is None:
            self._places = _later_words(self.command, self.names)
        return self._places


_INTERPRETER_NAMES = frozenset({'pythonw', 'py', 'node', 'nodejs', 'deno', 'bun', 'ruby', 'perl', 'php', 'pwsh', 'powershell'})


def _kind_of_text(text, depth, read=None):
    """The first and the second reading, for a command line, at any depth.
    "read" holds what has been read already: a command line read twice in the
    same way (the two readings of a line that holds \\;) is read once. A line
    that holds \\; is read both as the Unix shells read it (find's end mark)
    and as PowerShell and cmd do (a break), and the stricter name counts: the
    plugin cannot always tell which shell runs a line."""
    if read is None:
        read = _Read()
    key = (depth, text)
    if key in read.texts:
        return read.texts[key]
    kind = _read_text(text, depth, read)
    read.texts[key] = kind
    return kind


class _Read:
    """What has been read in one command line: each line handed on, and each
    simple command (a simple command met again is read once, at each level)."""

    __slots__ = ('texts', 'commands', 'kinds', 'names')

    def __init__(self):
        self.texts = {}
        self.commands = {}
        self.kinds = {}
        self.names = {}

    def command(self, words):
        key = tuple(words)
        c = self.commands.get(key)
        if c is None:
            c = self.commands[key] = _Command(words, self.names)
            c.key = key
        return c


def _read_text(text, depth, read):
    if re.search(r'\bDROP' + _S + r'+(TABLE|DATABASE)\b', text, re.I | re.A):
        return 'delete'
    subs = []
    commands = _parse(text, True, True, subs)
    if '\\;' in text:
        commands += _parse(text, False, True, subs)
    # A line that holds ` before a quotation mark, read as bash reads it, at the last level only.
    others = _parse(text, True, False, subs) if re.search('`["\']', text) else []
    mine = [read.command(c) for c in commands]
    theirs = [read.command(c) for c in others]

    # A script's own calls that delete, in a line that runs an interpreter, as a command's program or as a later word.
    def runs_script(c):
        if c.p is not None and INTERPRETERS.fullmatch(c.p[0]):
            return True
        return c.interpreter and any(INTERPRETERS.fullmatch(c.names[i]) for i in c.places)

    runs = any(runs_script(c) for c in mine) or any(runs_script(c) for c in theirs)
    if runs and SCRIPT_DELETES.search(text):
        return 'delete'
    release = False
    # A script's call that hands a command line to the system: the line read again with its quotation marks, brackets
    # and commas as spaces, so that the strings handed on are read as command lines (subprocess.run(['git', 'push'])).
    if runs and depth < 4 and re.search('["\'`]', text) and SCRIPT_RUNS.search(text):
        kind = _kind_of_text(re.sub(r'["\'`\[\],]', ' ', text), depth + 1, read)
        if kind == 'delete':
            return 'delete'
        if kind == 'release':
            release = True
    # Each command line inside a part in "..." that a shell runs there ($( ... ), `...`), read one level down. At the
    # last level, it is read flat, with its quotation marks as spaces, so that one nested deeper still is not left unread.
    for sub in dict.fromkeys(subs):
        kind = _kind_of_text(sub, depth + 1, read) if depth < 4 else _kind_of_text(re.sub('["\']', ' ', sub), 4, read)
        if kind == 'delete':
            return 'delete'
        if kind == 'release':
            release = True
    for k, c in enumerate(mine):
        kind = _command_kind(c, depth, read)
        if kind == 'delete':
            return 'delete'
        if kind == 'release':
            release = True
        # A shell given nothing but options, after a single |, runs what the command before it writes (echo "rm -rf x" |
        # sh): the words handed to that command, read one level down as its command line.
        p = c.p
        if (depth < 4 and k > 0 and isinstance(commands[k], _Piped) and p is not None and p[0] in SHELLS
                and all(a.startswith('-') for a in p[1]) and mine[k - 1].p is not None):
            kind = _kind_of_text(' '.join(mine[k - 1].p[1]), depth + 1, read)
            if kind == 'delete':
                return 'delete'
            if kind == 'release':
                release = True
    for c in theirs:
        kind = _command_kind(c, 4, read)
        if kind == 'delete':
            return 'delete'
        if kind == 'release':
            release = True
    return 'release' if release else None


def _command_kind(c, depth, read):
    """The first and the second reading of one simple command, read once at each level."""
    key = (depth, c.key)
    kind = read.kinds.get(key, _UNSET)
    if kind is _UNSET:
        kind = read.kinds[key] = _kind_of_command(c, depth, read)
    return kind


_UNSET = object()


def _kind_of_command(c, depth, read):
    """The first and the second reading of one simple command."""
    command, words, names, p = c.command, c.words, c.names, c.p
    release = False
    kind = _kind_of(words, depth, read, p)
    if kind == 'delete':
        return 'delete'
    if kind == 'release':
        release = True
    # Below, each part of the command is handed one level down once at most: after the part that "after" stands at.
    n = len(words)
    after = n if _hands_rest_on(p, depth) else 1
    # Whether anything may still be handed one level down from here: else only the known programs are looked at.
    down = depth < 4 and after < n
    if not down and not c.known:
        return 'release' if release else None
    places = c.places
    is_place = set(places) if down else ()
    # The words looked at, in order: the places of known programs, shells, eval, ssh, watch and parallel; and the
    # words in quotation marks, which may hand a command line on.
    starts = {i for i in places if names[i] in KNOWN or (down and names[i] in LINE_STARTS)}
    # (Every option that hands a command line on begins with "-".)
    values = {i for i in range(after, n) if command[i][1] and (words[i - 1][:1] == '-' or words[i][:10].lower() == '--command=')} if down else set()
    # The words that are not options, where an option's program is looked for: the nearest before the option.
    plain = [j for j in range(1, n) if not words[j].startswith('-')] if values else []
    for i in sorted(starts | values):
        if i in starts:
            name = names[i]
            # The second reading: a known program, read as the start of a command, with at most 64 words after it.
            if name in KNOWN:
                kind = _known_kind(c, i, min(i + 65, n))
                if kind == 'delete':
                    return 'delete'
                if kind == 'release':
                    release = True
            # A shell, eval, ssh, watch or parallel: its command line read one level down, up to the next such word.
            if name in LINE_STARTS and depth < 4 and i >= after and (p is None or i != p[2]):
                end = i + 1
                listed = False
                while end < n and end < i + 65 and not (end in is_place and names[end] in LINE_STARTS):
                    if _ARGUMENT_LIST.fullmatch(words[end]):
                        listed = True
                    end += 1
                # A shell named to Start-Process, with -ArgumentList after it: the list is read below, after the shell's name.
                line = None if listed else _line_of(name, words[i + 1:end])
                if isinstance(line, str):
                    kind = _kind_of_text(line, depth + 1, read)
                    if kind == 'delete':
                        return 'delete'
                    if kind == 'release':
                        release = True
                    after = end
        # A value written in quotation marks after an option that hands a command line on (su -c "..."), read one level
        # down; the value of -ArgumentList or -Args whatever program it is for.
        if i in values and i >= after:
            # The program the nearest word before the option names (the first word where there is none).
            j = bisect.bisect_left(plain, i) - 1
            owner_name = names[plain[j] if j >= 0 else 0]
            handed_to = owner_name not in SHELLS and owner_name not in TEXT_PROGRAMS and not INTERPRETERS.fullmatch(owner_name)
            glued = re.match(r'--command=', words[i], re.I | re.A) is not None
            listed = _ARGUMENT_LIST.fullmatch(words[i - 1]) is not None
            if listed or (handed_to and (glued or _lines_option(owner_name, words[i - 1]))):
                # A list of arguments is read after the name of the program it is for (Start-Process powershell
                # -ArgumentList "-Command ..."), where that name is a short one.
                # Written as a list ("/c","del x"), its items are read as words of one line.
                value = words[i].replace(',', ' ') if listed else words[i]
                if glued:
                    line = words[i][10:]
                elif listed and len(owner_name) <= 64 and _js_length(owner_name) <= 64 and not any(_space(ch) for ch in owner_name):
                    line = f'{owner_name} {value}'
                else:
                    line = value
                kind = _kind_of_text(line, depth + 1, read)
                if kind == 'delete':
                    return 'delete'
                if kind == 'release':
                    release = True
                after = i + 1
    return 'release' if release else None


def _known_kind(c, at, end):
    """What _kind_of gives at the last level for the words of a command from a
    known program at "at" up to "end" (not included), in a time that does
    not grow with the number of words: whether a word of some kind stands
    among them is looked up in a table made once for the command (the place
    of the next such word from each place). A known program's name is never a
    setting, a redirection or a wrapper, so it is the program of those
    words."""
    name = c.names[at]
    tables = c.next

    def has(kind, start, stop=end):
        if start >= stop:
            return False
        table = tables.get(kind)
        return (table if table is not None else _next_of(c, kind))[start] < stop

    if name in DELETES:
        return 'delete'
    if name in MOVES:
        return 'delete' if has('nullDevice', at + 1) else None
    if name == 'find':
        return 'delete' if has('-delete', at + 1) or has('execDelete', at + 1, end - 1) else None
    lower = _lower_of(c)
    if name in ('git', 'hub'):
        # git's command: the first word after git's own options (and their values), where it stands before "end".
        s = _next_of(c, 'gitCommand')[at + 1]
        sub = lower[s] if s < end else ''
        if sub == 'push':
            return 'delete' if has('pushForce', s + 1) else 'release'
        if sub == 'rm':
            return None if has('cached', s + 1) else 'delete'
        if sub == 'reset':
            return 'delete' if has('hard', s + 1) else None
        if sub == 'clean':
            return None if has('dryRun', s + 1) else 'delete'
        if sub in ('branch', 'tag'):
            return 'delete' if has('branchDelete', s + 1) else None
        if sub == 'stash':
            return 'delete' if s + 1 < end and lower[s + 1] in ('drop', 'clear') else None
        if sub == 'checkout':
            return 'delete' if has('checkoutForce', s + 1) or has('--', s + 1, end - 1) else None
        if sub == 'restore':
            return None if has('staged', s + 1) and not has('worktree', s + 1) else 'delete'
        return None
    if name in ('npm', 'pnpm', 'yarn', 'bun'):
        return 'delete' if has('unpublish', at + 1) else 'release' if has('publish', at + 1) else None
    what = lower[at + 1] if at + 1 < end else None
    how = lower[at + 2] if at + 2 < end else None
    if name == 'gh':
        if what in ('repo', 'release') and how == 'delete':
            return 'delete'
        if what == 'api' and (has('methodDelete', at + 1) or has('methodThenDelete', at + 1, end - 1)):
            return 'delete'
        if what == 'release' and how in ('create', 'upload', 'edit'):
            return 'release'
        if what == 'repo' and how == 'edit':
            return 'release'
        if what == 'pr' and how in ('create', 'merge'):
            return 'release'
        return None
    if name == 'twine' and what == 'upload':
        return 'release'
    if name in PUBLISHERS:
        return 'delete' if what in ('unpublish', 'yank') else 'release' if what == 'publish' else None
    if name in PUSHERS:
        return 'delete' if what == 'yank' else 'release' if what == 'push' else None
    if name == 'dotnet':
        return 'delete' if what == 'nuget' and how == 'delete' else 'release' if what == 'nuget' and how == 'push' else None
    if name in ('docker', 'podman'):
        return 'release' if what == 'push' or (what in ('build', 'buildx') and has('--push', at + 1)) else None
    if name == 'rsync':
        return 'delete' if has('rsyncDelete', at + 1) else None
    if name in COPIES:
        return 'delete' if has('nullDevice', at + 1, end - 1) else None
    if name in SQL_CLIENTS:
        return 'delete' if has('sqlDelete', at + 1) or has('deleteThenFrom', at + 1, end - 1) else None
    if name == 'redis-cli':
        return 'delete' if has('flush', at + 1) else None
    return None


def _lower_of(c):
    """The words of a command in small letters, made once."""
    if c.lower is None:
        c.lower = [w.lower() for w in c.words]
    return c.lower


def _holds(word, letter):
    """A cluster of one-letter options, such as -fu, that holds the letter."""
    return letter in word and _CLUSTER.fullmatch(word) is not None


def _push_force(word):
    """A push that can take history or branches away: forced, deleting, or with a refspec that forces (+) or deletes (:)."""
    return word[:1] in _FORCE_STARTS and (
        word in ('--force', '--delete', '--mirror', '--prune') or word.startswith('--force-with-lease') or word.startswith('--force-if-includes')
        or _holds(word, 'f') or _holds(word, 'd') or (not word.startswith('-') and (word.startswith('+') or word.startswith(':'))))


_FORCE_STARTS = frozenset({'-', '+', ':'})


# The kinds of word that _known_kind looks for, each as a test of all the words of a command at once.
_WORD_KINDS = {
    'nullDevice': lambda low, words, names: [w in NULL_DEVICES for w in low],
    '-delete': lambda low, words, names: [w == '-delete' for w in low],
    'execDelete': lambda low, words, names: [low[w] in _EXECS and w + 1 < len(words) and names[w + 1] in DELETES for w in range(len(words))],
    'unpublish': lambda low, words, names: [w == 'unpublish' for w in low],
    'publish': lambda low, words, names: [w == 'publish' for w in low],
    'methodDelete': lambda low, words, names: [w in ('--method=delete', '-xdelete') for w in low],
    'methodThenDelete': lambda low, words, names: [low[w] in ('-x', '--method') and w + 1 < len(words) and low[w + 1] == 'delete' for w in range(len(words))],
    'pushForce': lambda low, words, names: [_push_force(w) for w in words],
    'cached': lambda low, words, names: [w == '--cached' for w in words],
    'hard': lambda low, words, names: [w == '--hard' for w in words],
    'dryRun': lambda low, words, names: [w in ('-n', '--dry-run') for w in words],
    'branchDelete': lambda low, words, names: [w[:1] == '-' and (w == '--delete' or _holds(w, 'd') or _holds(w, 'D')) for w in words],
    'checkoutForce': lambda low, words, names: [w[:1] == '-' and (w == '--force' or _holds(w, 'f')) for w in words],
    '--': lambda low, words, names: [w == '--' for w in words],
    'staged': lambda low, words, names: [w in ('--staged', '-S') for w in words],
    'worktree': lambda low, words, names: [w in ('--worktree', '-W') for w in words],
    '--push': lambda low, words, names: [w == '--push' for w in low],
    'rsyncDelete': lambda low, words, names: [_rsync_deletes(w) for w in low],
    'sqlDelete': lambda low, words, names: [SQL_DELETE.search(w) is not None for w in words],
    'deleteThenFrom': lambda low, words, names: [low[w] == 'delete' and w + 1 < len(words) and low[w + 1] == 'from' for w in range(len(words))],
    'flush': lambda low, words, names: [w in ('flushall', 'flushdb') for w in low],
}


def _next_of(c, kind):
    """For each place of a command, the place of the next word of the kind (or
    the number of words where there is none), made once for the command.
    "gitCommand": where git's command stands when git's own options start at
    the place."""
    table = c.next.get(kind)
    if table is not None:
        return table
    words = c.words
    n = len(words)
    table = [n] * (n + 2)
    if kind == 'gitCommand':
        for w in range(n - 1, -1, -1):
            table[w] = table[min(n, w + (2 if words[w] in GIT_VALUED else 1))] if words[w].startswith('-') else w
    else:
        marks = _WORD_KINDS[kind](_lower_of(c), words, c.names)
        start = 0
        for at in [w for w, marked in enumerate(marks) if marked]:
            table[start:at + 1] = [at] * (at + 1 - start)
            start = at + 1
    c.next[kind] = table
    return table


def _kind_of(words, depth, read, p=_UNSET):
    """"delete", "release" or None, for one simple command (whose program,
    where it has been found already, is p)."""
    if p is _UNSET:
        p = _program(words)
    # A file emptied by a redirection alone ("> file", ": > file", "true > file"), not one sent to the null device.
    if p is None or p[0] in (':', 'true', ''):
        for i, w in enumerate(words):
            m = EMPTIES.fullmatch(w)
            if m is None:
                continue
            target = m.group(1) if m.group(1) is not None else (words[i + 1] if i + 1 < len(words) else None)
            if target is not None and target.lower() not in NULL_DEVICES:
                return 'delete'
    if p is None:
        return None
    name, args, _ = p
    if name in DELETES:
        return 'delete'
    if name in MOVES and any(a.lower() in NULL_DEVICES for a in args):
        return 'delete'
    # A shell, eval, ssh, watch or parallel: the command line it hands on, read one level down.
    line = _line_of(name, args)
    if line is not None:
        return _kind_of_text(line, depth + 1, read) if line is not False and depth < 4 else None
    lower = [a.lower() for a in args]
    if name == 'find':
        if '-delete' in lower:
            return 'delete'
        kinds = []
        i = 0
        while i < len(args) - 1:
            if lower[i] not in _EXECS:
                i += 1
                continue
            if _program_name(args[i + 1]) in DELETES:
                return 'delete'
            # The command find runs, up to its closing ";" or "+", or the next -exec, so that each word is read in one part
            # only and the time grows with the length of the line: read as a command of its own (find -exec sh -c 'rm ...').
            end = i + 1
            while end < len(args) and args[end] not in (';', '\\;', '+') and lower[end] not in _EXECS:
                end += 1
            if depth < 4:
                kind = _kind_of(args[i + 1:end], depth + 1, read)
                if kind == 'delete':
                    return 'delete'
                kinds.append(kind)
            i = end
        return _strictest(kinds)
    if name in ('git', 'hub'):
        return _git_kind(args)
    if name in ('npm', 'pnpm', 'yarn', 'bun'):
        if 'unpublish' in lower:
            return 'delete'
        return 'release' if 'publish' in lower else None
    if name == 'gh':
        what = lower[0] if lower else None
        how = lower[1] if len(lower) > 1 else None
        if what in ('repo', 'release') and how == 'delete':
            return 'delete'
        if what == 'api' and any(((a in ('-x', '--method')) and k + 1 < len(lower) and lower[k + 1] == 'delete')
                                 or a in ('--method=delete', '-xdelete') for k, a in enumerate(lower)):
            return 'delete'
        if what == 'release' and how in ('create', 'upload', 'edit'):
            return 'release'
        if what == 'repo' and how == 'edit':
            return 'release'
        if what == 'pr' and how in ('create', 'merge'):
            return 'release'
        return None
    if name == 'twine' and lower[:1] == ['upload']:
        return 'release'
    first = lower[0] if lower else None
    second = lower[1] if len(lower) > 1 else None
    if name in PUBLISHERS:
        return 'delete' if first in ('unpublish', 'yank') else 'release' if first == 'publish' else None
    if name in PUSHERS:
        return 'delete' if first == 'yank' else 'release' if first == 'push' else None
    if name == 'dotnet':
        return 'delete' if first == 'nuget' and second == 'delete' else 'release' if first == 'nuget' and second == 'push' else None
    if name in ('docker', 'podman'):
        return 'release' if first == 'push' or (first in ('build', 'buildx') and '--push' in lower) else None
    if name == 'rsync':
        return 'delete' if any(_rsync_deletes(a) for a in lower) else None
    # cp /dev/null x empties x: a null device that is not the last word.
    if name in COPIES:
        return 'delete' if any(a in NULL_DEVICES for a in lower[:-1]) else None
    if name in SQL_CLIENTS:
        return 'delete' if any(SQL_DELETE.search(a) for a in args) or any(a == 'delete' and k + 1 < len(lower) and lower[k + 1] == 'from'
                                                                          for k, a in enumerate(lower)) else None
    if name == 'redis-cli':
        return 'delete' if any(a in ('flushall', 'flushdb') for a in lower) else None
    return None


_GIT_COMMANDS = ('push', 'rm', 'reset', 'clean', 'branch', 'tag', 'stash', 'checkout', 'restore')


def _git_kind(args):
    """git: the command is the first word that is not one of git's own options."""
    i = 0
    while i < len(args) and args[i].startswith('-'):
        i += 2 if args[i] in GIT_VALUED else 1
    sub = args[i].lower() if i < len(args) else ''
    if sub not in _GIT_COMMANDS:
        return None
    rest = args[i + 1:]

    def has(*flags):
        return any(a in flags for a in rest)

    def short(letter):
        # A cluster of one-letter options, such as -fu, holds each of its letters.
        return any(_holds(a, letter) for a in rest)

    if sub == 'push':
        # A push that can take history or branches away: forced, deleting, or with a refspec that forces (+) or deletes (:).
        return 'delete' if any(_push_force(a) for a in rest) else 'release'
    # git rm removes the working files, unless it only stops tracking them (--cached).
    if sub == 'rm' and not has('--cached'):
        return 'delete'
    if sub == 'reset' and has('--hard'):
        return 'delete'
    if sub == 'clean' and not has('-n', '--dry-run'):
        return 'delete'
    if sub in ('branch', 'tag') and (has('--delete') or short('d') or short('D')):
        return 'delete'
    if sub == 'stash' and (rest[0].lower() if rest else '') in ('drop', 'clear'):
        return 'delete'
    # Changes in the working files thrown away.
    paths = rest.index('--') if '--' in rest else -1
    if sub == 'checkout' and (has('--force') or short('f') or (0 <= paths < len(rest) - 1)):
        return 'delete'
    if sub == 'restore' and not (has('--staged', '-S') and not has('--worktree', '-W')):
        return 'delete'
    return None


def _without_quoted(text):
    """The text with every part in quotation marks taken out, each such part as
    one space (a quotation mark after \\ or ` is a plain character, as in the
    first reading)."""
    # Read from the left: an escaped quotation mark is kept, and a part in quotation marks, to its closing mark or the
    # end, becomes one space.
    return _QUOTED_OR_ESCAPED.sub(lambda m: m.group() if m.lastindex == 1 else ' ', text)


_QUOTED_OR_ESCAPED = re.compile(r'''([\\`]["'])|"[^"]*"?|'[^']*'?''')


# The third reading: the patterns of the first version of the recorder beside Claude Code, as they were, outside quotation marks.
def _first(pattern, flags=0):
    """The pattern as JavaScript reads it: \\s as JavaScript's spaces, \\b and
    letter case in ASCII, and . not across a line break."""
    out = []
    in_class = False
    for token in re.findall(r'\\.|.', pattern, re.S):
        if token == r'\s':  # noqa: S105 -- "token" is a piece of a pattern being read, not a secret
            out.append(_S[1:-1] if in_class else _S)
        elif token == '.' and not in_class:  # noqa: S105 -- "token" is a piece of a pattern being read, not a secret
            out.append('[^\n\r\u2028\u2029]')
        else:
            if token == '[':  # noqa: S105 -- "token" is a piece of a pattern being read, not a secret
                in_class = True
            elif token == ']':  # noqa: S105 -- "token" is a piece of a pattern being read, not a secret
                in_class = False
            out.append(token)
    return re.compile(''.join(out), flags | re.A)


_FIRST_DELETES = [
    _first(r'(^|[\s;&|(])rm\s'),
    _first(r'(^|[\s;&|(])rmdir\s'),
    _first(r'(^|[\s;&|(])del\s', re.I),
    _first(r'\bRemove-Item\b', re.I),
    _first(r'\bgit\s+(reset\s+--hard|clean\b|branch\s+-D\b|tag\s+-d\b)'),
    _first(r'\bDROP\s+(TABLE|DATABASE)\b', re.I),
    _first(r'\bunlink\s'),
    _first(r'\btruncate\s'),
]
_FIRST_RELEASES = [
    _first(r'\bgit\s+push\b'),
    _first(r'\bnpm(\.cmd)?\s+publish\b'),
    _first(r'\btwine\s+upload\b'),
    _first(r'\bgh\s+release\s+(create|upload|edit)\b'),
    _first(r'\bgh\s+repo\s+edit\b'),
    _first(r'\bgh\s+pr\s+(create|merge)\b'),
]
_PUSH = _first(r'\bgit\s+push\b')
_FORCE = _first(r'--force|-f\b')
_LINE_BREAK = re.compile('[\n\r\u2028\u2029]')


def _forced_push(text):
    """Whether the text holds git push and, later on the same line, --force or
    -f: what git\\s+push\\b.*(--force|-f\\b) finds (. stops at a line break),
    without trying the rest of the line again from each push."""
    forces = [m.start() for m in _FORCE.finditer(text)]
    if not forces:
        return False
    k = 0
    line_end = -1
    for push in _PUSH.finditer(text):
        end = push.end()
        while k < len(forces) and forces[k] < end:
            k += 1
        if k == len(forces):
            return False
        if end > line_end:
            found = _LINE_BREAK.search(text, end)
            line_end = found.start() if found else len(text)
        if forces[k] < line_end:
            return True
    return False


def _kind_of_first(text):
    if any(r.search(text) for r in _FIRST_DELETES) or _forced_push(text):
        return 'delete'
    if any(r.search(text) for r in _FIRST_RELEASES):
        return 'release'
    return None


def command_action(command):
    """The action name for a shell command: a deletion, a release, or a run."""
    text = command if isinstance(command, str) else ''
    kind = _strictest([_kind_of_text(text, 0), _kind_of_first(_without_quoted(text))])
    if kind == 'delete':
        return 'provared.data.delete'
    if kind == 'release':
        return 'provared.code.release'
    return 'provared.code.run'
