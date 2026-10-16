# <img src="https://prova.red/favicon.svg" alt="" width="36"> Provared beside Claude Code

A coding agent, Claude Code, recorded by Provared: every tool call it
makes is checked against a permission the person signed with a passkey,
refused if it is outside it, and receipted if it is taken. The result is
a book that anyone can check with the free checker.

*Evidence, not a verdict.*

## From nothing to a recorded session

Five commands and one step with your passkey. It needs Node.js 24.7 or
later.

```
npm install -g provared-claude-code
cd your-project
provared-claude-code init
```

`init` makes the agent's keys, writes the hooks into the project's
`.claude/settings.local.json` (next to anything already there), and
prints a link and **the fingerprint of the agent's key set** (`keys`
prints it too). **Open the link in a browser:** the signing page at
prova.red opens with a starting permission for this agent filled in.
Write your name and read the permission: the page shows the same
fingerprint of the agent's key set, and if it differs from the one
`init` printed, the page holds someone else's keys, so do not sign. Change
the permission if you wish, sign with your passkey, and save the file it
gives you. Keep the passkey's thumbprint the page shows. The part of the
link after `#` stays in your browser; it is never sent to any server. The
page offers nothing to sign when another site shows it inside its own
page: open it in a tab of its own.

```
provared-claude-code use ~/Downloads/slip.json
claude
provared-claude-code check --issuer <your passkey's thumbprint>
```

`use` puts the signed permission in place and starts the recorder.
Every tool call Claude Code then makes in that project is checked and
recorded. `check` gives the checker's answer for the book, trusting the
passkey you name and no other.

On Windows, if PowerShell refuses to run the command, write
`provared-claude-code.cmd` in its place.

## The starting permission

The link carries the same starting point as the signing page's own: the
agent may read, change and run code (at most 500 runs and 500 changes in
any hour), read the web and start helper agents, for seven days from when
you open the page. It may not delete anything, and it may not publish
(`git push`, `npm publish`, a page on a server): add
`provared.data.delete` or `provared.code.release` to its actions, with a
limit, and take `destroys` out of `never`, before you sign, if you want
it to. It also states rules of conduct (`conceal`, `deceive`, `bypass`,
`escalate`, `continue-after-stop`), which are your signed instruction and
which no checker can test.

## A new permission when the one before ends

A permission ends at the time it states. Sign a new one (run `init`
again for a fresh link) and take it into the book:

```
provared-claude-code renew ~/Downloads/slip.json
```

It works whether the recorder is running or not. A running recorder
checks the new permission (the passkey's signature, with the library's
own checker, and that it names this agent's keys), opens the book with it
added, and only then switches to it. It never stops listening, so no
tool call finds it gone; a call made at that moment waits until the
switch is done. On Windows, a file held open by another program (a virus
scanner, an uploader) can hold a renewal up for as long as about 40
seconds; calls made meanwhile are refused, never let through
unrecorded. The book keeps both permissions, and every receipt for a
call asked after the switch is under the new one. A call allowed under
the permission before and finished after the switch keeps that
permission: the hook hands over Claude Code's identifier of the call
(`tool_use_id`) both times, and the recorder files the receipt under the
permission the call was allowed under, with the writer it kept from
before the switch, so that such a receipt costs no further reading of
the book. The permission before is kept beside it, as
`slip-<its fingerprint>.json`.

The recorder takes a permission only from a passkey on its list,
`trusted-passkeys.json` in its folder: the first `use` writes it, with
that permission's passkey, and only `renew --new-passkey` adds to it.
A permission signed by any other passkey is refused, whether it is
handed to `renew` or put in place by hand, and the recorder does not
start while its book, or `slip.json`, holds one. If you made a new
passkey yourself, add `--new-passkey`; whoever checks the book must then
name both passkeys. This raises the bar; it does not close the gap: see
"What the record shows, and what it does not".

## The commands

| Command | What it does |
|---|---|
| `init` | Make the keys if they are missing, write the hooks into this project's `.claude/settings.local.json`, and print the link to sign a permission |
| `use <file>` | Put a signed permission in place and start the recorder; where a book exists already, the same as `renew` |
| `renew <file>` | Take a new signed permission into the book, while the recorder runs or not; `--new-passkey` where you signed it with a passkey of yours that signed none before |
| `start` | Run the recorder in this terminal, and see what it says |
| `ensure` | Start the recorder in the background if it is not running (the hooks run this when a session starts) |
| `status` | What the recorder holds: the permission, until when, the number of entries |
| `seal` | Seal the book now, with the recorder's three keys |
| `check` | The checker's answer for the book. Name your passkey with `--issuer <its thumbprint>`, once for each passkey of yours; without it, `check` lists the passkeys the book's permissions name, as read from the book, and the checker takes none of them as one you trust |
| `stop` | Stop the recorder |
| `keys` | Make the keys, and print the agent's public keys |

`check` runs the library's own command-line checker, so its words and
its exit code are the checker's: 0 only where the record is intact,
within its permissions, and checked against the passkey you named. It
names the recorder you expect (`--sealer`) from the recorder's own
folder, and says so; to name it yourself, from a fingerprint you noted
earlier, give `--sealer` too. The same check, with nothing of the
recorder's own:

```
npx provared-check ~/.provared/claude-code/book.jsonl --issuer <your passkey's thumbprint> --sealer <the recorder's fingerprint>
```

`status` prints the recorder's fingerprint; the signing page shows the
passkey's thumbprint when it signs.

## How it works

Claude Code can run a small program before and after each tool call (its
"hooks"). The hook here, `hook.mjs`, names the call as an action from the
format's shared list (`actions.mjs`), fingerprints the call's arguments,
and asks a small service on this computer, `recorder.mjs`, which holds
the stub writer open on one book:

- **Before the call** (PreToolUse): the check before acting says whether
  the action is within the permission. If not, the call is refused and
  Claude Code is told why, in the checker's words. If the recorder is not
  running, the call is refused too: no record, no action.
- **After the call** (PostToolUse): a receipt (a stub) is written, signed
  with the agent's two keys, naming the tool and the SHA-256 fingerprint
  of its arguments. If it cannot be written, Claude Code is told, so that
  the gap is known.
- **After a call that started and failed** (PostToolUseFailure): a stub
  is written too, because a failed call may have done part of its work.
  It names the tool as failed (`Bash (failed)`), and a second document,
  `error`: the SHA-256 of the error text Claude Code reported, as UTF-8,
  a broken character written as U+FFFD, so that no error text can keep
  the stub from being written.
- **Arguments that cannot be written in the one form of RFC 8785** (a
  number too large to hold, a broken character) are fingerprinted as
  JavaScript's `JSON.stringify` writes them, as UTF-8, except that a
  number too large to hold is written as it was sent (`1e400`, `-1e400`),
  bare, where no JSON value could stand, so that two such numbers are not
  written alike. The document's name says so: `Bash (arguments in the
  fallback form)`. The tool is always named, cut to 120 characters if it
  is longer.
- **If the hook itself fails** (input it cannot read, a library it cannot
  load, a fault in it), the call is refused before it is taken, and
  Claude Code is told after it. It waits up to 25 seconds for the
  recorder, within the hooks' own 30, and says "not written" only where
  the recorder refused the stub or was not there; where it gave up
  waiting, it says the stub is not confirmed. The recorder writes the
  stub of a call that was taken all the same, late, whether or not the
  hook still waits. Where the hook cannot even start, the
  hooks that `init` writes carry `"onFailure": "block"`, so that Claude
  Code refuses the call. Claude Code reads that setting from version
  2.1.295; an earlier version sets it aside, and then a hook that cannot
  start, or that runs past its time limit, lets the call go ahead
  unrecorded.
- **Seals:** whoever runs the agent seals the book when they choose
  (`seal`), with the recorder's three keys. This recorder names no
  outside time-stamp service.

How tool calls are named, by the hook and not by the agent:

| Tools | Action |
|---|---|
| Read, Grep, Glob, LS, NotebookRead | `provared.code.read` |
| Edit, Write, MultiEdit, NotebookEdit | `provared.code.change` |
| WebFetch, WebSearch | `provared.web.read` |
| Agent, Task, Workflow, SendMessage (starting another agent, or handing it a message) | `provared.agent.instruct` |
| Artifact (publishing a page on a server) | `provared.code.release` |
| Bash, PowerShell | `provared.code.run`, except: a command that removes something is `provared.data.delete`, and one that publishes is `provared.code.release`; where a command line does both, the deletion counts (see below) |
| AskUserQuestion, TodoWrite, TodoRead, ExitPlanMode, EnterPlanMode, Skill, ToolSearch, EndConversation | not recorded: they only talk to the person, or change what the model itself holds |
| Any other tool: those of MCP servers, and any tool not known here | `provared.code.run`, the widest name, so that a new tool is checked and recorded, never let through |

A command line is read three ways, and the strictest name any of them
finds counts, so that a later reading can only add to what an earlier one
found:

- As a shell reads it, roughly: quotation marks taken off (a quotation
  mark after `\` or `` ` `` is a plain character), comments left out, and
  split into simple commands at `;`, `&`, `|`, brackets, back-quotes,
  `$(` and line breaks, except that `>&`, `2>&1` and `&>` are
  redirections, and a word that is exactly `\;` or `{}` (as in
  `find -exec … {} \;`) is a plain word; a line that holds `\;` is also
  read with it as a break, as PowerShell and `cmd` read it, and the
  stricter name counts. A program is known by its name in any letter
  case, without its folder or its ending (`.exe`, `.cmd`, `.ps1`), after
  any `NAME=value` settings, redirections (`2>/dev/null`) and wrappers
  such as `sudo -u root`, `env -u X`, `timeout -s KILL 10` or `xargs`; a
  shell handed a command line (`bash -c` or `-lc`, `cmd /c`, also written
  `cmd /c"…"`, `powershell -Command`) has that line read the same way, as
  have the words of `eval`, `iex` and `Invoke-Expression`, the words
  `ssh` runs after its destination, the words after `watch` and
  `parallel`, and the command that `find -exec` runs; so has a value in
  quotation marks after `-c`, `--command`, `-Command` or `-ArgumentList`
  (`su -c "…"`, `script -qc "…"`, `Start-Process cmd -ArgumentList
  '/c …'`) or after `env -S`, unless it is handed to a program that only
  searches or shows text (`grep -c "rm -rf"` is a run), to `git`, to
  `ssh` or to an interpreter. Inside `"…"`, a quotation mark after `` ` ``
  is a plain character, as PowerShell reads it; and a line that holds
  `` ` `` before a quotation mark is also read as bash reads it (`` ` ``
  starts a command). This reading also finds a script's own calls that
  delete (`shutil.rmtree`, `os.remove`, `fs.rmSync`, `Path(…).unlink()`,
  `File.Delete` and the like) in a command line that runs an interpreter
  (Python, Node.js, Ruby, Perl, PHP, Deno, Bun, PowerShell), a script
  written into the line after it (`python - <<EOF`) included, and reads
  again the strings of a script that hands a command line to the system
  (`subprocess.run(['git', 'push'])`, `os.system`, `child_process`); a
  move to the null device (`mv x /dev/null`); and a file emptied by a
  redirection alone (`: > file`).
- In each simple command, every later word that names a known program
  or an interpreter is read as the start of a command, whatever stands
  before it: `docker exec c rm`, `wsl rm`, `python -m twine upload`,
  `npx npm publish`; and a later shell, `eval`, `ssh`, `watch` or
  `parallel` has its line read as above (`docker exec c sh -c "…"`). A
  word written as a program's path counts (`docker exec c /bin/rm`,
  `strace \rm`, `C:\Tools\rm.exe`), but not a word with `/` or `\` inside
  it (a path to a file, a web address, a `sed` expression). A word
  written in quotation marks counts only after a program that runs
  another one (`docker exec c "rm"`, `npx "npm"`, `python -m "twine"`),
  and not once a program that only searches or shows text stands after
  that one (`sudo grep -w "rm"`). The value of `-m` does not count after
  a program whose `-m` takes a message (`git`, `hg`, `svn`, `docker`,
  `npm` and a few more), nor the value of `--message`: so
  `git commit -m "Remove the rm calls"` is a run, and
  `nsenter -t 1 -m shred x` a deletion.
- With the patterns of this hook's first version, kept as they were, in
  the text outside quotation marks. So a word that names a deletion
  counts even where a shell would not run it (`echo rm`, `git clean -n`):
  the hook errs towards the stricter name, though not inside a quoted
  message, a path or a web address.

A recorder written in Python, elsewhere in this repository, reads a
command by the same rules, and the tests of both hold the same rows.

- Deletions: `rm`, `rmdir`, `rd`, `del`, `erase`, `ri`, `Remove-Item`,
  `Clear-Content`, `unlink`, `truncate`, `shred`; `find` with `-delete`
  or `-exec rm`; `npm unpublish` (and pnpm, yarn, bun); `gh repo delete`,
  `gh release delete`, `gh api` with the method DELETE; and in git, with
  any of git's own options before the command (`git -C dir`, `git -c
  name=value`): `rm` (not `--cached`); a push that is forced (`--force`, `-f`,
  `--force-with-lease`), deletes (`--delete`, `-d`, `:branch`), mirrors
  or prunes, or has a refspec starting with `+`, because each can take
  history away; `reset --hard`; `clean` (not `-n`); `branch` or `tag`
  with `-d`, `-D` or `--delete`; `stash drop` and `stash clear`;
  `checkout --force` or `checkout -- <paths>`; `restore` of the working
  files. And `DROP TABLE` or `DROP DATABASE` anywhere in the text;
  `DELETE FROM` given to a database client (`psql`, `mysql`, `sqlite3` and
  a few more); `redis-cli FLUSHALL` or `FLUSHDB`; `rsync --delete` (and
  its other deleting options); `cp /dev/null x`; `gem yank`, `cargo yank`,
  `dotnet nuget delete`.
- Releases: `git push` (with git's options before it, and `hub push`),
  `npm publish` (pnpm, yarn, bun; any options before `publish`), `twine
  upload`, `publish` given to `uv`, `poetry`, `cargo`, `hatch`, `flit`,
  `pdm`, `vsce` or `ovsx`, `gem push`, `helm push`, `dotnet nuget push`,
  `docker push`, `docker build` or `buildx` with `--push`, `gh release
  create`, `upload` or `edit`, `gh repo edit`, `gh pr create` and `gh pr
  merge`.
- Also read, one level down: each `$( … )` and `` `…` `` inside `"…"`
  (`echo "$(rm -rf x)"`), but not inside `'…'`, nested to any depth: a
  quotation mark inside a `$( … )` does not end the `"…"`
  (`echo "$(cd "/tmp"; rm -rf x)"`), nor does the `)` of a `case`
  pattern end the `$( … )` (`echo "$(case x in a) rm -rf y;; esac)"`), nor
  a `)` in a `#` comment there, and a `\$` or `` \` `` written in
  `"…"` is plain text (`grep -rn "\$(rm" docs`); what a command writes
  into a shell given nothing but options after a single `|`
  (`echo "rm -rf x" | sh`); a here-string (`bash <<< "…"`); and
  `-ArgumentList` written as a list (`"/c","del x"`).

This is a reading of the command's text, and it can always be got round:
a script that deletes in a way not listed here or from a file, a program
renamed or copied, a name built in a variable, an upload with `curl` or
`scp`. That is why the record says the kind of action is the hook's
reading of the call, not a fact about it. Known gaps, as of 16 October
2026: a command line in a file (`pwsh -File clean.ps1`, `sh script.sh`)
or in a variable (`x=rm; $x -rf y`); PowerShell's `-EncodedCommand`;
text piped into a shell that is also given a script or other words, or
from a file (`cat cmds.txt | sh`); a program's name written in escaped
quotation marks inside a quoted line (`bash -c "\"rm\" -rf x"`), because
`\"` inside `"…"` is not read as an escape, so that a Windows folder
written `"C:\x\"` ends its quotation where cmd ends it, and the same
holds for a quotation inside a `$( … )` (`echo "$(echo "\")\"" ; rm x)"`
is a run); SQL other than
`DROP` and `DELETE FROM` (`TRUNCATE TABLE`, `UPDATE`); publishing tools
not listed above; and a request that deletes or publishes through an
API, such as `curl -X DELETE`.

The stub holds the action, the time, the tool's name and the fingerprint
of its arguments: never the arguments themselves, and never a file's
contents. Whoever kept the transcript can show the arguments later, and
the fingerprint shows whether they are the ones the stub names.

## Where the record is kept, and keeping it safe

The recorder keeps everything in one folder, `~/.provared/claude-code`
(in your home folder) unless you name another: the agent's private keys
(`agent-keys.jwk`), the recorder's private keys (`recorder-keys.jwk`),
the permission it acts under (`slip.json`) and those before it, the list
of passkeys whose permissions it takes (`trusted-passkeys.json`), and
the book (`book.jsonl`). Never share the files that end in `.jwk`.
After each receipt the new lines are added to the end of the book: the
cost does not grow with the book, where the file is as the recorder left
it; where someone else changed it, the recorder compares the whole file
and writes its own book back.

**Anything that deletes that folder deletes the record with it**: an
agent that deletes your home folder takes the evidence of what it did
along with everything else. To keep the record on another disk:

- Name a folder there in the environment variable
  `PROVARED_CLAUDE_CODE_DIR` before you run `init`, so that Claude Code
  and the recorder both see it. On Windows:
  `setx PROVARED_CLAUDE_CODE_DIR "E:\provared\claude-code"`, then open a
  new terminal. On macOS or Linux, add
  `export PROVARED_CLAUDE_CODE_DIR=/Volumes/Other/provared/claude-code`
  (or a path on your other disk) to your shell's start-up file.
- Keep copies of the book somewhere else as well, on another disk or
  another computer. A book only grows, so a copy is a plain copy of
  `book.jsonl`, with the `slip*.json` files beside it.
- A seal shows only that the book was whole when it was sealed, by the
  recorder's own word, with keys kept in the same folder. It helps
  against a book cut short or rewritten only once its fingerprint is
  held somewhere else: written down, sent to someone, or time-stamped by
  an outside service. This recorder does not send seals anywhere.

## What the record shows, and what it does not

- It shows every tool call that went through the hook, in order, signed
  by the agent's keys, under the permissions the person signed, and
  whether each call was within them; failed calls included.
- It does not show a call that was refused before it was taken, by the
  hook, by the person at a permission prompt, or by Claude Code's own
  checks: a refused call leaves no entry, so the record does not show
  how often the agent was stopped.
- It does not show a call that did not go through the hook: a session
  run with hooks switched off, a hook that could not start (with Claude
  Code before 2.1.295), or another program on this computer that asked
  the recorder to write a stub. The record is of what this computer's
  agent did, as its own software says.
- **Nothing on the computer is out of the agent's reach.** The agent runs
  as you, and can run commands: any program on the computer, the agent
  included, can change the files in the recorder's folder (the list of
  trusted passkeys among them), ask the recorder to take a new permission
  with `--new-passkey`, stop it, or edit the settings that run the hooks.
  The list of trusted passkeys raises the bar; it does not close the
  gap. The evidence that holds is a checker that names your own passkey
  (`check --issuer`, or `provared-check --issuer`): a permission signed
  by any other passkey is then reported as a problem in the record.
  Where you do not want the agent able to switch the hooks off, put them
  in Claude Code's managed settings, which only an administrator can
  change, and set `"allowManagedHooksOnly": true` there, so that Claude
  Code runs only the hooks set there: `C:\Program Files\ClaudeCode\managed-settings.json`
  on Windows, `/Library/Application Support/ClaudeCode/managed-settings.json`
  on macOS, `/etc/claude-code/managed-settings.json` on Linux (Claude
  Code's documentation, "Deploy managed settings", read on 13 October
  2026). The recorder's own folder stays writable by the agent all the
  same.
- Calls asked at the same moment (Claude Code can run several tools side
  by side, and helper agents run in parallel) are each checked against
  the book as it stands, before any of them is recorded. Near a limit
  they can together go over it: with room for two runs, five asked at
  once are all allowed, and the book then shows the last three as
  outside the permission.
- Every stub is one-sided: there is no other party to countersign a tool
  call. The checker says so.
- The naming of a command (a deletion, a release, a run) is this hook's
  reading of its text. A command written to look harmless reads as a
  run.

## What `init` does to a settings file

`init` adds its hooks to `.claude/settings.local.json` beside whatever
is there and changes nothing else. It takes a hook for one of its own
only where the whole command is exactly the one it writes (`node`, the
warning switch, the script's path, and `ensure` for the start of a
session), written with `args` or as one command line: such a hook is not
added twice (where you gave it a longer time-out, that is kept), and an
earlier entry of it, under another matcher or in an earlier shape, is
replaced. Every other hook stays as it is, also one of yours that runs
this recorder's hook and then something more, saves its status to a
file, or runs a file whose name only begins like its own; `init` points
out each hook that names Provared and is not its own.
A file with a byte-order mark keeps it. A file that is not JSON is left
as it is, with a message. Where a settings file of the project says
`"disableAllHooks": true`, `init` says that no hook will run. The file is
read and written as JSON, so where `init` changes it, a whole number too
large for JavaScript to hold exactly, or a member given twice, is not
kept exactly as it was written.

## Working from a copy of the repository

The recorder names its library `provared`, as it is named when installed
from npm. To run it on the repository's own library instead, with
nothing installed:

```
node integrations/claude-code/tools/use-repository-library.mjs
node integrations/claude-code/recorder.mjs init
```

The first command writes `integrations/claude-code/node_modules/provared`
as a few small files that only point at the repository's `src/` and
`bin/`: nothing is linked or copied. The commands are then
`node integrations/claude-code/recorder.mjs <command>`.

The tests always run against the repository's own library, whatever
`node_modules` holds (`test/local-library.mjs`):

```
node --test "integrations/claude-code/test/*.test.mjs"
```

They make permissions with the library's development stand-in for a
passkey, start the recorder in temporary folders on free ports, and run
the hook as Claude Code would, with its JSON on standard input.

## Licences

Copyright 2026 Pavel Izmaylov. The code: Apache License 2.0
(`LICENSE`). This document: Creative Commons Attribution 4.0
International (`LICENSE-CC-BY-4.0.txt`).
