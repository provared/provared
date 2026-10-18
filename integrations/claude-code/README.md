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

## A new book at 90,000 entries

A book may hold at most 100,000 entries, and once it is full every tool
call would be refused. So when the book reaches 90,000 entries, the
recorder seals it, keeps it beside the new one as `book-1.jsonl` (then
`book-2.jsonl`, and so on, in the order kept, after the highest number
in the folder; the highest a kept book may have is 999,999,999, and where
the folder holds a book at that number, no new book is started and
`status` says why), and starts a new
`book.jsonl` that begins with the permission in force. It does the same
at 100 MB of text (100,000,000 bytes), whichever comes first: with
receipts of about 7 KB each, 90,000 of them would be about 630 MB, longer
than Node.js can hold as one text, and 100 MB stays under the size GitHub
takes as one file. While a new book cannot be started, the book in force
goes on growing past 100 MB and costs more with each receipt: on the
author's computer, at about 256 MB, about 120 thousandths of a second for
each receipt, about 1.5 GB of memory and over a minute to start, with
every call refused meanwhile; near 76,000 entries it no longer fits in
Node.js, and every call is refused. So check `status` when a new book is
due. To start a new book yourself, at any time:

```
provared-claude-code new-book
```

It works whether the recorder is running or not. Recording does not
stop: a call asked during the switch waits its turn, and a call allowed
under the old book and finished after the switch is recorded in the old
book, which is then sealed again after it (if the recorder stops before
that, the kept book is sealed when it next starts). A call whose receipt
never comes keeps the old book open for 15 minutes at most; a receipt
that comes later goes into the book in force, under the permission it
was allowed under where that book holds it, or else under the
permission in force. Each book checks on its own, with the same passkeys
and recorder named:

```
provared-claude-code check book-1.jsonl --issuer <your passkey's thumbprint>
```

The switch is three steps on disk, each whole: the seal is added to
`book.jsonl`; `book.jsonl` is renamed `book-<n>.jsonl`; a new
`book.jsonl` is written. If the recorder stops between the first two,
the book is as it was, with a seal (run `new-book` again; a book that
was full is switched at the next start); between the last two, there is
no `book.jsonl`, and the next start begins one with the permission in
`slip.json`, which completes the switch, even where that permission has
ended since (the recorder then starts, refuses every call, and `status`
and `seal` work). A switch took 1.9 seconds on a
book of 3,000 receipts (21 MB), measured on the author's computer, most
of it the seal's quantum-safe signature, and takes longer on a full
book; calls asked meanwhile wait, and one that waits longer than the
hook does (25 seconds) is refused, never let through unrecorded. Where the rename cannot be made
(on Windows, the file held open by a program that does not allow it, for
longer than the recorder waits), the recorder goes on with the book in
force, tries again a minute later, and `status` says why
(`newBookProblem`). Another program that follows `book.jsonl` (an
uploader) sees the file start again after a switch; one that reads the
books through the feed (below) goes on in the same book under its kept
name, and is told of the new one.

**The recorder enforces every limit across its books.** A new book
starts no limit again. The recorder keeps, for each permission, the time
and amount of every receipt in its kept books (those figures only, not
the books' text, read again from the kept files when it starts), and its
check before acting counts them, with the book in force and the calls
allowed and not yet recorded, for every limit of that permission: totals,
counts, and either within a period. So one release a day stays one
release a day, however many new books are started, by command or by
themselves, and across a restart. A new permission (a renewal) starts its
own counts, as it always has. The figures are read from the kept files as
they stand: a kept book changed by hand is not checked when the recorder
starts (a checker shows it). A kept book moved, renamed or removed while
the recorder is stopped is not counted at all, and nothing in the record
shows it (the record page points out a gap in the numbers of the kept
books, but not a missing last one); this is the same as moving
`book.jsonl` itself, which anyone who can write the folder could always
do.

Starting the recorder reads the book in force in full. With a book near
100 MB in force, that took about 25 seconds on the author's computer;
the recorder answers no call until it has read the book, so tool calls
asked meanwhile are refused, never let through unrecorded. A renewal of
a book near that size costs about the same: calls asked meanwhile wait,
and one that waits longer than the hook does (25 seconds) is refused.

**A checker given one book counts within that book only.** It has no
other book to count with. So around a switch the record shown to a
checker can hold, across two books, up to twice a limit within one
period, though the recorder held the agent to the limit; and a total for
the whole permission is split between the books. To see the whole, check
every book, and add up the receipts of the last of one book and the
first of the next.

Any program that can reach the recorder's port on this computer can
start a new book, as it can ask for a seal; since a new book starts no
limit again, this gains it nothing but another file.

## A feed of the books, for an uploader on this computer

Another program that wants the book's lines as they are written (the
Provared application's uploader, which sends them, sealed, to a server
that cannot read them) should ask the recorder, not open the book file.
On Windows a program that holds a file open can make another's writing
or renaming of it fail: on 11 October 2026 an uploader reading
`book.jsonl` made the recorder's rename of it fail, and seven receipts
were lost. So the recorder answers, on its own port, with the lines of
its books, to a reader that proves it holds the token in the recorder's
folder:

```
GET http://127.0.0.1:8794/hello            (opens a conversation)
GET http://127.0.0.1:8794/books
GET http://127.0.0.1:8794/lines?id=<identity>&from=<n>
```

- **The token, which never travels.** At its first start the recorder
  writes a token (32 random bytes) into its folder as `feed-token`,
  readable by your user alone on macOS and Linux (on Windows a file takes
  the rights of its folder: in your user folder, your user, the system
  and the computer's administrators; on another disk, see who may read
  the folder). A reader that holds it opens a conversation with
  `GET /hello`, sending a random number (`Provared-Feed-Hello`); the
  recorder answers with a random number of its own and HMAC-SHA-256,
  keyed by the token, over both: its proof that it knows the token. The
  reader trusts nothing it is told until that proof checks. Each question
  then carries the session, a random number used once and an HMAC over
  the question under a key both sides work out from the token and the two
  numbers (the reader's proof); each answer carries an HMAC under the
  same key over the question's number, the answer's code and every byte
  of the answer (the recorder's). Every proof is compared in constant
  time, and a question asked twice is refused. Each of these 32-byte
  values (the session, the reader's number, the number used once, each
  proof) is taken only in the one way it can be written in base64url, so
  none can be given again under another spelling of the same bytes. So a program on this
  computer that cannot read the folder cannot read the book through the
  feed, and one that listens on the recorder's port while the recorder is
  stopped learns nothing and is believed in nothing; one that can read
  the folder could read the book file anyway. **A hello keeps nothing:**
  the recorder's number for a conversation is worked out from the time of
  the hello, the reader's number and a secret only the running recorder
  holds, and the reader sends its number again with each question. A
  conversation is kept only from its first question that carries the
  reader's proof, which must come within 10 minutes of its hello; at most
  16 such conversations are kept (the one used longest ago gives way to a
  new proved one), each ended after 10 minutes unused or after 100,000
  questions, and one that has ended cannot be begun again. So a program
  without the token, however many hellos it asks for, cannot push out a
  conversation in use. What it can still do: keep the recorder busy
  answering its hellos and refusing its questions, at about a thousandth
  of a second each, which slows the hook's questions in proportion (on the
  author's computer, with 64 programs asking for hellos without pause,
  about 8,000 to 8,600 in all, the hook's two questions took 73 to 356
  thousandths of a second over two runs; every round of the uploader went
  through), and, while the recorder is
  stopped, listen on its port, where it learns nothing but makes the
  uploader stop and say so. A
  `feed-token` that holds no token is not replaced: the feed refuses
  every question and `status` says why (`feed.problem`); move the file
  out of the folder, and the recorder makes a new one at its next start.
  The application's uploader speaks this conversation; `feed.mjs` also
  gives one for other programs (`feedReader`).
- **`/books`** lists the books oldest first: the kept ones by number,
  then the one in force. Each has its name (`book-3.jsonl`,
  `book.jsonl`), its number, its size in bytes and its **identity**: the
  volume, the number the file system gives the file, and the file's
  creation time. A rename keeps all three, so the book in force keeps its
  identity when it is kept as `book-<n>.jsonl`, and a new `book.jsonl`
  has another, though it begins with the same permission line. Where the
  file system gives files no number, the identity is `null`, and a book
  is known by its name.
- **`/lines`** answers for one book, named by `id=<identity>`, or by
  `book=<name>`, or with neither for the book in force, from place `from`
  (0 for the first line): up to 500 lines (`max` asks for fewer, 0 for
  none), and at most 4 MiB of them but always one, with where each starts
  and ends in the file, in bytes; the line before place `from`, with its
  fingerprint (SHA-256, base64url) and where it is; the number of lines
  (`size`), the book's size in bytes, and the fingerprint of its last
  line. Lines are counted as the application's uploader and the checker
  count them: an empty line, and a carriage return before a line break,
  are set aside, and a line with no line break yet is not a line.
- **Waiting.** Where the book holds no line at `from` yet, the question
  waits up to 25 seconds (`wait`, 0 to 25) and is answered as soon as any
  book is written: a new receipt, a seal, a new book, or a late receipt
  and the seal again in a kept book. At most 8 questions wait at once; one
  more is answered at once with 429 ("ask again in a few seconds").
  Stopping the recorder answers every waiting question.
- The books the recorder holds open (the one in force, and a kept one
  that a call allowed under it may still come back to) are read from its
  own copy in memory, but only as far as it has written them to their
  files, so the feed answers even while another program holds
  `book.jsonl` open with no sharing, and never gives out a receipt whose
  save failed. A kept book it no longer writes is read from its file,
  4 MiB at a time, and the file is closed again between pieces.
- **Busy.** One answer is made at a time, with a pause between two so
  that the hook's questions are answered in between, and at most 16 are
  taken on at once; one more is answered at once with 429 ("ask again in
  a moment"). Measured on the author's computer with a book of 98 MB: the
  first question took about 110 thousandths of a second (the recorder
  finds where each line is, once), and reading the whole book through the
  feed 1.8 seconds. A hook's two questions (before and after a call) took
  a median of 61 thousandths of a second and at most 145 with no reader;
  a median of 160 and at most 266 with two readers reading the whole book
  again and again; a hook's question took 149 thousandths of a second
  with 300 feed questions at once, and 971 with 1,500 at once (the hook
  waits 25 seconds before it refuses the call). The hold-up is at most
  the making of one answer (about 150 thousandths of a second on that
  book) and the reading of the questions that arrive meanwhile, about a
  thousandth of a second each, refused or not. So very many at once do
  hold the hook up, in proportion: in the independent review, 6,000 at
  once from one holder of the token held a hook's question up for 5.3
  seconds, and about 25,000 at once would reach the 25 seconds after
  which the hook refuses the call.

The recorder never replaces `book.jsonl` because it could not read it:
where another program holds the file for a moment, the recorder waits up
to ten seconds to read and add to it, and replaces it only where it read
the file and found that it no longer holds the book's start (another
program changed it). Such a replacement gives the file a new identity,
and the uploader then stops and says so: that is a book to look at.
Where the file is held for longer than ten seconds, the receipt is signed
and held by the recorder, the hook says that it is not yet in the book
file, and the recorder writes it with the next save of that book; it is
lost only if the recorder stops before then. The feed gives it to no
reader until it is in the file.

The feed shows the book's lines, nothing more: whoever holds the token can
read the book, as whoever can read the folder always could. The recorder
still listens on 127.0.0.1 only; give its address as `127.0.0.1`, not
`localhost`, which may lead to another program on the computer's other
address.

## The commands

| Command | What it does |
|---|---|
| `init` | Make the keys if they are missing, write the hooks into this project's `.claude/settings.local.json`, and print the link to sign a permission |
| `use <file>` | Put a signed permission in place and start the recorder; where a book exists already, the same as `renew` |
| `renew <file>` | Take a new signed permission into the book, while the recorder runs or not; `--new-passkey` where you signed it with a passkey of yours that signed none before |
| `start` | Run the recorder in this terminal, and see what it says |
| `ensure` | Start the recorder in the background if it is not running (the hooks run this when a session starts) |
| `status` | What the recorder holds: the permission, until when, the number of entries, the calls allowed and not yet recorded (`callsNotYetRecorded`), the books kept (`keptBooks`), when a new one is started (`newBookAt`), and the feed's token file and how many questions wait (`feed`) |
| `seal` | Seal the book now, with the recorder's three keys |
| `new-book` | Seal the book, keep it as `book-<n>.jsonl`, and start a new one that begins with the permission in force (done by itself at 90,000 entries, or at 100 MB of text) |
| `check [file]` | The checker's answer for the book, or, given a name such as `book-1.jsonl`, for a book kept before it. Name your passkey with `--issuer <its thumbprint>`, once for each passkey of yours; without it, `check` lists the passkeys the book's permissions name, as read from the book, and the checker takes none of them as one you trust |
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
  the gap is known; if it was signed and could not yet be written to the
  book file (the file held by another program for longer than ten
  seconds), Claude Code is told that, and the recorder writes it with its
  next save.
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
of passkeys whose permissions it takes (`trusted-passkeys.json`), the
book (`book.jsonl`), the books kept before it (`book-1.jsonl` and
so on), and the token of its feed (`feed-token`, below). Never share the
files that end in `.jwk`, nor `feed-token`.
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
  `book.jsonl`, with the `slip*.json` files and the kept `book-*.jsonl`
  beside it.
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
  the book as it stands, and against the calls already allowed and not
  yet recorded: where the permission limits how many of an action may be
  taken, a call is allowed only while the receipts of that action in the
  period, the calls of that action allowed and not yet recorded, and
  this one fit. With room for two runs, of five asked at once two are
  allowed and three refused. A call allowed and not yet recorded counts
  for 15 minutes at most, so that one refused at the person's prompt
  after the hook allowed it, which never comes back for its receipt,
  does not hold the count for ever; a call that runs longer than that
  (a long command, a helper agent) stops counting after it, and calls
  asked then can together go over a limit, as the book then shows. The
  calls allowed and not yet recorded are held in the recorder's memory
  only: a restart of the recorder forgets them, so calls asked just
  after a restart can, with those still running, go over a limit, as
  the book then shows. Only calls that Claude Code names (`tool_use_id`)
  are counted, and only limits on how many may be taken, not limits on
  an amount (the hook gives no amount). A call is still recorded under
  the permission it was allowed under however long it ran, within one
  book (see "A new book at 90,000 entries" for a call that outlasts a
  switch).
- The recorder enforces every limit across its books, but a checker
  given one book counts within that book only (see "A new book at 90,000
  entries"): around a new book, the record a checker is shown can hold up
  to twice a limit within one period across two books, though the agent
  was held to the limit. A kept book moved, renamed or removed while the
  recorder is stopped is not counted, and nothing in the record shows it,
  as with `book.jsonl` itself.
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
