# <img src="https://prova.red/favicon.svg" alt="" width="36"> Provared beside Claude Code

A coding agent, Claude Code, recorded by Provared: every tool call it
makes is checked against a permission the person signed with a passkey,
refused if it is outside it, and receipted if it is taken. The result is
a book that anyone can check with the free checker.

*Evidence, not a verdict.*

## From nothing to a recorded session

A few commands and one step with your passkey. It needs Node.js 24.7 or
later. To have Claude Code install it, with its hooks, see "Install as a
Claude Code plugin" below.

```
git clone https://github.com/provared/provared.git
cd provared/integrations/claude-code
npm pack
npm install -g provared-claude-code-0.1.0.tgz
cd your-project
provared-claude-code init
```

This package is not yet on npm, so the first four lines install it from
a copy of the repository; `npm pack` makes the package as npm would, so
that its one dependency, `provared`, is installed with it. Once it is
published, they become `npm install -g provared-claude-code`.

`init` makes the agent's keys, writes the hooks into the project's
`.claude/settings.local.json` (next to anything already there), and
prints a link and **the fingerprint of the agent's key set** (`keys`
prints it too). **Open the link in a browser:** the signing page
opens with a starting permission for this agent filled in. (The link
begins `https://sign.prova.red/`, the signing page's own address since
25 October 2026; a link printed by an earlier version begins
`https://prova.red/sign/`, which now says so: open the same link with that
part replaced by `https://sign.prova.red/`.)
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

## Install as a Claude Code plugin

The recorder is also a Claude Code plugin, which brings its hooks with
it: nothing is written into a project's settings. It needs Node.js 24.7
or later, and npm, which comes with Node.js, on the computer's path. In
Claude Code:

```
/plugin marketplace add provared/provared
/plugin install provared-recorder@provared
```

From a terminal, the same is `claude plugin marketplace add
provared/provared` and `claude plugin install provared-recorder@provared`.
Adding the marketplace downloads a copy of this repository (about 60 MB);
`claude plugin marketplace add provared/provared --sparse .claude-plugin
integrations/claude-code` downloads only the two folders the plugin uses.

Claude Code copies this folder into its plugin cache
(`~/.claude/plugins/cache/provared/provared-recorder/0.1.0/`). The library
`provared` comes separately:

- Some versions of Claude Code install it beside the plugin, from
  `package-lock.json`; others do not (version 2.1.167 did not, for a plugin
  fetched from a git repository). Where it is there, it is used.
- Where it is not, the plugin installs it itself the first time a session
  starts (or at the first command you run): `npm ci --ignore-scripts` from
  the same `package-lock.json`, so exactly version 0.6.0, checked against
  the fingerprint the lockfile holds, with no install script run, into the
  plugin's data folder (`~/.claude/plugins/data/provared-recorder-provared/`),
  which Claude Code keeps across updates. That needs the npm registry
  once, and takes a few seconds.
- The library is loaded from one of those two places only, by its exact
  path, never from a folder above the plugin (such as your home folder),
  where an unrelated copy could be.
- If it cannot be installed (no npm, no network), the session says so, every
  tool call is refused, and each refusal gives the one command that mends
  it: `node <the plugin's folder>/plugin.mjs install-library`.

A plugin is installed for you in every project unless you say otherwise
(the scope "user"). From then on every tool call, in every session, is
refused until you have signed a permission: no record, no action. To
record one project only, install it from that project's folder with
`claude plugin install provared-recorder@provared --scope local`, or
choose that scope in `/plugin`.

The first session after installing says what to do, and so does each
call it refuses:

1. In a terminal: `node <the plugin's folder>/plugin.mjs init`. Claude
   Code's message gives the whole path. `init` makes the agent's keys and
   prints a link to https://sign.prova.red/ with the fingerprint of the
   agent's key set; run through the plugin, it writes no hooks.
2. Open the link, write your name, read the permission, compare the
   fingerprint with the one `init` printed, sign with your passkey, and
   save the file the page gives you.
3. `node <the plugin's folder>/plugin.mjs use <the saved file>`

Nothing signs for you. From then on each tool call is checked and
recorded, as with the hooks `init` writes. The other commands (`check`,
`seal`, `status`, `renew` and the rest) run the same way:
`node <the plugin's folder>/plugin.mjs <command>`. `plugin.mjs` is the
plugin's entry: it finds the library as above, then runs the recorder's
own command. A copy installed from npm (`provared-claude-code <command>`)
does the same: both use the folder `~/.provared/claude-code`.

What the plugin brings (`hooks/hooks.json`): the hooks `init` writes,
before, after, and after a failed call, for every tool, with
`"onFailure": "block"`, each run through `plugin.mjs`; and, when a
session starts, `session-start`, which installs the library if it is
missing, starts the recorder as `ensure` does and, where something stands
in the way (no library, no permission yet, a recorder that does not start
or is still starting, or the recorder's hooks in force twice), tells you
and Claude, so that the refusals that follow are not taken for a fault.
Where all is well it says nothing. It keeps within 27 seconds, inside the
hook's 30.

The record is not kept in the plugin's folder: it stays in
`~/.provared/claude-code` (or the folder `PROVARED_CLAUDE_CODE_DIR`
names), so updating or uninstalling the plugin leaves the books, the
permissions and the keys as they are. Uninstalling removes the plugin's
data folder, and with it the copy of the library; a later install fetches
it again.

**Updates.** The plugin's version is the one in
`.claude-plugin/plugin.json`, the same as the npm package's, so Claude
Code offers an update only when that version changes
(`claude plugin update provared-recorder@provared`, or `/plugin`). A
recorder already running keeps the code it started with until it is
stopped and started again (`stop`, then `ensure`), and the commands
printed before an update name the folder of the version before it.

**Not twice.** Claude Code runs a plugin's hook and the same hook in a
settings file side by side. Where the recorder's hooks are both in a
settings file (written by `init`, or by hand) and brought by the plugin,
each call would be asked about, and recorded, twice. So before each call
the plugin's hook looks in your own settings (`~/.claude/settings.json`,
or the folder `CLAUDE_CONFIG_DIR` names) and the project's
(`.claude/settings.json` and `.claude/settings.local.json`), in the hooks
before, after, and after a failed call, for a hook whose command names a
recorder's `hook.mjs`. It recognises these forms, and only these:

- a word of the command (or of its `args`) that is a path to a file
  `hook.mjs` with `recorder.mjs` and `actions.mjs` beside it, written
  whole or relative to the project's folder;
- with the project's folder written as `${CLAUDE_PROJECT_DIR}`,
  `$CLAUDE_PROJECT_DIR`, `%CLAUDE_PROJECT_DIR%` or
  `$env:CLAUDE_PROJECT_DIR`, and the home folder as `~` at the start of
  the word, `$HOME`, `${HOME}`, `%USERPROFILE%` or `$env:USERPROFILE`;
- with parts of one word in quotation marks, which are joined to the rest
  of the word as a shell joins them (`node "$CLAUDE_PROJECT_DIR"/x/hook.mjs`);
- a path to a `hook.mjs` that is no longer there, where the path names
  Provared (a copy since deleted or moved, whose hook still runs, and
  fails, at every call).

A hook that reaches the recorder in any other way (a script of your own
that calls it, a variable of your own, an organisation's managed
settings) is not recognised, and each call is then asked about and
recorded twice. Where it finds one, it refuses the call and says how to
take one of the two out:

- `remove-hooks`, run in the project's folder, takes out of
  `.claude/settings.local.json` the hooks that `init` wrote, from any copy
  of this recorder, and nothing else there (not a hook of yours that runs
  the recorder's hook and something more). It writes the file anew as JSON
  indented by two spaces, so other formatting in it is not kept; it writes
  a new file that then takes the old one's place, and leaves the file as
  it is where it changed while being read;
- or turn the plugin off (`/plugin`, or
  `claude plugin disable provared-recorder@provared`).

Then start Claude Code again: it reads hooks when a session starts.
Refusing is chosen over stepping aside: a refused call costs a moment,
while a call that neither recorded, where the other hooks were not in
fact in force, would leave a gap. While both are in force, the other hook
may already have asked the recorder about a call that the plugin then
refuses; that call holds a place against the permission's limits for up
to 15 minutes, as an allowed call that was never recorded does. After a
call has been taken, the plugin records it whatever it finds, since two
receipts for one call show in the record and a missing one would not.

So that it always answers in time, the plugin looks only so far: a
settings file larger than 1 MB is not read, at most 20,000 words of hooks
are looked at, for at most 2 seconds. Past any of these, the call is
refused, and the message says which. And the hook waits for the recorder
for at most 25 seconds from its own start, whatever came before.

`init` run through the plugin (or from a copy in Claude Code's plugin
cache) writes no hooks, and `init --no-hooks` does the same from any copy;
`init` run from another copy, where the plugin is installed, writes them
and warns. Which copy is the plugin's is read from Claude Code's plugins
folder, `~/.claude/plugins` (or the folders `CLAUDE_CONFIG_DIR` and
`CLAUDE_CODE_PLUGIN_CACHE_DIR` name): where the terminal names other
folders than Claude Code was started with, run `init` through
`plugin.mjs`, or give `--no-hooks`.

**What turns it off.** The plugin records only while Claude Code loads it:

- A settings file that sets `"enabledPlugins": {"provared-recorder@provared": false}`
  turns it off from the next session. That includes the project's own
  `.claude/settings.json` and `.claude/settings.local.json`, which the
  agent can write, as it can any file in the project; the record then
  shows no receipts from that session on, not a refusal.
- Where an organisation's managed settings set `allowManagedHooksOnly`,
  Claude Code runs no plugin's hooks unless those settings turn the plugin
  on themselves.
- `"disableAllHooks": true` in a settings file turns off every hook.

**Versions of Claude Code.** As with `init`'s hooks, Claude Code before
version 2.1.295 sets `"onFailure": "block"` aside (see "How it works"): a
hook that fails or runs out of time then lets the call through. The
plugin was tried with 2.1.167. The documents read on 31 October 2026 name
no first version for plugin hooks, `${CLAUDE_PLUGIN_ROOT}`,
`${CLAUDE_PLUGIN_DATA}` or hooks written with `args`; where Claude Code
names no data folder, the plugin works out the one it uses from where its
copy is.

The marketplace file is at the top of the repository
(`.claude-plugin/marketplace.json`), because
`/plugin marketplace add provared/provared` looks for it there; the plugin
itself is this folder.

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
name both passkeys.

Once you sign with a new passkey (say, one made at sign.prova.red, a
name that serves nothing else), retire the old one:
`retire-passkey <its thumbprint>`. A retired passkey stays on the list,
so the permissions it signed stand in the record, the recorder still
starts on the books that hold them, and still counts limits across those
books; but a new permission from it is refused, whether or not
`--new-passkey` is given, until `admit-passkey <its thumbprint>`. The
command takes effect at once, while the recorder runs or not. The file
holds both lists (`passkeys`, and among them `retired`); a file written
by an earlier version has no `retired`, and retires none. If a command
changes the list while a renewal adds a passkey, both changes are kept:
the file is read again just before it is written, and no passkey is
ever taken off it. A narrow window remains between that reading and the
renaming of the new file into place, since no lock is held. A list that
would hold no passkey is never written.

Retirement stops new permissions; it does not stop a program that can
change the recorder's files. At start-up, only the permission last in
force escapes the checks: the last permission line of `book.jsonl`, or,
where the recorder starts with no `book.jsonl` (a switch to a new book
that a stop interrupted), the last permission line of the last kept
book. That one is taken without the checks, so that a permission that
has ended since does not stop the recorder from starting. Any other
permission put in `slip.json`, even one that `book.jsonl` or a kept book
holds further up, is checked, a retired passkey's among them, and is
refused if its passkey was retired. So what remains: a program on this
computer that puts back the permission last in force (in `slip.json`,
after removing `book.jsonl` where it was last in force in the kept book)
can resume it, even if its passkey was retired afterwards; and so can
one that adds a permission's line at the end of either book. This raises the bar; it does not close the gap: see "What
the record shows, and what it does not".

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
never comes keeps the old book open for 15 minutes at most, and only
until the new book is first sealed (see "Each book follows on from the
one before", below); a receipt
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

### Each book follows on from the one before

A seal may say which book it is of (the format description, section
21.6). The recorder numbers its books in one sequence for each person and
agent, as a witness knows them (below):

- The first seal of a new book gives the book's number (`book`: 2, 3 and
  so on) and names, as the seal before it, the last seal of the book
  before. Its later seals give the same number, and each names the seal
  before it, as always. The first book gives no number, so every seal
  written before (the record so far included) reads exactly as it did,
  and a book whose seals give no number goes on giving none.
- "The book before" is the latest kept book whose first line is a
  permission from the same passkey, for the same agent, sealed with this
  recorder's keys, as a witness knows a sequence: the recorder reads it
  from the kept files, so the numbers hold across a restart. A book that
  begins with a permission from another passkey (one taken with
  `--new-passkey`) begins a sequence of its own, with no number and no
  seal before it; a later book that begins with the first passkey's
  permission again follows the last book of that passkey.
  Where a kept book cannot be read when the book in force is first
  sealed (another program holds it for longer than ten seconds), no seal
  is made, rather than one with a number that may be wrong; `seal` says
  why, and works again once the file can be read.
- So the number in a kept book's file name (`book-3.jsonl`) is the order
  in which the books were kept, and the number in its seals is its place
  in its sequence. The two can differ.
- Before the book in force is first sealed, every kept book that a call
  allowed under it could still come back to is closed, and sealed again
  where something came after its seal: the seal the new book names is
  then the last seal of its book, and no seal is added to that book
  after it. A call that comes back for such a book later is recorded in
  the book in force, as after 15 minutes.
- A book is kept as `book-<n>.jsonl` only once it is made sure to be on
  the disk: the next book's first seal will name its last seal, and a
  witness may be shown it. Where that cannot be done, no new book is
  started yet, and the recorder tries again a minute later.

A checker of one book cannot see the seal that the book's first seal
names, and says so. To compare the two, check the book before with that
seal handed over beside it (`--seal`), as the format description,
section 21.6, sets out. A checker of the library's version 0.5.0 or
earlier refuses a seal that gives a number: see "The library this needs".

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

## Witnesses for the seals

A seal fixes everything before it, but whoever keeps a book can show a
second, different history to someone else, sealed with the same keys,
and a reader who holds one copy cannot see the other. A **witness** is a
program with keys of its own (Ed25519 and ML-DSA-87) that keeps, for each
recorder, person and agent, the latest seal it has signed for, and signs
a short statement for a new seal only where the new seal extends that
one: in the same book, by a consistency proof (RFC 9162, section
2.1.4), or as the first seal of the next book (the format description,
section 29). The package has one, `provared-witness`, which runs as a
small service on this computer.

### Setting one up

```
provared-claude-code status
provared-witness init --recorder <the "sealer" that status printed>
provared-witness start --ready
provared-claude-code add-witness http://127.0.0.1:8796 <the fingerprint init printed> ~/.provared/witness/witness-token
```

- `init` makes, in the witness's folder (`~/.provared/witness`, or the
  folder `PROVARED_WITNESS_DIR` names), its keys, two tokens (one for the
  recorders it serves, one for its operator's commands) and an empty
  journal, and names the recorders it serves, by the fingerprint of each
  one's key set; it prints the fingerprint of its own key set. Run it
  again to name more recorders; start the witness again for a change to
  take effect. To start a new witness in a folder that held one, move
  all of these out of it together first: `witness-keys.jwk`,
  `journal.jsonl`, `state.json`, `checkpoint.json` and
  `journal-mark.json` (each that is there). Left behind, any one of them
  would give the new witness what the old one kept; `init` refuses to
  make new keys while any of the last four is there. The tokens and
  `witness.json` may stay; give the recorders the new witness with
  `add-witness`.
- `start` runs it in that terminal, on 127.0.0.1, port 8796 (`--port`, or
  `PROVARED_WITNESS_PORT`, for another). At every start, the first
  included, it signs nothing until you say that its folder was not put
  back to an older copy: `--ready` says so as it starts, and
  `provared-witness ready` says so later (see "Keeping a witness sound").
- `add-witness` checks that the witness answers there, proves that it
  holds the token, and signs with the key set named, and then writes it
  into the recorder's `witnesses.json` with its token (at most four
  witnesses: a seal's line holds at most four statements). One that does
  not answer at that moment is named all the same, with a warning; one
  that signs with another key set, or cannot prove that it holds the
  token, is not. `remove-witness <fingerprint>` takes one out. A running
  recorder reads the list each time; nothing needs restarting.
- Whoever checks the book names the witness they trust by its
  fingerprint: `--witness <fingerprint>`.

### What the recorder does with them

- **After each seal**, it asks each witness what it holds and whether it
  signs now, and shows a witness that does the seals it has not signed
  for, in order, each with its proof (as RFC 9162 sets out, made from the
  book's line fingerprints, which the recorder keeps as the book grows,
  so that no proof reads the book again) and the book's first line. A
  witness that holds no seal of this recorder, person and agent is shown
  the latest seal only: a witness signs whatever it is first shown. A
  witness that does not sign now is shown nothing, and no proof is made
  for it. The line fingerprints of a book are kept while the recorder
  holds that book, and of two kept books at most, which are worked out
  again from their files when needed. A kept book's are worked out again
  whenever its file's size, modification or change time, or identity
  changes; a book the recorder holds is its own copy, which only grows.
  On this computer's file system (NTFS) the change time was seen not to
  move for a change made within a moment of the one before, so a kept
  book changed at once after it was last written may not be seen. That
  can only hold witnessing up: a witness checks every proof, and refuses
  a wrong one.
- **Only seals whose line is made sure to be on the disk** (fsync) are
  shown, so that a witness never signs for a seal that a stop could
  leave out of the book: such a witness would refuse every later seal.
  The seal that `seal` makes is the one exception, so that its
  statements can stand on its own line: the recorder first keeps the
  seal's entry apart, on the disk (`pending-seal.json`), then asks the
  witnesses, waits up to five seconds, writes the seal's line with the
  statements that came, and makes sure it is on the disk. If it stops
  before the line is written, it writes the seal at its place at the
  next start, before anything else is added to the book, or lets the
  file go where its line is in the book already, or in a book kept since.
  Where the book no longer ends where the seal begins, or the seal does
  not cover the entries it holds (it was changed while the recorder was
  stopped), nothing is written: the file is kept as
  `pending-seal-not-placed-<time>.json`, and `status` says so. One seal
  is kept apart at a time: while the line of one is not yet known to be
  on the disk, the next seal is not held for the witnesses.
- **No tool call waits for a witness.** `seal` waits only while no other
  request waits: a tool call that arrives ends the wait at once, and the
  seal's line is written without the statements still to come. A seal
  made at a new book, after a late call, or when the recorder starts, is
  not waited for at all. A tool call does wait for the seal's own work,
  which is not a wait for a witness: a call that arrives while a seal is
  being made waits until the seal is written, about 3.2 seconds on a
  book near 90 MB, the same with no witness named. Once the seal is
  written, the check before a tool call took at most 51 thousandths of a
  second on a book of 92 MB.
- **A statement is taken only where the library's own checker passes
  it** for that seal, as signed by the witness named; one that does not
  is never written, on a line or beside the book. One that comes after
  the seal's line was written is kept beside the book, in the folder
  `witnessed`, one file for each seal (`<the seal's fingerprint>.json`),
  in the form the checker takes beside a book with `--seal`.
- **`check` hands them over**: for the book checked, the files of the
  seals that stand in that book (the latest 64, the most a checker
  takes), and the witnesses in `witnesses.json`, named as trusted
  (`--witness`); it says so. The checker can take a late statement only
  with a copy of its seal, which it calls a seal "held elsewhere": these
  are not, they are copies of the book's own seals from the recorder's
  folder, which the agent can write, and they cannot show the book cut
  short. `check` says so plainly, before and after the checker's answer.
  For that, hand over a seal you hold yourself, apart from this computer.
  Give `--seal` or `--witness` yourself to name your own instead. With the checker alone:
  `npx provared-check book.jsonl --issuer <thumbprint> --sealer <fingerprint> --witness <fingerprint> --seal ~/.provared/claude-code/witnessed/<seal>.json`.
- **A witness that is down, refuses, or hands back what does not pass
  never stops recording.** `status` shows, for each witness, the seal it
  holds, whether that is the latest on the disk (`upToDate`), and, where
  it is behind, why (`problem`: a code and plain words, such as
  `unreachable`, `witness-not-ready`, `recorder-not-served` or
  `witness-invalid`). The recorder asks again after each seal, and every
  minute while a witness is behind (a witness that is not ready, or
  stopped, is asked only what it holds). One code is worth looking at at
  once: `witness-holds-another`, a witness that holds a seal of this
  recorder, person and agent that is in none of the recorder's books. No
  seal is sent to it; it is asked what it holds each minute. A book was
  moved, cut short or replaced, or the witness was shown another history.
  `witness-stopped` is a witness that could not save what it holds: it
  gives out nothing until it is started again.
- **The record page** (`tools/make-record-page.mjs`) checks each book
  with the checker as before: the statements on seals' lines are read,
  and shown as not counted, since the page names no witness; the
  statements kept beside the book are not handed over.

### The witness's commands

| Command | What it does |
|---|---|
| `init [--name <label>] [--recorder <fingerprint>]... [--port <n>]` | Make the witness's keys, tokens and journal where they are missing, and name the recorders it serves |
| `start [--ready] [--port <n>]` | Run the witness in this terminal. `--ready` is your word, at this start, that its folder was not put back to an older copy |
| `status` | What the running witness holds: whether it is ready, each sequence it holds (the recorder, the passkey, the agent, the book, the number of entries and the seal), its journal, its limits |
| `ready` | Tell the running witness that its folder was not put back to an older copy: at every start, the first included, it signs nothing until you do |
| `update <book> [--seal <file>]...` | Hand the running witness, from a copy, the statements it signed for the seals of a book (on their lines, and in files handed over beside it): it takes, in order, those later than what it holds |
| `forget <sequence>` | Stop holding a sequence (`status` names each by its fingerprint). The witness then signs, for that recorder, person and agent, whatever seal it is next shown, a second history too: forget only a sequence that no recorder you serve still uses, such as one a recorder filled the witness with |
| `stop` | Stop the running witness |

`status`, `ready`, `update`, `forget` and `stop` prove that they hold the
operator's token, `operator-token` in the witness's folder. Never give
that file, nor `witness-keys.jwk`, to anyone; give `witness-token` to the
recorders it serves, and to nothing else.

### Keeping a witness sound

- **It saves before it gives anything out.** For each new statement it
  adds a line to its journal (`journal.jsonl`) and replaces its state
  (`state.json`) and its journal mark (`journal-mark.json`: how many
  journal lines it has saved, kept apart from the state), each made
  sure to be on the disk, and only then gives
  the statement out. What it says it holds (to a recorder, and in
  `status`) is what it last saved, never what it holds in memory. If
  anything cannot be saved (a full disk, or the journal held by another
  program for longer than ten seconds), it gives out nothing more, by any
  route, and cannot be told `ready`, until it is started again; started
  again, it holds what is on the disk. The same seal asked for again gets
  the same statement, and adds nothing.
- **Its journal stays small.** Every 256 lines (`journalLines`) it writes
  a checkpoint (`checkpoint.json`: the latest seal of each sequence, with
  its statement, which is all it needs to refuse a fork) and begins the
  journal again; the earlier lines are dropped. A start reads the journal
  a line at a time, and reads in full only the lines its state does not
  yet reflect.
- **At every start, the first included, it signs nothing until you say
  so.** It first takes again every journal line its saved state does not
  yet reflect, then answers every request to sign with
  `witness-not-ready` until you run `provared-witness ready` (or started
  it with `--ready`). It cannot tell by itself whether its folder was put
  back to an older copy, journal and all, even a copy taken before its
  first statement: **that is your word.** A witness put back, and
  told it is up to date, can be made to sign a fork. Before you say so,
  you can hand it what a recorder holds:
  `provared-witness update <the recorder's book> --seal <each file in its witnessed folder>`.
  A witness on a computer that restarts without you there stays
  unready until you come; `start --ready` in a start-up script is your
  word given in advance.
- **It refuses to start where something is missing or changed**: a
  journal that has gone while the keys are there (it would have
  forgotten every seal it signed for; to start a new witness instead,
  move out the files named under "Setting one up", all together), a
  journal line that is not one it
  writes, lines numbered out of order, a state that reflects more lines
  than the journal holds, a journal that follows a checkpoint it does not
  have, a journal that holds lines of two segments, a line longer than
  any it writes, and a journal mark that says more lines were saved than
  the journal holds (so a journal emptied or cut short is seen even where
  `state.json` is lost). A last journal line cut off in the middle, by a
  stop while it was written, was never answered and nothing of it was
  given out: it is taken off, and `status` says so. A lost `state.json`
  is rebuilt from the checkpoint and the journal; a stop between the
  steps of a checkpoint is mended at the next start. **What this needs:**
  with both `state.json` and `journal-mark.json` lost (or a witness made
  before the mark was kept), a journal emptied or cut short is not seen:
  the witness starts from its checkpoint, or from nothing, holding an
  older seal, and once told it is ready it can be made to sign a fork,
  as a folder put back to an older copy can. Keep the two files as
  safely as the journal, and never move them out together.
- **One witness at a time on a folder**: two would each hold, in memory,
  what they signed, and could sign a fork between them. The lock is
  `witness.lock`; one left by a process that has ended is taken over,
  under a second file (`witness.lock.takeover`) that only one start can
  make, so two starts that find the same stale lock cannot both take it.
  (On Windows a process number can be given to another program later:
  where the witness then says another runs and none does, move the lock
  out of the folder.)
- **Its limits**, each in `witness.json`: at most 120 new statements in
  any hour, shared by every recorder it serves (`statementsPerHour`), at
  most 64 sequences held (`maxSequences`), a checkpoint every 256 journal
  lines (`journalLines`), at most 8 questions that sign taken on at once,
  a body of at most 1 MiB, a conversation of one question. Past a limit
  it answers 429 or 503 and signs nothing. A journal line is about 70 KB
  (the seal, the statement and the book's first line), so the journal
  stays under about 18 MB, and the state and checkpoint under about 5 MB.
- **A new sequence starts only from a permission that passes the
  library's check**, its passkey's signature included.

### What a witness protects, and what it does not

It protects, where the person checking names the witness, the passkey
and the recorder (the format description, section 29.4):

- A second history of the entries before a witnessed seal, sealed by the
  same recorder and starting from any permission that passkey gave the
  same agent, needs that witness to sign for it too, and it does not.
  That holds across the books of that person and agent: a new book
  cannot start from an earlier seal than the latest the witness holds.
  Two witnesses need two to fail.
- With the latest seal a witness holds (its `status` names it), handed
  over beside the book it is of, the end of that book cannot be cut off
  back to before that seal unnoticed.

It does not protect:

- **Against anything the agent can reach.** The agent runs as you. Under
  your own user account it can read the recorder's keys and sign seals
  of its own, read the witness's folder and use its keys or its tokens,
  stop it, put its folder back, or tell it that it is up to date. A
  witness under the same account as the agent shows only that the
  recorder's own side kept to the rules. For it to mean more, run it
  under another user account (the recorder then holds only its token,
  which lets it ask for statements that follow the rules), on another
  computer reached through a tunnel to a port here, or have someone else
  run it. A witness on another computer, reached directly over a
  network, is not built yet.
- **Against a holder of the token reading what it holds, or filling
  it.** One token serves every recorder the witness serves: each can ask
  it to sign for its own seals, and can read what it holds for any
  sequence. A recorder it serves (and the agent, which can act as one on
  the same computer) can fill its 64 sequences with permissions signed by
  passkeys of its own, and use up the 120 statements an hour that all
  recorders share; `forget` frees a sequence, at the cost said above. The
  operator's token is apart.
- **What travels is not encrypted.** No token ever travels, and every
  question and answer is proved with HMAC-SHA-256 (RFC 2104), but the
  seal, the proof and the book's first line (your permission: your
  passkey's public key, the name you typed, the agent's keys, its
  actions, limits and purpose) can be read by a program that watches the
  connection on this computer.
- **What is never shown to it**: a book, or the end of a book after the
  latest seal it signed for. A history sealed with other recorder keys,
  or that starts from a permission for another agent or from another
  passkey, is another sequence to it.
- **Time, or the truth of the entries**: a statement's time is the
  witness's own word, and it sees fingerprints, not entries.
- **Limits across books**, and a book that repeats or leaves out what an
  earlier book holds: each book is checked on its own.
- **A book that holds a permission from another passkey, or for another
  agent, than its first line**: a checker counts no statement for it (a
  renewal by the same passkey is fine). After a renewal with
  `--new-passkey`, the book in force holds both, so its seals are not
  counted as witnessed; the next book begins a sequence of its own.

### The library this needs

Numbered seals and witness statements need version 0.6.0 or later of
the library: a checker of version 0.5.0 or earlier refuses a seal that
gives a book number and a seal's line that holds statements. So the
package depends on `provared` 0.6.0 or later. Anyone who checks a book
that this recorder has numbered, or that holds statements, needs that
version too (`npx provared-check` takes the latest).

## The commands

| Command | What it does |
|---|---|
| `init` | Make the keys if they are missing, write the hooks into this project's `.claude/settings.local.json`, and print the link to sign a permission; with `--no-hooks`, or run from the Claude Code plugin's folder, write no hooks |
| `use <file>` | Put a signed permission in place and start the recorder; where a book exists already, the same as `renew` |
| `renew <file>` | Take a new signed permission into the book, while the recorder runs or not; `--new-passkey` where you signed it with a passkey of yours that signed none before |
| `retire-passkey <thumbprint>` | Take no new permission from that passkey, with or without `--new-passkey`; what it signed stands, and limits are still counted across the books it signed |
| `admit-passkey <thumbprint>` | Take new permissions from a retired passkey again |
| `start` | Run the recorder in this terminal, and see what it says |
| `ensure` | Start the recorder in the background if it is not running (the hooks run this when a session starts) |
| `status` | What the recorder holds: the permission, until when, the number of entries, the passkeys whose permissions are in the record and those retired (`trusted`, `retired`), the calls allowed and not yet recorded (`callsNotYetRecorded`), the books kept (`keptBooks`), when a new one is started (`newBookAt`), the feed's token file and how many questions wait (`feed`), and for each witness what it holds and why it is behind (`witnesses`) |
| `seal` | Seal the book now, with the recorder's three keys, and ask the witnesses named, waiting up to five seconds while no other request waits |
| `new-book` | Seal the book, keep it as `book-<n>.jsonl`, and start a new one that begins with the permission in force (done by itself at 90,000 entries, or at 100 MB of text) |
| `check [file]` | The checker's answer for the book, or, given a name such as `book-1.jsonl`, for a book kept before it. Name your passkey with `--issuer <its thumbprint>`, once for each passkey of yours; without it, `check` lists the passkeys the book's permissions name, as read from the book, and the checker takes none of them as one you trust. It names the witnesses in `witnesses.json` (`--witness`) and hands over the statements kept beside the book (`--seal`), unless you give your own |
| `add-witness <address> <fingerprint> <token file>` | Ask a witness (at `http://127.0.0.1:<port>`) to sign for each seal from now on, after checking that it answers there and signs with that key set |
| `remove-witness <fingerprint>` | Ask that witness no more |
| `remove-hooks` | Take the hooks `init` wrote, from any copy of this recorder, out of this project's `.claude/settings.local.json`, and nothing else: for a project where the Claude Code plugin brings them |
| `session-start` | What the Claude Code plugin runs when a session starts: `ensure`, and what stands in the way, if anything, told to you and to Claude, within 27 seconds |
| `install-library` | Only through the plugin's entry (`node <the plugin's folder>/plugin.mjs install-library`): install the library into the plugin's data folder now |
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
  (`seal`), with the recorder's three keys, and the recorder asks the
  witnesses named in `witnesses.json`, if any, to sign for each seal
  ("Witnesses for the seals", above). This recorder names no outside
  time-stamp service.

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
of passkeys whose permissions are in the record, and which of them are
retired (`trusted-passkeys.json`), the book (`book.jsonl`), the books kept before it (`book-1.jsonl` and
so on), the token of its feed (`feed-token`, above), the witnesses it
asks, with their tokens (`witnesses.json`), the statements they handed
back after a seal's line was written (`witnessed/`), and, while `seal`
waits for the witnesses, the seal kept apart (`pending-seal.json`).
Never share the files that end in `.jwk`, nor `feed-token`, nor
`witnesses.json`.
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
  held somewhere else: written down, sent to someone, time-stamped by
  an outside service, or signed for by a witness (above). This recorder
  sends seals to no one but the witnesses named in `witnesses.json`, on
  this computer, and to none where it names none.

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
  with `--new-passkey`, admit a retired passkey again, stop it, or edit
  the settings that run the hooks.
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
- A witness's statement shows only that the witness saw the seal and
  will sign for no other history that does not extend it; under the same
  user account as the agent, it shows that only as far as the agent left
  the witness alone ("What a witness protects, and what it does not",
  above).
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
`node integrations/claude-code/recorder.mjs <command>`, and the
witness's `node integrations/claude-code/witness.mjs <command>`.

The tests always run against the repository's own library, whatever
`node_modules` holds (`test/local-library.mjs`):

```
node --test "integrations/claude-code/test/*.test.mjs"
```

They make permissions with the library's development stand-in for a
passkey, start the recorder in temporary folders on free ports, and run
the hook as Claude Code would, with its JSON on standard input.

To try the plugin from a copy of the repository, add the copy itself as
the marketplace (`claude plugin marketplace add <the copy's folder>`).
Claude Code may then load the plugin in place, from the copy; run
`node integrations/claude-code/tools/use-repository-library.mjs` first,
so that the plugin uses the repository's own library rather than install
version 0.6.0, and run the commands through
`node integrations/claude-code/plugin.mjs <command>` (or give `init`
`--no-hooks`), so that `init` writes no hooks beside the plugin's.

## Licences

Copyright 2026 Pavel Izmaylov. The code: Apache License 2.0
(`LICENSE`). This document: Creative Commons Attribution 4.0
International (`LICENSE-CC-BY-4.0.txt`).
