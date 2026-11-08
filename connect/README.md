# provared-connect

**One line connects the recorder beside an AI agent to a book in the
Provared application.** A person opens the book's page in the application,
copies the line it shows, and runs it on the agent's computer:

```
npx --logs-max=0 provared-connect provared-connect:1:eyJ2ZXJzaW9uIjoxLCJzZXJ2ZXIiOiJ3c3M6Ly9...
```

(`--logs-max=0` tells npm, which `npx` is, to keep no debug log of the
run; it would otherwise hold the line. The page offers the command with
it.)

That checks the line, saves the connection beside the recorder where only
that computer's user can read it, and starts the uploader in the
background. From then on the uploader sends each line of the agent's book,
sealed under the book's key, to the application's server, which cannot read
it; and it hands the renewals and cancellations the person signs in the
application to the recorder, through the recorder's feed. No file is saved
or moved by the person.

**The line is the secret.** It holds the key that opens the book and the
capability that adds lines to it. Whoever holds the line can read
everything in the book and add to it, as whoever holds the connection file
can. Keep it as a password is kept: paste it only into the agent's
computer, never into a chat, a ticket, a screenshot or a shared document.
Where it has got out, give the book a new key in the application, which
stops every old line and link, and run the new line.

The package holds the uploader and the hand-over that used to live in the
application, and nothing else of the application. It needs Node.js 24.7 or
later. Its only dependencies are the three engine packages the uploader
has always used (`@microtoll/crypto-core`, `@microtoll/identity`,
`@microtoll/access`, each pinned to 0.1.1). No telemetry: it speaks to the
recorder on this computer and to the application's server named in the
line, and to nothing else.

## What the command does

`npx provared-connect <line>`:

1. **Checks the line**: its prefix, its version, and every field (below).
   A line that is not one, or was copied with a piece missing, is refused
   with one sentence saying what to do, and nothing from the line is
   printed back. A line made for a newer version of the format says to run
   `npx provared-connect@latest`.
2. **Finds the recorder.** Unless told otherwise it takes the recorder
   beside Claude Code: its feed at `http://127.0.0.1:8794`, and its token
   in `~/.provared/claude-code/feed-token` (the folder and port the
   recorder itself takes from `PROVARED_CLAUDE_CODE_DIR` and
   `PROVARED_CLAUDE_CODE_PORT` are honoured). `--feed <address>` and
   `--feed-token <file>` name another recorder's feed and token. Where the
   token file is not there, it says to start the recorder once (which
   writes the token), or to name the token file. For a recorder that
   offers no feed, `--book <file>` names its book file instead: the fragile
   way, which reads the file.
3. **Saves the connection** as `provared-app-connection.json` in the
   recorder's folder (the folder that holds the token; with `--book`, the
   folder that holds the book file), the file the uploader has always
   read. It is written whole beside its final name and then renamed over
   it, so no reader sees half of it. **Only its owner can read it** means:
   on Linux and macOS, the file has mode `0600`, as a key file has. On
   Windows a file's mode means little; who may read a file is decided by
   its access list, which a new file inherits from its folder. So on
   Windows the command replaces the file's access list with the system's
   own tool, `icacls`: inheritance off, and the user who runs the command
   the only name on it, with full control (administrators and the system
   lose their inherited entry; an administrator can take it back). Where
   `icacls` cannot be run, the file is still saved, and the command says
   that the file is as readable as its folder; a folder under the user's
   own profile (`C:\Users\<name>`) is readable by that user, administrators
   and the system only.
4. **Starts the uploader in the background**, as the uploader's own
   `--ensure` does, unless one already runs for this recorder. The program
   it starts is given the file's name (`--connection <file>`), never the
   line or anything in it: the secret is in no command line of a
   long-running program, and in no log this package writes. (npm keeps a
   debug log of each `npx` run, with its arguments, unless told not to;
   the page offers the command with `--logs-max=0`, which tells it not
   to.) Its output goes to
   `book.jsonl.uploader.log` beside the recorder's book; its process
   number to `book.jsonl.uploader.pid`.

Run again with the same line, it changes nothing: where the uploader runs,
it says so and stops; where it does not, it starts it. Run with a line from
a **new key of the same book** (the application's "Give the book a new
key"), it replaces the connection, stops the uploader that ran with the old
one and starts it again; the uploader goes on from where it was, since its
state beside the book is of the same book. Run with a line for **another
book**, where this recorder has already sent lines of a book (the uploader's
state is beside the book), it refuses and says what to do: that state is of
the other book and would be ahead of the new one.

The line itself is on the command line of `npx provared-connect` while it
runs, which is a moment, and it may be kept by the shell in its history
file, which the command cannot prevent, and by npm in its debug log where
the command is run without `--logs-max=0`; see "What the line exposes".

## The uploader, as before

With a connection file saved earlier, or saved by the command, the uploader
runs as it always has:

```
npx provared-connect --connection <file> --feed http://127.0.0.1:8794 --feed-token <the recorder's folder>/feed-token [--once | --ensure]
npx provared-connect --connection <file> --book <the recorder's book.jsonl> [--once | --ensure] [--same-book]
```

With neither `--feed` nor `--book`, the recorder beside Claude Code is
taken, as above. `--once` uploads what is new and stops (through the feed,
it also hands over what is due once); `--ensure` starts the uploader in
the background unless one runs; `--same-book`, with `--book` only and
once, after a program saved the book under a new identity. Beside the book
the uploader keeps `book.jsonl.uploaded.json`: for each part, the file it
reads and that file's identity, how many lines are on the server, and the
fingerprint and place of the last one. A restart goes on from there. A book
file that is not the one already sent from, or no longer holds what was
sent, is refused, and nothing more is sent. Through the feed the uploader
opens no book file: it asks the recorder for the lines, over a conversation
proved with the feed's token, and keeps its own files under the names the
`--book` way gives them for `book.jsonl` in the recorder's folder.

Records the person signed in the application (a renewal, a cancellation)
are kept with the book, sealed; the uploader opens them with the book's key
and hands each to the recorder through the feed (`POST /hand-over`), as
soon as the book's content changes and once a minute besides. The recorder
checks each itself and takes it or refuses it; what it refuses or holds,
the uploader says in one sealed note a book, which the page shows as an
unproved hint. Through the feed only: with `--book`, nothing is handed
over.

## The line's format

Version 1:

```
provared-connect:1:<base64url of the JSON>
```

- `provared-connect:` names what the line is.
- `1` is the version of the format. A reader refuses a version it does not
  know, with a sentence saying to run a newer `provared-connect`.
- The rest is base64url (RFC 4648 §5, no padding) of one JSON object with
  exactly these fields, every one a non-empty string, and no other:

| field | what it is |
| --- | --- |
| `version` | `1`, the same as in the prefix (a number) |
| `server` | the application's WebSocket address, `ws://` or `wss://` |
| `origin` | the page's address, `http://` or `https://`, with nothing after the host and port; sent when the uploader signs in |
| `namespace` | the engine's namespace the sealing is bound to (`provared-app`) |
| `objectId` | the book's id, a UUID |
| `kObject` | the key that opens the book, base64url |
| `appendCapabilitySecret` | the capability that adds lines to the book, base64url |

These are the fields of the connection file the application has saved
until now, without its `about` sentence. Saved to a file, the same fields
with `about` and `version` added give that connection file, so a saved
line and a saved file are one thing. A line is about 390 characters. No
new cryptography is involved: the line is the connection's fields written
as text, and it is as secret as they are.

## What the line exposes

Whoever holds the line, or the file, holds the key that opens the book and
the capability that adds to it. They can read every line of the book (the
permissions, receipts and seals, the book's name and the agent's name, the
keys the person marked as theirs, the records kept with it) and add lines
to it, as the uploader does, and write the note of outcomes. They cannot
sign a permission or a receipt (that needs the person's passkey or the
agent's keys), cannot change or remove what is already sealed, and cannot
delete the book or change its name or its trusted keys (that needs the
owner's account). With an account of their own they can add themselves as
a member of the book, which gives them nothing a line does not. The server
and the page's address are also in the line.

A line copied into a place others can read (a chat, a ticket, a shared
note, a screenshot, a command's history) gives all of that to whoever reads
it there, for as long as the book keeps that key. The way out is a new key
for the book in the application, which stops every line and link given
before; then run the new line beside the recorder, and clear the two
places below where the old line may still be.

Two places on the agent's computer may keep the line after the command
ran, both readable by the same user, administrators and the system. The
shells of most systems keep the commands typed into them in a history
file; how to keep a command out of the history, or to take it out,
depends on the shell. And npm, which `npx` is, writes a debug log of
each run with its arguments, and keeps the last ten, in `_logs/` under
its cache folder (`~/.npm/_logs` on Linux and macOS,
`%LOCALAPPDATA%\npm-cache\_logs` on Windows); `npx --logs-max=0 ...`,
as the page offers the command, writes none. Where the line was run
without it, that folder holds the line until ten later npm runs have
pushed it out, or until the log is taken out of it.

## Choices this package makes that the design leaves open

Numbered on from the application's and the executor's choices.

1059. **The line's form** is a fixed prefix (`provared-connect:`), the
      version, a colon and base64url of the JSON, with no padding. The
      plainest form that carries the same fields and lets a reader see the
      version before it reads the rest.
1060. **`about` is not carried** in the line and is added when the
      connection is saved. It is a sentence for whoever opens the file,
      and a shorter line is less often broken by a paste.
1061. **The file is saved as `provared-app-connection.json`** in the
      recorder's folder (beside its token), or beside the book file with
      `--book`. The name the uploader has always read by default, and the
      place the application's instructions have always named.
1062. **Only its owner can read it** is mode `0600` on Linux and macOS,
      and on Windows the access list set with `icacls` (inheritance off,
      the user alone, full control); where `icacls` fails, the file is
      kept and the failure is said. The system's own tool, and the
      plainest statement of what is done. The file is made empty,
      restricted, and only then written, so the secret is never on disk
      under the folder's inherited list.
1063. **The checks on each field** are shapes: `ws:`/`wss:` for the
      server; an `http:`/`https:` origin with nothing after the host and
      port; a namespace of letters, digits, dots, dashes and underscores;
      a UUID for the book's id; base64url of 22 to 128 characters for the
      two secrets (a key of 32 bytes is 43). The design does not fix the
      secrets' lengths, so a range rather than one number. A field this
      version does not know is refused; so is a `version` other than 1
      where there is one, and a `server` that carries a user name or a
      password. The uploader reads a connection file with the same
      checks, so the command and the uploader agree on what a connection
      is.
1064. **The same line again** changes nothing where the uploader runs, and
      starts it where it does not.
1065. **A line for the same book under a new key** (or at another server)
      replaces the connection and restarts the uploader, keeping the
      uploader's state, which is of the same book.
1066. **A line for another book** is refused where the uploader's state
      is beside the book, with what to do, and replaces the connection
      where there is none yet. A connection file that is there but is not
      one this version reads is treated the same way, never as if there
      were none.
1067. **The recorder beside Claude Code is the default** for the uploader's
      command line too: with neither `--feed` nor `--book`, where it used
      to refuse, it now takes `http://127.0.0.1:8794` and
      `~/.provared/claude-code/feed-token`, honouring the recorder's own
      `PROVARED_CLAUDE_CODE_DIR` and `PROVARED_CLAUDE_CODE_PORT`.
1068. **The uploader is stopped with `SIGTERM`** (on Windows, where that
      ends the process at once) and up to ten seconds are waited; where it
      does not stop, the new connection stays saved and the person is told
      to stop it and run the command again.
1069. **Exit codes**: 0 connected (or already so), 1 refused or failed, 2
      the command line is wrong.
1070. **The uploader's messages begin `provared-connect:`** where they
      began `provared-app uploader:`.
1071. **Any word on the command line that is not an option is taken for
      a line** and is never printed back, so that a half-copied line is
      not echoed into a log. One function (`bareWords`) decides what is a
      word and what an option's value, for the command and for the flow.
1072. **`provared` is not a dependency.** The uploader and hand-over never
      import it; the tests that run the real recorder resolve the name to
      the repository's own library (`test/local-library.mjs`).
1073. **Exports**: `provared-connect` (the command's parts), `./line`,
      `./store`, `./upload`, `./handover`, `./entry`, `./outcomes` and
      `./book`, so the application and the tests use the same code through
      the package's interface.
1074. **In the application, the page offers the whole command**
      (`npx provared-connect <line>`) to copy, not the bare line, so that
      one paste is the whole step; saving the file stays behind a fold
      under it, for a recorder that offers no feed.
1075. **In the application, the line is made by the page's own small
      module** (`web/connect-line.js`), the same format written twice,
      because the page is served from the application and does not load
      this package; the application's test checks the line it makes
      against this format.
1076. **The page offers the command with `--logs-max=0`**
      (`npx --logs-max=0 provared-connect <line>`), because npm writes a
      debug log of each run with its arguments, and that option is the
      one that stops it; `--loglevel=silent` does not. The line stays an
      argument: one line to copy is the decision.
1077. **A connection file that cannot be read as one is never taken for
      none**: with the uploader's state beside the book it is refused, as
      a line for another book is; without, it is replaced.
1078. **An uploader that runs is stopped whenever the connection on disk
      changes or there was none**, before the new one is started, so the
      one that runs is always the one with the saved connection.
1079. **A refusal names no field name and no version from the line**,
      only the sentence; a line could otherwise print what it liked into
      a terminal or a log.
1080. **The page shows the line only after "Show the line"**, in the
      first connection, after a new key and under sharing alike, so that
      a screen shared or captured does not carry it.
1081. **`--feed` without `--feed-token` is refused** by the command, as
      the uploader refuses it, rather than paired with the default token.

## Working from a copy of the repository

```
cd connect
npm install
npm test
```

The tests use `node:test`, no framework, and run through the package's own
interface (`import ... from 'provared-connect'`). They run the uploader
against stand-ins for the server and the recorder's feed, the command as a
program (the uploader's command line never holds the secret, nor its log),
and, with the recorder beside Claude Code from the same repository
(`integrations/claude-code/recorder.mjs`), the real recorder: lines through
its feed, and records handed over. The name `provared` is taken to mean the
repository's own library (`test/local-library.mjs`), so those tests run
against the library as it is in the same commit. On Windows, the test of
the saved file's access list runs `icacls` for real.

## Licences

Apache License 2.0 for the code (`LICENSE`); Creative Commons Attribution
4.0 for the documents (`LICENSE-CC-BY-4.0.txt`). Copyright 2026 Pavel
Izmaylov.
