# Changelog: provared-connect

## 0.1.0

- **The connection by one line.** `npx provared-connect <line>` takes the
  line copied from a book's page in the Provared application, checks its
  prefix, its version and every field, saves the connection as
  `provared-app-connection.json` in the recorder's folder where only its
  owner can read it (mode 0600; on Windows the access list set with
  `icacls` to the user alone, and a failure of that said), and starts the
  uploader in the background with the file's name, never the line. The
  same line again changes nothing; a line from a new key of the same book
  replaces the connection and restarts the uploader; a line for another
  book is refused, with what to do, where lines of a book were already
  sent. A line that is not one, or was copied with a piece missing, is
  refused with one sentence, and nothing from it is printed. The recorder
  beside Claude Code is taken unless `--feed` and `--feed-token`, or
  `--book`, name another. The line's format is in the README, with the
  choices numbered 1059 to 1075.
- **The uploader and the hand-over moved here** from the application
  (`connector/upload.mjs`, `connector/handover.mjs`), with what they used
  of the application's shared code (`entry.mjs`, `outcomes.mjs`, the
  reading of a book's content in `book.mjs`). They work as before, as
  `npx provared-connect --connection <file> ...`, with `--feed`,
  `--feed-token`, `--book`, `--once`, `--ensure` and `--same-book` as they
  were; with neither `--feed` nor `--book`, the recorder beside Claude Code
  is taken, where the uploader used to refuse. Their messages begin
  `provared-connect:`. Dependencies: `@microtoll/crypto-core`,
  `@microtoll/identity` and `@microtoll/access`, each exactly 0.1.1, and
  nothing else.
- **Tests**: the uploader's and hand-over's tests moved with them, and new
  ones for the line's format, the command's flow, the saved file's
  protection (on Windows, `icacls` for real) and the command as a program
  (its long-running process's command line and log hold no secret). They
  run with the recorder beside Claude Code from the same repository.
- **After a first independent review by an AI reviewer** (the same
  version, before publication):
  npm's own debug log of each `npx` run holds the line, so the page
  offers the command as `npx --logs-max=0 provared-connect <line>`, and
  the README names that log beside the shell's history as a place the
  line may stay, and says what to do. A connection file that is there but
  is not one this version reads is never taken for none: refused where
  the uploader's state is beside the book, replaced where not; and an
  uploader that runs is stopped whenever the connection on disk changes or
  there was none, including where only its process number is left. The
  uploader reads the connection file with the command's checks, so the
  two agree. A refusal names no field name and no version from the line,
  whatever they hold. On Windows the file is restricted while still empty
  and written only then. A `version` other than 1 in a file, and a
  `server` with a user name or a password, are refused; `--feed` without
  `--feed-token` is refused as the uploader refuses it; one function reads
  the bare words of a command line for the command and the flow. Seven
  tests added (`test/review.test.mjs`), each failing before its fix;
  131 tests pass. Choices 1062, 1063, 1066 and 1071 updated; 1076 to
  1081 added.
- **Two fixes before publication**: a line for another book where nothing was sent, and a line for the same book at another address, each get their own true sentence (both said "connected again with the book's new key"); and the stop signal goes only to a process whose command line shows it is this package's uploader (`node`, `bin.mjs`, `--connection`), a stale pid file whose number another program now holds being removed and said so, with a test for each (`test/before-publication.test.mjs`).
