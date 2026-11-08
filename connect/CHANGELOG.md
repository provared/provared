# Changelog: provared-connect

## 0.1.0 (not yet published)

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
  (its long-running process's command line and log hold no secret). 124
  tests, all passing, with the recorder beside Claude Code from the same
  repository.
