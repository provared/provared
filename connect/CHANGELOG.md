# Changelog: provared-connect

## Not yet released

- **The records no longer wait for the agent note.** A hand-over round
  (`handOverRound`) hands the records over first and puts the note after
  them; `putAgent` takes the server's `unknown-type` refusal at once,
  instead of waiting 20 seconds at every round. Tests: two, in
  `test/agent-note.test.mjs`.
- **The agent note.** The agent's public key set, from the recorder, is
  put with the book in a sealed note of its own, `{ version: 1, agent: {
  name, keys } }`, under the book's key with the book's id bound in
  (`agent.mjs`: `sealAgent`, `openAgent`, `agentContext`, the context
  `"<namespace>/agent/v1" ‖ 0x00 ‖ object id`). It opens with the book's
  current key only. `bookSide.putAgent` sends it as `provared-put-agent`,
  with the append capability; `createAgentNote` puts it at each hand-over
  round where its text differs from the last one put. An earlier recorder,
  which does not give the key set, is said once, and nothing is put. The
  application's server does not take the note yet. Tests: nine, in
  `test/agent-note.test.mjs`.
- **One conversation with the recorder at a time.** Questions the
  uploader asks its feed at once share one conversation, begun once,
  instead of each beginning its own. Test: one, in
  `test/agent-feed.test.mjs`.
- **What is handed over again, and how many.** `AGAIN` gains
  `waits-for-yes` and `nothing-in-force`. In a round, at most one new
  permission for each passkey is handed over: the one that starts latest,
  of those not answered for good. Tests: three, in
  `test/handover-again.test.mjs`.
- **The agent's public key set, from the recorder's feed.** `feedClient`
  gains `agent()`, for the recorder's new `GET /agent`: the key set, from
  an answer with the recorder's proof, in the form a new module,
  `agent.mjs`, reads (`readKeySet`: public members only, none dropped).
  An earlier recorder's 404, which carries no proof, is read as "not
  given", and nothing in it is used; any other answer without the proof
  is refused. `agent.mjs` is in the package, as `provared-connect/agent`.
  Tests: five, in `test/agent-feed.test.mjs`.
- **A pause where the recorder has no book.** Through the feed, a round
  that finds no book in force (the recorder waits for its first
  permission) comes back at once; the uploader now waits 25 seconds
  (`NO_BOOK_PAUSE_MS`) before the next, or less where the book's content
  changes on the server first, instead of asking the recorder for its
  books again at once and without end. The rounds are in a new function,
  `feedRounds`, which `main` runs; the uploader gives `bookInForce()`, for
  whether the last list of books named a book in force. Tests: five, in
  `test/pause.test.mjs`. Before the change, three of them failed: the
  uploader asked 50 times, where the test stops it, in 30 seconds of the
  test's own time.
- **A record the recorder refuses while it is still starting is handed
  over again.** The refusal code `not-started` joins the codes for which
  the uploader hands a record over again in its next round
  (`handover.mjs`, `AGAIN`), instead of taking the refusal as final until
  the uploader is started again. Test: one new, in
  `test/handover.test.mjs`.

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
- **Two fixes before publication**: a line for another book, where nothing had been sent to the one before, and a line for the same book at another address now each get a true sentence of their own (both had said "connected again with the book's new key"); and the stop signal now goes only to a process whose command line has the marks of this package's uploader (`node`, `bin.mjs`, `--connection`). Where the saved process number now belongs to another program, the file holding it is removed, nothing is signalled, and the command says so. Where the command line cannot be read, nothing is signalled and the command asks you to stop the uploader yourself. A test for each is in `test/before-publication.test.mjs`. Where there is no `/proc`, as on macOS, the command line is read with `ps -o command=`; this was tried on Linux, with the code pointed at a folder that does not exist in place of `/proc`, not on a Mac.
