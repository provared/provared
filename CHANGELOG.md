# Changelog

## 0.9.1 (22 November 2026)

Version 0.9.1 changes no code of the library, in JavaScript or in Python. What changes: the library's own tests now fail where library code opens a network connection; the guide and the threat model gain two pieces of guidance; and the README and three pages are brought up to date. No signed byte, label, field's meaning or rule of the format changes.

- **Versions.** The library is 0.9.1, in `package.json` and `python/pyproject.toml`. `examples/frameworks/package-lock.json` gives the library's version as 0.9.1. The guide and the Python README say 0.9.1. No range changes: the Hermes plugin's `provared>=0.4.0,<0.10` takes 0.9.1. The checker in the checking page has not changed, so the guide's fingerprint stays `486471a5b8f3108d08acaacb96d7c27ceeecf95b93bce8e47721b8872a9b1bbc`. No other package's version changes.
- **A watch on the network while the library's tests run** (`test/helpers/no-network.mjs`, `test/helpers/no-network-worker.mjs`, `test/no-network.test.mjs`, `python/tests/test_00_no_network.py`, `python/tests/test_zz_no_network.py`). In JavaScript, `npm test`, the test workflow and the publish workflow load the watch before every test file with `--import`; in the publish workflow the only change is to the run line of "Run the tests" in the JavaScript test job, which gains `--import ./test/helpers/no-network.mjs`. The watch adds itself to `NODE_OPTIONS` so that a program a test starts with Node.js, the checker for one, is watched too, and so is a worker started from a file. It watches a socket's connect (which `net`, `tls`, `http`, `https` and `http2` all go through), `http` and `https` `request` and `get`, `http2.connect`, a UDP socket's `send` and `connect`, the name lookups of `dns`, and the global `fetch`, `WebSocket` and `EventSource`; and, from library code, one of those (or `net.connect` or `tls.connect`) handed to `setTimeout`, `setInterval`, `setImmediate`, `queueMicrotask`, `process.nextTick` or a promise's `then` or `catch`, a worker run from a string, and `process.binding` of the network bindings. A call whose innermost frame in the repository is in `src/` or `bin/` is stopped, and its test file fails through the exit code even where the library catches the error. A listener on the process's exit sets the exit code to 1 as it ends where anything was found, after whatever code the program asked for with `process.exit` (shown by a run on Node.js 24.19.0: `process.exit(0)`, `process.exit(2)` and `process.exit(7)` each ended with 1). Each program and worker also writes what it finds to a file that the process which started it reads as it ends, so that the test file that started it fails too, even where its test expects the checker to end with 1. `test/no-network.test.mjs` no longer imports the watch, and fails unless the watch was loaded by `--import` on the command line or in `NODE_OPTIONS`, or where a test file imports it. The watch's opening comment lists what it does not see: code a child Node.js runs from a string, a child started without `NODE_OPTIONS`, code in a worker run from a string that the tests start, a network function handed to any other scheduler, other bindings, and programs that are not Node.js. Left out by design: `net/`, the package's network code, kept apart so that `src/` makes no request; `page/`, the browser pages, which load their own files; and `test/`, whose helpers start servers on this computer and talk to them. In Python, an audit hook (`sys.addaudithook`) watches `socket.connect`, `socket.sendto`, `socket.sendmsg`, the name lookups of `socket`, `http.client.connect` and `urllib.Request`; a call whose innermost frame is in the installed library is stopped with an error that an `except Exception` does not catch, and the last test of the run fails where any was made. The hook is put in place by `test_00_no_network.py`, the file that sorts first, which finds the library without importing it, so a call the library makes as it is imported is watched; a thread that library code starts on a function of Python's own is judged by the library (the watch notes who started a thread both from Python's audit event and by wrapping `threading.Thread.start`, since Python 3.11 raises no audit event when a thread starts). The Python library has no network code of its own, so nothing in it is left out; the tests' own files are. The file's docstring lists what it does not see: native code called through `ctypes`, another program the library starts (a Python one included), a thread a test started, and calls after the last test. Shown to work, each in a copy of the repository, each breach caught and set aside there: a connection at the top of `bin/provared-check.mjs` failed 12 of the 15 tests of `test/cli.test.mjs` and the file (with the watch as first written, 12 passed); a test that expects the checker to end with 1 on the sample book passed with the watch as first written and now fails; a worker that library code starts from a file in `src/` and that connects, passed and now fails; `node --test test/no-network.test.mjs` without `--import` passed 5 of 5 and now fails 7 of 8; a test file that imports the watch fails `test/no-network.test.mjs`; a name lookup at the top of `provared/__init__.py` passed all 142 Python tests with the watch as first written and now fails 1 of 144. All were taken out.
- **The guide: short documents.** Where it describes the documents a tool's stub names, the guide now says that a document of your own that is short or easy to guess is best fingerprinted over exactly 16 random bytes, fresh for each document, followed by the document, with the bytes kept beside the document and not in the record, so that the fingerprint cannot be reversed by trying likely values. The length is fixed so that the bytes and the document split only one way. Where the action needs the person's approval, the approval's `details` must carry the same salted fingerprint as the stub's, as the checker requires (format description, section 17). It is guidance, not a rule of the format: the checker checks only the form of a fingerprint, and the reserved names of section 27 keep their fixed text. The format description is unchanged.
- **The threat model: an approval used in two books.** It now says that an approval's single use is shown within one book: the record cannot show that the same approval was not used in another book.
- **The README.** "What it does not do yet" no longer says that sealing the record is not built: it is, in the guard from version 0.5.0, with the limits the guard's README lists (among them: where the keys that seal are in the guard's own files, whoever can read those files can seal a book of their own; a central sealer must run on the same computer; seals held elsewhere and witnesses are not built); keys held in a key service are still not built. The list of packages names `provared-shopify` 0.1.0, on npm since 21 November 2026, and says the gateway is on npm as `provared-gateway` 0.1.0, since 22 November 2026. The Status section says that the library's own code, in `src/`, makes no network request, that its tests fail if that code opens a network connection while they run, and that two parts kept apart in `net/` do: `provared/net/timestamp`, which asks a time-stamp service, and the network code of the command `provared-headers`, which asks only the Bitcoin nodes named to it (and the computer's name service for a node given by name).
- **The pages.** The home page and "Provared in three minutes" name `provared-shopify` beside the other packages. The home page, "Provared in three minutes" and "Over the limit" give the library's version as 0.9.1. The home page and "Provared in three minutes" link the gateway on npm, and "Provared in three minutes" names `provared-claude-code` 0.1.1. Nothing else on the pages changes.

## 0.9.0 (21 November 2026)

Version 0.9.0 adds a new, separate module to the library and changes how the central sealer in the library asks a time-stamp hook. What changes for a user: `provared/net/timestamp` (`net/timestamp.js`, with `net/timestamp.d.ts`; a new export of the package) asks a time-stamp service that follows RFC 3161 for a time-stamp over a seal's fingerprint, and checks what it gets back with the library's own `checkStamp`. It is a separate module: `src/` still makes no network request, and no other entry of the package loads it. A program that does not import it is unchanged. In `src/sealer.js`, the `stamp` hook of `openSealer` is now given a second argument, `{when, after}`, the seal's own time and the latest time that a service's time-stamp gave the seal before it (read with `checkStamp`, which asks nobody), and a hook that gives no answer within `signWithin`, or throws something other than a `Refusal`, is now `stamp-not-given`, where it was `check-failed`. `src/types.d.ts` shows the new argument. The Python library has no change of its own in 0.9.0: its version is raised to match, the Hermes plugin's bound is raised, and nothing else in `python/` differs from 0.8.1 but the version its READMEs name. No signed byte, label or field's meaning changes, and nothing else in the library changes.

- **Versions.** The library is 0.9.0, in `package.json` and `python/pyproject.toml`. `examples/frameworks/package-lock.json` gives the library's version as 0.9.0. The Hermes plugin's bound on the library is raised from `provared>=0.4.0,<0.9` to `provared>=0.4.0,<0.10`, so that it takes 0.9.0, and the test workflow's comment on that bound agrees; the workflow's check of the bound passes. The README, the guide, the Python README, the plugin's README and three pages say 0.9.0. The checker in the checking page has not changed since 0.8.1, so the guide's fingerprint stays `486471a5b8f3108d08acaacb96d7c27ceeecf95b93bce8e47721b8872a9b1bbc`. The guard, the gateway and the central sealer ask for 0.9.0 (see "Not yet released"), and 0.9.0 was published on 21 November 2026, through the workflow.

- **The library: `provared/net/timestamp`** (`net/timestamp.js`, with
  `net/timestamp.d.ts`; part of `provared` 0.9.0, published on 21 November 2026 through the workflow). A
  new entry of the package, kept apart from the library as `net/`
  is: `src/` still makes no network request, and none of the library's
  other entries loads it. `askForStamp(fingerprintBytes, {address,
  timeout, clock})` sends the request of RFC 3161, section 2.4.1, by
  HTTP POST (`application/timestamp-query`): version 1, SHA-256 written
  with no parameters (RFC 5754, section 2), the 32 bytes of the seal's
  fingerprint, a random 64-bit number used once (X290), and the
  service's certificate asked for, which the format needs the
  time-stamp to carry. `http:` and `https:` addresses are both taken,
  with no user name, password, query or fragment (X291, X311). A redirect is not
  followed, as the sealer's client follows none (X288); the answer is
  read up to 12,544 bytes, a time-stamp of the largest size the format
  allows and 256 bytes for the status beside it, and the whole request
  is given up after its time limit, 10 seconds unless given, from 100
  milliseconds to 60 seconds (X292). A status of 0 or 1 gives the
  time-stamp; any other is said with the service's own text and
  reasons (X293). The time-stamp is kept only if the library's
  `checkStamp` passes it for this fingerprint, the device can check
  its signing method, and it carries the number used once that was
  sent (X294), and only if the time it states is within 300 seconds of
  this device's clock, since a book holding one further off would fail
  rule 7 of section 21.2 or rule 4 of section 21.1 under a checker who
  trusts the service (X295). Every failure is a `Refusal`:
  `stamp-not-given` for the request itself, or the code `checkStamp`
  gave (X296). `stampService({address, timeout, clock})` gives the
  `stamp` that `openSealer` takes. The package's exports gain
  `./net/timestamp` (X297).
- **`src/sealer.js` and `src/types.d.ts`.** The `stamp` hook of `openSealer` takes a second argument, `{when, after}`: `when` is the seal's time as a checker reads it, and `after` the latest time that a time-stamp from a service gave the seal before it, where the sealer holds that seal, or `null`. The sealer reads those times with `checkStamp`, which asks nobody, so `src/` still makes no request. A hook that gives no answer within `signWithin`, or throws something other than a `Refusal`, is `stamp-not-given` (it was `check-failed`), and the answer says why (`stampProblem`). A hook that takes one argument works as before.

## 0.8.1 (21 November 2026)

Version 0.8.1 changes how the library reads one kind of time and what the signing page will sign. A time in a time-stamp, or in its service's certificates, written in the long form with a year from 0000 to 0099, is now read as the year written; both libraries, JavaScript and Python, refused it before. What changes for a user: such a time-stamp now goes on to the later checks, so 0.8.1 refuses it as `stamp-invalid` (dated outside its service's certificate), where earlier versions refused it as `stamp-bad-data`; and five stored answers in the shared test files changed. The signing page, in this repository, now refuses to sign a permission, asked for by another page, that starts more than 300 seconds after the device's clock, and warns where the device's clock looks behind. No signed byte, label or field's meaning changes, and nothing else in the library changes. A reader in this repository of another project's receipts (not published) now reads such years in the same way, as its entry below says.

- **Versions.** The library is 0.8.1, in `package.json` and `python/pyproject.toml`. `examples/frameworks/package-lock.json` gives the library's version as 0.8.1. No range changes: the Hermes plugin's `provared>=0.4.0,<0.9` still takes 0.8.1, and the test workflow's check of that bound passes. The README, the guide, the Python README and three pages say 0.8.1. The guide gives the checking page's new fingerprint, `486471a5b8f3108d08acaacb96d7c27ceeecf95b93bce8e47721b8872a9b1bbc`, since the checker in it changed.

- **A time in a time-stamp or in its service's certificates, written
  in the long form (GeneralizedTime) with a year from 0000 to 0099, is
  now read as the year written** (`timeOf` in `src/der.js`, `time_of`
  in `python/src/provared/der.py`). Before, both libraries refused it
  (`stamp-bad-data`, "a time names a moment that does not exist"): in
  JavaScript because `Date.UTC` reads a year from 0 to 99 as 1900 to
  1999, so that the date did not come back as it went in, and in
  Python to match. The format description never stated that refusal,
  and a checker written from it alone reads such a year; the
  description is unchanged, and the libraries and the shared test
  files now agree with it. JavaScript sets the date with
  `setUTCFullYear`, which takes every year as given; Python no longer
  refuses a year below 100. A date that does not exist in those years
  (29 February 0099, a thirteenth month, hour 24) is refused as in any
  other year. The short form (UTCTime) names 1950 to 2049, as before.
- **What a checker now answers.** Such a time goes on to the rules
  that follow the reading of it (format description, section 21.2). A
  time-stamp that states a time in the year 0050, under a certificate
  in force from 2026 to 2036, was refused as `stamp-bad-data`; it is
  now refused as `stamp-invalid`, "A time-stamp is dated outside the
  time its service's certificate was in force." No case in the shared
  test files, and no test here, has such a time-stamp pass: for that,
  a trusted service's certificates would have to be in force in those
  years.
- **Shared test files whose stored answers changed** (five, against
  the files before this change; each new answer is the one the library
  gives): `test-vectors/stamps.json`, case 59, "statement: a time in
  the year 50": refused `stamp-bad-data` before, refused
  `stamp-invalid` now, with the words above.
  `test-vectors/der-times.json`, four cases, each refused
  `stamp-bad-data` before and read now, in milliseconds since 1970:
  `00000101000000Z` -62167219200000; `00500101000000Z`
  -60589296000000; `00990101000000Z` -59042995200000;
  `00991231235959Z` -59011459201000.
- **Shared test files with more cases.** `der-times.json` gains six
  (61 before, 67 now). Three are read: `00010101000000Z`
  -62135596800000; `00960229000000Z` -59132592000000;
  `00991231235959.5Z` -59011459200500. Three are refused in those
  years as in any other: 29 February 0099, a thirteenth month in 0050,
  and hour 24 in 0050.
  `test-vectors/times.json` gains seven cases (18 before, 25 now) for a
  record's own time (`parseTime`, `parse_time`; format description,
  section 3.6), which was and is the year it says in both libraries:
  the last second of 0000, the first of 0001, 0050, 29 February 0096
  (a leap year), 29 February 0099 (not one), the last second of 0099
  and the first of 0100.
- **Tests.** `test/timestamp.test.mjs` (one test) and
  `python/tests/test_small_years.py` (one) hold the reading of those
  years and the dates still refused; both fail on the earlier code.
  `test/encoding.test.mjs` (one) and the second test of the Python
  file hold a record's own time, and pass on the earlier code too.
- **The signing page sets its own limit on a start**
  (`startRefusal` in `page/sign-page.js`). A review of the hand-over
  (3 November 2026) found that the five-minute rule rests on the clock
  of the device the person signs on, and that the signing page set no
  limit of its own on a start: it signed whatever start the page that
  asked gave it. Now a permission another page asks for (`#request=`,
  kind `permission` or `renewal`) is not signed where it starts more
  than 300 seconds (the allowance between clocks the format uses, and
  the one by which the recorder beside Claude Code refuses a renewal
  handed over, `starts-later`) after this device's clock at the press
  of Sign. It is checked at every press, on what was read and is about
  to be signed, before any warning is shown or a passkey asked, and
  the page says why. The limit covers such requests only. A link with
  `#permission=` carries its own start, which the page takes as the
  link gives it (`readStartingPermission`), and that way of signing
  has no limit on the start, as before: it is meant for a permission
  kept as a file. A start that is not a time is left to the format's
  own check, as before.
- **The signing page warns where this device's clock looks behind**
  (`clockWarning`). Where a request carries an earlier permission
  (a renewal or a cancellation), whose passkey signature the page has
  checked, and by this device's clock that permission will not start
  for more than 300 seconds yet, either it has not started or the
  clock is behind: the page shows a warning with the others, and signs
  only once the person presses again. Nothing signed changes: a
  cancellation is dated by the same clock as before.
- **The recorder's README** (`integrations/claude-code/README.md`,
  "Limits") said that the signing page sets no limit of its own on the
  start. It now says what the page in this repository does, that the
  limit covers requests (`#request=`) only, that a link with
  `#permission=` carries its own start and has no such limit, that the
  limit is measured by the signing device's clock, and that a copy of
  the page from before this change (the one served at
  https://sign.prova.red, until it is brought up to date) sets none.
- **The reader of another project's receipts**
  (`integrations/agent-middleware/judge.mjs`, `parseAmwTime`; not
  published) reads a time in the years 0000 to 0099 as the year
  written, for the same reason and in the same way (`setUTCFullYear`
  in place of `Date.UTC`). **This changes what it answers:** a receipt
  dated in those years was "Not compared: the receipt's time cannot be
  read"; it is now compared, and one outside the permission's period
  is found `outside-valid-time`. A date that does not exist in those
  years is still a time that cannot be read. One test
  (`integrations/agent-middleware/test/judge.test.mjs`), which fails
  on the earlier code.
- **What these two do not do.** Both read the same clock, the signing
  device's. A clock that is ahead is not noticed, and with such a
  clock a start that far ahead of the true time is still signed. A
  request with no earlier permission gives the page nothing to compare
  the clock with. The page asks no one the time, and sends nothing
  anywhere, as before.
- **Tests** (`test/sign-start.test.mjs`, seven): the limit at 300
  seconds and one second past it, for both kinds; no limit with no
  request; a start that is not a time; the warning at the same two
  points, and with a clock a year behind; the warning's words the same
  from one press to the next; and, read from the page's own text, that
  the limit comes before the warnings and the passkey, and that both
  signing buttons work the warning out. In a browser with a virtual
  passkey (`test/sign-window.test.mjs`, one test, skipped where there
  is no browser): a renewal that starts ten minutes ahead is not
  signed, no warning is shown, nothing goes back and the passkey is
  not asked; and with a clock a day behind, a cancellation's first
  press shows the warning and signs nothing, and the second signs.

## Not yet released

- **The recorder beside Claude Code: a first permission through the feed, the first part** (`integrations/claude-code/`, not yet published).
  - *One owner of the port.* A new module, `port.mjs`, makes the recorder's one HTTP server and listens once. Its request listener runs 0.1.1's checks (`Origin`, `Sec-Fetch-Site`, `Host`, then the feed's own requests, then `Content-Type`), moved out of `startService` into one function, `portChecks`, and then hands the request to the handler in place, which the owner can swap in one step. The feed is made once, by the owner. `startService` takes a new option, `on`, the owner of a port that listens already: it then takes that owner's feed, makes no server and does not listen, and gives back its handler. Without the option it makes its own owner and listens, as before. A new module, `waiting.mjs`, holds the waiting recorder's handler and `startWaiting`: `GET /status` answers `{ waiting: true, version, agentKeySet, sealer, waitingPermissions, feed, started, folder }`; `POST /before` refuses every call with `no-permission-yet`; `POST /record`, `/seal`, `/renew` and `/new-book` are refused (409, `no-permission-yet`) and nothing is written; `POST /stop` stops it; its feed lists no book. `package.json` lists both files. New tests, in `test/waiting-port.test.mjs`: the cases of `test/local-port.test.mjs` against the waiting recorder (each route, `/admit`, `/renew` and `/stop` among them, refuses a web page's request, before its body is read, and every file in the folder is unchanged; the feed's routes refuse it and give no session; the feed's reader is answered and lists no book), and its own clients are answered. `test/local-port.test.mjs` passes unchanged.
  - *The feed's proof on `/admit`, and on `/renew` with a new passkey.* Both handlers check such a request with the feed's own check of a question with a body (`feed.mjs`, `conversation`, now also given out as `checkQuestion`), after the port's checks and before anything is done: the question must be asked in a conversation the recorder began, with the feed's token from the folder, proved over `POST <path>` and every byte of its body, and each question once; the answer carries the recorder's proof. No new label, layout or derivation. Without the proof the request is refused (401) and nothing is written. `/renew` with a passkey already trusted, and `/stop`, take no proof, as before. `admit-passkey`, and `renew` or `use` with `--new-passkey` while the recorder runs, ask through the feed's reader, which checks the recorder's proof on the answer; where the token file cannot be read they say so, and take nothing. New tests, in `test/admit-proof.test.mjs`: without a proof, refused and nothing written; with the token's proof, answered with the recorder's proof; a proof made for another path, another method or another body refused; a question sent twice refused the second time; the waiting recorder's `/admit` needs the proof too; the three commands say so where the token cannot be read. Each failed before the change. Changed tests: two in `test/renew.test.mjs` and one in `test/handover.test.mjs` that sent such a request with no proof now send it with the feed's reader, as the commands do.
  - *Shared hand-over checks.* The checks of a permission handed over that need no permission in force (a start no more than 300 seconds ahead, looked at before the passkey; a sound permission with a valid passkey signature; this agent's key set; not ended; not from a retired passkey; signed at the expected signing address; and, where a passkey is admitted, signed by that passkey) move out of `handOverRenewal` into one function, `handOverChecks`, which the full recorder and the waiting recorder both call. The full recorder's answers do not change: today's hand-over tests pass unchanged.
  - *The hand-over while the recorder waits.* The waiting recorder's feed takes a first permission handed over (`{ kind: 'renewal', slip }`): after `handOverChecks`, with no passkey trusted, it keeps it in `waiting-permissions.json` (`addWaitingPermission`, one for each passkey, the one that starts latest) and answers `refused` with the new code `waits-for-yes`, the passkey's thumbprint and the permission's fingerprint; where one from the same passkey that starts no earlier waits already, it keeps nothing and answers `refused` with the new code `not-kept`, which is final. It never writes `slip.json`, the list of trusted passkeys or a book. A permission for other keys (`other-agent`), signed at another address, starting more than 300 seconds ahead (`starts-later`), ended, or not sound, is refused and not kept; a cancellation is refused with the new code `nothing-in-force`. One record is taken at a time. New tests, in `test/waiting.test.mjs`: a sound first permission waits and none of those files is written; each of those permissions, and a cancellation, is refused and nothing is kept or written; `/before`, `/record`, `/seal`, `/renew` and `/new-book` refuse and write nothing while a permission waits. Each failed before the change.
  - *The admit rules* (`admitWaiting`, `POST /admit`). `POST /admit` now takes `{ fingerprint, thumbprint, take }`: the recorder takes the permission from its own waiting list by fingerprint, worked out from each permission itself, and never from the request; a request that carries a permission is refused (`not-understood`), and a fingerprint that does not wait is refused with the new code `no-such-permission`. `take: false` checks only. `{ fingerprint, thumbprint, decline: true }` declines. `admit-passkey`, exported as `admitWaiting`: with no argument it only lists what waits; for a passkey this computer does not trust it takes the thumbprint, or at least its first 16 characters (`ADMIT_THUMBPRINT_LEAST`; 96 bits, out of reach of trying keys until one starts alike), matched exactly and case-sensitively at the start of the thumbprint worked out from each permission, and its words say to paste it from the signing window, not from the application; where the start matches more than one passkey, nothing is taken and it asks for more characters; where none matches, it says how many others wait and points to saving the permission from the signing window as a file. It shows the permission and asks the person to compare its fingerprint with the signing window's. It asks only where its input is a terminal: from a pipe or a file it says so and takes nothing. Only a typed `yes` takes; only a typed `no` declines, and the declined fingerprint is remembered as `declined` in `waiting-permissions.json` (at most 64, `MAX_DECLINED`, the oldest left out first) and refused from then on with the new code `declined`, by both recorders; anything else leaves it waiting. The command no longer writes the waiting list: a check that fails leaves the permission waiting, and the command says why; the running recorder takes a permission out once taken or declined, and leaves out one that has ended when it writes the list. New tests, in `test/admit-rules.test.mjs`: a kept permission swapped for one of the same wording from another passkey is not admitted with the person's thumbprint; a permission sent in the request, or a fingerprint not waiting, is refused; `take: false` and a check that fails drop nothing; a start under 16 characters, in another case, or matching two passkeys takes nothing, and the first 16 characters take; no argument only lists; input from a pipe takes nothing; only a typed `no` declines, and the declined permission is refused afterwards. Before the change none of them passed (the command was not exported, and its rules were not there). Changed tests, whose behaviour this changes: four in `test/handover.test.mjs` (the person's answers are typed at a terminal, so the tests give them to `admitWaiting` directly; a check that fails now leaves the permission waiting instead of dropping it; the words where nothing waits from the passkey named; the recorder asked by fingerprint), and one in `connect/test/handover.test.mjs` (its `yes` is typed at a terminal, given to `admitWaiting` directly).
  - *Taking a first permission, and the switch to the full recorder* (`waiting.mjs`, `port.mjs`). The waiting recorder's `POST /admit`, with the feed's proof, in this order: one at a time (a second, while one runs, is answered 409 with the new code `busy`, and nothing is changed); the waiting recorder still in place (else `not-waiting`) and the folder still fresh (else `not-fresh`, nothing written); the permission from its own waiting list by fingerprint (else `no-such-permission`); `handOverChecks` with that one passkey admitted, then `startService`'s own checks on the slip, all before anything is written (`take: false` stops here: `would-take`); the list of trusted passkeys written as exactly this one passkey, with a new mode of `writeTrusted`, `replace`, that does not read or keep a list left in the folder; `slip.json` (`placeSlip`); the full recorder built with `startService`'s `on`, on the same port and feed, which writes the slip as the book's first line; the full recorder put in place by the port's owner in one step, with nothing closed and nothing listening again; and only then `taken`. Where the start fails, what this attempt wrote is put back (the trusted list, `slip.json`, and a `book.jsonl` that holds only that first line), the recorder stays waiting, the permission waits, and the answer is `refused` with the new code `not-started` and the reason. A `decline` takes the permission out of the list and remembers it, as in the full recorder. A record handed over that waited its turn behind the admit is passed on, once the full recorder is in place, to the full recorder, which answers it by its own rules: a cancellation of the permission just taken is `taken` (its test, in the same file, failed before the change). `freshFolder` says whether a folder is fresh (see the next item) and what stands in the way. New tests, in `test/waiting-admit.test.mjs`: after `yes` the book's first line is the slip, the trusted list is that one passkey, `/status` names the slip at once and a call inside it is allowed, and the feed's conversation holds; `taken` comes only once `/status` names the slip; two admits at once leave one passkey trusted and answer the other `busy`; a trusted list put in the folder while an admit runs is replaced, not merged; a start that fails (the book cannot be written) answers `not-started`, leaves no slip and no trusted list, and the permission waits; tool calls sent throughout the switch are each answered, refused or allowed, and none finds the port closed; in the waiting recorder a check drops nothing, a permission in the request or from another passkey is refused, and a declined permission is refused when handed over again. Each failed before the change.
  - *A fresh folder* (`start`, `ensure`, `use`). The recorder waits only in a fresh folder (`freshFolder`): the agent's keys are there, and none of `slip.json`, `book.jsonl`, a kept book (`book-<n>.jsonl`), a kept slip (`slip-<fingerprint>.json`), `trusted-passkeys.json` or `held-cancellations.json`; `waiting-permissions.json` may be there. `startWaiting` refuses any other folder, naming what stands in the way. `start` in a fresh folder starts the waiting recorder; in any other folder it starts the full recorder, which still refuses to start without a slip. `ensure` starts the recorder in a fresh folder too, and where the recorder that answers waits (`waiting: true`), it says so, with what to do next, instead of taking it for one that runs with a permission; in a folder that is neither fresh nor holds a slip it still starts nothing. `use <file>` while the recorder waits stops it, waits until the port is free (10 seconds at most), says so, and then takes the file as it does where nothing runs. The words of `init`, the start of a session and `status` for the waiting state are not changed yet. New tests, in `test/fresh.test.mjs`: each of those six files stops the waiting start, and `waiting-permissions.json` alone does not; `ensure` starts the waiting recorder in a fresh folder and says that it waits, and starts nothing in a folder that is not fresh and holds no permission; `use <file>` while the recorder waits stops it and takes the file, and the full recorder then runs under it. Each failed before the change.

- **The recorder beside Claude Code: a first permission through the feed, put right after review** (`integrations/claude-code/`, `connect/`, not yet published). Each new test failed before its change.
  - *A record handed over while a first permission is taken.* It waits its turn behind the admit, as before, and is then passed on to the full recorder now in place, which answers it by its own rules: a cancellation of the permission just taken is taken, and the permission is cancelled. Before, it was refused with the code `not-waiting`, which the uploader does not hand over again, so a cancellation could be lost until the uploader was started again. The uploader (`connect/handover.mjs`) now hands over again a record refused `not-started` (the recorder still starting). Tests: in `test/waiting-admit.test.mjs`, the test of records handed over during the switch now expects this; in `connect/test/handover.test.mjs`, one new test.
  - *A permission the waiting recorder does not keep.* Where one from the same passkey that starts no earlier waits already, the answer is now refused with the code `not-kept`, which the uploader does not hand over again, and no longer `waits-for-yes`, which said that this one waits. Test: one new, in `test/waiting.test.mjs`.
  - *Two checks of the admit now tested.* In `test/waiting-admit.test.mjs`: a folder that is no longer fresh when the admit comes (a file of held cancellations put there after the hand-over) is answered `not-fresh`, with nothing written; an admit that reached the waiting recorder before the switch, and whose body arrived after it, is answered `not-waiting`, and the other passkey is not trusted. The code does not change; each test fails with its check taken out.
  - *`use <file>` while the recorder waits.* The file is read and checked first, and the waiting recorder is stopped only once it passes; a file that is refused leaves the waiting recorder running, and the words no longer say it was stopped. The file is checked again once nothing runs, before it is put in place. The port is taken as free only where two questions in a row go unanswered, not one. After `ensure`, `use` asks whether what answers still waits: if so, it stops it and starts the full recorder, and where that fails it says that every tool call is still refused, with how to restart, and ends with 1, instead of saying that the recorder runs and checks each call. Tests: three new, in `test/fresh.test.mjs`, two of them against a stand-in on the port.
  - *An admit stopped between its two writes.* `ensure`, in a folder that holds no permission and is not fresh, now names the files that stand in the way and says to put the signed permission in place with `use <the saved file>`. Where a start after `yes` fails, each file written for it is removed with the same retry, for up to ten seconds, that the recorder uses when it writes its files on Windows, instead of in one attempt. Tests: one new in `test/fresh.test.mjs`, one new in `test/waiting-admit.test.mjs`.
  - *The options for tests.* The waiting recorder's `serviceOptions` can no longer replace the folder, the port's owner, the signing addresses or the clock the full recorder starts with. Test: one new, in `test/waiting-admit.test.mjs`.
  - *`renew <file>` while the recorder waits.* With or without `--new-passkey`, it now says that no permission has been signed yet and the recorder waits for its first one, so there is nothing to renew, and points to `use <the saved file>` and `admit-passkey`. With `--new-passkey` it said, wrongly, that the recorder did not prove it holds the feed's token. Test: one new, in `test/fresh.test.mjs`. In the full recorder, one value now decides both whether `/renew` needs the feed's proof and whether a new passkey is taken; what it does is unchanged.
  - *What `admit-passkey` shows.* Every value it prints from a permission (the label, the address, the agent, what it may do, the limits, the purpose, the times), and the recorder's words about it, now has each character that does not print written as an escape such as `\u001b`: controls, line breaks among them, format characters such as the marks that turn text right to left, and line and paragraph separators. Before, they reached the terminal as they were, and could move the cursor and write over what was shown. Test: one new, in `test/admit-rules.test.mjs`; the test helper `signSlip` can now set the label and the agent's name.

- **The recorder beside Claude Code: a first permission through the feed, put right after the second review** (`integrations/claude-code/`, not yet published). Each new test failed before its change, unless it says otherwise.
  - *A stop only for a recorder that waits.* `POST /stop` with the body `{"waiting": true}` stops only a recorder that waits for its first permission, and the recorder decides it in one step. The full recorder refuses it (409, `stopped: false`, the new code `not-waiting`) and goes on. The waiting recorder refuses it with `busy` while it takes a permission (`admit-passkey`), and with `not-waiting` where the full recorder is in place by the time the body is read; otherwise it stops. A `/stop` with any other body, or none, stops either, as before. The port's checks of 0.1.1 come first, as for every request. `use` now asks its stops this way. Before, it stopped whatever answered: where a permission was taken with `admit-passkey` between its question and its stop, it stopped the full recorder, and said, untrue, that it had stopped the one that waited. Now, after a refusal, it reads the status again: where the full recorder answers, it goes on with it, as with any recorder that runs; where a permission is still being taken, it asks again, for up to 10 seconds, and then ends with 1 and says to run it again in a moment. Tests: three new in `test/waiting-admit.test.mjs` (the waiting recorder answers `busy` during a held admit, the admit then completes, and the full recorder refuses with `not-waiting` and keeps running, behind the port's checks; a waiting recorder with no admit still stops, which passed before too; `use` during a held admit goes on with the full recorder once it is in place), and one in `test/fresh.test.mjs` (`use` goes on with the full recorder after it refuses the stop).
  - *`use` decides from the status `ensure` was given.* `ensure` now hands back, with its code, the status of what answered, and `use` decides from that whether the recorder waits, instead of asking once more and taking no answer for "does not wait". Where `use` asks again later and gets no answer twice in a row, it ends with 1 and says that it is not known whether the recorder still waits, and to run `status`. Tests: two new in `test/fresh.test.mjs`, against a stand-in on the port: questions left unanswered before and after the one `ensure` asks (before, `use` said the recorder runs and ended with 0); a stop refused and then two questions unanswered. One more new test, of what was already built: `use` ends with 1 and says every tool call is still refused where what answers still waits after it was stopped and the recorder started again; it fails with that branch taken out.
  - *Questions answered while a failed start is put back.* Where a start after `yes` fails and a file written for it is held open by another program, the waiting recorder still tries each removal again for up to ten seconds, but now waits between tries with a timer (`untilFreeLater`), and no longer holds its one thread: `/status` and other questions are answered meanwhile, and a stop asked by `use` is refused with `busy` until the admit has ended. Before, nothing was answered for up to ten seconds a file, and `use` could take the recorder for gone. Test: one new, in `test/waiting-admit.test.mjs`: while a removal is refused for 2 seconds, `/status` is answered within 1 second of the first refusal (before the change, after 2,029 ms).
  - *What `admit-passkey` shows, made clearer.* Each text it prints from a permission, and each of the recorder's messages, is now shown between quotation marks, as JSON writes a string, so that where it begins and ends is seen; the quotation mark and the backslash within it are escaped, so text typed as `\u001b` no longer reads like an escaped control. Beside the characters escaped before, it now escapes every space but the plain one (the no-break and ideographic spaces among them), characters that are ignored when shown (`Default_Ignorable_Code_Point`: the Hangul fillers, variation selectors, the combining grapheme joiner), and private-use and unassigned code points. A code point past U+FFFF is written as two escapes, as in JSON, instead of `\u{…}`. A limit or a condition is shown as its JSON text, escaped the same way. In `recorder.mjs`, `printable` and its comment now stand above `admitWaiting`'s comment, and a new `printableJson` does the same for JSON text. Tests: two new in `test/admit-rules.test.mjs`, one for the quotation marks and the backslash, one for each new kind of character. Changed tests, whose words this changes (the quotation marks): one in `test/admit-rules.test.mjs`, two in `test/handover.test.mjs`, one in `connect/test/handover.test.mjs`.
  - *A test of the recorder's messages in `admit-passkey`.* One new test in `test/admit-rules.test.mjs`, of what was already built: a stand-in for the recorder, over the folder's feed and with its proof, answers each question with a message full of controls, marks that turn text right to left, separators, blank-looking and private-use characters, quotation marks and a backslash; in each of the four places the command prints such a message, it is shown escaped and between quotation marks. It fails with the escaping taken off any one of the four. Of the fields of a permission, the library holds the address and the website name, the actions, the limits, the conditions, the never list, the services' ids and both times to a narrow form, so they cannot carry such text; the label, the agent's name and the purpose, which can, were tested already.
  - *What `status` prints.* `status` still prints the recorder's status as JSON, but every character that `admit-passkey` escapes is now written as a JSON escape (`\u009b`) wherever it stands in that text: in the agent's name and every other text from a permission or from what answers on the port. JSON escapes only the controls below U+0020 itself, so before, C1 controls, DEL and the marks that turn text right to left reached the terminal as they were. The output is still JSON, and reads as the same values. Test: one new, in `test/fresh.test.mjs`.

- **The recorder beside Claude Code and its uploader: a first permission through the feed, the second part** (`integrations/claude-code/`, `connect/`, not yet published). Each new test failed before its change, unless it says otherwise.
  - *The uploader's pause where the recorder has no book* (`connect/upload.mjs`). Through the feed, a round that finds no book in force, as while the recorder waits for its first permission, comes back at once, and the uploader asked the recorder for its books again at once, without end. It now waits 25 seconds (`NO_BOOK_PAUSE_MS`, as long as a round with nothing new already waits at the recorder) before the next round, or less where the engine says that the book's content changed, the same wake the hand-over rounds use. The rounds are in a new exported function, `feedRounds`, which `main` runs; the uploader gives `bookInForce()`. Tests: five, in `connect/test/pause.test.mjs`, on the test's own time: against a feed with no book, and against one with a kept book but none in force, the uploader asks for its books no more than twice in 30 seconds (before the change, 50 times, where the test stops it); the pause ends at the wake; with a book in force there is no pause (passed before too); a round that fails for now waits the retry time, and one that fails for good ends the rounds (passed before too).
  - *The feed's route `GET /agent`* (`feed.mjs`, `port.mjs`, `recorder.mjs`, `waiting.mjs`). Both the full and the waiting recorder answer it with `{ agent: { name, keys }, fingerprint }`: the agent's public keys, worked out at the start from the agent's key file (`loadAgentKeys`), never the file; the name of the starting permission (`Claude Code`), as in the link `init` prints; and the key set's fingerprint (`keySetFingerprint`), as `init` prints it. A new exported function, `agentKeySetAnswer`, makes it; a handler gives it to the port's owner as `agent()`. The answer is proved as every answer of the feed is, and without the feed's proof the question is refused (401). It takes nothing after its name (400) and GET only (405). The feed makes the answer afresh, and gives it only where each key holds public members only (`kty`, `alg`, `crv`, `x`, `pub`, each a string; `publicKeySet`, `PUBLIC_KEY_MEMBERS`); a key with any other member, a private one among them, is never given: the answer is then 500, proved, with no key in it. Where no handler is in place yet, it answers 503. A feed made without the new option `agent` does not know the route, as an earlier recorder's did not. The feed's reader gains `agent()`, which gives `{ given: false }` for an earlier recorder's 404 with no proof, and reads nothing in it; its errors for an answer with no proof now carry the answer's `status`. New tests, in `test/agent-route.test.mjs`: in each recorder, the public key set and its fingerprint, proved, with no private member and none of the private parts of the agent's key file in it; refused without a proof, and with the proof of a reader that does not hold the token; nothing after its name, and GET only; a key set with a private member is never given (it also fails with only the check of the members taken out); the answer while no handler is in place, and a feed that does not know the route.
  - *The uploader reads the key set* (`connect/upload.mjs`, `connect/agent.mjs`). `feedClient` gains `agent()`: from an answer with the recorder's proof, `{ given: true, agent: { name, keys }, fingerprint }`, in the form a new module, `agent.mjs`, reads (`readKeySet`: a name of 1 to 200 characters; 1 to 8 keys, each with `kty` and public members only, each a value of base64url letters; at most 8,192 characters as JSON; made afresh, and set aside whole where anything else is there). Where an earlier recorder answers with its own 404, which carries no proof, it gives `{ given: false }` and reads nothing in that answer; the conversation is begun again at the next question, as after any answer with no proof. Any other answer with no proof, or one not in that form, is refused (`feed-error`), and nothing in it is used. `package.json` lists `agent.mjs` and exports it as `provared-connect/agent`. New tests, in `connect/test/agent-feed.test.mjs`, against the recorder's own feed: the key set read, proved; an earlier recorder's 404 is "not given", nothing in it used, and the books and their lines are still read (it fails with the rule for the 404 taken out); a key set in an answer without the proof is never used; a proved answer with a private member, or a fingerprint not in its form, is not used; the form of the key set.
  - *The agent note* (`connect/agent.mjs`, `connect/handover.mjs`, `connect/upload.mjs`). A note of its own, `{ version: 1, agent: { name, keys } }`, sealed under the book's key with the book's id bound in, as the note of outcomes is (`sealAgent`, `openAgent`), under the bound context `"<namespace>/agent/v1" ‖ 0x00 ‖ object id (16 bytes)`, made with the engine's `frameContext` and `label` as `outcomesContext` makes its own (`agentContext`). It binds no key epoch: it opens with the book's current key only, and a note sealed under an earlier key does not open. A key set not in the form `readKeySet` reads is never sealed, and a note not in its form opens to nothing. `bookSide` gains `putAgent`, which sends `provared-put-agent` with the book's id, the append capability and the sealed note, and waits for `provared-put-agent-ok` or `provared-put-agent-failed`, as `putOutcomes` does for its note. A new `createAgentNote` reads the key set from the recorder at each hand-over round, before the records, and puts the note where its text differs from the last one put; a put that fails is tried again at the next round, and said once. Where the recorder does not give its key set (an earlier version), it says once "update the recorder to fill in the agent's keys by itself", puts nothing, and uploading goes on as before. The application's server does not take `provared-put-agent` yet, so until it does the put fails and is said once. The note is not proved to be the uploader's: anyone given a read-only link to the book holds the key it is sealed under. New tests, in `connect/test/agent-note.test.mjs`: the bound context's bytes; seal and open; a note for one book does not open for another, nor under an earlier key; a note of outcomes does not open as an agent note, nor the reverse; the note is put once, and again only when it changes; a put that fails is tried again and said once; nothing is put from an answer the feed client did not take, nor from a key set with a private member; what `putAgent` sends; against an earlier recorder's own feed, nothing is put, it is said once, and every line is still uploaded. Before the change the file did not load (`agent.mjs` had none of these).
  - *One conversation at a time* (`connect/upload.mjs`, `feedClient`). With the agent note, the uploader asks the recorder's feed for the key set while its first round of lines asks for the books. Each question that found no conversation began its own, and one could then be asked in a conversation another had just replaced. Now questions asked at once wait for one conversation, begun once, and each is asked and checked in the conversation it began with; one that loses it meanwhile is tried again later (`feed-busy`). Before, with the agent note in place, tests of the command in `connect/test/feed.test.mjs` failed: in the run that found it, two (a garbled state did not stop the long run within 20 seconds; a refused token ended with a crash of the process on Windows instead of exit code 1), and in a later run with the fix taken out, only the second; they pass unchanged now. New test, in `connect/test/agent-feed.test.mjs`: the key set, the books and the lines asked at once begin one conversation (before, more than one).
  - *What the uploader hands over again, and how many* (`connect/handover.mjs`). `AGAIN` gains `waits-for-yes` (a first permission waits on the agent's computer for the person's thumbprint and `yes`) and `nothing-in-force` (a cancellation came while no permission was in force), so both are handed over again a minute later, and a cancellation the person signed reaches the recorder once a permission is in force. In a round, at most one new permission for each passkey is handed over: of those the recorder has not answered for good, the one that starts latest (of two that start alike, the first kept), as the waiting recorder keeps one for each passkey. The passkey is read from each permission's content, not checked (the recorder checks it), with the members of its key in order; a permission whose passkey cannot be read is its own. New tests, in `connect/test/handover-again.test.mjs`: both codes are handed over again, and not within the minute; with three permissions from one passkey and one from another, only the latest of the first and the one of the other are handed over, the earlier ones never while the latest waits, and the next by its start once the latest is answered for good; two that start alike, and permissions whose passkey cannot be read. Each failed before the change. The existing tests of `connect/test/handover.test.mjs` pass unchanged.

- **The uploader: the second part, put right after review** (`connect/`, not yet published). Each new test failed before its change.
  - *The records no longer wait for the agent note.* A hand-over round (`handOverRound`, new and exported, which `main` runs) now hands the records kept with the book over first, and puts the agent note after them. `bookSide.putAgent` now waits for its answer itself (`SERVER_ANSWER_MS`, 20 seconds) and takes the server's own refusal of a message it does not know (`{ type: 'error', reason: 'unknown-type' }`, with the message's id) as a refusal at once. Before, while the application's server did not know `provared-put-agent`, every round waited the whole 20 seconds for the note before it handed anything over, so a cancellation the person signed reached the recorder 20 seconds late at every round. The uploader now says, once, that the server does not take the agent's keys yet. Tests: two new, in `connect/test/agent-note.test.mjs`: against a server that answers `unknown-type`, the put is refused within 2 seconds (before, after 20) and nothing is left listening; the records are handed over before the note is begun, and do not wait for it.
  - *One kept record no longer keeps a passkey's others back* (`connect/handover.mjs`, `connect/upload.mjs`). Of the new permissions from one passkey, the one that starts latest is handed over first, as before; where its hand-over fails (no answer from the recorder), the passkey's next, by its start, is handed over in the same round, and so on. A record larger than the recorder's feed takes (`FEED_MAX_HAND_OVER_BYTES`, 256 KiB, as `feed.mjs` has it) is no longer sent: `feedClient.handOver` refuses it with the new reason `too-large`, in words that say so, and the round counts it as answered for good, with the new code `too-large` in the note of outcomes. Before, such a record, kept with the book with the person's passkey and a later start by whoever can write the book's content, was the only one of that passkey handed over, failed at every round ("does not carry the recorder's proof", which was not the reason), and kept the person's real permission from ever being handed over. Tests: two new in `connect/test/handover-again.test.mjs` (where the latest's hand-over fails, the next is handed over in the same round; a record too large is not sent, not even a hello, is answered `too-large` for good, and the passkey's next is handed over), and one new in `integrations/claude-code/test/handover-shadow.test.mjs`, against the real waiting recorder: with a record of over 256 KiB beside it, the person's first permission waits on the computer after the first round (before, nothing was handed over in any round). Each failed before the change.
  - *Words that were ahead of the code.* The comments of `connect/agent.mjs` no longer say that the application's page opens the note or that the person compares the fingerprint in the signing window: neither is built yet (they now say so), and what guards the agent is the recorder, which takes no permission for other keys. The comment on the feed's requests in `integrations/claude-code/port.mjs` names `GET /agent`. The entry on one conversation at a time above says which tests failed in which run. (The words of `agent.mjs` changed with the first item; no code changed here.)

- **The recorder beside Claude Code, `provared-claude-code` 0.1.1: a web page cannot use its port.** With 0.1.0, a web page open in a browser on the same computer could ask the recorder to take a permission, trust a passkey, write a receipt for a call that never happened, or stop. 0.1.1 refuses what a browser sends for a web page, or under another website's name, on every route of the recorder's port, and for it reads and writes nothing. 0.1.0 is affected, and updating is not enough on its own: a recorder already running keeps the code it started with until it is restarted. After updating, restart it once, with both commands on one line so that no tool call falls between them: `provared-claude-code stop; provared-claude-code ensure`. With the Claude Code plugin, they are `node <the plugin's folder>/plugin.mjs stop; node <the plugin's folder>/plugin.mjs ensure`. A tool call does not start the recorder: while it is stopped, tool calls are refused, until `ensure` or the start of the next Claude Code session (with the plugin) starts it. From 0.1.1, `ensure` and the start of a session say so where the recorder that answers is not the version installed, with these commands; they do not stop it.
  In `integrations/claude-code/recorder.mjs`, every route, the feed's four (`/hello`, `/books`, `/lines` and `/hand-over`) among them, first refuses, before it reads the body, a request with an `Origin` header, with a `Sec-Fetch-Site` header other than `none`, or with a `Host` other than `127.0.0.1:<port>` (on port 80, `127.0.0.1` alone as well, as a client sends it there), and answers 403. Every route but the feed's then refuses, with 415, a POST whose `Content-Type`, read before the first `;`, trimmed and in any case, is not `application/json`. The port is kept once the recorder listens, so a request that came before the port closed (`close()`, or `POST /stop`) is still answered and its call recorded. Where the file `feed-token` holds no token, the feed's answer no longer names the folder, whose path names the person's account; the recorder's status still gives it. The status gives the package's version, from its `package.json`, as `version`. The hook, the recorder's commands, the feed's reader in `feed.mjs` and the uploader in `connect/upload.mjs` already sent all of this; the tests that ask the recorder directly, in `integrations/claude-code/test/` and `connect/test/`, now send `Content-Type: application/json` too, and three requests that `test/handover.test.mjs` writes by hand now name the port in `Host`. Any program on the computer can still use the port, as before; the README says so, in "What the record shows, and what it does not". `package.json`, its lockfile and `.claude-plugin/plugin.json` say 0.1.1, and the README names 0.1.1 where it names the version. New tests, in `test/local-port.test.mjs`: each route, with each of those headers wrong in turn (`Sec-Fetch-Site` of `same-site` or any value but `none`, a `Content-Type` that only names `application/json` after a `;`), is refused, the trusted passkeys, the permission in force and every file in the folder are unchanged, and the recorder still runs; a POST is refused with its body never sent; the feed's four routes refuse such a request and give it no session and no proof, and the feed's reader is still answered; a call whose request came before `close()` or `POST /stop` is answered and recorded; on port 80, `Host: 127.0.0.1` is taken (where port 80 can be taken); `ensure`, with an earlier recorder answering, says so and stops nothing. In `test/feed.test.mjs`, the feed's answer where its token file holds no token names no folder; in `test/plugin.test.mjs`, the start of a session says so where the recorder that answers is an earlier version. With any one of the checks taken out, a test fails. Published on npm on 22 November 2026, with the advisory GHSA-cj2m-rqh6-5984.

- **The gateway countersigns with a key set of its own** (`gateway/`,
  `provared-gateway` 0.1.0, on npm since 22 November 2026). Where the settings give the
  gateway its own keys (`gateway`) and an agent's slip names them in `with`
  for an upstream's service, the gateway countersigns each call to it that
  it lets through, with the library's `countersign` (format description,
  section 6), keeps its own tagged copy of the agent's calls apart from the
  book (`gateway/copy.mjs`), and `provared-gateway compare` holds the copy
  against the book, as the MCP executor's does. `provared-gateway keys
  --gateway` makes the key file and prints the slip's `with` entries. The
  package lists its new files, asks for `provared` 0.9.0 exactly, and has a
  change log of its own (`gateway/CHANGELOG.md`). The library does not
  change.
- **The gateway after the review of its countersignature** (`gateway/`,
  in 0.1.0). The gateway has a `with` entry of its own (`gateway`
  by default), which every receipt of an agent whose slip names it then
  names, so that its countersignature no longer reads as an upstream's. Its
  own copy, not the journal, decides at a start what happened to a call: a
  call the copy shows as sent and not finished waits for the administrator,
  a journal line the copy does not hold is never given a stub, and a stub
  found in the book settles a call only where it is the call the copy shows,
  countersigned. `compare` holds each receipt's content and countersignature
  against the copy, reports more than one receipt for a call, and agrees
  only where the book is fully checked and within its slips. Unknown
  settings are refused. Details in `gateway/CHANGELOG.md`. The library does
  not change.
- **The gateway after a re-check of those fixes** (`gateway/`, not yet
  published). With a copy, only the copy's own `set-aside` line sets a call
  aside: a call that the file beside the journal names and the copy shows
  open stops the agent and is listed (`set-aside-not-in-copy`). A journal
  line the copy lacks is passed over where the book holds the stub that is
  that call, so a gateway first given keys, or one whose copy was lost, is
  not stopped by calls whose receipts are sound. `compare` checks the
  countersignature of a stub written at a later start. A found stub needs
  the gateway's countersignature wherever its slip names the gateway's id
  with keys, not only its present keys. `acknowledge` looks at the book
  again before each stub, so trying again writes none twice. After a second
  re-check, `acknowledge` first makes sure the book file holds the book in
  memory, as the guard does, so a failed write of that file is never
  followed by a call settled from a stub only in memory; the README says to
  settle open calls before changing the gateway's `id`, and that a call
  whose `set-aside` line the copy could not take comes back at the next
  start. Details in `gateway/CHANGELOG.md`.
- **`provared-mcp-executor` 0.5.1 (published by hand to npm on 22
  November 2026): the MCP executor after the same review.** Review 3.4 of
  the gateway's countersignature found the same gaps in the executor. The
  executor still asks for `provared` 0.9.0, exactly.
  - **Versions.** 0.5.1 in `package.json`, its lockfile and `server.json`
    (both fields); the `npm pack` file name in the README. The README says
    the guard is listed in the MCP Registry, without naming a version. The
    root README, the home page and "Provared in three minutes" name 0.5.1
    as the guard's version, and the home page's "What is new" has an entry
    for it. The recipe (`recipes/claude-ai/compose/`) builds 0.5.1: its
    `package.json` names it, and its lockfile was made from npm after 0.5.1
    was published, with npm's hash
    (`sha512-j36/cBjICI7o0YxmpfB78l27fZ+MpSFzpgAX3JpjrJ2VHgoUPBdIjKZnHbdssP6sFO63OygLGNwbuN41T2xuJw==`);
    `node tools/release/check-recipe-lock.mjs --registry` passes. The
    recipe's README, the Dockerfile's comment and the Docker check's
    examples name 0.5.1, and the README no longer says the build waits for
    the version to be on npm. The release check's test reads the version
    from the recipe's `package.json`, so it need not change with each
    version.
  - **A receipt found in the book at a start** settles a call the copy
    shows as sent and not finished only where it is the only receipt naming
    the call, it is the call the copy's `sending` line shows (the same
    permission, action, amount and service; the line's documents first,
    then only `provared.tool-result`, `provared.error`,
    `executor.written-late` or `executor.acknowledged`), and, where the
    permission names the executor with keys, it carries a valid
    countersignature. It was taken on its `executor.call` document alone.
    Any other receipt is not written into the copy as the executor's: the
    log says `receipt-not-matching`; over stdio the executor does not
    start, and says so; over HTTP that agent's calls are refused; the call
    is listed for the administrator (`receiptsMissing`, with `inBook`) and
    can only be set aside. The same holds when the administrator
    acknowledges a call whose receipt has reached the book since the start.
    A `found-in-book` line now records whether the receipt was
    countersigned and the countersignature's fingerprint. (`executor.mjs`,
    `copy.mjs`.)
  - **`compare`** holds each receipt it matches against the copy's
    `sending` line (and the documents its `done` line holds), and against
    the countersignature the copy records: a receipt that is not the call
    sent goes to `differs` (each entry now says `why`: `another stub` or
    `not the call sent`); a countersignature missing, not valid, or another
    than the one recorded goes to the new list `countersignatures`; more
    than one receipt for a call goes to the new list `moreThanOne`. The
    summary gains `countersignatureProblems` and `moreThanOneReceipt`, and
    `agree` is false where either is found. `notInCopy` now lists every
    receipt the copy does not know, where before only one for each call
    was kept. (`compare.mjs`.)
  - **`compare`, a receipt written at a later start** (found by a re-check
    of these fixes). Where the copy's `done` line names no receipt and says
    it was countersigned, the receipt in the book must carry a valid
    countersignature; otherwise it goes to `countersignatures` and `agree`
    is false. Before, that branch checked none, so a one-sided receipt put
    into the book for such a call was `matched` and `compare` agreed.
    (`compare.mjs`; the README's "The copy, and comparing it with the
    book"; a test in `test/review5.test.mjs`, with and without the
    countersignature.)
  - **`compare` is stricter in 0.5.1 than in 0.5.0.** `agree` is now true
    only where the book was also fully checked and is within its slips, as
    the gateway's `compare` asks; before, a book outside its slips (a
    receipt under another service, say) or one this computer could not
    fully check still agreed where the copy matched. Such a book now ends
    `compare` with code 1, and `onlySetAside` is false for it, as in the
    gateway. The summary gains `bookFullyChecked` and `bookWithinSlips`,
    and `book` gains `withinSlips`. (`compare.mjs`; the README's "The copy,
    and comparing it with the book"; two tests in `test/review5.test.mjs`.)
  - **Tests** (`mcp-executor/test/review5.test.mjs`, 5): a receipt found at
    a start with other arguments, one-sided, or one of two; one that is the
    call, countersigned; a countersignature taken off or swapped; a receipt
    that is not the call sent; and two receipts for one call, with and
    without another fault. Two more for the administrator's acknowledgement:
    a receipt that reached the book after the start (the executor wrote it,
    and its copy could not say so) settles the call where it is the call
    sent, countersigned; one without the countersignature the permission
    names does not, and the call waits to be set aside.
  - **Three tests that failed now and then** no longer rest on timing they
    do not control. "A seal the sealer signed whose answer never came"
    (`test/central-sealer.test.mjs`) raced the executor's own retry two
    seconds after a failure: on a busy computer the seal was added before
    the test had looked, and it found calls taken. The stand-in sealer now
    holds the executor's questions until the test has looked. "A program
    that is not reading" (`test/http-local-faults.test.mjs`) measured
    "refused at once" on the system clock with a bound of two seconds
    against a timeout of three; it now measures on the monotonic clock,
    with a bound of ten seconds against a timeout of twenty. "An answer of
    the program to nothing in flight" waited five seconds; it now waits up
    to thirty. In every test, `until` (`test/world.mjs`) measures its limit
    on the monotonic clock, so a system clock put forward no longer ends a
    wait at once; and a test's slip lasts a day, not an hour, so a clock put
    forward by more than an hour no longer ends it under a running test.
  - **Documents.** The executor's README ("A call the executor was sending
    when it stopped"; "The copy, and comparing it with the book") and
    DESIGN.md (sections 7 and 8) say so.
  - **`files.mjs` is the gateway's again, byte for byte**, as
    `test/same-files.test.mjs` requires: it takes the gateway's line that
    describes a key file of the gateway's own, which the executor never
    makes. The test failed from the gateway's countersignature commit on.
- **The home page for businesses.** https://prova.red now opens for businesses that use AI agents a lot: what the guard does, how it works with claude.ai, when it keeps the tools' credentials from the agent, what a record does not prove, and how to try it. The developers' material follows, under "For developers". No code changes.
- **The pages and READMEs name the guard 0.5.0 as current.** The README, the
  home page and the three-minutes page say the guard is at 0.5.0, and the
  home page's "What is new" has an entry for it. The guard's README says the
  MCP Registry lists 0.5.0 since 21 November 2026, and the recipe's README, the
  design notes and this change log say that 0.5.0 (by hand to npm) and 0.9.0
  (through the workflow) were published on 21 November 2026. Text only.
  0.5.1 replaces this wording: see its entry.

- **The lockfiles carry what npm published.** The guard's lockfile
  (`mcp-executor/package-lock.json`) and the recipe's
  (`mcp-executor/recipes/claude-ai/compose/package-lock.json`) now give
  `provared` 0.9.0 and, in the recipe's, `provared-mcp-executor` 0.5.0, as
  published on npm on 21 November 2026, each with the hash npm gives:
  `sha512-rLql7z1btN6FL+bDIkv1TwCp+ARm98FAU6q2+Exz7hCYvecw/ir3qGU/CPACoNrfXTEYKCY7W3SYyBgs+f1yqA==`
  for the library and
  `sha512-0qIyZIUEDLrjTRlFIpemqKBPLBBXQ4uyC6Kg4W74zgU4yzdFPEkAk9LmUbQu56pSftUmEQQCJei2fGB43OUtDQ==`
  for the executor. The provisional mark (`package-lock.provisional.json`)
  is gone, and `node tools/release/check-recipe-lock.mjs --registry` passes.
  The recipe's tests now expect no mark and a hash on every entry.

- **Static analysis passes again on the executor.** Nine warnings in
  `mcp-executor` were checked and found to be false alarms: two loops whose
  condition changes in a callback, six patterns that cannot match the same
  text two ways, and one test of whether a variable is set, which compares
  no secret. Each now carries a comment that says why. No behaviour changes.

- **An outside time-stamp on each seal, asked for over the network.** A
  program that seals can now send each seal's fingerprint to a time-stamp
  service (RFC 3161) whose address its settings give, and put the
  time-stamp it gets back beside the seal, in `stamps` (format
  description, section 21.2). No service is named anywhere in the code,
  the examples, the documents or the tests. Left out of the settings,
  nothing is asked and nothing changes. No signed byte, label or field's
  meaning changes; a checker answers as before.
  - **The library: `provared/net/timestamp`** is part of `provared` 0.9.0 (published on 21 November 2026 through the
    workflow), and its entry is under 0.9.0 above.
  - **The executor** (`mcp-executor/`, part of 0.5.0, published by hand to npm on 21 November 2026):
    `recorder.stamp`, `{address, timeout}`, with the same rules, any
    other member refused (X298). Each seal the executor signs is sent to
    it. Not beside `recorder.sealer`: a central sealer asks for its own
    seals' time-stamps; where it was not given one, the executor logs
    its reason and hands it on (X299). A time-stamp never costs a seal:
    where the service gives none that passes, or the book does not take
    the seal with it, the seal goes in without one; the log has a
    `stamp-not-given` event, `seal` answers `stampProblem` and the
    command prints it, and a seal that carries one answers `stamped:
    true` (X300). The client is loaded only where the setting is given,
    so an executor without it runs as before on a library that lacks it
    (X301). `check` and `status` show the service. `DESIGN.md` holds
    X298 to X301; the README says what is sent, what a time-stamp shows
    and what it does not.
  - **The central sealer** (`sealer/`; `provared-sealer` stays 0.1.0,
    not published): its settings take `stamp`, `{address, timeout}`, with
    the same rules, and each seal is sent to that service through
    `stampService`. A failure is answered as `stampProblem` beside the
    seal, as before. The settings' `stamp` and a `stamp` function given
    to `startSealer` are not taken together (X302).
  - **The gateway** (`gateway/`; `gateway/package.json` stays 0.1.0):
    `recorder.stamp`, with the same rules, checked by `openGateway` and
    by `check`; each seal is sent to it, and a failure leaves the seal in
    the book without one, logged as `stamp-not-given` and answered as
    `stampProblem` (X303).
  - **Versions.** The sealer and the gateway ask for `provared`
    `>=0.9.0 <0.10.0`, and the executor for `0.9.0` exactly, the first
    version with `provared/net/timestamp` (0.9.0 was published on 21 November 2026 through the workflow; the
    lockfiles now carry npm's hash, as the first entry above says). Installed
    with an earlier version, a program whose settings give `stamp` is
    refused at its start, in words that say so: the refusal looks for the
    client, not for a version number.
  - **The format description** (section 21.2) says how the reference
    software asks for a time-stamp, what the service learns, and that a
    time-stamp not given never costs a seal; section 21.3 says what a
    time-stamp fixes and what it does not. `docs/guide.md` describes
    `provared/net/timestamp`, and no longer says that only
    `provared-headers` connects to anything.
  - **Tests.** All run against a time-stamp service on this computer that
    the OpenSSL program answers for (`test/helpers/tsa.mjs`: an HTTP
    server on 127.0.0.1 that hands each request to `openssl ts -reply`,
    under a key and certificate the test makes), and are skipped, saying
    why, where there is no OpenSSL program (`PROVARED_OPENSSL` may name
    it). None reaches beyond this computer. `test/stamp-request.test.mjs`
    (12): the request's bytes; a good answer, which checks; a refusal; a
    time-stamp with another number used once, and with none; one for
    another fingerprint; an answer too large with its length given and
    without; a redirect, which reaches no other address; a slow service;
    a status of 500 and bytes that are not an answer; a time 301 seconds
    either side of the clock; a service that cannot be reached; and the
    address and time limit refused. `mcp-executor/test/stamp.test.mjs`
    (5), three new tests at the end of `sealer/test/sealer.test.mjs`, and
    `gateway/test/stamp.test.mjs` (3): a seal that carries the
    time-stamp, counted for a reader who trusts the service and shown as
    not counted to one who does not; a refusal, a wrong number used once,
    a wrong fingerprint and a service that cannot be reached, each
    leaving the seal in the book without one and the reason said; and
    the settings refused. `test/package.test.mjs` now holds that `net/`
    has the two files, that neither names an address, and that only the
    entry `./net/timestamp` loads `net/`. Each check in
    `net/timestamp.js` (the number used once, the redirect, both limits
    on the size, the time limit, the clock, `checkStamp`, the status, the
    address) was taken out in turn: a test then failed every time. So did
    the executor's log of a time-stamp not given, its refusal beside a
    central sealer, and its keeping of the seal when the service fails.
  - **After the review of step 3.3** (X304 to X312):
    - The central sealer's `stamp.timeout` is 4 seconds unless its
      settings say otherwise, and at most 20 (it was 10 and 60): the
      sealer answers one question at a time, so the wait holds up every
      recorder, whose questions time out after 5 seconds unless their
      settings say otherwise. `startSealer` refuses a `stamp.timeout` that
      is not less than its `signWithin` (X304). In the library, a `stamp`
      hook that gives no answer within `signWithin`, or throws something
      other than a `Refusal`, is now `stamp-not-given`, not
      `check-failed` (X305). The sealer keeps, in memory, why each book's
      latest seal has no time-stamp, and answers it with the latest seal
      (`/latest`), so that an executor that takes the seal back after its
      answer was lost still logs the reason (X306).
    - The time a time-stamp states is also held against the seal's own
      `when` and the latest time that a service's time-stamp gave a seal
      before it: more than 300 seconds before either, it is not kept
      (`stamp-not-given`). `askForStamp` takes `when` and `after`;
      `openSealer` gives its hook a second argument, `{when, after}`,
      the seal before being the one it holds; the executor and the
      gateway take every seal of the book before (X307). `src/` still
      makes no request: the times are read with `checkStamp`.
    - The gateway checks `recorder.stamp` whenever it is there, so `null`,
      `""`, `false` and `0` are refused at the start as by `check` (X308).
    - `check`, for the executor and the gateway, loads the time-stamp
      client where `recorder.stamp` is given, and says plainly when the
      library installed has none. The READMEs name the library release
      needed (X309).
    - What a service writes is shown with no format characters (`\p{Cf}`,
      such as those that turn text round) as well as no control
      characters, cut at 200 characters in all; the executor's and the
      gateway's commands cut a problem's words at 600 (X310).
    - An address with a query (`?`) is refused, as one with a user name
      or password is (X311).
    - Wording: a time-stamp not given never "costs" the seal, rather than
      never "holds it up" (X312).
    - Tests: in `test/stamp-request.test.mjs` (20 now), bytes left over
      after the answer, a time-stamp larger than the format allows inside
      an answer that is not, status 1, a body sent slowly after its
      headers, a compressed answer and one that opens far larger, a
      signing method the device cannot check, format characters and long
      text, the seal's own time and the earlier time-stamp, and the clock
      test at 320 seconds either side (it was 301). `test/sealer.test.mjs`:
      what the hook is told, and a hook that never answers. The sealer:
      the time limits, the query, and the reason kept with `/latest` and
      lost at a start. The executor: the seal's own time, `stampContext`,
      a seal taken back with the reason, and `check` with the client
      hidden (`test/helpers/no-net-timestamp.mjs`). The gateway: `null`,
      `""`, `false`, `0`, the query, the seal's own time and `check` with
      the client hidden. Each new check was taken out in turn, and a test
      then failed.
  - **Not tested:** a seal the book does not take with its time-stamp,
    since the time-stamp is checked before it is offered.

- **`provared-mcp-executor` 0.5.0 (published by hand to npm on 21 November 2026).** Six pieces of
  work on the executor, each below with its own choices: the fixes of
  0.4.2 carried over to every transport, with a re-check of the local
  program; the findings of an independent review of the local program;
  over HTTP, a local program as the tool server; signing
  in through OAuth; `seal`, `acknowledge` and `status`, with a
  central sealer; and a recipe that runs the executor as a claude.ai
  connector with Docker Compose. 0.4.2, the entry after this one, is
  released.
  - **The fixes of 0.4.2 carried over, and the findings of a re-check of
    the local program.**
    What changes, in `mcp-executor/` (`DESIGN.md`, section 10.2, X249 to
    X253, and X241 to X248 as corrected):
    - **Carried over from 0.4.2, for every transport, a local program
      among them.** A rule on content refuses, as unreadable and with a
      denial, a call where a member on the way to a pointer the rule reads
      is written in other capitals (`Path` for `/path`), or where the way
      stops at a value that is neither an object nor a list (X249); before,
      both were taken for absent, and in front of a server that ignores
      capitals a rule could be skipped. A message nested more than 256
      levels deep is not read: the agent's is refused, the server's is a
      line the executor cannot read; and the two older refusals name their
      request (X250). A list of tools that the executor is to filter and
      cannot read is not handed to the agent: its request is answered with
      the error -32603 (X250). Which servers are known to be exposed, the
      wider folding, and "one line" for a reader of UTF-8, are said as in
      the 0.4.2 entry.
    - **A program's exit does not overtake its last lines (X251).** The
      calls that were with a program are settled once its output has ended,
      not at its exit. Before, in front of a local program on Linux, a
      program that wrote 1,500 notifications, then its answer, and ended
      lost the answer 20 times in 20: the call was receipted as "ended
      before it answered". The same order is now kept on stdio.
    - **The stop reaches what a program started, on Linux and macOS
      (X252).** A program is started as the leader of a process group of
      its own, and SIGTERM and SIGKILL go to the group; what a program
      leaves in its group counts as the program until it has gone. Before,
      a server behind a launcher that passes no signal on was never
      signalled, was not counted by `sessions.max`, and outlived the stop
      with its credentials. **On Windows** the executor ends the one
      process it started, and what that process started is ended only
      where Windows ties it to its parent: name the server itself in
      `server.command`, not a launcher. **What changes for whoever runs
      it:** on Linux and macOS the tool server is no longer in the
      executor's own process group, on stdio as over HTTP.
    - **The flood rule is counted by the clock's seconds (X245).** More
      than 1,000 messages in each of 5 seconds running, as the documents
      said; before, the count ran over windows of one to two seconds and
      ended a program writing about half as much in bursts.
    - **A method in other capitals is refused (X253):** `Tools/Call`, and
      the other three methods the executor acts on, with -32600; and with
      `"unlisted": "forward"`, a call whose tool name is a ruled tool's in
      other capitals.
    - **The `initialize` that begins a session is not held to the
      `MCP-Protocol-Version` header (X287).** In front of a local program,
      an `initialize` sent with no `Mcp-Session-Id` was refused with 400
      where its header named a version the executor does not serve, though
      the version is agreed inside `initialize`. It is now taken, and the
      version the program answers with is the session's; every other
      request keeps the rule of X247. For a POST with no session id the
      header's check now comes after the checks of the body (415, 413,
      408, and 400 for what is not one message), since the message must be
      read first; nothing else changes its place. The log line of a
      request refused for its version now has `"version"` (the version
      named, where it is written as a date; `"other"` where it is not) and
      `"session"` (whether a session id came with the request). Two more
      tests in `test/http-local-faults.test.mjs`, and each part was undone
      once to see its test fail. A re-check found three changes to this
      work that no test caught, and those tests now catch each: the log's
      form for a version not held at its start (a value such as
      `x2026-07-28` is now in the test's list), the check that waited
      moved after the mirrored headers, and a GET or a DELETE with no
      session id not refused for its version. Each change was made once,
      its test failed, and the code was put back.
    - **Tests.** `test/deep.test.mjs` (5), `test/list.test.mjs` (8, three
      of them in front of a local program), two more in
      `test/content-rules.test.mjs` and in `test/names.test.mjs`, and six
      more in `test/http-local-faults.test.mjs`, three of them on
      `local.mjs` alone with the clock in the test's hands: the five
      faults that the re-check put into the code and that passed every
      test are each caught now. The test of the launcher runs on Linux and
      macOS only, and takes a server that has ended but is not yet reaped
      (a zombie) to have gone: in a container with no init, nothing reaps
      a server whose launcher has ended, and the test failed there though
      the executor had ended it. Three tests that depended on the computer's speed no
      longer do (`seal.test.mjs`, `http.test.mjs`, and the timeouts of
      1,000 ms where a test starts a program), and the made-up server's
      log is read in whole lines.

  - **The findings of an
    independent review of the local program, one of them a serious weakness
    that every version up to 0.4.1 has.** What changes, in `mcp-executor/`
    (`DESIGN.md`, section 10.2, X241 to X248):
    - **Security: a message whose names differ only in capitals from the
      ones the executor reads is refused (X241).** The executor reads member
      names exactly. Some JSON readers do not: the standard JSON reader of
      the Go language takes `Method` for `method` and `Name` for `name` in
      the fields it knows, the later one winning. In front of a tool server
      with such a reader, `{"method":"ping","Method":"tools/call", ...}` was
      a ping to the executor, passed on with no check and no receipt, and a
      tool call to the server; `{"name":"echo","Name":"order", ...}` was
      checked and receipted as `echo`, and run as `order`. Who was exposed:
      anyone who runs the executor, on any transport, in front of a tool
      server whose JSON reader ignores capitals; a server that reads names
      exactly (Node.js, Python) is not affected, and which MCP servers read
      names that way was not checked. Now refused, with -32600 and nothing
      sent on (`readMessage` in `jsonrpc.mjs`): a message with a member at
      its top level other than `jsonrpc`, `id`, `method`, `params`, `result`
      and `error`, from the agent or from the server; a message of the
      agent's whose `params` hold, in one object at any depth, two names
      that differ only in capitals (or in the long s, or the Kelvin sign);
      a `tools/call` that writes `name`, `arguments` or `_meta` in other
      capitals, a `notifications/cancelled` that writes `requestId` so, and
      a `tools/call` whose `_meta` writes `red.prova/call-id` or
      `traceparent` so. A server's answer with such a top-level member is
      treated as any line that cannot be read; a filtered `tools/list`
      shows no tool with a second name in other capitals and leaves out a
      second list. **What changes for a caller:** arguments with two names
      in one object that differ only in capitals are refused in every call,
      with -32600 and no denial; before, they were refused with a denial,
      and only where a rule read the amount or the content from the
      arguments. `misspelt` is a new export of
      `provared-mcp-executor/jsonrpc`. The same fix is on the branch for
      0.4.2.
    - **Security: one message, one line (X248).** A message written to a
      program's standard input is made one line under every way of ending a
      line, and stays the same JSON (`oneLine` in `jsonrpc.mjs`): a line
      feed or a carriage return between its values becomes a space, and
      U+0085, U+2028 and U+2029 in a text are written as their JSON
      escapes. Before, over HTTP in front of a local program, a body with a
      whole `tools/call` between two line feeds was one `ping` to the
      executor and three lines to the program, the second a call that was
      never checked; and a body set out over several lines was never
      answered. That mode is not in any published version. On stdio, in
      every published version, the same holds with carriage returns in
      front of a server that ends a line at a bare carriage return (one
      that reads with `node:readline`), and a text with U+2028 left a call
      unanswered and recorded as "outcome not known". The demonstration's
      made-up server (`demo/server.mjs`) now ends a line at a line feed
      alone, where it read with `node:readline`.
    - **A program that will not end (X242).** A program still running
      `shutdownWait` after its input was closed is sent SIGTERM, and one
      still running after a second wait (`shutdownWait` again, at most 5
      seconds) is sent SIGKILL, on stdio and for each session's program.
      Before, a program that took no notice of SIGTERM was never ended, and
      the HTTP executor's stop never finished. The stop now always
      finishes: it waits for the programs for the two waits and 2 seconds
      more, and says in the log how many are still there
      (`servers-not-ended`).
    - **`sessions.max` bounds an agent's programs (X243).** The program of
      an ended session counts until it has gone, and one whose `initialize`
      is not answered counts too. An `initialize` that needs room now waits
      until a program of the agent's has gone, and is refused with 503
      where none goes in time. Before, 40 programs ran under a limit of 2.
    - **A program that is not reading (X244).** Where more than 16 MiB
      already wait to be written to a program, the next message is refused
      with 503, not held, and the session is ended. Before, such messages
      were held in memory without limit.
    - **A program that writes without pause (X245).** One read of a
      program's output is handled at a time; a line that goes nowhere is
      logged at most once a second for each session and kind, with a
      `count`; and a program that writes more than 1,000 messages that
      answer nothing in flight in each of 5 seconds running has its session
      ended (`server-flooding`). Before, one agent's program made another
      agent wait seconds, and each dropped message cost a line of the log.
    - **No program is started once the stop has begun (X246).** An
      `initialize` whose body arrives then is answered 503. Before, it
      started a program that outlived the executor.
    - **Against the specification, revision 2025-11-25 (X247).** In front
      of a local program, a request whose `MCP-Protocol-Version` names a
      version the executor does not serve is refused with 400 (it serves
      2025-11-25, 2025-06-18 and 2025-03-26, and the version a session's
      program answered `initialize` with); a request's method sent with no
      id is refused with 400, where it was answered 202, in front of a
      local program and of an upstream; a notification or a response that
      could not be written to the program is answered 503 or 502, not 202;
      a request other than a call that the program has not answered at
      `timeout` is cancelled for the program. Stated and not changed:
      every message of a program goes on the session's GET stream, since
      nothing says which request it belongs to; and calls that ask for a
      task are checked and receipted as any call. The design, the README
      and the recipe now say that this mode serves clients and programs
      that speak 2025-11-25, and that revision 2026-07-28 is not yet
      supported in it.
    - **A program's standard error** is written on in whole lines, so that
      it never runs into a line of the executor's own; a line of more than
      64 KiB is dropped.
    - **Four claims corrected:** "ended by force" (it was SIGTERM alone);
      the programs beside `sessions.max` (they had no limit); "answered 202
      once it is written" (202 was also the answer where it was not); and
      a session's end "when the executor stops" (a late `initialize`
      outlived it). Each is now true as written.
    - **Tests.** `test/names.test.mjs` (6), `test/lines.test.mjs` (5) and
      `test/http-local-faults.test.mjs` (23), with the made-up servers'
      new ways of misbehaving. The ten faults that the review put into the
      code and that passed every test are each caught now, and each fix
      was undone once to see a test fail. Two of them, the SIGKILL on
      stdio at the client's end and at the executor's stop, fail a test on
      Linux only: on Windows the first signal already ends a program.

  - **Over HTTP, the tool
    server may be a local program.** The HTTP executor could stand only in
    front of an upstream HTTP MCP server, so a tool server that is a program
    on the same computer, speaking MCP over its standard input and output,
    could be reached only over stdio, by one agent. No record of a new kind,
    no cryptography, and no new network request. What changes, in
    `mcp-executor/` (DESIGN.md, section 10.1, choices X231 to X240):
    - **The settings.** The HTTP settings name either `upstream` or
      `server`, never both. `server` and `shutdownWait` are the stdio
      executor's, read by the same code, with the same rules for the
      program, its folder and its credentials. `sessions`: `max` (8) and
      `idle` (1,800,000 ms). `check` describes the program, names its
      credentials and lists what is wrong with either.
    - **One program for each session** (`local.mjs`). The program is started
      when an agent sends `initialize`, and the answer carries a session id
      of 32 random bytes. A session is the agent's that began it; another
      agent that names it is answered 404. A `tools/call` goes through the
      same check, receipt, countersignature and copy, under the slip and
      into the book of the agent that sent it. A request is answered with
      one JSON body; the program's own requests and notifications go on the
      session's GET stream.
    - **When a session ends**, its program is ended: at the agent's DELETE,
      at the program's own end, after `sessions.idle` with nothing from the
      agent, to make room where the agent is at `sessions.max`, at the end
      of the connection made through OAuth it was begun under, and at the
      executor's stop. A program that ends with a call in flight gives the
      receipt it gives on stdio. A program that cannot be run, or that does
      not answer `initialize`, begins no session.
    - **A call's id is its session's**: two sessions of one agent may each
      have a call under the same id at once. In front of an upstream HTTP
      server nothing changes.
    - **`init --http --demo`** writes settings that run the demonstration's
      made-up server (the tools `echo` and `add`) as the local program,
      with the OAuth sign-in, and the two files it needs. Nothing is
      overwritten, and nothing is signed by a stand-in.
    - **Not built, and not tried.** The rules of the Streamable HTTP
      transport are those of revision 2025-11-25 as the builder holds them:
      its text was not fetched for this step. A request of the 2026-07-28
      revision, which has no sessions, is refused in front of a local
      program. The program's credentials are not looked for in what it
      answers, as on stdio. No client but the tests' own has been tried.
    - **Tests**: `test/http-local.test.mjs`, 14 tests, through the
      executor's settings and its HTTP address, with the tests' made-up
      program: a full call by an agent's secret and through the OAuth
      sign-in; two agents at once; a program that ends in the middle of a
      call, and one that will not start; the two limits; twelve programs at
      once; cancelling; the executor's stop; the settings; and
      `init --http --demo`.

  - **Signing in through
    OAuth.** Over HTTP, an agent had to be handed a secret, so a client that
    signs in only through OAuth could not connect. No record of a new kind
    and no cryptography of the executor's own: tokens are random bytes, kept
    as their SHA-256. What changes, in `mcp-executor/` (DESIGN.md, section
    14, choices X201 to X216, X228 and X229):
    - **The settings.** `"oauth": {"issuer", "clients", "state"}`: the
      public address (https, or `http://127.0.0.1:<port>` for tests), the
      URLs of the clients' metadata documents that may connect (none, then
      no client can), and the state file. An agent marked `"oauth": true`,
      in place of `secretHash`, is kept for one connection, with its own
      slip, keys and book. Agents with secrets work as before.
    - **The front door** (`oauth.mjs`): the resource's metadata and the
      server's metadata at their well-known addresses; a 401 that names the
      resource's metadata; the owner's page at `/oauth/authorize`; codes and
      refresh tokens at `/oauth/token`. A client's document is fetched over
      HTTPS (5 KiB, 5 seconds, no redirection), kept for its cache age, and
      its copy used, for at most 7 days, where a later fetch gets no answer
      or a 5xx; any other failure refuses the client. One fetch is made at
      a time for each client, and none for a minute after one that failed.
      The redirect address is matched exactly, but for the port of a
      loopback IP address. PKCE with S256 only. Codes last 60 seconds and
      work once. Access tokens last an hour, for one resource, client and
      agent. Refresh tokens are rotated at each use, and one used twice ends
      the connection. A GET stream opened with an access token ends with the
      token and with the connection. Failed attempts are not counted and
      shut nothing. A request waiting at the page is kept in the page's
      form, under HMAC-SHA-256 with a key made at each start and never
      written. The state file holds hashes only and is written whole,
      through a new file with mode 0600, synced before it is put in place;
      memory is changed only once the file is written, but for the end of a
      connection, which holds at once and is written as soon as it can be
      (below).
    - **The timeout.** With `oauth`, its default is 230,000 ms, under the
      240 seconds a client gives a tool call. Without, it stays 300,000 ms.
    - **The owner's check, by the owner's passkey** (`owner.mjs`,
      `owner-steps.mjs`, `owner-page.mjs`; DESIGN.md, section 14.1, choices
      X218, X221, X223 to X228 and X270 to X279). The command `http` uses
      it. `provared-mcp-executor owner --config â€¦`, on a stopped executor,
      prints a link that works once, within 15 minutes. The owner is one
      plain passkey, made by the library's own `createPasskey` wherever the
      browser offers to keep it; the executor keeps its identifier, its
      public key and the hash of a recovery code, which is shown once. At
      the authorisation page the passkey signs a challenge of the
      executor's (32 bytes, once, 2 minutes, sealed into that one request),
      and the executor checks the answer with the library's
      `checkAssertion`: its own origin, its own host as the relying party,
      the user verified, the signature against the stored key. The setup
      and the first approval take one prompt (below). One owner: a second
      setup is refused, and `owner --reset` removes the owner and ends every
      connection. The pages run only the executor's own scripts, from its
      own address. The passkey belongs to the issuer's host: after a change
      of address the recovery code still approves, and a reset makes a new
      owner.
    - **Changed after a review, before any release** (the commits before
      these had the faults; each fix has a test in `test/review3.test.mjs`
      that fails without it):
      - The owner could approve nothing from a real browser. The pages were
        sent with `Referrer-Policy: no-referrer`, under which a browser
        sends a page's own form with `Origin: null`, and the executor
        refused it. The pages are now sent with `same-origin`; the 303 to
        the client keeps `no-referrer`; `null` is still never taken. The
        test reads the header. Outside the tests, headless Chrome 157 then
        sent the form with the executor's `Origin`, at the local address,
        and an approval by the recovery code went through.
      - Anyone could hold the setup, the approval and the token endpoint
        shut, for as long as they liked: 5 failed owner's checks in 15
        minutes, or 20 failed token requests in a minute, shut that address
        for everyone, and 1,000 requests pushed the owner's waiting page, or
        its challenge, out of memory. Failed attempts are no longer counted
        (X211): what is guarded is 160 or 256 random bits, or a signature.
        A waiting request is now kept in the page's form under
        HMAC-SHA-256, as a JWS with HS256 (X228), and its one challenge is
        sealed into it (X221), so nothing is kept that anyone can push out.
        The answer `too-many-attempts` (429) is gone.
      - A GET stream opened with an access token stayed open after the
        token had expired or the connection had ended. It is now ended
        (X229). A call already taken is still finished and receipted.
      - The page now says: "Approve only a connection you began yourself,
        just now." The settings' list admits a client as a whole, not one
        account at it (X212).
      - On a device whose own passkey gives no PRF, the setup stopped, with
        no owner. The setup page now offers a passkey on a phone or a
        security key after `prf-unsupported` or `not-allowed`, and the
        passkey's `transports` are kept and given back to the browser at
        each unlock (X230). The setup message's `passkey` may hold
        `transports` (X219). Since replaced: the passkey is now a plain
        one, and needs no PRF (below).
      - Where the state file could not be written during a refresh, the
        client's next try was taken for a token used twice, and its
        connection ended. Memory is now changed only once the file is
        written; the client gets 500 `server_error` and keeps what it had.
        The new file is synced before it takes the old one's place. A write
        is tried for 1 second a step, not 10 (X210).
      - A used code shown again by anyone ended the connection. It now does
        so only where the request is otherwise right: the client and the
        PKCE verifier (X207).
      - A client taken off the list and put back got its old connections
        back. At a start, the connections of clients no longer on the list,
        and of agents no longer marked `oauth`, are now taken out of the
        state file (X215).
      - The state file was read before the agents' locks were taken, so an
        `owner --reset` at that moment could be undone. It is now read once
        the locks are held (X210).
      - Every request at the page could make a fetch of the client's
        document; a 404 counted as a moment out of reach, so a withdrawn
        document stayed usable for ever; `no-store` was kept an hour. See
        the front door above (X205).
      - Three places stricter than the standards: the token request needed
        `redirect_uri`, which OAuth 2.1 takes out of it; `resource` in
        capitals was refused; an empty `scope=` was kept and given back.
        `redirect_uri` is now checked only where sent, the scheme and host
        of `resource` may be in capitals, and an empty scope is no scope
        (X207, X214).
      - Said, not changed: an approval leaves no mark in the agent's book
        (X201); a client gives a sign-in request and a refresh 10 and 30
        seconds, not 240 (X213); what a program on the owner's own computer
        does to the pages is outside what the executor sends (X212); the
        tests workflow's note on what `npm ci` installs.
    - **Changed after a second look at those fixes, before any release**
      (each fix has a test in `test/review4.test.mjs` that fails without
      it):
      - A connection that had been ended could come back. Where the state
        file could not be written at the moment a connection was ended (a
        refresh token or a code used twice, or a client off the list at a
        start), the end held in memory only: the file still held the
        connection, and the next start brought it back, with its tokens.
        The executor now tries the write again every second until it is
        made, and once more when it closes. Where the end is still
        unwritten then, `close()` gives the connections (`endsNotWritten`),
        and the command `http` names them on its error output and ends with
        code 1, not 0. The log says `oauth-state-not-written`,
        `oauth-state-written` and `oauth-ends-not-written`. Not covered: an
        executor killed, or without power, while an end is unwritten; the
        next start then brings the connection back (X210).
      - A GET stream stayed open after later refreshes had pushed its
        access token out (a connection keeps its 16 newest). A stream is
        now held under its token and ended when the executor would no
        longer take that token, for whatever reason; the log's
        `stream-ended` names `token-dropped` beside `connection-ended` and
        `token-expired` (X229).
      - A transport name outside the executor's form (`Internal`, say), or
        a ninth name, refused the owner's setup after the passkey had been
        made. Such a name is now left out and the owner set up (X230).
        Since replaced: no transports are sent or kept (below).
      - Two tests that were missing: the answer `not-written` (500) where
        the state cannot be written at the owner's setup, and no challenge
        for a request that has ended or been approved.
    - **Changed before any release: a plain passkey, in place of one that
      had to give PRF** (DESIGN.md, X270 to X279; X217, X219, X220, X222 and
      X230 are marked as replaced). Until this change the passkey's PRF
      output opened a key kept in the browser, which signed the executor's
      challenge, and two packages (`@microtoll/identity`,
      `@microtoll/crypto-core`) did the cryptography. A device whose own
      passkey gives no PRF could not set an owner up at all.
      - The owner is one plain passkey. The executor checks its signature
        with the library's `checkAssertion` and its key's form with the
        library's `checkKey`, loaded from the library's own files, since
        the library does not name them among its exports (X270). The setup
        asks for no attestation: what makes a key the owner's is the setup
        link's code.
      - The setup and the first approval take one passkey prompt (X272).
        The setup page keeps the link's code in the browser's storage for
        the executor's address; the authorisation page, where there is no
        owner, then makes the passkey on Approve, and the one setup message
        makes the owner and approves that one request. The page shows the
        recovery code, and the form goes when the owner presses Continue.
        Where the authorisation page was opened first, the setup link
        offers to show that request again while it waits (10 minutes), and
        approves nothing by itself. The link alone still makes the passkey,
        and says what to do next. Nothing is approved without the owner
        pressing Approve on a page that shows the request and its warning,
        and no one becomes the owner without the link's code.
      - A later approval is one prompt: the passkey signs the SHA-256 of
        the executor's challenge (X273), and the form carries the passkey's
        three values (X274).
      - The recovery code is 160 random bits, made by the executor, in 32
        characters of base32, shown once; only its SHA-256 is kept. Typed
        at the authorisation page it approves that connection (once: see
        the review below). It makes no new passkey: for that the owner is
        reset (X276).
      - One call makes the passkey, with no authenticator named, so the
        browser offers the device, a phone or a security key itself. The
        second button and the passkey's transports are gone (X275).
      - The authorisation page is headed "Approve `<host>` connecting to
        your guard", with the client named by the host of its document's
        address, and no longer by the name its document gives (X279).
      - The issuer may be `http://localhost:<port>`, for tests: a browser
        makes no passkey at an IP address (X277).
      - A state file whose owner is in the earlier form stops the start,
        and says to run `owner --reset` (X278).
      - Gone: the two packages, from `package.json` and
        `package-lock.json`; the addresses `/oauth/owner/passkey`,
        `/oauth/owner/recovery` and `/oauth/owner/lib/identity/â€¦` and
        `â€¦/crypto-core/â€¦` (the pages are served the library's files under
        `/oauth/owner/lib/provared/`); the step of the tests workflow that
        installed them. The executor's only runtime dependency is
        `provared` again.
      - Each check was undone once, to see its test fail, and put back.
    - **Changed after an independent review of the plain passkey, before
      any release** (the commits before these had the faults; each fix has
      a test that fails without it):
      - Any page could put its own request in the place of the one the
        owner had begun. Where there was no owner, the authorisation page
        kept its request in the browser's storage as it opened, with nothing
        pressed; a second such page, opened in the same browser by anyone,
        took the first one's place, and the setup page then offered it as
        "the connection that is waiting". The page now keeps its request
        only when the owner presses "Keep this connection for the setup
        link" on it; a page that merely opens keeps nothing and takes
        nothing out (X272).
      - A recovery code worked for ever, from anywhere, and the log did not
        tell its approvals from a passkey's. A code is now spent by its
        first use: the executor writes a new code's hash in its place and
        shows the new code on a page of its own, whose Continue then
        approves, as the first approval does. The log's line for an
        approval says by which proof: `"by": "passkey"`, `"recovery"` or
        `"setup"`, and `owner-recovery-spent` when a code is used. The box
        is `type="password"` (X274, X276).
      - Where the answer to the setup was lost on its way, the next press
        said only that an owner was already set up and a second setup
        refused, as if someone else had taken the executor. The page now
        says that the answer did not arrive and the setup may have
        finished; the executor's message for an owner that exists says that
        the setup finished, that the passkey approves, and that `owner
        --reset` and a new setup give a recovery code; and Approve on that
        page then asks the passkey just made (X280).
      - The library was named at `^0.7.0`, though the executor takes two
        functions from its files that it does not name among its exports.
        It is now named at exactly `0.7.0`, in `package.json` and
        `package-lock.json`; where the functions are not found, nothing
        starts, and the message says what was looked for (X281). The next
        release of the library should name `checkAssertion` and `checkKey`
        among its exports.
      - Tests that were missing: "Make the passkey" pressed while a request
        waits approves nothing; two answers with one challenge checked at
        the same moment; a setup's or a recovery code's note for another
        owner; the three faults above.
      - Smaller: the JSON answers are sent with `X-Content-Type-Options:
        nosniff`; X221 and the README no longer say that a new challenge
        ends an earlier one, or that the browser's storage is emptied when
        a code ends; the design names a limit of the library's check of
        `crossOrigin` (X270).
    - **Changed after a second look at those fixes, before any release**
      (X282, the founder's decision of 15 November 2026; each fix has a
      test that fails without it):
      - A recovery code is used once and is no longer replaced. The fix
        above made a new code at each use and showed it to whoever had
        typed the old one: so one code that leaked gave approvals without
        end, each with the code the page before had shown, and two presses
        of Approve lost the owner the new code. A code now approves one
        connection and is spent; none is made in its place. The page that
        answers its use says so, and that a new code comes from stopping
        the executor and running `provared-mcp-executor owner --config
        <settings> --reset` on the server. Every authorisation page after
        that says that the code is spent, and has no box for one. The
        setup, `owner --reset` and the passkey are as they were.
      - The code is spent in one step: of two presses, or of several
        answers at once that hold the same code, one is taken and the
        others are refused in words that say the code was already used
        (the log: `owner-recovery-refused`). The state file marks a spent
        code with `"recoverySpent": true` in its owner; a file without the
        mark reads as before.
      - The page's script sends an approval once: Approve and Continue are
        disabled after the first press, and a second press sends nothing.
      - The owner's check approves by answering `true`, or `passkey`,
        `recovery` or `setup`, and by nothing else. Any text that was not
        empty approved before; the check built in answered only those
        three.
      - "Keep this connection for the setup link" says so where it takes
        the place of a connection that was kept before.
      - Where the library lacks the passkey checks, the command prints the
        message on one line and ends with 1; before, the message came
        inside an uncaught error with its stack. No command runs, as
        before.
      - A test of `test/review3.test.mjs` failed now and then on a busy
        computer: the real time that passed between the making of a token
        and the opening of a stream came out of the half second the test
        left the token. The test now sets its clock from the moment before
        the token was made, and leaves two seconds.
    - **Low faults found by a re-check of X282, fixed before any release**
      (each fix has a test that fails without it):
      - A recovery code typed late on its page was spent for nothing: the
        page that follows kept the end of the first page's 10 minutes, so
        its Continue was told that the request had ended, and no page had
        named a limit. That page now has 5 minutes of its own, or what was
        left of the 10 where that is more, and says so (X283). A request
        is still answered once: the executor keeps an approved request's
        id for five minutes past its end. A test now also holds that a
        passkey's challenge gives a request no time of its own: a re-check
        found that a change making every challenge do so failed no test.
      - Approve with a code typed, then Refuse before the answer came,
        sent both forms: the code was spent, the browser went back to the
        client as refused, and the page with Continue was never seen. Once
        an approval has been sent, the page's script now sends nothing
        more, and disables every submit button of the form, Refuse
        included (X284).
      - Two executors whose settings named the same state file, with
        other agents, both started. Each kept its own copy of the owner,
        so the one recovery code approved a connection at each, and each
        wrote over what the other had written. The state file now has a
        lock of its own, of the kind a book has: `http` takes it before it
        reads anything, and `owner` holds it while it works. A second
        program is refused with the code `LOCKED` and is told that two
        executors need a state file each (X285). Where a second `http` on
        the same settings was refused before in words that named a book,
        it is now refused in words that name the state file.
      - Where a program that opens the executor as a library gave it a
        log that threw at the line `owner-recovery-spent`, the code was
        spent and the owner was told only that the check did not pass,
        with no page to continue from. That line can no longer change the
        answer (X286). Nor can the approval's own line, `oauth-approved`,
        one step later: a log that threw there had Continue answered 500,
        with the code spent and nothing approved. The browser is now sent
        back with its code whether or not the log took the line (X286; a
        test in `test/owner.test.mjs` fails without it).
    - **Not built:** no upstream OAuth, no one-command setup, no dynamic
      client registration, no revocation endpoint. No passkey on a device
      (a computer's own, a phone, a security key) has been tried, and no client
      but a stand-in: the tests use a stand-in page and a software passkey,
      and outside the tests the pages were run in headless Chromium 153
      with a virtual authenticator, at `http://localhost`, through to a
      tool call. The recovery code as it now is (X282) was run in a
      headless Chromium browser, version 157, with no authenticator: two
      presses of Approve and of Continue sent one form each. Where a
      client's callback sends the
      browser on to another site, the page's own policy (`form-action`)
      stops the browser there, though the connection was made; the recipe
      says to watch for it.
    - **A recipe**, `mcp-executor/recipes/claude-ai/`: the settings for one
      client, with its limits, and the steps to try the passkey by hand,
      with what to watch the first time.
    - **Tests**: `test/oauth.test.mjs`, 11 tests: the whole flow in plain
      HTTP requests, and each refusal. `test/owner.test.mjs`, 34 tests: the
      page's own steps, and the page's script itself (`owner-page.mjs`)
      fetched from the executor and run on a stand-in page with the
      library's `passkey-browser.js` as served, with a software passkey;
      the setup and the first approval in one prompt, in each order; a
      later approval with an ES256, an RS256 and an Ed25519 key; the
      recovery code; and each refusal (another origin, another relying
      party, the user not verified, another key, a challenge that has
      expired, is for another request or was never given, a request whose
      seal is broken or that has ended, an answer sent twice, a setup link
      used twice, expired or wrong, a second setup, a passkey missing or
      malformed, a state file in the earlier form).
      `test/review3.test.mjs`, 17 tests: the review's findings.
      `test/review4.test.mjs`, 7 tests: the second look's findings, with the
      state file made unwritable while a connection is ended, in the
      executor and in the command as a real process.
      Their shared helpers are in `test/oauth-world.mjs` and
      `test/owner-world.mjs`.

  - **`seal`,
    `acknowledge` and `status`.** The executor could not seal a book, and a
    call sent under a permission that had since been replaced stopped the
    start until the old permission was put back. No record of a new kind
    and no signature of the executor's own making: a seal is the library's
    (format description, section 21.1). What changes, in `mcp-executor/`:
    - **The fixes of 0.4.2.** 0.5.0 holds every change of 0.4.2 (the entry
      after this one), with its tests: in the form carried over for every
      transport (the first item of this entry), and with the last changes
      of 0.4.2, which came with this work: the upstream's own error answer
      to `tools/list` goes on as it is, under any id or a null one, and
      the executor's own error in its place is sent as JSON (X260); and
      the design and the README say which unreadable lists are still
      handed on, and how wide a rule's folding is. Its choices are X241
      and X248 to X250, in section 10.2 of `DESIGN.md`, and X260 after
      X253 there.
    - **Tests on a slow disk** (no change to the program). In `test/central-sealer.test.mjs` the sealer and the
      executor run in one process, and each holds its one thread while a
      line goes to the disk. On Linux in a container here that took 100
      to 370 ms a time, so the tests that gave the sealer 400 or 500 ms
      to answer a question failed now and then, with a time-out at a
      start. They now give it the tests' usual 2 seconds. The one test in
      which a question is meant to time out gives it 1.5 seconds, and
      allows a call or a seal 4.5 seconds (it was 0.4 and 3), still short
      of the 5 seconds a question takes where the settings do not say.
      And a test that failed before it closed its executor left it open,
      so the file never ended under the workflow's command, which has no
      time limit. Now whatever a test leaves open is closed after it
      (`closeAll` in `test/sealer-world.mjs`), and a test whose start
      fails reports that failure, not "w.close is not a function". The
      same disk made one older test in `test/http.test.mjs` fail once
      ("two simultaneous calls by one agent, and by two agents"): its two
      calls of 400 ms had ended before the calls meant to find them in
      progress. They now take 3 seconds, and a call may take 10 there.
      And in `test/review2.test.mjs` the first R1 test, which wants an
      answer "at once, not by the timeout", took over its 2 seconds once:
      a call may now take 10 seconds there, and "at once" is under 5.
    - **The recorder's keys.** The settings may name a recorder:
      `"recorder": {"keys": <file>, "name": <text>, "sealEvery":
      <milliseconds>}`. `keys` makes its key file where there is none
      (Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s) and says on its standard
      error the fingerprint of the key set, which a reader names as the
      recorder they expect; its standard output is unchanged. The name on a
      seal is the executor's `name` unless given. `check` shows the
      recorder, names a missing recorder key file as a problem, and warns
      where the settings name none. Every use of the recorder's key file
      goes through a new file, `sealing.mjs`; the third key signs outside
      the program's own thread, so that a seal, which takes a second or
      two to sign, holds up no other agent.
    - **A seal in a book must be the recorder's.** Where the settings name
      a recorder, every check the executor makes of a book names it as the
      recorder expected, so on a book sealed with other keys the executor
      does not start. `compare` does the same where the recorder's key file
      is there.
    - **`seal`** seals one book now. The seal goes into the book through
      the stub writer, which takes it only if the whole book still passes
      its check with it; nothing is sealed while a call waits to be
      acknowledged, or where the book file is not as the executor left it.
      Over HTTP `seal --agent <name>` asks the running executor
      (`POST /provared/seal`); with `--offline` the files are opened, for an
      executor that is not running. Over stdio there is no address to ask,
      so `seal` takes `--offline` only.
    - **One program at a time.** A book and its copy are locked for the
      program that opens them to write (`stdio`, `http`, a command with
      `--offline`), before it reads them, by a lock the operating system
      takes away when the program ends: a named pipe on Windows, a socket
      in the abstract namespace on Linux, a socket file in `/tmp`
      elsewhere (`lock.mjs`). A second program is refused, having read and
      written nothing; 0.4.1 let a second `http` on the same settings
      write a late receipt for a call the first had in flight before it
      failed to listen. A command with `--offline` is not a start: it
      writes no late receipt by itself, and `seal --offline` does not seal
      a book while a call waits for one. The lock has been tried on
      Windows only.
    - **A seal on a timer**, on both transports, where the settings give
      `recorder.sealEvery` (1,000 to 604,800,000 milliseconds; off unless
      given; under a minute is warned about). At a start a book that holds
      an entry after its last seal is sealed where that seal is at least
      `sealEvery` old, or there is none; then, every `sealEvery`, a book
      that holds an entry after its last seal is sealed. Each agent's book
      has its round to itself, so one agent's long call holds back no
      other agent's seal. No seal is written over a seal. Over HTTP the
      timer starts once the executor is listening. Once the executor has
      ended no seal is asked for; one already waiting its turn is written.
      A seal that cannot be written is logged once for as long as the
      reason stays the same.
    - **The executor's own addresses over HTTP**: `GET /provared/status`,
      `POST /provared/seal` and `POST /provared/acknowledge`, for the
      administrator, whose secret the settings hold as a hash
      (`"admin": {"secretHash": â€¦}`) and the commands read from
      `PROVARED_MCP_EXECUTOR_ADMIN_SECRET`. Without `admin` they answer
      404. An agent's secret is refused there, the administrator's is
      refused at the MCP endpoint, and settings in which the two are the
      same are refused; a request that names an `Origin` is refused
      whatever `allowedOrigins` says; a body is read up to 64 KiB and no
      further, whatever `bodyLimit` is; an executor that is stopping
      answers 503; and `path` may not be `/provared` or under it.
    - **The commands send the secret to the executor alone.** Before a
      command sends the administrator's secret it sends a fresh challenge
      to a fourth address, `POST /provared/hello`, with no secret; the
      executor answers with the signatures of its own two keys over the
      challenge and the address and port it was asked at; the command
      checks them against the executor's public keys (those in
      `executor.keys`, or in a file of the public keys alone) and against
      the address it connected to, and sends the secret on that same
      connection (`identity.mjs`; `DESIGN.md`, X138). Another listener at
      that address, or one that passes the challenge on, is sent no
      secret. The connection is still plain HTTP.
    - **`acknowledge`**, for a call the copy shows as sent, with no receipt
      in the book, under another permission than the one in force. **This
      changes what a start does:** over HTTP the executor now starts, and
      that agent's calls to tools that have a rule are refused (error
      1001) until none waits (a call to a tool no rule names is answered
      as it always is), where
      0.4.1 did not start at all; over stdio it still does not start, and
      names `acknowledge --offline` where it named putting the old
      permission back. A call sent under the permission in force is given
      its late receipt at the start, as before. For each call acknowledged
      a receipt is written from its line in the copy by a stub writer
      opened for the permission it was sent under, dated with the time the
      copy gives for the call, countersigned by the executor at the
      acknowledgement, and taken into the book only if the book still
      passes its check with it. It names the outcome the copy holds, or
      `provared.error` with a new fixed text ("The executor recorded that
      it was sending this call, and has no record of its outcome."); a
      new label, `executor.acknowledged`; and `executor.written-late` with
      a second new text. The three texts and their fingerprints are in the
      README and in `DESIGN.md` (X140), and a test holds them letter for
      letter. A receipt is written only from a line that holds what the
      executor writes, under a permission the book holds that names the
      agent's keys as held now and the executor's keys as held now or as
      held in a key file the settings name under `executor.formerKeys`
      (new: the key files the executor held before, used only to
      countersign such a receipt), dated not after this start; any other
      can only be set aside (`--set-aside`), which leaves the call with no
      receipt and is noted in the copy (`set-aside`) and the log. The book
      is looked at again before each receipt is written, so trying again
      writes none twice. `acknowledge` says what it did and what it did
      not, call by call, and goes on after a call that fails.
    - **`status`**: asked of a running HTTP executor, for each agent the
      permission in force, the book's entries and bytes, its last seal,
      whether it passes its check, why the agent takes no call, and the
      calls waiting to be acknowledged. Over stdio, and with `--offline`,
      it reads the files, writes nothing, and says so
      (`"from": "files"`). It ends with code 1 where a book does not pass
      its check, a call waits or an agent has stopped.
    - **`compare`** lists a call set aside under `setAside`, and does not
      agree where there is one: the executor sent a call the book does not
      show. Where the calls set aside are the only disagreement the answer
      says `onlySetAside: true` and the command ends with code 3, so that
      this known state can be told from a new one (code 1).
      `compare --sealer <fingerprint>` names the recorder a seal must be
      signed by, for whoever compares without the recorder's key file, and
      the answer says which recorder was expected
      (`book.sealersExpected`), or `null` where none was.
    - **`seal`, `acknowledge`, `status` and `compare` refuse an option
      they do not know.** `secret` says that the secret it makes may be an
      agent's or the administrator's.
    - **The copy is written by one program at a time.** Before each line
      the copy file must be the size the executor left it; a line added by
      another program (a command run with `--offline` beside a running
      executor) stops the writing, where it would have given a line a
      number already used.
    - **A book sealed by a central sealer.** In place of the recorder's
      key file, the settings may name a central sealer, the program in
      `sealer/`, which holds the recorder's three keys: `"recorder":
      {"sealer": {"address", "name", "token", "keySet", "timeout",
      "maxUnsent"}, "sealEvery"}`. The token is read from a file or from
      the environment, never from the settings; `keys` or `name` beside
      `sealer` is a problem with the settings; with no `sealer` nothing
      changes. The executor then holds no key that makes a seal. From the
      one place where a line reaches a book file, the leaf fingerprint of
      each new line is sent to the sealer, in order, each at its place
      (the book's first line itself, as the sealer asks), and the seals,
      by the timer and by `seal`, are asked of the sealer and added
      through the stub writer's `add`. The questions and their proofs are
      the sealer's own client, copied into `sealer-client.mjs` and held to
      the sealer's by a test; the leaf fingerprint is the library's. No
      record of a new kind and no signature of the executor's making.
      - At a start the sealer must answer, and what it holds is compared
        with the book file before anything is written: its key set, that
        it holds no more lines than the file, that its latest seal is the
        book's last, and that no later book follows. Where they do not
        agree the executor does not start. A seal the sealer signed that
        the book never took is added then.
      - While the sealer does not answer, no question waits longer than
        `timeout` (5 seconds unless given), the lines wait in the book
        file and are sent in order when it answers again, and no seal is
        asked for. Past `maxUnsent` unsent lines (100 unless given) a
        call is refused with a denial and the code `sealer-behind`.
        `status` shows, for each agent, how many lines are unsent and
        since when; read from the files, it asks the sealer how many
        lines it holds.
      - A seal is asked for only after the sealer has said what it holds
        and has every line. A refusal leaves no seal and the agent at
        work. A seal the book refuses stops the agent: the book and what
        the sealer was sent do not agree. Where the answer to the
        question for a seal does not come, no line is written until the
        sealer has said whether it signed.
      - `keys` says the fingerprint of each agent's key set, which the
        sealer is told when the recorder is added. `compare` expects the
        sealer's key set.
      - Not built with it: bringing a sealer up to date after its record
        was lost or put back; a second book under one permission; going
        on with a book already sealed with a key file; witnesses. The
        sealer listens on 127.0.0.1 only, so the two programs are on one
        computer. `DESIGN.md`, X147 to X159.
      - Tests (`test/central-sealer.test.mjs`,
        `test/central-sealer-e2e.test.mjs`, `test/same-files.test.mjs`; 43
        tests, 38, 2 and 3, with those of the third review and its
        re-check below): the
        sealer's program set up by its own commands and run
        as a process of its own on 127.0.0.1, ended and started again
        while calls go on, with the timer's seals; a sealer stopped and
        started in the same process; the limit of unsent lines; a sealer
        that never answers; an answer with no proof, another key set,
        another number of lines, a place it does not hold, answers out of
        form, and a refusal to sign; a seal whose answer never came,
        added while the executor runs, at the next start, and with a new
        permission waiting; a book cut short, put back and written on,
        and changed in a line the sealer was sent; a sealer behind the
        book's seals; a later book at the sealer; an agent the sealer was
        not told; a restart; a book begun before a sealer was named; two
        agents over HTTP; the status; the settings. 27 defences were
        taken out one at a time, each with its test run after, on
        Windows: every one then failed that test.
    - **Not built.** No outside time-stamp is put beside a seal: its time
      is the recorder's own word. Seals held elsewhere and witnesses are
      later steps. The example settings name no recorder and no
      administrator.
    - **For those who run 0.4.1.** A `recorder` or `admin` member already
      in a settings file (copied from a gateway's, say) was set aside with
      a warning, and is now acted on. `check` warns everyone whose
      settings name no recorder, and `check` and `compare` give new
      members in their JSON. Going back to 0.4.1 after a call was set
      aside: 0.4.1 does not know a `set-aside` line in the copy, and takes
      the call for unfinished again.
    - **Fixes from a second review** (X160 on):
      - Two tests now hold that the executor signs the address it was
        reached at (X138), which none did: the tests reached it at
        127.0.0.1 only. An executor that listens on every address is asked
        at 127.0.0.2 and at 127.0.0.1 and must sign each. And a relay at
        127.0.0.1 passes the command's challenge on to an executor at
        127.0.0.2 on the same port: the executor signs 127.0.0.2, the
        command refuses, and the relay is sent no secret. With the
        executor made to sign the fixed text 127.0.0.1, both tests fail.
        They are skipped, with the reason, on a computer that cannot
        listen at 127.0.0.2. The code is unchanged.
      - `status`, `seal` and `acknowledge` check a running executor with
        its public keys alone (X166). They had read `executor.keys` with
        the reader that loads the private keys, so the administrator had
        to be able to read the keys that countersign every receipt, and a
        file of public keys was refused with "Unsupported key usage for
        Ed25519 key". They now take the public parts of the two keys and
        load no private key. `keys --public-keys <file>` writes the two
        public keys alone to a new file (the form of a key file, with
        nothing private in it), and `--public-keys <file>` names it to the
        three commands in place of `executor.keys`. The check is as it
        was: both signatures, the address and port connected to, the same
        connection. A file that holds no usable keys is said to hold none,
        and nothing is sent; an executor given a file of public keys says
        that it holds public keys only. The README now says that through
        an SSH tunnel, a published container port or a reverse proxy the
        command refuses, which is the defence working, and advises naming
        one address in `listen.host` rather than every address.
      - `acknowledge` no longer prints "Still waiting: <call>: can be
        acknowledged" for a call it has just tried and been refused: it
        gives the reason, says that acknowledging it again gives the same
        refusal until that changes, and that where it will not, the call can
        only be set aside, and then has no receipt.
      - The lock (`lock.mjs`): on Windows the book's folder is written
        out in full by `realpathSync.native`, so that a short name for it
        is the same lock (X162). Where a socket file is the lock (not
        Windows or Linux), clearing one left behind is done by one program
        at a time, the one that makes a folder beside it, and a socket file
        that gives no answer within 2 seconds counts as live (X163). A
        start asks again for the lock for 10 seconds (over stdio, for
        `shutdownWait` and 5 seconds more where that is longer), so that
        a client that restarts the executor while the one before is ending
        is not refused; a command asks once (X164). A test now holds the
        longer wait over stdio (`shutdownWait` at 8 seconds, a lock let go
        after 11): until it, taking that rule out made no test fail. The
        code is unchanged.
      - A `done` line of the copy names the kind of outcome (`"outcome":
        "answer"`, say) only beside the outcome's documents (X165). Where
        those documents could not be made and the book could not be
        written either, the line had named the kind with no document, and
        a receipt acknowledged from it then said "The executor recorded
        that it was sending this call, and has no record of its outcome."
        beside a copy that held its kind. The text is as it was.
      - An SLH-DSA signature is made one at a time, for every recorder in
        the program (X161). Four books sealed at once had filled Node.js's
        thread pool, which has four threads unless set, and another
        agent's call had then waited some 2.5 seconds for them; it now
        takes a small part of that.
      - `POST /provared/hello`, which needs no secret, reads a body of 256
        bytes at most, waits 5 seconds at most for it, and takes 8 such
        questions at once; a ninth is answered 503 with nothing signed
        (X160). Before, it read up to 64 KiB for as long as `timeout`, for
        any number of callers. The third review, below, changed the 5
        seconds to 1 and what the 8 count.
    - **Fixes from a third review** (X167 on), of the book sealed by a
      central sealer and of the fixes above:
      - One seal that comes two ways is added once, and the agent is not
        stopped (X167). After a seal's answer was lost, the executor's
        own question to the sealer and a seal asked for in that moment
        (the timer's next round with `sealEvery` at 2,000, or `seal`)
        were both handed the same seal. The book took it once and
        refused it the second time, and the agent was then stopped with
        "the book and what the sealer holds of it do not agree", which
        was not true: the book was sound, and a restart started. Now
        nothing is added where the book's last line is that entry byte
        for byte, the book's check takes it as a sound seal, and its
        fingerprint is the one the sealer named; any other entry goes to
        the book as before, and a refusal still stops the agent. The link
        to the sealer also hands one seal to the agent's turn at a time.
        Five tests in `test/central-sealer.test.mjs`: the two ways; an
        entry changed in one member; the book's last line handed back
        where it is a receipt, and where it is the last seal under
        another fingerprint; and one hand-over while the turn does not
        come. Each of the five parts of the fix, undone, makes its test
        fail.
      - Unfinished questions to `POST /provared/hello` no longer keep the
        administrator's commands out (X168). The limit of 8 above counted
        a question from the moment it arrived, for up to 5 seconds, so a
        caller with no secret who held 8 bodies begun and never ended,
        each begun again when it was given up on, had `status`, `seal`
        and `acknowledge` answered 503 and ended with code 2. Now a body
        has 1 second; a question takes a place only once its body has
        arrived whole, for the two signatures alone; and of the 8 places
        callers at one address hold 4 at most. A command that is told
        `busy` asks again after half a second, five times in all, and
        then says that what answers is busy, where it had said that it
        "did not show that it is the executor". Not closed: programs at
        one address count as one caller, and a caller who sends whole
        questions without pause still costs two signatures each. Four
        tests in `test/seal-http.test.mjs` (three new, one changed): the
        1 second and 20 unfinished questions that take no place; twelve
        unfinished questions begun again and again while `status` and
        `seal` end with 0; the 8 and the 4, with a signer made slow; and
        a listener that answers `busy`, asked five times and sent no
        secret. Each of the six parts of the fix, undone, makes its test
        fail.
      - An answer at the sealer's address is read up to 8 MiB and no
        further (X169). The client read the whole answer into memory
        before it looked at its size or its proof, so whatever listened
        at `recorder.sealer.address` (any program on the computer, while
        the sealer is stopped) could fill the executor's memory: with 200
        MB offered, all of it was read and memory rose from 54 MB to 679
        MB. A length declared over the limit is now refused before the
        body is read, and a body is read in pieces with a count that
        stops the reading at the limit: of the same 200 MB, 16 MB left
        the listener and memory stayed at 80 MB. The change is in
        `sealer/sealer.mjs` (`connectSealer`; `provared-sealer` stays
        0.1.0, not published) and in the executor's copy,
        `sealer-client.mjs`, which the test `same-files.test.mjs` holds
        the same. One test in each package, with 96 MiB offered, its
        length declared and not; each part of the fix, undone in either
        file, makes a test fail.
      - Seven defences that no test held now have one each (no change to
        the program). The review took 52 defences out one at a time; for
        seven, no test failed. (1) The test that holds the executor's
        copy of the sealer's client to "no other code"
        (`test/same-files.test.mjs`) let through a line of code that
        began with a comment mark, such as `/** */ run();`. It now takes
        for a comment only a line that begins `//`, a block comment on
        one line that ends at its first closing mark, or a block that
        opens and closes on lines of their own with every line between
        beginning ` *`; a line that holds a carriage return or a line or
        paragraph separator counts as code. A second test puts fifteen
        such lines into the copy and holds that each is found. (2) At
        the end of a book's link to the sealer, the last try to send
        what is unsent, and nothing sent after it. (3, 4) Over stdio and
        over HTTP, the link is ended, with that last try, before the
        lock on the book is let go: the lock is refused while the
        sealer's answer is out. (5) A seal that the sealer hands back
        under another fingerprint than the one it named as its latest is
        not added. (6) The status read from the files shows nothing held
        by a sealer that signs with another key set than the settings
        name. (7) `keys` runs on settings whose `recorder.sealer` names
        an address and no token yet (X157), in the end-to-end test and
        in the test of the settings. With each of the seven taken out
        again, its test fails.
      - What was left of the timing fault of the tests (no change to the
        program). The short time limits are gone from
        `test/central-sealer.test.mjs` ("Tests on a slow disk", above).
        The error that hid a failed start, "w.close is not a function",
        could still come from the other tests: a world made for the
        stdio executor or the HTTP executor and not yet opened had
        nothing to close it with. Both now have (`test/world.mjs`,
        `test/http-world.mjs`; over HTTP it closes the made-up
        upstream), one test holds that, and the end-to-end test closes
        its executor where it fails part-way, so that the file ends.
      - The count of tests under "Tests", below, said 41 for
        `test/seal.test.mjs` and `test/seal-http.test.mjs`, the number
        before the second review. The two files hold 29 and 24, and the
        entry says so.
      - The lock, after a re-check of an older `lock.mjs` (X171). Where
        the lock is a socket file (not Windows or Linux), one left in
        `/tmp` by another user's program, an executor once run as root,
        say, may not be connected to and cannot be cleared away by this
        user. The start was refused with "An executor is running on the
        book â€¦", whether or not one was. It is still refused, and the
        refusal now names the file and says that that user or an
        administrator takes it away (`lockAt` puts `notAsked` and `why`
        on its `LOCKED` error). One test, which runs for a user other
        than root on a system with socket files; it fails with the fix
        taken out. The re-check's two other points do not hold here, and
        the code for them is unchanged: two programs taking over one
        socket file left behind (X163 closes it: on Linux, with Node.js
        told it runs on another system, never two holders at once in 60
        rounds of 8 starts, 150 rounds of 2 and 30 rounds of 8 starts
        that ask again; with X163's folder taken out, 28 of 30 and 15 of
        60), and a second lock on Windows through a folder's short name
        or `\\?\` in front (X162 closes it; the test of the short name
        now holds `\\?\` too). The README names a share of the computer's
        own drive as a path that is another lock.
    - **Fixes from a re-check of the third review's fixes:**
      - One seal that comes two ways is passed over wherever the book
        holds it, not only as its last line (X167). Where a line was
        written between the two arrivals (the denial of a call for a tool
        no rule names), the second was put to the book, which refused it,
        and the agent was stopped with the same untrue message as before.
        Now nothing is added where any line of the book is the entry byte
        for byte and the book's check takes that line as a sound seal under
        the fingerprint the sealer named (`heldSeal` in `executor.mjs`).
        One test in `test/central-sealer.test.mjs`, with a denial written
        between the two; it fails with the old condition put back.
      - A test of `heldSeal` by itself, so that each of its conditions is
        held: a seal the book's check faults is not taken as held. No
        running executor is known to reach that case, since the writer's
        book always passes its check, so no other test failed with the
        condition taken out; this one does.
      - The count of the central sealer's tests, above, gave
        `test/same-files.test.mjs` 2 tests; it holds 3, one of them of the
        gateway's files. The README now names `::$DATA` after the book
        file's name as another lock on Windows, as X171 said it did.
      - Where the lock is a socket file (not Windows or Linux), every try
        for it is now made under the folder `<socket file>.clearing`
        (X163). The first try to listen had been made without the
        folder, so two programs could hold one lock at once where a third
        let it go in that moment; X171 had said X163 closed this, which
        held only for a file left by a program ended by force. X163 and
        X171 now say what is true. A folder left by a program stopped in
        that moment now refuses the lock also where its place is empty.
        One test in `test/lock.test.mjs`, which runs where there are
        socket files (on Linux, with Node.js told it runs on another
        system for the two locks): while the folder is there nobody
        listens, through `lockAt`, `lockFiles` or `lockState`. It fails
        with the old `lockAt` put back.
      - Two more files of another user's in `/tmp` are named in the
        refusal of the lock (X171): a socket file that this user may
        connect to and where nothing answers, and a link that leads
        nowhere. Both had been refused with "An executor is running â€¦"
        alone. `lockAt` puts `notCleared` and `why` on its `LOCKED`
        error. One test in `test/lock.test.mjs`, for both, which runs
        where there are socket files and makes taking the file away fail
        as `/tmp` does; it fails with the fix taken out.
      - The sealer's client follows no redirect (X288). `connectSealer`
        followed one, so whatever listened at the sealer's address could
        have the question, with its five `provared-sealer-` headers but
        not the token, sent again to an address it named. Its `fetch`
        now carries `redirect: 'error'`, and an answer of 301, 302, 303,
        307 or 308 makes the question fail. The change is in
        `sealer/sealer.mjs` (`provared-sealer` stays 0.1.0, not
        published) and in the executor's copy, `sealer-client.mjs`. One
        test in each package (`sealer/test/sealer.test.mjs`,
        `test/central-sealer.test.mjs`); each fails with the line taken
        out of its file.
      - A start asks again for the lock on its state file for 10
        seconds, as for a book's lock, before it is refused (X289, the
        founder's decision; it amends X285 for starts). It had been
        refused at once, so a client that started the executor again
        while the one before was still ending was turned away. The
        command `owner` still asks once, as every command does (X164).
        One test in `test/owner.test.mjs`: a start that waits and then
        starts once the executor before has closed, and one refused once
        its time is up; it fails with the old call put back. The test of
        X285 asks once.
    - **Tests** (`test/seal.test.mjs`, `test/seal-http.test.mjs`; 53
      tests, 29 and 24, with those of the second and third reviews): the
      seal checks under the recorder's keys with the library's
      checker, chains to the seal before, and a reader who names another
      recorder is told; other keys in the recorder's file stop the start;
      a changed book file is not sealed; the timer's rules, on both
      transports, with a stop that comes while a seal waits its turn, one
      agent's long call beside another's seal, and a start that cannot
      listen; a seal that does not hold up the program; a command with
      `--offline` beside a running executor with a call in flight, which
      is refused, and the call's true receipt; a waiting call stops a
      stdio start and holds one agent over HTTP; the acknowledged
      receipt's permission, date, documents and countersignature, with
      the fixed texts and their fingerprints written out; a former key
      file; eighteen lines from which no receipt is written, each with its
      reason; other agent keys, other executor keys and a permission the
      book does not hold; a receipt the library refuses, and the calls
      after it; no second receipt after the copy could not be written; a
      call set aside stays so, and `compare` reports it, with its exit
      codes and the recorder it expected; the addresses refuse no secret,
      an agent's secret, a web page, a body that goes on past 64 KiB and
      a wrong address, and answer 503 while stopping; the challenge the
      executor signs, and the commands sending no secret to another
      listener, to one that passes the challenge on, or on another
      connection; unknown options; and the commands, run as real
      processes, over stdio and over HTTP. 75 defences were taken out one
      at a time, each with the test named for it run after, on Windows:
      every one then failed that test. An independent review had taken out
      33 and found five that no test held (two checks of the timer at its
      end and both together, the 503 while stopping, and `compare` naming
      its recorder); the timer now has one such check, and each of the
      three is held by a test.
    - **The README** has a new part, "Sealing, acknowledging, and what the
      executor says about itself", the settings `recorder`, `admin` and
      `executor.formerKeys`, and, under what it does not do: no outside
      time-stamp, where the recorder's keys are, where the lock does not
      reach, that the administrator's secret travels in the clear, and
      that a call set aside has no receipt. Under "A central sealer": the
      settings, how it is set up, what is sent, what happens where the
      sealer does not answer, at a start and at a seal, and what such a
      seal shows and does not.
    - **Versions.** 0.5.0 in `package.json`, `server.json` (both fields)
      and the command's `--version`; the `npm pack` file name in the
      README; `sealing.mjs`, `sealer-client.mjs`, `lock.mjs` and
      `identity.mjs` in the package's files. The library range stays
      `^0.7.0`.
    - **Choices** are X120 to X146 in `DESIGN.md`. X138 (how a command
      knows the executor), X140 (the label and the three texts of an
      acknowledged receipt), X141 (former key files) and X142 (`compare`
      after a call is set aside) wait for the founder's review, and the
      texts are not to change once 0.5.0 is published. For a central
      sealer they are X147 to X159; X152 (the sealer must answer at a
      start), X153 (the limit of unsent lines) and X156 (no line while a
      seal may have been signed) wait for the founder's review. Those of
      the second review are X160 to X166, those of the third X167 to
      X171, and those of the re-check of its fixes X288 and X289.
  - **A one-command recipe for claude.ai, with Docker Compose**
    (`mcp-executor/recipes/claude-ai/compose/`; nothing in the package
    changes, and the recipe is not in its files). The guard and Caddy, in
    two containers, started by `docker compose up -d --build`, with a
    third that runs once to give the data folders to their users. The
    guard's image is built on the server with `npm ci`, from a lockfile
    with SHA-512 hashes, on the official Node.js image, following the
    Node.js 24 line (`node:24-bookworm-slim`); a build argument takes a
    packed `.tgz` instead. Caddy's official image follows the 2.11 line
    (`caddy:2.11-alpine`), and Caddy gets the certificate for the domain
    set in `.env`. So the update command brings the security fixes of
    Node.js and Caddy, and may bring a patch the recipe was not tried
    with; the README says how to go back to the versions tried (Node.js
    24.22.3, Caddy 2.11.9). The lockfile's entry for the executor 0.5.0
    is that of a pack of this tree, to be made again from npm once 0.5.0
    is published; with a packed copy, `npm install` keeps the library's
    hash. The README takes the recipe from a signed release tag of the
    repository, checked with `git tag -v` against `.github/release-signers`. The guard keeps its rule and listens on
    127.0.0.1 in Caddy's network, so its port is published nowhere; only
    80 and 443 are. Everything kept is in three plain folders beside the
    compose file. Each container runs as a user of its own, read-only,
    with every capability dropped and no new privileges. The first-start
    program (`start.mjs`) runs the guard's own commands: it writes the
    demonstration's settings, sets the issuer and claude.ai's document,
    makes the keys, says in the log what the person must sign and where
    the file and the thumbprint go, and waits; it never fills in either.
    Once `check` passes it writes the owner's link to a file only the
    guard's user can read, before the guard runs, and then starts it.
    Where Caddy's container is restarted on its own, the guard stops after
    a minute so that Docker starts it in Caddy's new network. One update
    command, and a weekly timer that is off until switched on. The README
    of `recipes/claude-ai/` gives the steps, what to back up, and what has
    and has not been tried. Tests: `mcp-executor/test/recipe-compose.test.mjs`
    (17), and `mcp-executor/test/recipe-compose/docker-check.sh`, outside
    `npm test`, run in Docker on one computer with Caddy's own
    certificate authority: every check passed, after its first runs
    had found the rules file left readable by others (644) and the guard
    cut off by a restart of Caddy alone, both now mended. Not tried on a
    real server, with a public certificate, or with claude.ai. Choices
    X313 to X343, in `tmp/choices-3.7e.md`.
  - **After four reviews: time-stamps, the recipe, the lock and the local
    program** (choices from X344, in `tmp/choices-fixes-2026-11-17.md`).
    - **Which service signed a time-stamp (X344 to X347).** The check of a
      service's answer shows it was made for this seal, not who made it:
      over plain `http:`, anyone in between could answer with a key of
      their own and have the time-stamp kept and reported. A new optional
      setting, `authority` in `recorder.stamp` (executor, gateway) and in
      the sealer's `stamp`, names the service's certificate by its
      fingerprint, or a list of up to 16, as a checker's `stampServices`
      does; a time-stamp signed by any other is not kept
      (`stamp-not-given`, naming who signed it), and the seal goes in
      without it. The library's `askForStamp` and `stampService`
      (`provared/net/timestamp`, part of `provared` 0.9.0, published on 21 November 2026
      through the workflow) take `authority` and pass it to `checkStamp` as `trusted`;
      `stampAuthority` reads it. Whether or not it is given, a seal that
      carries a time-stamp answers `stampedBy`, the fingerprint of the
      certificate that signed it, in the `seal` answer (executor,
      gateway, the sealer's `/seal`), the executor's `sealed` event, the
      commands' "Sealed:" line and `status` (with the last seal). `check`
      (and the sealer's start) warns where the address begins `http:` and
      no `authority` is named. Left out, everything is as before. The
      reason given for taking `http:` (X291, DESIGN X298) said the
      time-stamp was checked "not by the connection"; it now says what
      the checks do and do not show.
    - **A central sealer's time-stamp is said (X348).** A seal from a
      central sealer answers `stamped: true` with `stampedBy` where it
      carries a time-stamp, and `stamped: false` (printed "with no
      time-stamp") where it carries none; before, both looked the same.
    - **The recipe: the guard's own addresses stay on the server (X349).**
      Caddy answers 404 itself for `/provared` and everything under it;
      before, `status`, `seal`, `acknowledge` and `hello` answered from
      the internet once the settings named an administrator's secret.
      The Docker check holds that Caddy's 404 has an empty body, read
      from curl's own output (it had first looked for a file that curl's
      container wrote, which the check does not see, and so passed
      whatever the body).
    - **The recipe: a command that writes is refused beside the guard in
      any network (X350).** While the guard runs, its start listens on
      `guard-data/guard-running.sock`, and `owner`, `http`, `stdio` and any
      command with `--offline` are refused (code 2) where something
      answers there. Before, for up to a minute after Caddy's container
      was restarted alone, such a command did not see the guard's lock and
      ran beside it. The start now looks for Caddy's port every 5 seconds
      and stops the guard after three misses (was 15 seconds and four).
      The README says to run every command that writes with the guard
      stopped.
    - **The recipe: an agent added later (X351).** Where an agent that
      waits for its permission has no entry in `permission-entries.json`,
      or no key file, the start makes them and writes the file again,
      keeping the one before beside it. The README gives the order that
      keeps the guard running for the first agent meanwhile.
    - **The recipe: the provisional lockfile is marked (X352).**
      `compose/package-lock.provisional.json` says that the lockfile's
      entry for the executor 0.5.0 was not made from npm (its hash is
      known not to be npm's), and `tools/release/check-recipe-lock.mjs`
      stops while that file is there, or, with `--registry`, where the
      hash is not the one npm gives. The README's release rule: publish,
      make the lockfile again from npm, take the mark away, run the check,
      and only then cut the tag. The release workflows are not changed:
      the check is run by hand.
    - **A local program's standard error is bounded (X353).** At most 256
      KiB of each program's is written on in each second, and nothing while
      more than 1 MiB already waits; the rest is dropped and counted in the
      log (`server-stderr-dropped`). Before, a program writing without pause
      made the executor hold it all in memory on Linux, and stopped it for
      every agent on Windows.
    - **The sealer's wait for a time-stamp is shorter (X354).** Its
      `stamp.timeout` is 2.5 seconds unless set (was 4). While the seal is
      signed and the service is asked, the sealer answers no other
      recorder, and a recorder's question times out after 5 seconds: with
      a service that never answered, another recorder's question was
      answered after 4.1 to 4.5 seconds here, where with 4 it timed out.
    - **The executor's and the gateway's wait for a time-stamp (X355).**
      `recorder.stamp.timeout` is 5 seconds unless set (was 10), and at
      most 20 (was 60). The executor's `check` warns above 8 seconds: a
      seal holds the book's files that long, and an executor started on
      the same files meanwhile waits 10 seconds for them and is refused.
    - **A service's words, shown plainly (X356).** What a time-stamp
      service or a sealer says is shown with padding characters (no-break
      and wide spaces, the blank Hangul and braille characters) as plain
      spaces, no more than one accent on a letter, its own quotation marks
      changed so that they cannot end the quoted part, and cut at a whole
      character. The commands' printing of a sealer's words follows the
      same rule (`plainText`, now in `sealing.mjs` and `gateway.mjs`).
    - **The recipe after a restart of the server (X357).** The Docker check
      stopped both containers and started them again in each order: Caddy
      first, both came back; the guard first, it could not join Caddy's
      network and stayed stopped, as Docker does not try a failed start
      again. A unit in `compose/boot/`, off until switched on, runs
      `docker compose up -d --no-build --pull never` once Docker has
      started, which starts Caddy and then the guard; the README says how
      to switch it on, and to run `docker compose up -d` after a restart
      without it.
    - **The recipe: smaller things the review found (X358 to X360).** After
      `check` finds a problem, the start runs it again at every look (every
      10 seconds), whichever file was mended, and says the same problems
      once; before, it looked again only once the settings or a permission
      changed, and mending a token file left it waiting silently. A command
      run through the start (`keys --out`, for one) writes its files for
      the guard's user alone, as the start does (the umask is set for
      every command). The image makes `package.json`, `package-lock.json`
      and `start.mjs` readable whatever their modes on the server (`COPY
      --chmod=0644`): a copy made under umask 027 or 077 stopped the guard
      at once. The README says to run `chmod 644 Caddyfile` there; that
      the update command starts a guard stopped on purpose, and leaves the
      images it replaces on the disk; that `caddy:2.11-alpine` stops
      bringing fixes once Caddy has a newer line; that the line `tag <tag>`
      of `git tag -v` must name the tag asked for, and that no second place
      publishes the release key's fingerprint yet; where the passkey's
      thumbprint is shown; how an upstream in a container of its own
      would be reached; the Docker tried, BuildKit, and that rootless
      Docker and user-namespace remapping were not tried; and that two
      copies of the folder on one server are one Compose project. The
      reason given for X332 is corrected to match.
    - **The lock's refusals, where the lock is a socket file (X361,
      X362).** Not Windows or Linux. A program that finds the folder of
      another's clearing looks again for 100 milliseconds, a command too,
      and says the folder was left only where it is more than 5 seconds
      old; before, two programs that asked at one moment were told that a
      folder was left, which was gone. A socket file that nothing answers
      at and that this user may not take away now has a refusal of its
      own, which no longer begins "An executor is running", and guesses
      whose the file is only for `EPERM` and `EACCES`. The README and X163
      now say that any program ended by force in its first try for the
      lock can leave the folder, which then refuses every later start
      until it is taken away; that is unchanged.
    - **A busy program past the bound is given its time (X363).** Where
      more than 16 MiB wait for a local program, the session still ends
      and the message is refused with 503, but the program is given
      `shutdownWait` before it is signalled, as at every other end; before,
      a program busy with a long call was ended at once, part-way through
      it. A test now holds that a session begun once the stop has begun
      starts no program, before the sessions are closed (`noMore`).
    - **The recipe's mark from the start's first step (X364).** The start
      listens on `guard-data/guard-running.sock` from its first step, not
      only once the guard runs. The Docker check found an `owner --reset`
      taken while a start that Docker had begun again was still at its
      first steps, in Caddy's new network; such a command is now refused
      too. The Docker check also holds that the image's three files are
      644 when the copy's were 600.
    - **A second start is refused (X365).** `docker compose run --rm guard`
      with no command, while the guard runs, now ends with code 2 before it
      makes a mark of its own; before, it took the running guard's mark
      away, and a command that writes was then refused only by the guard's
      lock.
    - **The boot unit's limits said (X366).** The recipe's README says that
      the unit runs once at each start of the server, not after a restart
      of Docker alone, and that it starts a guard stopped on purpose.
    - **The release check refuses a mistyped option (X367).**
      `tools/release/check-recipe-lock.mjs` took its first word as allowed
      where `--recipe` was not given, so `--registy` ended with code 0; it
      now stops on any word that is not an option, and on `--recipe` with
      no folder.
    - **Caddy away for longer (X368).** The recipe's README says that where
      Caddy is not running when Docker starts the guard again, the guard
      stays stopped until `docker compose up -d`. The Docker check found
      this with Caddy stopped for 45 seconds, and holds that
      `docker compose up -d` brings the guard back; it also holds that a
      second start beside the running guard is refused.
    - **What was tried with claude.ai, corrected.** The recipe's README
      said claude.ai had not been tried. It now says that the recipe has
      not been, and that the guard on its own was, on 15 November 2026: an
      earlier build of this version, on a server with a Let's Encrypt
      certificate, connected to claude.ai after one passkey prompt.

- **The site and the READMEs after `provared-mcp-executor` 0.4.2.** The
  home page, "Provared in plain words", "Over the limit", the top-level
  README and the executor's README tell readers to use 0.4.2 or later
  and link to the security advisory GHSA-q53c-6wvv-gfj8; the home page's
  "What is new" names 0.4.0, 0.4.1 and 0.4.2, and its status line gives
  the guard's version beside the library's. The pages, the READMEs and
  the descriptions of the recorder beside Claude Code (`package.json`,
  the plugin's `plugin.json` and the marketplace) no longer say it
  records every tool call: eight tools, those in `NOT_RECORDED` in
  `integrations/claude-code/actions.mjs`, are not recorded, and the
  README names them. Its README says the plugin installs library 0.8.0
  from its lockfile, where it said 0.6.0. The executor's README says the
  MCP Registry lists 0.4.2. The record page and its generator, tools/make-record-page.mjs, name the eighth tool left out, the end of the conversation. No other code changes.
- **`provared-mcp-executor` 0.4.2 (15 November 2026): a security fix for
  two weaknesses. In front of a tool server whose JSON reader ignores
  capitals, or of one that ends a line at a bare carriage return, an
  agent could have a tool call run that the executor never checked, with
  no receipt; in front of the first, also a tool other than the one its
  receipt names, or a change that a rule on content forbids. 0.4.2
  refuses the messages that did the first, and writes every message to
  the server as one line, which ends the second. Every version from 0.1.0
  to 0.4.1 has both weaknesses.**
  - **The second weakness: one message read as several lines.** The
    executor ends a line at a line feed alone. Some readers end one at a
    bare carriage return too: `node:readline` does (and at U+2028 and
    U+2029), and so does a text reader with universal newlines. Python's
    `io.TextIOWrapper` reads that way unless told otherwise; the official
    Python SDK's stdio server reads through one; and Python opens its
    standard input that way on Windows. JSON allows a carriage return
    between its values. So one line of the agent's,
    `{"jsonrpc":"2.0","id":"outer","method":"ping","params":{"a":[<CR>{"jsonrpc":"2.0","id":"hidden","method":"tools/call","params":{"name":"order","arguments":{"total":999999}}}<CR>]}}`,
    was a `ping` to the executor, which passed it on with no check, and
    three lines to such a server, the second a call of `order` for
    999,999: it ran, with no receipt and no denial, and its answer came
    back to the agent. A text argument with U+2028 in it reached a server
    that reads with `node:readline` as two lines, was not answered, and
    was recorded as "outcome not known". **Who was exposed:** anyone who
    runs the executor on stdio in front of a tool server that ends a line
    at a bare carriage return. A server that ends a line at a line feed
    alone is not affected. Servers built on the official Python SDK read
    standard input through `io.TextIOWrapper`, so they end a line at a
    bare carriage return; other servers have not been checked. Over HTTP
    the executor sends the upstream a body, not lines,
    and is not affected. **What 0.4.2 does** (`oneLine` in
    `mcp-executor/jsonrpc.mjs`, used by `toServer` in
    `mcp-executor/executor.mjs`; `mcp-executor/DESIGN.md`, X248): every
    message written to the server's standard input is first made one
    line, and is still the same JSON: a line feed or a carriage return
    between its values becomes a space, and U+0085, U+2028 and U+2029 in
    a text are written as their JSON escapes. This makes it one line for
    a reader that takes the bytes as UTF-8. A reader that takes them as
    another encoding may still cut a line inside a character beyond
    ASCII; such a cut falls inside a text, where quotation marks are
    escaped, so it can spoil a message and cannot hide a call. `oneLine`
    is a new export of `provared-mcp-executor/jsonrpc`. **Tests:**
    `mcp-executor/test/lines.test.mjs` sends such messages in front of
    the made-up server reading each of the two ways (`FAKE_LINE_ENDS` in
    `test/fake-server.mjs`); both of those tests fail without the fix.
    The demonstration's made-up server (`demo/server.mjs`) still reads
    with `node:readline`; behind the executor it is now sent one line
    for each message.
  - **The first weakness: what was weak.** The executor reads member names exactly. Some
    JSON readers do not: the standard JSON reader of the Go language
    takes `Method` for `method` and `Name` for `name` in the fields it
    knows, the later one winning. A message with both was therefore one
    message to the executor and another to such a server. A review ran
    three, in front of a made-up server that reads names that way:
    `{"method":"ping","Method":"tools/call", ...}` was a ping to the
    executor, which passed it on with no check, no receipt and no
    denial, and a tool call to the server, which ran it;
    `{"method":"notifications/initialized","Method":"tools/call","ID":13, ...}`
    likewise; and `{"name":"echo","Name":"order","arguments":{},"Arguments":{"total":999999}}`
    was checked, receipted and countersigned as `echo` with no
    arguments, and run as `order` for 999,999. **A rule on the content
    of a change could be skipped the same way.** A rule reads the
    arguments by the names it is given. With the README's own example
    rules, `write_file` with `{"Path":"config/settings.json","content":"{\"scan\":true}"}`
    was let through and receipted as an allowed change: the rule's
    `when` found no `path`, so the rule did not apply, and such a server
    read `Path` as `path` and wrote the file with the scan on. An
    `edit_file` of `settings.json` under `Path`, and a lone `"SCAN": true`
    inside the content, passed in the same way. Rules on content came
    with 0.2.0, and every version from then to 0.4.1 does this.
  - **Who was exposed.** Anyone who runs the executor, on stdio or over
    HTTP, in front of a tool server whose JSON reader ignores capitals
    in member names. A server that reads names exactly, as the JSON
    readers of Node.js and Python do, is not affected. Servers built on
    the official Go SDK before 1.3.1 ignore capitals
    (GHSA-wvj2-96wp-fq3f); other servers have not been checked. Every
    version from 0.1.0 to 0.4.1 has the weakness: `readMessage` in
    `mcp-executor/jsonrpc.mjs` has looked only for a name given twice
    exactly since the first version.
  - **What 0.4.2 does** (`readMessage` in `mcp-executor/jsonrpc.mjs`,
    `handleCall` and `filteredList` in `mcp-executor/executor.mjs`;
    `mcp-executor/DESIGN.md`, X241). A message with a member at its top
    level other than `jsonrpc`, `id`, `method`, `params`, `result` and
    `error`, written exactly so, is refused, from the agent and from the
    server. A message of the agent's is refused where its `params` hold,
    in one object at any depth, two names that differ only in capitals
    (or in the long s for `s`, or the Kelvin sign for `k`); where a
    `tools/call` writes `name`, `arguments` or `_meta` in other
    capitals, or a `notifications/cancelled` writes `requestId` so; and
    where the `_meta` of a `tools/call` writes `red.prova/call-id` or
    `traceparent` in other capitals. The agent is answered with the
    error -32600, as for a member name given twice, and nothing is sent
    to the server. A server's answer with such a member at its top level
    is treated as any line the executor cannot read: the receipt says
    the answer could not be read and names no result. In a `tools/list`
    answer that the executor filters, a tool with a second name in other
    capitals is not shown, and a second list (`Tools`) is left out.
  - **What 0.4.2 does for the rules on content** (`unreadableAt` and
    `holds` in `mcp-executor/rules.mjs`; DESIGN.md, X249). Where a rule
    reads a pointer, in its `when` or its `test`, and an object on the
    way holds a member that is the pointer's name in other capitals and
    is not written as the rule reads it, the call is refused as
    `content-unreadable`, with a denial: `Path` where the rule reads
    `/path`, `SCAN` in the content where it reads `/scan`. So is a call
    where the way to the pointer stops, with names still to follow, at a
    value that is neither an object nor a list: a rule that tests
    `/debug` in `options` refused `{"options":{"debug":true}}` and let
    through `{"options":"{\"debug\":true}"}`, a text that a server may
    read as the object. Such a value was taken for absent before.
  - **The reading never ends the executor** (`foldedInParams` and
    `readMessage` in `mcp-executor/jsonrpc.mjs`; DESIGN.md, X250). The
    check for names in other capitals walks the message's text as it
    came, and calls nothing that calls itself. And a message nested more
    than 256 levels deep is not read at all (`MAX_DEPTH`): the agent's
    is refused with -32600 under its id; the server's is treated as any
    line the executor cannot read, so that a call's receipt says its
    answer could not be read. A list of tools that the executor is to
    filter (`hideUnlisted`) and cannot read, where it can match the
    answer to the request, is no longer handed to the agent as it was,
    which showed it the tools the executor is to hide: the request is
    answered with the error -32603 under its id, and the log says
    `tools-list-not-read`. That is, on stdio, a line whose one top-level
    id is the request's; over HTTP, a JSON body, or an event under the
    request's id. A list the executor cannot match to its request is
    still handed on as it was, and the request is not answered
    (DESIGN.md, X250): on stdio a line with an id given twice, no id or
    a null one, a list of messages (a batch), or a byte order mark
    before the message; over HTTP an event with no id, under another id,
    or holding a list of messages. A tool shown so is still refused when
    it is called, unless the settings forward such calls (`unlisted`).
    Over HTTP the upstream's own error answer to `tools/list` goes on as
    it is, with its status, under the request's id, another or a null
    one, where the body is an error answer and nothing more
    (`errorAnswer` in `mcp-executor/jsonrpc.mjs`; DESIGN.md, X260): a
    server may refuse a request it could not read, or a session it does
    not know, with a 400 or a 404 and an error under a null id. And
    where the executor writes its own error in place of an upstream's
    answer, it is sent as `application/json; charset=utf-8` with
    `cache-control: no-store`, and not under the upstream's content type
    or its word on caching (`test/list.test.mjs`, 14 tests, on stdio and
    over HTTP as a JSON body and as an event stream). Before, one deep
    answer of the server's ended the
    executor: its error, or its list of tools, which the executor writes
    out afresh, overflowed the stack (run). An agent's deep cancellation
    of a call in flight, written afresh in the same way, ended it too
    (run in the review's re-check: 0.4.1 ends at `executor.mjs:1214`).
    (As first built for 0.4.2,
    and never released, the check for names did the same on any line
    5,000 levels deep.) What changes for a caller: a message deeper than
    256 levels, which 0.4.1 passed on where it was not a call, is
    refused. The two older refusals, for a member name given
    twice and for a whole number beyond 2^53 - 1, are now answered under
    the request's id where it can be found; before, under no id, so that
    a client on stdio waited out its own timeout.
  - **What changes for a caller.** Arguments with two names in one
    object that differ only in capitals (`path` and `PATH`) are now
    refused in every call, with -32600 and no denial; before, they were
    refused, with a denial, only where a rule read the amount or the
    content from the arguments. A call that a rule on content cannot read
    exactly, in the two ways above, is now refused where it was let
    through. That takes in a structure written as null where a rule
    reads inside it: `{"options": null}` is refused as
    `content-unreadable` where a rule tests `/debug` in `options`, while
    `{"options": {}}` is taken as before, and a member that is not there
    at all is still absent. `misspelt`, `foldedInParams`, `oneLine`,
    `deeperThan`, `errorAnswer` and
    `MAX_DEPTH` are new exports of `provared-mcp-executor/jsonrpc`, and `unreadableAt` of
    `provared-mcp-executor/rules`.
  - **What it does not cover.** The folding is that of capitals and a
    little wider: it also makes one of the long s and `s`, the Kelvin
    sign and `k`, the sharp s and `ss`, the dotless i, the dotted capital
    I and `i`, and the ligatures and their letters, so that `Masse` and
    `MaÃŸe` in one object are refused too. It errs on the side of
    refusing. A reader that takes two names for one in some other way is
    not covered. A rule on content sees a name in other capitals only on
    the way to a pointer it reads: a rule that tests `/scan` does not see
    `SCAN` in an object it does not walk through. A list that is asked
    for a member by name is still taken as having none.
  - **Tests.** `mcp-executor/test/names.test.mjs` sends eleven such
    messages on stdio and over HTTP, in front of the made-up servers
    reading names without regard to capitals (`FAKE_FOLD` in
    `test/fake-server.mjs`, `foldNames()` in `test/fake-http-server.mjs`),
    and reads each server's own record of what it ran; each of its five
    tests fails without the fix. Two older tests that expected a denial
    for such arguments now expect the error. Two new tests in
    `test/content-rules.test.mjs` run the rules' cases, the first in
    front of the made-up server that ignores capitals; and
    `test/deep.test.mjs` (5 tests) sends 200,000 levels of nesting each
    way on stdio and over HTTP (the agent's requests, a call and a
    cancellation; the server's result, error, list of tools and
    notification), and reads the ids of the older refusals; an
    older test that expected such a refusal under no id now expects the
    request's. `test/list.test.mjs` (14 tests) also holds what stays: a
    list the executor cannot match to its request is handed on, in five
    ways on stdio and three as an event. The review's re-check took 14
    parts of these fixes out, one at a time, and a test failed for 12.
    For two, no test fails in the code as it stands, since the limit on
    nesting now comes first: the check for names in other capitals
    walking the text (`foldedInParams` in `readMessage`), which was the
    fix for a deep line before the limit was there and is a second layer
    behind it now; and the catch-all in `readMessage`, which no line is
    known to reach. The nine parts of the two changes over HTTP (X260)
    were each undone once, and a test failed for each.
  - **Versions.** 0.4.2 in `mcp-executor/package.json` and
    `mcp-executor/server.json` (both fields).

- **The threat model, corrected on time-stamps.** Two places in
  `docs/threat-model.md` said an outside time-stamp settles a stub's
  date. It shows only that the stub existed by the stamp's time: it catches
  forward dating, not back dating. No code changes.

- **`provared-mcp-executor` 0.4.1 (11 November 2026, on npm and the MCP Registry):
  `demo --stdio`, for an MCP client or a directory's inspector.** A
  directory that builds the package in a container and lists its tools
  has no passkey and no settings to give it. What changes, in
  `mcp-executor/`:
  - **`provared-mcp-executor demo --stdio`** makes the same new
    temporary folder, settings, keys and stand-in permission as `demo`,
    with the same code (`prepareDemo` in `demo.mjs`, which `demo` now
    uses too), runs `check`, and then runs the executor over stdio in
    front of the made-up server, as `stdio` does (`runStdio` in `bin.mjs`,
    which `stdio` now uses too), until its input closes. Its standard
    output carries MCP messages only. On its standard error it says, in
    one line, that this is a demonstration under a development stand-in
    whose records prove nothing about anyone, when its permission ends
    (after which every call is refused until it is started again), and
    where the book is; the executor's own JSON lines follow. It writes nothing outside that
    folder. `stdio` with settings of a person's own works as before.
  - **`demo` refuses any argument but `--stdio`**, and then writes
    nothing; 0.4.0 took no notice of one.
  - **The made-up server's tools** (`demo/server.mjs`) begin their
    descriptions with "Demonstration only: a made-up tool", and `add`
    describes its two arguments.
  - **Tests** (`test/newcomer.test.mjs`): `demo --stdio`, started as a
    client starts it, answers `initialize` and `tools/list` with the two
    tools, lets `echo "hello"` through, refuses `echo` with the word
    "password" with the denial text, puts nothing but MCP messages on its
    standard output and one line for a person on its standard error,
    ends with code 0 when its input closes, and leaves a book that checks
    clean (intact, fully checked, within the permission, no problem found)
    in the folder it names; and `demo` with another argument is
    refused.
  - **The README** says what `demo --stdio` is for, under the paragraph
    on `demo`.
  - **Versions.** 0.4.1 in `package.json`, `server.json` (both fields)
    and the command's `--version`; the `npm pack` file name in the README.
    The library range stays `^0.7.0`.
  - **Choices.** The permission lasts one hour, as for `demo`, since the
    preparation is the same; a client that needs longer starts it again.
    The line for a person is plain text, not JSON, since a person reads
    it; it starts "provared-mcp-executor:", as the line
    from `keys` does. `demo` refuses an unknown argument, as `init` does,
    so that a mistyped `--stdio` does not run the other demonstration and
    print text on the standard output.

- **`provared-mcp-executor` 0.4.0 (11 November 2026): the
  first five minutes, with no passkey.** A trial from a fresh install of
  0.3.0, following only the README, found that nothing could be seen to
  work without a passkey. What changes, in `mcp-executor/`:
  - **`provared-mcp-executor demo`** (`demo.mjs`): in a new folder of its
    own in the system's temporary folder, which it names at the start and
    leaves in place, it writes settings, makes the keys with the
    executor's own `keys` command, has the library's development
    stand-in for a passkey sign a permission (its issuer's name ends with
    "(development)"; it proves nothing about anyone, and the output says
    so at the start and the end), runs `check`, starts `stdio` in front of
    the made-up tool server, sends `echo "hello"`, which is let through,
    and `echo` with the word "password", which a rule on content refuses,
    and checks the book with the library's checker. It writes nothing
    anywhere else, and ends with exit code 0 only where each step went as
    it should. `demo/server.mjs` and `demo/content-rules.json` are now in
    the npm package, for this command; the rest of `demo/` is not.
  - **`provared-mcp-executor init`** copies `executor.example.json` and
    `content-rules.example.json` into the current folder as
    `executor.json` and `content-rules.json` (`init --http`: the HTTP
    executor's, as `executor-http.json`), says what to fill in next, and
    writes nothing if either file is already there.
  - **The example settings** mark what a person must fill in as a text
    wholly in angle brackets: the server's program, its folder and its
    credential file (they named a `files-server.mjs` and a
    `secrets/files-token` that no one has), the upstream's credential
    file, the passkey's thumbprint and the agents' secret hashes. They
    give `edit_file` and `apply_patch` a rule in `tools`, since the
    example rules on content name them.
  - **`check` lists every problem it can find on its own in one run**:
    the settings, each placeholder left, the server's program and folder
    (a `server.cwd` that does not exist is now a problem), each
    credential, the rules file, each key file (a missing one with the
    command that makes it) and each slip. Only where none is found does it
    hold the slips against the keys and the rules, as a start does; that
    part stops at the first difference, as a start does.
  - **`keys` reads and checks everything before it writes**: the
    settings, the rules file, every key file already there, and that the
    folder of each file it would write can be made (no file stands where a
    folder would be); `--out` may not name a key file. 0.3.0 made the
    executor's key file and then stopped on a missing rules file. A write
    can still fail after these checks (a full disk, a folder it may not
    write in), and leave the files written before it. It no longer needs the
    passkey's thumbprint, which is known only once the person has signed,
    or the agents' secret hashes, which it does not use. It prints the same JSON as before, and one line on
    the standard error saying what to do with it; `--out <file>` writes the
    JSON to a new file instead, making its folder where needed, as it makes
    the key folders.
  - **One warning set aside**: the command (`bin.mjs`, through
    `quiet.mjs`) does not print Node.js's notice that its ML-DSA-87
    signing is experimental, and prints every other warning, the notice
    about SLH-DSA included. The library and code that imports the
    executor set nothing aside.
  - **`provared-mcp-executor --version`** prints the version.
  - **The README** opens with a quick start (`demo` first, then `init`,
    `keys` and `check`), says where the example files are and why the
    ML-DSA-87 notice appears, gives the steps in an order that works,
    marks what is only in the repository, and says that the MCP Registry
    listed 0.2.0 as its latest version when it was looked at on
    11 November 2026.
  - **Versions.** 0.4.0 in `package.json`, `server.json` and the
    command's `--version`. The library range stays `^0.7.0`.
    `demo/package.json`, which installs the published 0.2.0 for the
    repository's other demonstration, is unchanged.
  - **Choices.** The demonstration's folder is left in place, so that the
    book can be looked at, and its permission lasts one hour, since it is
    used once. `init` copies into the current folder only and has no way
    to overwrite. A placeholder is one of the six texts in angle brackets
    in the two example files, word for word, so that no value of a
    person's own is taken for one. Where a slip's folder does not exist,
    `check` says to make it (`init --http` writes no `slips/`), so that
    `init` writes only its two files. The line from `keys` goes to the standard error, so that what it
    prints on the standard output stays JSON, which `demo/start.mjs`
    reads. `--out` makes a new file only. Only a warning of the type
    `ExperimentalWarning` whose text begins "The ML-DSA-87 Web Crypto API
    algorithm is an experimental feature" is set aside, by wrapping
    `process.emitWarning` in the command alone.
  - **Tests**: `test/newcomer.test.mjs`, thirteen tests: `demo`,
    `init`, the examples agreeing with each other, `check` listing every
    problem (stdio and HTTP), the placeholders and the wording of
    `check`'s messages, `keys` reading and checking all it needs before
    it writes and needing no thumbprint, `--out` making its folder, the
    warning set aside and no other, the version, and the package holding
    every file the command loads.
  - A workflow, started by hand, publishes the guard's listing on the MCP Registry with GitHub's identity token for the run (.github/workflows/mcp-registry.yml).
- **A new package, `provared-connect` 0.1.0 (`connect/`): the connection by one line.** A person copies one line from a book's page in the Provared application and runs `npx --logs-max=0 provared-connect <line>` on the agent's computer; the recorder beside the agent is connected, with no file saved or moved by the person. The command checks the line (its prefix, version and every field), saves the connection beside the recorder where only its owner can read it (mode 0600; on Windows the access list set with `icacls` to the user alone, before anything is written), and starts the uploader in the background with the file's name, never the line, so the secret is in no long-running command line and in no log the package writes (`--logs-max=0` keeps it out of npm's own debug log; the shell's history may still hold it, and the README says so). The same line again changes nothing; a line from a new key of the same book replaces the connection and restarts the uploader; a connection file that cannot be read as one is never taken for none; a refusal names no value from the line. The uploader and the hand-over that used to live in the application moved into the package, with their tests, and run as before with `--connection <file>`; the uploader reads the connection file with the command's checks. The line's format and the choices made (numbered 1059 to 1081) are in `connect/README.md`. 131 tests pass, with the recorder beside Claude Code from the same commit; the six findings of a first independent review by an AI reviewer are fixed, each held by a test.
- **The recorder beside Claude Code, as a plugin, installs library 0.8.0.** `integrations/claude-code/package.json` asks for `provared` `^0.8.0` (0.8.0 or later, before 0.9.0), where it asked for `>=0.6.0 <0.8.0`, and its lockfile installs 0.8.0, where it installed 0.6.0. The published `provared-claude-code` 0.1.0 is unchanged. Its README says so. The plugin's 18 tests pass.
- **The home page** says what is new in 0.8.0.
- **An example: an agent with a shell, kept from the tool server's
  credential** (`mcp-executor/recipes/agent-with-a-shell/`, not in the npm
  package). `run.sh` puts the agent, the guard (0.3.0 from npm) and a
  stand-in tool server in three Docker containers on one computer, the
  link to the guard encrypted by a small TLS proxy, and prints seven
  checks; all passed with Docker Desktop on Windows. Not tried on separate
  computers. The top README, the home page and the package README point
  to it, where they said no tested recipe was written.
- **`provared-mcp-executor` 0.3.0 runs over HTTP, for several agents**
  (on npm since 7 November 2026). `provared-mcp-executor http
  --config executor-http.json` runs the executor as a Streamable HTTP MCP
  server in front of one upstream HTTP MCP server. Each agent signs in with
  a secret of its own (`Authorization: Bearer <secret>`; the settings hold
  its SHA-256, which `provared-mcp-executor secret` prints) and has its own
  slip, keys, book and copy; through the executor, one agent cannot write
  to, read from or act under another's, though an agent that can read the
  executor's files is not held by this. The agent's `Authorization` header
  is removed and the upstream's bearer token, read from a file, is added;
  the executor sends an agent the token in no header, body, error or log:
  the upstream's headers come back by allow-list, its refusal of the token
  and any redirection are not relayed, and the token's text is replaced
  wherever it would appear in what an agent is sent. That holds for the
  token as it is in the file, and only for what passes through the
  executor: a token the upstream encodes or splits is not seen, and an
  agent that can read the executor's files, or reach the upstream another
  way, has it. One message per POST, read as strictly as a line
  on stdio; the answer as JSON or as a stream of events forwarded as they
  arrive, with the response under the executor's id as the outcome; legacy
  sessions pass through, each bound to the agent that opened it; the agent
  closing its stream cancels the call on the 2026-07-28 revision, which
  is recorded as not known; `MCP-Protocol-Version`, `Mcp-Method`,
  `Mcp-Name` and `Mcp-Param-*` headers must agree with the body, and a
  mismatch is refused with -32020. An `Origin` is refused unless the settings
  allow it, and the executor listens on 127.0.0.1 by default. The rules,
  the check, the documents, the countersignature and the copy are the same
  code as on stdio (`callCore` in `executor.mjs`), and the check still
  happens before anything reaches the upstream; the stdio path behaves as it did, its handling of a call now in the
  shared `callCore`, and its 70 tests pass as they were. `check`, `keys` and
  `compare --agent <name>` read the HTTP settings too. New files
  `mcp-executor/http.mjs`, `executor-http.example.json`,
  `test/http.test.mjs`, `test/http-cli.test.mjs`, `test/fake-http-server.mjs`
  and `test/http-world.mjs`; `DESIGN.md` sections 2, 10, 12 and choices
  X101 to X112; the README's "Over HTTP, for several agents".
- **The HTTP executor after an independent review by an AI reviewer** (`mcp-executor/http.mjs`; part of 0.3.0). An agent that reads nothing of a stream no longer makes
  the executor buffer the upstream without bound: the upstream is paused
  until the agent drains, and an agent whose connection does not take what
  is waiting within `timeout` is cut off (X113). Sessions are capped for each agent (1,000), so an
  agent can evict only its own (X114). A stop on request (SIGINT,
  SIGTERM, `close()`) settles a call in flight as the executor's stop
  (`EXECUTOR_STOPPED`, the first sentence of `OUTCOME_UNKNOWN`), writes
  its receipt and answers the agent before closing the connections, where
  it blamed the agent before (X115). A 4xx with a JSON-RPC error under the
  call's id is the call's outcome, relayed scrubbed with its status, where
  it was "outcome not known" (X116). `Mcp-Param-*` is compared with the
  call's argument at the `inputSchema` property the upstream's `tools/list`
  annotates `x-mcp-header`, decoded from the Base64 form, and `Mcp-Method`
  and `Mcp-Name` with the body's method and name; a mismatch or a header
  the executor cannot check is refused with 400 and -32020, and absence is
  never refused (X110 rewritten, X117). On a legacy session the agent's
  `notifications/cancelled` is sent on under the upstream's id for the
  call, and a disconnection alone is not a cancellation (X111 rewritten).
  The four upstream headers that come back are scrubbed (X118); the
  reading of a POST body has a time limit (408; X119); the test script
  ends the run when the tests do. Each of the transport's defences in
  depth now has a test that fails without it; the one that cannot be told
  apart from Node's own behaviour (`up.complete`) is named as redundant.
  New file `test/signal-wrapper.mjs`; the stdio path behaves as it did.
- **The HTTP executor after a re-check** (`mcp-executor/http.mjs`; part of 0.3.0). `Mcp-Name` is compared with `params.uri` on a
  `resources/read`, where a correct header was refused before, and with
  `params.name` on a `tools/call` or `prompts/get`, as the specification's
  table says; on any other method it is refused with 400 and -32020, as a
  message with no such field always was, where a `params.name` that agreed
  used to pass (X110). An `Mcp-Param-*` header against a number in the body
  is compared as a number, exactly and only in JSON's form of a number, so
  `42.0` agrees with 42, which it did not, and `0x2A`, an empty value and
  `Infinity` do not (X110). The log and receipt text "nothing read for N
  ms" claimed more than the code does, and now says what happens: an agent
  whose connection does not take what the executor has waiting within
  `timeout` is cut, and a very slow reader can be cut too; the code is as it
  was, and a new test shows the slow reader cut (README, X107, X113). X117
  said the executor generates no mirrored header and that a request of only
  a body goes on as it is, where the body's protocol version goes on as
  `MCP-Protocol-Version`; it now says so, and that `Mcp-Method`, `Mcp-Name`
  and `Mcp-Param-*` are never generated. The 503 to a new request during a
  stop has a test that fails without it. The redundant `up.complete` check
  is gone: a short body ends in the `error` and `aborted` handlers, never
  at `end`. X113 says how narrowly `BACKLOG_LIMIT` can be reached. The
  README and section 10 state a limit that was not stated: a JSON answer
  nobody reads is held after its slot is freed, up to 16 MiB for each
  connection, until the connection closes.

- **The recorder's README states more limits of records handed over,**
  from a review of 3 November 2026: the 300-second rule rests on the clock
  of the device the person signs on, and on the application's page, since
  the signing page sets no limit on a start; a start refused as
  `starts-later` is remembered in memory only, so "refused for good" is
  corrected; a clock more than about six minutes ahead has a renewal from
  the application refused if it is handed over soon after the press. The message for a
  `held-cancellations.json` the recorder cannot take now says to take out
  only the others where the file also holds one the person signed.

- **The recorder beside Claude Code takes records handed over from the
  application** (`integrations/claude-code`, not published; the library
  is unchanged). A renewal or a cancellation the person signed in the
  application's signing window, and the application kept with the book,
  sealed, is handed to the recorder by the application's uploader through
  the feed, with no file carried by hand: `POST /hand-over`, proved as
  every question of the feed is, and over every byte of the body as well,
  under a label of its own. Before any byte of the body is read, the
  recorder checks the length it states (`Content-Length`, at most 256 KiB;
  411 without one) and the form of the proof's headers in a conversation
  it began; at most four are taken on at once, counted from before the
  body is read, and a body not whole within 10 seconds is let go. The
  recorder checks each record itself and answers with a code
  (`taken`, `already`, `held` or `refused`, with a reason). Each must
  have been signed at https://sign.prova.red, or where
  `PROVARED_CLAUDE_CODE_SIGNING_ORIGIN` says (`other-signing-address`). A
  renewal is taken as `renew` takes one without `--new-passkey`, and is
  never one the recorder held before, nor one that starts before the
  permission in force, nor one that starts before any cancellation the
  recorder holds, in a book or held beside it (`before-cancellation`), so
  that a record held back and handed over late cannot start the agent
  again. A renewal from a passkey the recorder does not trust is refused,
  never added; the refused permission waits in `waiting-permissions.json`,
  and `admit-passkey <thumbprint>` for a passkey never trusted shows it in
  full and takes it, with its passkey, only once the person types `yes`
  on that computer (with nothing waiting from that passkey, it admits
  nothing). A cancellation is taken only for the permission in force:
  every call under it is refused at once, and the cancellation and the
  agent's acknowledgement are written into the book (the library's
  `add`); handed over again, it changes nothing and gives back the same
  acknowledgement. One dated ahead of the clock is held beside the book and
  kept in `held-cancellations.json`, which is given to the writer at each
  start, so a restart does not lose it; one more than 24 hours ahead is
  refused (`too-far-ahead`). A renewal while one is held is taken only if
  it starts after its date (`cancellation-held`, also for `renew`), and the
  cancellation stays held. While the permission in force is cancelled, or
  a cancellation is held, no new book is started; `status` says
  `cancelled`. A cancellation of a permission a later one replaced is
  refused (`not-in-force`: the agent acts under the later permission,
  which this does not stop). A permission refused with a passkey not on
  the list now carries a code (`passkey-not-trusted` and the others, on
  the error). What changes for a user: `retire-passkey` on a passkey not
  on the list says "not on the list of passkeys this recorder trusts", and
  a record handed over must name the signing page's address. Tests:
  `test/handover.test.mjs`.

- **Records handed over: the fixes of a second review** (the recorder
  beside Claude Code, not published). A permission does not say when it
  was signed, so: a renewal handed over that starts more than 300 seconds
  (the allowance between clocks the format uses) ahead of the recorder's
  clock is refused (`starts-later`, a new code, checked before its
  passkey, so such a one never waits; handed over again it is still
  refused while the recorder runs, within the limits its README states); and `before-cancellation` now refuses
  a renewal that starts less than 300 seconds after any cancellation the
  recorder holds, where it refused one that started before it. With the
  application's own rule (a renewal it sends starts no more than 300
  seconds after the press of Sign), and where the clocks agree, a renewal
  signed before a cancellation is refused whatever start the application
  allows, and one signed after it, starting 300 seconds after it, is
  taken; no permission handed over starts sooner than five minutes after
  the cancellation's date.
  `admit-passkey <thumbprint>` for a passkey never trusted no longer takes
  the permission through the plain `renew`: it asks the running recorder
  (a new route, `POST /admit`) to run every check a record handed over
  goes through, with that one passkey admitted for that one permission,
  and it refuses while the recorder is stopped. Before, a renewal from the
  person's new passkey that waited from before a cancellation was taken
  after it, and the agent acted again. A waiting permission that fails a
  check is dropped from the list and said; the rest are shown with the
  thumbprint worked out from each permission, the one that starts latest
  first, and that one is taken on `yes`. `waiting-permissions.json` keeps
  at most one permission for each passkey, the one that starts latest,
  so that whoever hands records over cannot choose which of the person's
  is shown. A cancellation handed over is taken whatever address the
  permission it cancels was signed at, where it was refused for the
  signing-address setting: it only takes away, and it checks against the
  permission's own passkey and address. A `held-cancellations.json` that
  holds a cancellation the recorder cannot take stops the start with a
  message that names the file and what to do. The time the feed waits for
  the body of a record handed over can be shortened for tests
  (`handOverReadMs`). What changes for a user: a renewal handed over must
  now start between 300 seconds after the latest cancellation and 300
  seconds after the recorder's clock; `admit-passkey` for a passkey never
  trusted needs the recorder running. Tests: `test/handover.test.mjs`.

## 0.8.0 (1 November 2026)

Version 0.8.0 changes the library's browser part, `src/passkey-browser.js`, which a web page uses to have a person sign with a passkey. A new function, `signChallengeWithChosenPasskey`, lets a page whose browser has forgotten which passkey signed before ask the device to offer the passkeys it holds for the website; the page must then check what comes back against the key it expects. Every signing function now also says which passkey signed (`credentialId`). What changes for a user: every other signing function now refuses, before the device is asked, a passkey that does not name its identifier as text of at least one character, with a `PasskeyError` of code `cancelled` and the words "No passkey was named, so nothing was signed." A missing or non-text identifier already failed with that code, with other words; a passkey whose identifier was empty text was handed to the device, and now throws instead. The signing page uses all this to open as a small window for another page (the Provared application), sign a new permission, a renewal or a cancellation there, and hand the record back; the signing page is served at sign.prova.red and is not in the npm package. Nothing else in the library changes: no record's bytes, no rule of the checker, nothing in the Python version but its version number, so a book checks with 0.8.0 exactly as with 0.7.0. Beside the library, in this repository, with entries in the list below: `provared-mcp-executor` 0.2.0, with rules on the content of a tool call, already published on npm on 1 November 2026; and a reader of Agent Middleware's receipts, `provared-agent-middleware`, not published. The framework packages `provared-langchain` and `pydantic-ai-provared` stay at 0.2.0, unchanged.

- **Versions.** The library is 0.8.0, in `package.json` and `python/pyproject.toml`. The Hermes plugin (not published) asks for `provared>=0.4.0,<0.9`, where it asked for `<0.8`, which left 0.8.0 out; the test workflow checks that bound. `examples/frameworks/package-lock.json` gives the library's version as 0.8.0. No other package's range changes: the others' tests run against the repository's own library whatever range they state, and the ranges of the published `provared-mcp-executor` 0.2.0 (`^0.7.0`) and `provared-claude-code` 0.1.0 (`>=0.6.0 <0.8.0`) are left as published, since neither needs anything of 0.8.0. The README, the guide, the Python README and three pages say 0.8.0, and the guide gives the checking page's new fingerprint.

- **The signing page opened as a small window by another page** (the
  Provared application, which signs nothing itself). `page/sign.html` and
  `page/sign-page.js` take a request after `#request=` in the address: a
  new permission, a renewal or a cancellation, with the fields to fill,
  the earlier signed permission, the passkey's public key, the address to
  hand the result back to, and a short text handed back unchanged. The
  page trusts the earlier permission only once the library's checker has
  confirmed its passkey signature, then shows what the new permission
  changes against it, part by part. It shows the return address before
  signing, and warns, asking for a second press, before a new passkey is
  made, before an agent's key set is signed for the first time on that
  device, before a passkey other than the earlier one signs, and where the
  return address is not one of the application's own two addresses,
  exactly (`https://app.prova.red:8443` and `https://app.prova.red`;
  `http://localhost` is taken and always warned of). The warnings are
  worked out again at every press, and a press signs only where every
  warning that stands then was shown and confirmed; a passkey prompt that
  fails, or a passkey this browser forgets, takes the confirmation back. A
  passkey is made only where the warning that one will be made was among
  those confirmed. Where the browser has forgotten which passkey signed
  before, the device is asked to offer the passkeys it holds for the
  website, and what it signs is kept only if the checker passes it with
  the expected public key. A cancellation is signed only by the passkey
  that signed the permission, at this page's own website name and
  address: a request to cancel one signed elsewhere, or with a passkey for
  another website name (a parent name included), is refused, and a
  cancellation never makes a passkey. A cancellation for an address that
  is not the application's asks for a second press too. The signed record
  is sent by `postMessage` to the exact return address, and the page says
  it was handed over only once that page answers; it closes once that page
  answers, from the window that opened it and from the return address
  exactly, that it kept the record (`{ provared: 'received', kind, state,
  kept }`), and stays open with the file offered where it says it did not,
  or says nothing within ten seconds. With no window that opened it, the
  page offers the file first, then a button that goes back with the record
  after `#signed=`. A signature that arrives after the permission was
  changed is not kept. A page shown inside another page still offers
  nothing.
- `src/passkey-browser.js`: `signChallengeWithChosenPasskey(challenge,
  rpId)` asks the device to offer the passkeys it holds for the website,
  for a caller that checks the answer against the key it expects; the
  answer of every signing function now names the passkey's identifier
  (`credentialId`). Every other function still refuses a passkey with no
  identifier, so that no caller is offered a choice it did not ask for.
- Tests: `test/sign-request.test.mjs` (the request, the return address,
  what changed, the messages each way) and `test/sign-window.test.mjs`
  (the window driven in a browser with a virtual passkey, at phone and
  desktop width: a new permission, a renewal and a cancellation handed
  back; the wrong passkey refused; the answer that the record was not
  kept, and no answer; the way back by a link for all three kinds; a
  request that cannot be read; a framed page),
  `test/sign-window-review.test.mjs` (the cases an independent review
  found, at made-up https addresses: a failed passkey prompt, a passkey
  forgotten between two presses, a cancellation for a parent website name
  or another address, a cancellation for an unknown address, a record
  sent to a page at another address, an answer from another window, a
  change while the passkey is asked, a cancellation by another passkey)
  and `test/passkey-browser-guard.test.mjs` (a passkey with no identifier
  is refused before the device is asked).
- **After an independent re-check of the signing window, 1 November
  2026:** once a cancellation asked for by a request has been signed and
  handed back (or offered to take back by a link), the "sign the
  cancellation" button stays off: while the page that asked waits, after
  it says it did not keep it, and after no answer. Before, it was switched
  on again, and a second press signed a second cancellation with no new
  warning. The file stays offered; a new request starts the page afresh.
  Held by `test/sign-window.test.mjs`.

- **`provared-mcp-executor` 0.2.0** (published on npm on 1 November 2026
  and listed in the official MCP Registry as
  `io.github.provared/mcp-executor`; the library stays at 0.7.0, and the
  executor still asks for `^0.7.0`). It carries the rules
  on the content of a change, below (choices X56 to X77), and names itself
  for the official MCP Registry: `package.json` gains
  `"mcpName": "io.github.provared/mcp-executor"`, and
  `mcp-executor/server.json` describes the package for the registry, with
  the command line `stdio --config <settings file>` (choices X78 to X81 in
  `mcp-executor/DESIGN.md`). `server.json` is not in the npm package; the
  registry's publishing tool reads it from the folder. Beside it,
  `mcp-executor/demo/` (not in the package): the executor in front of a
  made-up tool server with two harmless tools, set up on its first start
  with a permission signed by the library's development stand-in for a
  passkey, so that a directory of MCP servers can start it with no
  settings and no secret; a `Dockerfile` on the official `node` image,
  pinned by digest; its records prove nothing about anyone, as its README
  says (choices X82 to X89). One new test starts it as a real process.
  After an independent review (choices X90 to X99): the README and the
  design say that only an Owner of the organisation may publish to the
  registry, with a token that can read its members, and only after the
  npm version is out; the demonstration uses only an empty folder or one
  it marked as its own, keeps each set-up in a folder of its own and never
  renames or empties a folder, writes its paths afresh on every start (so
  it survives a move or a new Node.js), lets two starts at once on an
  empty folder each set up, says plainly when a folder cannot be written,
  and its server compares the made-up credential's value; the container
  is built from four named files, with a packed executor handed over as
  a context of its own and never copied in. Four more tests. After a
  second, narrow review (choice X100): an empty mark left by a start that
  was stopped no longer refuses the folder for good, a file error inside
  the folder gets the same plain words, and a name that is a file is said
  to be one. Two more tests.
- **The MCP executor tests rules on the content of a change before a
  call is let through** (F-157, F-158; `mcp-executor/rules.mjs`; choices
  X56 to X70 in `mcp-executor/DESIGN.md`). A permission allows kinds of
  action; being allowed to change a file is not being allowed to change
  everything the file controls. The new setting `contentRules` names a
  JSON file of rules: each names a tool, says which calls it applies to
  (`when`: conditions on the arguments), where the proposed content is
  and how to read it (`content`: a JSON Pointer, as JSON text or as plain
  data) and what must hold in it (`test`: `equals`, `oneOf`, `absent`,
  `matches` a plain glob, each at a JSON Pointer, with `orAbsent`). A rule
  with no `test` refuses every call it applies to, which is how a tool
  that carries only a partial edit is closed: the executor reads no file
  and keeps no content. A call a rule refuses (`content-rule`), or whose
  content the rule cannot read exactly (`content-unreadable`: not JSON, a
  member named twice or twice once folded, a number beyond 2^53 - 1,
  nothing at the pointer, not text, a text too long to match), is not
  sent; the model is told which rule and what it asked for, never a value
  from the arguments, and a denial is written. Every receipt and denial
  names `executor.rules`, the SHA-256 of the rules file's parsed content
  in the one form of RFC 8785; a denial by a rule also names
  `executor.rule`, the fingerprint of the rule's name; both are labels.
  The person puts the same fingerprint into the permission's
  `agent.software` (`keys` prints the entry); where the permission states
  software and the rules in force are not among it, the executor does not
  start; where it states nothing, it warns. `check` reports the rules and
  whether the permission states them; `compare` reports which rules
  fingerprints the records name and whether a slip states each. The
  README says plainly what the rules can never promise: an edit by
  another route, a tool whose arguments do not show the resulting file, a
  file type the executor cannot read, a pattern that matches characters
  rather than files. Content in YAML, TOML or line-based forms is later
  work. No record and no rule of the format changes. 12 new tests, among
  them a label change let through and the same edit with a hidden setting
  switched on refused.
  After an independent review (choices X71 to X77): with `unlisted`
  `forward`, a content rule for a tool that `tools` does not name stops
  the start, since such a call was sent on before any content rule was
  tested and the warning said the opposite; a permission whose
  `agent.software` states rules on content (an entry named `Content rules
  of â€¦`) stops the start where the settings name no rules file, and
  `compare` lists the executor's receipts and denials under such a slip
  that name no rules file (`withoutRules`); a `/` or a `\` in a pattern
  matches either separator, as promised, so `**/settings.json` matches
  `C:\proj\settings.json`; a rules file holds at most 20,000 pattern parts
  in all, which keeps one call to about a quarter of a second where a
  chosen file took 9.6 seconds; the file is decoded as strict UTF-8; a
  JSON Pointer with a `~` not followed by `0` or `1` is refused. Four more
  limits are stated in the README: a `when` value that is not text does
  not match; a member in other capitals in the content passes an
  `absent` or `orAbsent` test; a path with a trailing full stop is another
  text; JSON text inside a JSON string is not read. 7 new tests.
- **A reader of another project's receipts: Agent Middleware (AMW)**,
  `integrations/agent-middleware/` (`provared-agent-middleware` 0.1.0, not
  published): the first of the plan's readers of the closest other
  projects' receipts. It checks an AMW permit or receipt by the gateway's
  published Ed25519 key (the key found by `kid`, its status read; an
  envelope compared with the signed content; AMW's own six answers,
  reproduced for every one of its 96 published test cases, which are
  copied into `test/vectors/` under their Apache License 2.0 with a notice
  of where they came from), maps each verified receipt onto the fields
  the checker compares (the tool as the action, `credits_charged` as the
  amount in a unit and scale the reader states, `created_at` as the time,
  `permit_id` as the permit it names), and judges a set of receipts
  against a Provared slip that names the AMW gateway in `with`: the
  checker's own codes where they apply (`action-not-allowed`,
  `prohibited`, `outside-valid-time`, `over-limit`, `over-each-limit`,
  `over-count-limit`, `over-period-limit`, `amount-missing`,
  `approval-missing`), with words that say "AMW receipt"; codes of its
  own (`amw-permit-â€¦`) where only the AMW permit can be compared; and a
  stated list of what cannot be judged (no chain, so omission and cut
  ends do not show; no countersignature; no signature of the person on
  the AMW permit; approvals by identifier only; which agent; with whom).
  A denied AMW receipt is shown as the gateway's refusal and never
  counted against the agent; a receipt that does not verify is not shown.
  `receiptDocument` carries an AMW receipt by its fingerprint in a
  Provared receipt's `details` under the name `agent-middleware.receipt`.
  A command, `provared-agent-middleware verify | judge`, with the
  checker's exit codes. Written from AMW's published data and the
  standards alone; no AMW program was read or run. Its tests run in the
  test workflow beside the other packages.
- **The AMW reader after an independent review**, each fix held by a
  test (`test/review.test.mjs`): a slip's countersignature condition, or
  an approval named by identifier only, is listed on the receipt it
  applies to (`notJudged`), and such a receipt is never said to be within
  the slip (`withinSlip` is `null`, not known) nor gives exit code 0
  (before, both gave "within" and 0); a P-256 key over content that says
  "Ed25519" reads `unsupported` (before, `verified`); signed text that is
  not well-formed Unicode, names a member twice in one object, or gives a
  `kid` that is not text is `malformed`; times are compared to the
  nanosecond (before, cut to milliseconds, so two receipts 3,599.9996
  seconds apart fell in different hours); a receipt handed over twice is
  counted once and listed as a duplicate; a receipt that fails its check
  shows no identifier (the envelope's is not signed), only its place; the
  command shows control and invisible characters as a mark, and escapes
  them in `--json`; `verify` loads no library, and the README's `judge`
  command works from a copy of the repository; `cannotShow` also states
  that cancellations cannot be handed over, that outcomes other than
  success are left out of totals, and that retired keys check receipts
  of any date. The package no longer pins a development copy of
  `provared` 0.6.0, which its peer range excludes.

## 0.7.0 (1 November 2026)


Version 0.7.0 makes three more document names part of the format (section 27 of the format description: `provared.tool-name`, `provared.tool-call-id` and `provared.tool-result`), and lets whoever checks a record name the addresses at which a permission must have been signed (`issuerOrigins`, Python `issuer_origins`, `--origin` on the command line, and a box on the checking page), so that a permission that another page under the passkey's website name had the passkey sign, by presenting it as a sign-in, is refused. Beside the library, two programs are published on npm for the first time, each at 0.1.0: `provared-mcp-executor`, an executor for MCP tool servers, which holds the tool servers' credentials, refuses a tool call the permission does not allow, and countersigns each receipt with keys of its own; and `provared-claude-code`, the recorder beside Claude Code, which can now also be installed as a Claude Code plugin. Releases are now published from the author's signed tag by a GitHub workflow, and each npm version waits for the author's approval with a passkey. What a reader must know: no record's bytes change, and a book written by 0.6.0 checks as it did, since 0.6.0 refused the three new names and so never wrote them; but a book that names any of the three new names checks in full only with a checker of 0.7.0 or later, because a checker of 0.5.0 or 0.6.0 refuses it (`bad-field`, as for every `provared.` name it does not know) and one of 0.4.0 or earlier reads the names as labels. The MCP executor writes two of them in every receipt, so its books need 0.7.0. The framework packages `provared-langchain` and `pydantic-ai-provared` stay at 0.2.0, unchanged: they ask for `provared` 0.6.0 or later, and what they write is the same with 0.7.0.

- **Versions.** The library is 0.7.0, in `package.json` and `python/pyproject.toml`. Ranges on the library: `provared-mcp-executor` and the OpenTelemetry bridge (not published) now ask for `^0.7.0`, where they asked for `>0.6.0 <0.8.0`; the recorder beside Claude Code, the gateway and the sealer (neither of the last two published) ask for `>=0.6.0 <0.8.0`, where they asked for `^0.6.0`, which left 0.7.0 out (the recorder's `package-lock.json`, which a Claude Code plugin installs from, still holds 0.6.0, which the new range accepts, and the plugin's test of that lockfile now takes a range of that form as well as a caret range); the Hermes plugin (not published) asks for `>=0.4.0,<0.8`, where it asked for `<0.7`. The README and the guide name the two packages now on npm, with their install lines.

- The gateway's test "M3: an agent may have only so many calls waiting"
  no longer depends on how busy the computer is: each wait has 120
  seconds, not 20, and the status is shown to answer without waiting for a
  call by the upstream still holding that call, not by a time under one
  second. It checks the same limit.
- **Three more reserved document names** (format description, section
  27), in both languages: `provared.tool-name` (the fingerprint of the
  tool's name, exactly as the agent's software called it, which is not the
  slip's action name), `provared.tool-call-id` (the fingerprint of the
  identifier the model gave the tool call, exactly as received) and
  `provared.tool-result` (the fingerprint of the tool's result in the one
  form of RFC 8785, as `provared.arguments` is of the arguments; never the
  result itself). Each may be named once in a record; the three
  identifiers of 0.5.0 are still the only names that may be named more
  than once. The first two are fingerprinted with `identifierFingerprint`
  (`identifier_fingerprint`), the third with `argumentsFingerprint`
  (`arguments_fingerprint`); no new function. `recordTools`,
  `record_tools` and `record_function` still name the arguments only, so
  what the published framework packages write is unchanged. The MCP
  executor writes `provared.tool-name` and `provared.tool-result` in place
  of its labels `mcp.tool` and `mcp.result`; the OpenTelemetry bridge
  writes `provared.tool-call-id` where a tool gives `callId`, which before
  went on the span only, and still never writes `provared.event-id`, the
  platform's identifier, which only the caller can name. Both packages now
  need 0.7.0 or later (`^0.7.0`). Shared test files:
  `stub-contents.json`, `http-fingerprints.json` and `denial-contents.json`
  remade, with the three names accepted once, refused twice, and names
  close to them (`provared.Tool-result`, `provared.tool_result`,
  `provared.tool-call`) refused as unknown. **Compatibility:** no book
  written by version 0.6.0 fails its check because of this change, since
  0.6.0 refused these names and so never wrote them; a checker of version
  0.5.0 or 0.6.0 refuses a book that names any of the three
  (`bad-field`, as for every `provared.` name it does not know), and a
  checker of 0.4.0 or earlier, from before the names were reserved, reads
  them as labels; so a book written with them checks in full only with a
  later version. The guide, the Python README, the list of threats and the
  type declarations say so.
- **An executor for MCP tool servers**, `mcp-executor/`
  (`provared-mcp-executor` 0.1.0), stage 1: the stdio
  transport. An executor, in the words of the Internet-Draft
  `draft-izmaylov-agent-permission-receipts-02`, is software other than
  the agent that holds what its actions need and refuses an action the
  permission does not allow. The agent's MCP client starts the executor as
  if it were the tool server; the executor starts the real server with its
  credential (from a file or the executor's own environment, never the
  agent's), and passes every message of either revision of the protocol
  through unchanged except two. `tools/call` is matched to an action by
  the tool's name in a rules file, checked by the check before acting
  through the agent's stub writer, which the executor holds; a call the
  permission allows is sent on and gets a receipt that names the executor
  in `with`, binds the arguments and the server's result by fingerprint,
  and is countersigned with the executor's own key set once the outcome is
  known; a call it does not allow is answered as a tool error that says
  why, and written as a denial. `tools/list` comes back without the tools
  that have no rule. Beside the book the executor keeps its own copy, one
  tagged line before each call is sent (made sure to be on the disk
  first) and one once its receipt is in the book, and `compare` holds that
  copy against a book to find a receipt that was left out, which the draft
  leaves unspecified. A call the executor cannot record is not sent. A
  call cut off by a stop gets its receipt at the next start, from the copy,
  naming `provared.error`. Lines from the agent are read strictly (no
  batch, no member name given twice, an id that is text or a whole number),
  and refused otherwise. The design, the HTTP transport and the content
  rules of the plan's F-157 (design only), and 36 numbered choices for
  review are in `mcp-executor/DESIGN.md`. Nothing in the library changes.
  The test workflow runs the package's tests, and ESLint covers the folder.
  An independent review of the first draft found one serious fault and
  six of medium weight, each now fixed and a test (`test/review1.test.mjs`):
  a receipt lost for good where the book file could not be written after a
  call (the copy now keeps the outcome and the next start writes the
  receipt from it); a late answer from a server that ignores cancellation
  taken for a later call's under the same client id (each call now goes to
  the server under an id of the executor's own); a `tools/call` sent as a
  notification forwarded unchecked (dropped); the process staying alive
  after its server ended (it ends with the server's code); no cap on calls
  or list requests waiting (`maxWaiting`, default 16; 256 lists); a bare
  program name found through the client's `PATH` (named by path, or
  `server.path`, with a warning otherwise); a result that cannot be
  fingerprinted leaving no outcome in the receipt (`provared.error` with a
  fixed text). Smaller points: each copy line carries its number, so a
  line taken out, put twice or moved stops the start; `compare` tells a
  receipt the executor could not write apart from one the book lacks, does
  not agree where the book has a problem, and makes no key; a whole number
  beyond 2^53 - 1 anywhere in a line is refused; `check` writes nothing;
  a permission naming other services beside the executor is warned about.
  The founder's decision F-158 (content rules in the executor's settings,
  fingerprinted into receipts and into the permission's `agent.software`;
  the automatic late receipt kept; reserved names for a tool's name and
  result to come in the library and draft -03) is recorded in `DESIGN.md`.
  A narrow second review of those fixes found one serious and one medium
  fault in the id mapping, both fixed and tests (`test/review2.test.mjs`):
  a server answer holding a whole number beyond 2^53 - 1 was refused as
  unreadable, so the call timed out and the receipt named a false timeout
  (the server's lines are now read without that rule, reach the client in
  the server's own bytes with only the id replaced, and such a result is
  named as one that cannot be fingerprinted; an answer that cannot be read
  at all still reaches the client, and the receipt says so); and only tool
  calls were renamed, with guessable ids, so a `ping` under a call's id
  could settle the call with the ping's answer (every request now goes
  under an id with a random part). Requests the server never answers are
  forgotten past 1,000. A receipt written at a restart names
  `executor.written-late`, so that the book itself says so. A final check
  found two small points, fixed: a server line naming `id` twice at its
  top level, or a batch, is matched with no call and handed on as it is,
  and the call ends by the timeout with a "no answer" receipt.

- **The recorder beside Claude Code as a Claude Code plugin.** It can now
  be installed, with its hooks, in two commands in Claude Code:
  `/plugin marketplace add provared/provared`, then
  `/plugin install provared-recorder@provared`. A marketplace file at the
  top of the repository (`.claude-plugin/marketplace.json`, the place
  `/plugin marketplace add` looks) lists one plugin, the folder
  `integrations/claude-code`, which gains `.claude-plugin/plugin.json`
  (the name `provared-recorder`, the package's version) and
  `hooks/hooks.json`: the hooks `init` writes, each run through the
  plugin's entry, `plugin.mjs`, by the plugin's own paths
  (`${CLAUDE_PLUGIN_ROOT}`), and at the start of a session a new command,
  `session-start`. It starts the recorder as `ensure` does and, where
  something stands in the way (no library, no permission yet, a recorder
  that does not start or is still starting, the recorder's hooks in force
  twice), tells the person and Claude in Claude Code's own fields for
  that, within 27 seconds; where all is well it says nothing. Nothing
  signs for the person: they run `init` (which, run through the plugin,
  writes no hooks), sign at https://sign.prova.red/ with their own
  passkey, and run `use`, as the first session tells them. Before each
  call the hook, where no permission was ever put in place, now says that,
  with the same steps, rather than only that the recorder is not running,
  and it waits for the recorder for at most 25 seconds from its own start.

- **The plugin's library, by an exact path.** Claude Code 2.1.167 copied a
  plugin fetched from a git repository into its cache without the library
  `provared`, so every call was refused and the start of a session failed;
  and Node.js would have looked for the name in the folders above the
  plugin, such as the person's home folder. The plugin's entry
  (`plugin.mjs`, with `plugin-library.mjs`) now takes the library from
  the plugin's own `node_modules` where Claude Code put it there, or else
  installs it itself, at a session's start or at a command the person runs,
  with `npm ci --ignore-scripts` from the folder's new `package-lock.json`
  (exactly 0.6.0, the package checked by npm against the fingerprint
  the lockfile holds, no install script run, npm's own program run by Node.js
  with no shell and stopped for certain at its time limit), into the
  plugin's data folder, and loads it from there alone, in this program and
  in every program it starts. After that, the copy is trusted by where it
  sits, and is not checked again before each use. Whatever goes wrong in
  the entry itself (a damaged copy, a missing lockfile, a Node.js without
  `module.registerHooks`), a call is refused before it is taken and Claude
  Code is told after it, as the hook itself does. A settings file with
  comments is looked through for the recorder's hooks as JSON with
  comments. Where it cannot, the session says so,
  every call is refused, and each refusal gives the one command that mends
  it (`plugin.mjs install-library`). Checked with Claude Code 2.1.167's own
  `claude plugin validate`, with and without `--strict`, and by installing
  the plugin, from a marketplace whose entry names a git copy of this
  branch, into a Claude Code settings folder of its own, then running its
  hooks and `session-start` from the copy in the plugin cache.

- **Not recorded twice.** Claude Code runs a plugin's hook and the same
  hook in a settings file side by side. Before each call, the plugin's
  hook (and only it: Claude Code names the plugin's folder to it) looks in
  the person's and the project's settings files for a hook that runs a
  recorder's `hook.mjs`, in the forms the README lists (a word joined from
  quoted and unquoted parts as a shell joins it; the project's and the
  home folder written as variables or `~`; a copy since deleted, on a path
  that names Provared); where it finds one, it refuses the call and says
  how to take one of the two out. It reads no settings file larger than
  1 MB, looks at no more than 20,000 words, for no more than 2 seconds,
  and refuses the call past any of these. After a call it records it
  whatever it finds. A new command, `remove-hooks`, takes the hooks `init`
  wrote, from any copy of the recorder, out of a project's
  `.claude/settings.local.json`, and nothing else, by writing a new file
  that then takes the old one's place, and only where the file did not
  change while it was read. `init` gains `--no-hooks`, refuses any other
  word after it, and warns where it writes hooks while the plugin is
  installed. The new file `settings-hooks.mjs` is in the npm package.

- **The heading of the top fingerprint.** The checking page heads the card
  of a record's top fingerprint "The top fingerprint (the Seal)" only where
  the record holds a seal, and "The top fingerprint" where it holds none
  (`topFingerprintHeading` in `page/render.js`). The "try it" page no
  longer relabels the heading itself. Nothing else the page shows changes,
  and the command-line checker, the Python version and the shared test
  files never held these words.

- **OpenSSF Scorecard.** A workflow, `.github/workflows/scorecard.yml`,
  runs the Open Source Security Foundation's Scorecard on each push to
  main, every Sunday and when a branch protection rule changes, and
  publishes the result to api.scorecard.dev and to this repository's code
  scanning page. Laid out as the Scorecard project's own example; no
  permission at the top, and only `security-events: write` and
  `id-token: write` in its one job. It is the first workflow here to use
  an action that is not GitHub's own (`ossf/scorecard-action` v2.5.0,
  pinned to its commit). Pinning fixes the action's own files, not all
  that runs: at that commit the action runs the container
  `ghcr.io/ossf/scorecard-action:v2.5.0`, chosen by its tag (on
  31 October 2026 the tag named the image
  sha256:1e1481c65fc2407d3fd6ab18a23c741eb4d1c0d9359ebafc4b3ab13aa61d8627).
  It cannot be pinned by that fingerprint, because the Scorecard service
  takes a result only from the named action. The job's token can only
  send results to the code scanning page and ask for an identity token,
  so at worst a changed container could publish a false result. The
  README shows the Scorecard badge.

- **Static analysis.** `.github/workflows/tests.yml` gains a job that runs
  ESLint over the JavaScript and Ruff over the Python on every push and
  pull request, with rules that look for faults (eval, unsafe regular
  expressions, child processes, weak fingerprint methods, subprocess with
  shell=True and the like), not style. Both are development tools only,
  kept in `tools/lint/` at exact versions (its `package-lock.json`, and
  `requirements.txt` with each file's fingerprint), and are in neither
  published package. A finding that is not a fault is set aside on its
  own line, with a comment giving the reason. Faults found and fixed, none
  changing what the library does: the Hermes plugin's `cli.py` used a
  backslash inside an f-string's braces, which Python 3.11, the oldest
  the plugin supports, cannot read; three Python tests expected any
  exception where the library raises `Refusal`, and now expect
  `Refusal`; three imports were never used. ESLint also covers
  `conformance/`, and Ruff also covers `tools/release/`; there
  `compare_wheel.py` now reads only `https://` addresses, since the
  second address it reads comes from the index's own answer.

- **Warnings are failures.** The Python tests run with `python -W error`
  (with two filters: a warning raised inside a LangChain dependency on
  Python 3.14, and, in the Hermes plugin's job, the plugin's own notices to
  the person, which it raises inside Hermes on purpose). The JavaScript tests no longer hide Node.js's warnings,
  and a step after each run fails on any warning other than Node.js's
  notice that ML-DSA or SLH-DSA is experimental
  (`tools/lint/node-warnings.sh`); each run keeps its own exit code
  (`set -o pipefail`), so a failing run is not hidden by the step that
  saves its output. One was found and fixed: the seal
  writer handed a Web Crypto key of another method to Node.js's
  `createPrivateKey`, which Node.js has deprecated (DEP0203); such a key
  is now refused before it is handed over, with the same answer as before.

- **Smaller changes.** The site's publishing workflow gives each job only
  the permissions it needs (`pages: write` and `id-token: write` in the
  deploy job alone) and checks out without keeping a token.
  `CONTRIBUTING.md` names GitHub's private reporting form beside email
  for security faults, and says that a change in behaviour comes with
  tests.

- **A reader may name the address a permission must have been signed
  at** (25 to 31 October 2026), in both languages. A passkey can be asked
  to sign by any page under the website name it was made for (its relying
  party), and what it signs is a fingerprint the person cannot read on the
  device's prompt; so a page served under that name, or a script on one,
  could have a passkey made for `prova.red` sign a permission it wrote, by
  presenting the permission's fingerprint as a sign-in challenge, and a
  checker, which compared the address only with what the permission itself
  said, would pass it (the list of threats, section 3, said so since 0.6.0,
  with no option to close it). Now the checker's option `issuerOrigins`
  (Python `issuer_origins`; the command line `--origin`, which may be
  repeated; a box on the checking page) names the addresses at which
  permissions must have been signed, each in the one form the format
  allows for `issuer.origin` (`isPageAddress`, Python `is_page_address`,
  gives the form). A permission signed anywhere else is refused with the
  new code `issuer-origin-not-expected`, after the passkey has been
  compared as before, and the stubs under it are not compared; a
  permission signed at an address named gets a note that says so; a list
  that is not in that form, or longer than 64, is a problem with the whole
  check (`bad-field`), never set aside. An approval and a cancellation are
  held to the permission's address by the passkey check already. The
  command-line checker says "Signed at an address you named?" where
  `--origin` was given, and refuses a value not in its plain form. Nothing
  changes for a reader who names no address, and no record's bytes change.
  Format description, section 4.4; the list of threats, sections 3, 7 and
  8; the guide, "How signing works". Shared test files: `slips.json` is
  made again with eleven new cases (every record in it is signed afresh),
  `denial-constants.json` with the new code, and `issuer-origins.json`
  and `issuer-origin-shows.json` are new. Tests:
  `test/issuer-origins.test.mjs`, `python/tests/test_issuer_origins.py`,
  and cases in `test/cli.test.mjs`, `test/page.test.mjs` and
  `test/refusals.test.mjs`.

- **The signing page says why it is served at a name of its own**, and
  the one tool that writes that site. The page (`page/sign.html`) now
  says that the passkey it makes belongs to the page's website name and
  to nothing else, why the page is served at a name that serves nothing
  else, and that whoever checks a record can name that address; shown
  inside another page, it now says to open sign.prova.red in a tab of its
  own (before: prova.red/sign/; the pages name no address with its
  scheme, which a test holds). `tools/make-sign-site.mjs`
  writes the whole of the repository `provared/sign`, from which
  sign.prova.red is served, from this repository: under `site/` the page
  as `index.html`, its script, the renderer, the style sheet and every
  module of the library, each byte for byte, with `site/files.sha256` in
  the form `sha256sum --check` reads; and the repository's own README,
  publishing workflow (with the actions pinned to the commits this
  repository's workflow pins) and licence. It takes `--from <tag or
  commit>`, which the README and the workflow name as where the copies
  come from, and reads every file with git at that tag or commit, never
  from the working tree: a file not committed, or changed and not
  committed, cannot reach the site, and the modules copied are those git
  holds directly under `src/` there. A name that git cannot find is
  refused (code 2), and nothing is written. A tag is named as the tag;
  any other name as the commit's full hash. With `--check` it compares a
  folder written before with the same files, read the same way, and names
  what differs. Run against the copy made by hand on 25 October 2026 from
  tag v0.6.0, with `--from v0.6.0` it finds every file equal; with
  `--from` this branch's commit it finds the seven files that this change
  and the one above change (the page, its script, the renderer, and
  `src/book.js`, `check.js`, `denial.js` and `slip.js`) and their list of
  fingerprints different, and the README and the workflow, which name
  where the copies come from. Test: `test/sign-site.test.mjs`, which
  builds a small repository of its own with a tag, so that it needs
  neither this repository's tags nor its history.
  The guide's table of folders names the tool.

- **The recorder beside Claude Code and the Hermes plugin print links to
  https://sign.prova.red/** (their `SIGNING_PAGE`), where they printed
  links to prova.red/sign/; their READMEs say what a link printed by an
  earlier version begins with and how to open it at the new address.

- **The recorder beside Claude Code: a passkey can be retired.** The
  recorder's list of passkeys, `trusted-passkeys.json`, served two
  purposes with one list: which passkeys may sign a new permission, and
  which passkeys' permissions it opens its books with (the book in force
  and the kept ones, for late receipts and for counting limits across
  books), and it refuses to start where the book in force holds a
  permission from a passkey not on it. So a passkey that had signed
  permissions in the record could not be taken off the list without
  stopping the recorder. Now the file holds two lists: `passkeys`, every
  passkey whose permissions are in the record, written and added to as
  before and never shortened; and among them `retired`, written by the
  new commands `retire-passkey <thumbprint>` and
  `admit-passkey <thumbprint>`. A retired passkey's permissions stand,
  the recorder still starts on the books that hold them and still counts
  limits across those books, and a new permission from it is refused,
  with or without `--new-passkey`, by `renew`, by `use`, by the running
  service and at start-up where a new permission was put in place by
  hand, until the person admits it again; only a passkey on the list can
  be retired. The retired list is read from the file at each renewal, so
  the command counts at once, while the recorder runs or not. The list is
  read again just before it is written, and the two are merged: every
  passkey on the file and every one added, never fewer, and the retired
  list with the one change asked for, written to a temporary file of its
  own and renamed into place; so `retire-passkey` run at the same moment
  as a renewal that adds a new passkey keeps both changes (a narrow
  window remains between that reading and the renaming, since no lock is
  held); a list that would hold no passkey is never written. At start-up,
  only the permission last in force is taken without the checks: the
  last permission line of `book.jsonl`, or, where a switch to a new book
  was interrupted and there is no `book.jsonl`, the last permission line
  of the last kept book. Any other permission put in `slip.json`, even one
  that either book holds further up, goes through the checks, a retired
  passkey's among them, and no line is added for it. What is left: a
  program on this computer that puts back the permission last in force
  (removing `book.jsonl` where it was last in force in the kept book) can
  resume it, even if its passkey was retired afterwards, and so can one
  that adds a permission's line at the end of either book. Retirement
  stops new permissions; it does not stop a program that can change the
  recorder's files. A file written by an earlier version holds
  `passkeys` alone and is read as retiring none, so a recorder updated in
  place starts on its folder as it is; a `retired` that is not a list of
  thumbprints from `passkeys` stops the recorder, as a malformed
  `passkeys` does. `status` names the retired passkeys (`retired`). Test:
  `integrations/claude-code/test/retire.test.mjs`.

- **A workflow that publishes a release from the founder's signed tag**
  (25 October 2026). `.github/workflows/publish.yml` runs only when a tag
  such as `v0.7.0` is pushed. Before anything is published it checks that
  the tag is signed by the release key in `.github/release-signers` and
  by nothing else, that the tag, `package.json`, `python/pyproject.toml`
  and the newest heading of this change log name the same version, and
  that the JavaScript and Python libraries pass their tests on the tagged
  commit, with the tests of every framework package against the library
  from that commit. It then publishes the Python packages and stages the
  npm package, through each registry's trusted publishing, with no stored
  password or token, and makes the GitHub release with the checking page
  as one file and its SHA-256. The npm version is staged
  (`npm stage publish`) and becomes public only when the author approves
  it on npmjs.com; the run shows the stage ID and the package's
  integrity value, so that the author approves that one stage, and the
  release notes say, for each registry, what the run sent there. The
  Python files are checked
  against the SHA-256 recorded when they were built before they are
  uploaded. A version already on a registry is not published again, so a
  framework package is published only when its own version is raised;
  where its version is already published and its code differs, the run
  stops before anything is published. The scripts it runs are in
  `tools/release/`. Nothing in the npm package or the Python packages
  changes. Version 0.6.0 and earlier were published by hand.
- `tools/make-single-page.mjs` refuses an option, or more than one
  argument, and writes nothing: `--out x` used to write a file named
  `--out`. It still takes one optional argument, the file to write.

- **A conformance kit**, in `conformance/` (not published): another
  implementation of the format, in any language, is tested against the
  shared test files through a small program of its own (an adapter),
  which the kit hands one case at a time as a line of JSON and whose
  answer it compares. By default it compares the codes and the shape of
  each answer, not the words meant for people, as `test-vectors/README.md`
  sets out; `--words` compares every value. It ends with code 0 only where
  every case compared matched. An adapter for Provared's own JavaScript
  library passes all 14,742 cases word for word. Passing it shows
  agreement on these cases only; it is not a certificate. Its tests run in
  the test workflow beside the sealer's.

- **The conformance kit, two changes.** By default it no longer counts the
  sentences in the lists named `notes` and `limits`: another implementation
  may say the same thing in more or fewer sentences, so only the codes,
  the items that are not texts and the shape of each answer are compared;
  `--words` still compares every word and every sentence. And a second,
  example adapter, `conformance/adapters/provared-public.mjs`, is written
  only on the functions the npm package offers (`provared` and
  `provared/check`), and can be pointed at an installed copy of the
  package with `--package`: it answers 3,099 of the 14,742 cases, all of
  them matching word for word, and skips the other 11,643, which test
  parts of the library that are not offered to other programs, saying why
  for each.

- **The conformance kit, after an independent review.** By default, the
  findings of an entry (`problems`, `breaches`, `disclosureProblems`) are
  compared in any order, as the format description says their order is
  not part of the format; and an entry's own `problems` may hold only
  some of those stored, at least one, since a checker may stop at the
  first way an entry fails its own check (where it stopped before the
  countersignature, "unchecked" is taken in its place). Breaches are
  still compared in full. `--words` keeps the stored order. The verdict
  now says how many cases were skipped and not tested, the functions
  skipped entirely are listed, and `--no-skip` counts any skip as a
  failure. A reply holding both an answer and a skip is a fault of the
  adapter. The example adapter reports an error it does not expect as a
  crash, where it gave the code `check-failed`. The guide gains a table
  of every function the shared test files name: its section of the
  format description, whether another implementation may skip it, where
  its answer is declared, and how its cases are written; and it lists
  the stored values that are particular to Provared's own library.

- **An OpenTelemetry bridge**, `provared-opentelemetry` 0.1.0, in
  `integrations/opentelemetry/` (not published). It puts each tool call's
  receipt on the trace span that observability tools already show, in one
  call: `traceTools` (as `recordTools`) or `traceAct` (as the stub
  writer's `act`). The span
  gets `provared.outcome`, `provared.action`, `provared.stub.fingerprint`,
  `provared.stub.seq`, `provared.stub.countersigned`,
  `provared.stub.trace_bound`, `provared.slip.fingerprint` and, for a call
  not taken, `provared.check.codes` and `provared.denial.fingerprint`; a span
  the bridge starts is an `execute_tool` span as OpenTelemetry's
  conventions for generative AI describe it. The receipt names the
  fingerprint of the span's trace id as `provared.trace-id` only for a tool
  that the caller says sends the trace out with its call, in a
  `traceparent` header (`sendsTrace: true`; off by default), as section
  27 of the format description defines the name; the bridge cannot see
  whether the tool really does. The model's identifier for the call goes
  on the span as `gen_ai.tool.call.id`, never into the receipt. Only
  fingerprints, names and codes reach a span: never arguments, amounts,
  documents, keys, the words of a finding or an error's message. A span is
  the agent's side's own word; the receipt and the checker are the
  evidence. `@opentelemetry/api` and `provared` are peer dependencies; the
  library itself still has none. An error that the tool, or one of its own
  functions, throws is the tool's error, even a `NotTaken` from another
  stub writer. `traceAct` adds nothing to a request that comes with an
  approval made beforehand, or whose `details` is not a list. Its tests run
  in a job of their own in the test workflow, at the locked versions and
  again at the newest releases of OpenTelemetry.
- **An example for a JavaScript agent framework** in
  `examples/frameworks/` (not in the npm package): an agent built with the
  Vercel AI SDK (`ai` 7.0.153), with its tools put behind the stub writer
  with `recordTools`. One order within the slip is run and receipted; one
  over its limit is not run, leaves no stub, and the agent is told why; the
  checker finds the book intact and within its slip, and the output says
  that the slip was signed by a development stand-in, not a person. It
  uses the SDK's own mock model and passes `telemetry: { isEnabled: false }`.
  It runs with a guard (`_offline.mjs`) open from before any module is
  loaded until the program ends, which replaces with refusing functions
  Node.js's socket connections, `dgram` sends, `dns` look-ups (both
  `Resolver` classes included), the functions that start a program (`child_process`, `ChildProcess.prototype.spawn` and, where it exists, `process.execve`),
  `worker_threads.Worker`, `fetch`, `WebSocket`, and `process.binding`
  for the bindings beneath them; the tests check that nothing was refused.
  Its own `package.json` and lock file pin every version, so the library
  keeps no dependencies. A new job in the test workflow runs it. In
  `docs/guide.md`, the links to the examples and to the Python version's
  examples now give their full addresses on GitHub, since `examples/` and
  `python/` are not in the npm package.

- **A "try it" page** at prova.red/try/ (`site/try/`, live since 25 October 2026).
  One button. Where the browser has Ed25519 and ML-DSA-87 built in (Chrome,
  Edge and Brave 155, tried on 13 October 2026), the page makes a new
  record with the development stand-in for a passkey, under a limit on
  orders in GBP that the visitor may change, writes a receipt for each of
  four orders (on purpose, even where the check before acting says no) and
  checks the record. Elsewhere it reads the sample record and checks it one
  entry at a time, and says why. The words about the record, what the page
  does not do and what the check trusts are those of the path shown.
  Nothing is sent, nothing is stored, and the record made has no seal; the
  card of its top fingerprint is then headed "The top fingerprint". Linked
  from the home page and the site map; its logic (`site/try/story.js`) is
  tested in `test/try-page.test.mjs`. The site's style sheet gains the
  checking page's rules for the checker's answer, scoped to the new page.

- **Signing moved to https://sign.prova.red** (25 October 2026). A browser
  lets a passkey sign only for the website name it was made for and the
  addresses under it, so a passkey made at prova.red/sign/ could be asked
  to sign by any other page under prova.red (the list of threats, section
  3). The signing page is now served at sign.prova.red from its own
  repository, https://github.com/provared/sign, which holds only that page
  and the library's files, each a byte-for-byte copy of the files at tag
  v0.6.0, and serves nothing else. prova.red/sign/ now says that
  signing has moved and offers no signing (`site/sign/index.html`; the
  publishing workflow no longer copies the signing page there). The
  gateway's README points to the new address. (The recorder beside Claude
  Code, the Hermes plugin and the signing page itself named the old
  address until the change above; their READMEs said how to open such a
  link at the new address.)
- The test workflow is no longer started by a push that changes only the
  record page and the sitemap.

- On the "try it" page the checker's answer entry by entry is folded away behind "Show every entry", which opens in place; the story, the summary and what the check does not show stay open.
## 0.6.0 (25 October 2026)

Version 0.6.0 adds three kinds of record and the services that use them: the denial (the agent's own side states that an action it was asked for was not taken), seals held elsewhere and handed over beside a book, and witness statements beside a seal, with consistency proofs; and, beside the library, a central sealer, a gateway that writes the receipts for agents that cannot be wrapped, and a recorder beside Claude Code that numbers its books and has them witnessed (none of these three programs is published). What a reader of a book made by 0.5.0 or earlier must know: every such book reads as it did, apart from the cases below; but a checker of 0.5.0 or earlier refuses a book that holds a denial, a seal that gives `book`, or a seal that holds `witnesses`, so a book made with these needs a checker of 0.6.0. The fingerprint of a tool call's arguments is now named `provared.arguments` by default, where it was `arguments`; the fingerprint itself is the same. And a checker of 0.6.0 refuses some time-stamps and keys that 0.5.0 accepted, each listed below: a time-stamp that is not strict DER, that names its signing certificate twice in the same form, or that is signed with Ed25519 under a method other than SHA-512 or with parameters; an ES256 key that is not a point on its curve; and an Ed25519 signature whose number S is not below the order L. A passkey and a time-stamp service that follow their standards produce none of these; the sample record gets the same findings and the same exit code from the command-line checker of both versions, and 0.6.0 adds only a line on witnesses and, with `--json`, the empty members for denials and witnesses.

- **The fingerprint of a tool call's arguments is named
  `provared.arguments` by default**, in both languages (24 October 2026).
  `recordTools`, `record_tools` and `record_function` name the one
  document they write by default with the reserved name of section 27 of
  the format description, where 0.5.0 and earlier named it `arguments`
  (the default was kept in 0.5.0 so that the published framework packages
  would not change what they write without a version of their own). The
  fingerprint is the same; only the name changes, and every checker reads
  both: one of 0.5.0 or later knows the reserved name, an earlier one
  reads it as a label. A tool that names its own documents through
  `details` is unchanged, and so are the recorder beside Claude Code, the
  gateway and the Hermes plugin, which name their documents themselves.
  No rule of the format changes. Shared test files: `tool-scenarios.json`
  and `denial-scenarios.json` are made again; their stored answers differ
  only in that name, and every record in them is signed afresh. The name
  comes with the library: a framework package of an earlier version writes
  the new name too once `provared` is upgraded to 0.6.0. The two published
  framework packages gain versions that require it, `provared-langchain`
  0.2.0 and `pydantic-ai-provared` 0.2.0, whose READMEs say what changes,
  and which can be installed only once `provared` 0.6.0 is published; `provared-agno` (not published)
  requires 0.6.0 too. The Hermes plugin's bound is raised to below 0.7;
  it does not use the default. The version in `package.json` and
  `python/pyproject.toml` is now 0.6.0, so that the packages' bounds hold
  against the library in this repository. Tests:
  `test/documents.test.mjs` and `python/tests/test_record_function.py`.
- **One correction and three smaller changes from a narrow review of the
  five fixes below (24 October 2026)**, in both languages. None changes
  the bytes of any record; one widens what a checker accepts back to what
  services in use write.
  - *The order of a set is held only where a standard requires DER.* The
    five fixes held every set the checker reads as a set to the order of
    X.690, section 11.6, the list of certificates among them. The review
    found three genuine time-stamps of 2017 from a public service, kept
    as test data by the open-source Go library digitorus/timestamp
    (nothing of which is copied here), that list their two certificates
    in chain order, the signing certificate before its issuer, which is
    the reverse of DER order: before the five fixes they checked as valid,
    and the five fixes refused them in both languages. RFC 5652 requires
    DER of the signed attributes alone, "even if the rest of the structure
    is BER encoded" (section 5.3). So now the signed attributes (RFC 5652,
    section 5.3) and every set inside them, the statement (RFC 3161,
    section 2.4.2) and every set inside it, and each certificate (RFC
    5280, section 4.1) and every set inside it are held to that order;
    the signed data's own sets (the list of fingerprint methods, the list
    of certificates, the list of withdrawn certificates and the list of
    signers) and the parts of a signer outside its signed attributes may
    be in any order. Every other rule of strict DER still holds everywhere
    (format description, section 21.2, item 1, which now names the sets
    held to order). A test in each language builds a time-stamp with its
    certificates out of DER order and expects it to pass; the made-up
    time-stamps are enough for that.
  - *What is walked under a tag that hides its kind*, said exactly. The
    five fixes said such a part "is read as bytes only". In both
    languages a part written in parts under such a tag has the parts
    inside it read like any other (the review's probe, an `otherName`
    holding a whole number not in its shortest form, is refused as such);
    the tagged part itself is only neither refused as a string written in
    parts nor held to the order of a set; and one written in one piece is
    read as bytes only. The format description, the code's own notes and
    the two entries below now say so.
  - *RFC 5652, section 11*, forbids a second instance, and a second value,
    of the signing-time attribute too (section 11.3), not of the
    content-type and message-digest attributes only; corrected below.
  - *The count of sets in the real time-stamps*, below, was wrong: the
    sample record holds one time-stamp (`samples/office-supplies.jsonl`,
    line 10), repeated in its Show, not two; and the four real time-stamps
    hold 43 sets between them, not 53. Each of the 43 is in DER order, so
    the five fixes refused none of them.
  - *Shared test files remade:* `stamps`, `stamps-openssl`,
    `stamps-flips-ecdsa`, `stamps-flips-ed25519` and `stamps-flips-rsa`.
    Three stored answers of `stamps` change in substance: "certificates:
    two certificates out of DER order" and "wrapper: two fingerprint
    methods listed out of DER order" are now valid, and "wrapper: the
    signed data that is a set" is refused for its kind, not its order.
    Fifteen changed-byte cases that tripped the order of a set before
    anything else (four of `stamps-openssl`, six of `stamps-flips-ecdsa`,
    three of `stamps-flips-ed25519`, two of `stamps-flips-rsa`) are now
    refused for what the changed byte does next. Every other difference
    is a made-up service's fresh key (`stamps-flips-ecdsa` has one case
    more, its signature a byte longer). A re-check then found the three
    re-walks held by no deliberate case (weakened, every test still
    passed), so `stamps` gains three refused cases, each caught in both
    languages: a message-digest attribute whose second, larger value
    stands before its first; a relative distinguished name out of DER
    order inside a certificate; and one inside the statement's name of
    the service. The JavaScript unit test builds the first of these too,
    and checks that the list of fingerprint methods may be in any order,
    as the Python test did. The tests are `test/audit-fixes.test.mjs` and
    `python/tests/test_audit_fixes.py`.
- **Five fixes from the independent review of the audit fixes (24 October
  2026)**, in both languages. None changes the bytes of any record; four
  narrow what a checker accepts, and one adds to the shared test files.
  - *Strict DER is now what the checker enforces.* A string of bits, bytes
    or characters, or a time, written in parts (the constructed form,
    which X.690, section 10.2, forbids in DER) is refused
    (`stamp-bad-data`); before, a certificate whose signature was a bit
    string in two parts passed in both languages. The items of a set must
    be in the order X.690, section 11.6, requires, where a standard
    requires DER of the set (narrowed to those places by the review
    above; as first made, every set the checker read as a set was held to
    it). Every real time-stamp the repository holds was checked first:
    the three made with the OpenSSL program (`test/fixtures/stamps.json`)
    and the one in the sample record (repeated in its Show) hold 43 sets
    between them, every one in that order. The made-up services of the
    tests now write their sets in that order, as a real service does;
    before, the one that makes the shared test files wrote the signed
    attributes of its SHA-512 cases out of order (format description,
    section 21.2, item 1).
  - *A time-stamp signed with Ed25519 gives its fingerprint method and
    its signing method no parameters*, as RFC 8419, section 3.1, requires
    (`stamp-invalid`); before, only the method's name was checked, and
    the made-up services wrote NULL parameters, which that section
    forbids. The refusal has words of its own that name the cause (a
    method other than SHA-512, or parameters), where before it said the
    signature did not fit the certificate. The list of fingerprint methods
    in the signed data is read for its form only (section 21.2, item 4).
  - *A second written form of a P-256 key* is in the shared test files:
    the point with x = 5 and the point with y = 5, each as itself
    (accepted) and with that half written as 5 plus the prime (refused as
    `bad-key`), so that a checker that reduced a half instead of refusing
    it would fail `keys.json`. Before, every case at or above the prime
    also failed the curve's equation.
  - *Citations.* The one-instance rule for the signing-certificate
    attribute is RFC 5035's (section 3 for the newer form; section 5,
    which writes section 5.4.2 of RFC 2634, for the older), not RFC 5652
    section 5.3's, which requires DER; RFC 5652 forbids a second instance,
    and a second value, of the content-type, message-digest and
    signing-time attributes (sections 11.1 to 11.3) and says nothing of
    this one. Corrected in
    the entry below, the format description, the list of threats and the
    code. The format description now says that using the newer form where
    both are present, without comparing the two, is this format's choice
    (section 15, item 22): RFC 5035, section 7, lets a reader refuse such
    a time-stamp.
  - *Reach.* "Every bit string in a time-stamp" and "every part is read"
    now say what the checker reads as such: a value inside an octet string
    (an extension's value) is read as bytes only, as is a part written in
    one piece under a tag that hides its kind; one written in parts has
    the parts inside it read like any other (made exact by the review
    above).
  - *Shared test files remade:* `keys` (four cases added: the point of
    P-256 with x = 5 and the point with y = 5, each as itself and with
    that half written as 5 plus the prime); `der-strict` (thirteen added,
    for strings written in parts and sets in and out of DER order; twelve
    stored answers change: "a constructed octet string", "an unknown
    constructed tag", which is a character string in parts, and ten random
    cases are now refused, or refused in other words, for a string in
    parts or a set out of order); `stamps` (eleven added, among them an
    Ed25519 service with parameters in each place and sets out of DER
    order; "attributes: in another order" is now refused as not DER,
    "signing method: Ed25519 named with parameters" is now refused, and
    the two Ed25519 cases that name another method have the new words;
    the "unused bits" cases of a certificate's key are now two each, one
    with the unused bit zero and one with it set, where before the answer
    depended on the last bit of a key made at random);
    `stamps-strict-keys` (the same split of its three "unused bit"
    cases); `stamps-openssl`, `stamps-flips-ecdsa` and `stamps-flips-rsa`
    (thirteen, fourteen and fifteen changed bytes of the real and made-up
    time-stamps now trip the order of a set before anything else, and
    fifty cases of the RSA set hit other bytes because its signed
    attributes are now written in DER order); `stamps-flips-ed25519` (the
    time-stamp is four bytes shorter, its two NULLs gone, so its cases do
    not compare by name with the earlier set). The reviewer's probes were
    run again on the fixed code: its 16 ways round the checks and 2,534
    random cases give the same answer in both languages, words included.
    The tests are `test/audit-fixes.test.mjs` and
    `python/tests/test_audit_fixes.py`; each new refusal fails without its
    fix.
- **Eight fixes from the audit of the Internet-Draft (24 October 2026)**,
  in both languages, for version 0.6.0. None changes the bytes of any
  record. Five narrow what a checker accepts, so that two checkers built
  from the format description cannot disagree; three change the documents
  only.
  - *A time-stamp that names the certificate that signed it more than once
    in the same form* (two ESSCertIDv2 attributes, or two ESSCertID
    attributes) is refused (`stamp-invalid`), as RFC 5035 requires
    (section 3 for the newer form; section 5, which writes section 5.4.2
    of RFC 2634, for the older). Before, the last ESSCertIDv2 was used or,
    where there was none, the first ESSCertID. Where both forms appear
    once each, the newer still names the certificate (format description,
    section 21.2, item 3).
  - *A DER bit string whose unused bits are not zero* is not strict DER
    and is refused (`stamp-bad-data`), as X.690, section 11.2.1, requires;
    before, only the count of unused bits was checked. A string of no bits
    must count none. This reaches every bit string the checker reads as
    such (not one inside an octet string's value, such as an extension's,
    nor one written in one piece under a tag that hides its kind), not
    only the key's (section 21.2, item 1).
  - *An ES256 key that is not a point on the curve P-256*, or either half
    of which is not below the curve's prime, is refused as `bad-key`
    wherever a key is checked, before any signature is tried (section
    3.8). Before, it passed the key check and was reported as
    `signature-invalid` when a signature was checked under it. A slip, an
    approval, a cancellation or a vouching record that names such a key
    now fails on the key.
  - *An Ed25519 signature whose number S is not below the order L* is
    refused by the library itself, in every record and in a time-stamp, as
    RFC 8032, section 5.1.7, requires (section 3.8). Before, both
    languages relied on the library beneath them (OpenSSL), which refuses
    it; a third implementation on another library might not. The twelve
    cases of the paper "Taming the many EdDSAs" (Chalkias, Garillot, Kondi
    and Nikolaenko, 2020) are a new shared test file,
    `test-vectors/ed25519-signatures.json`, with ten cases made here, each
    with the answer the format's rules give, so that the rules are pinned
    and not the library: a small-order or non-canonical key is `bad-key`;
    a small-order or non-canonical R, or an S not below L, is invalid; a
    mixed-order key is checked without the cofactor and may pass.
  - *A time-stamp signed with Ed25519 must name SHA-512* as the signer's
    fingerprint method, as RFC 8419, section 3.1, requires; one that names
    SHA-256 or SHA-384 is refused (`stamp-invalid`), on every device, as a
    mismatched method is for RSA and ECDSA (section 21.2, item 4). This
    settles open issue 4 of the Internet-Draft. A service that follows RFC
    8419 produces nothing else; the made-up service of the tests now does
    the same, and writes the method with no parameters, as that section
    also requires (see the entry above).
  - *The format description* now says that a time-stamp's time is read to
    the millisecond and compared in milliseconds between seals (sections
    21.2 and 21.3), which is what the code always did ("taken to the
    second, rounded down" described only how it is shown); that a checker
    SHOULD bound the total size of a book it accepts and MAY stop at the
    first problem, since 100,000 entries of 131,072 bytes would be about
    13 gigabytes (section 9); and the rules above, in sections 3.8, 14, 15
    and 21.2.
  - *The list of threats, section 3,* states a limit the audit found: a
    passkey used for anything else at the same website is a signing
    oracle. Any page at an origin under the slip's `rpId` can hand the
    device a record's fingerprint as an ordinary sign-in challenge and have
    it signed; the person sees a sign-in prompt. So records should be
    signed only with a passkey registered to a relying party used for
    nothing else, and a signing page should show the record first. The
    checker has no option yet to name the origin a reader expects.
  - *Shared test files remade:* `keys` (six cases added for P-256);
    `der-strict` (six added; "a bit string with 7 bits unused" and
    thirteen random cases now refused); `stamps` (nine added and two
    removed, the sound Ed25519 cases being remade with SHA-512; the four
    cases with the signing-certificate attribute twice now refused);
    `stamps-strict-keys`, `stamps-openssl`, `stamps-flips-ecdsa`,
    `stamps-flips-rsa` and `stamps-flips-ed25519` (changed bytes that now
    trip the bit-string rule first; the Ed25519 token names SHA-512);
    `vouching-contents` and `vouchings-written` (the made-up passkey is
    now a point on the curve). New: `ed25519-signatures`. The tests are
    `test/audit-fixes.test.mjs` and `python/tests/test_audit_fixes.py`;
    each refusal fails without its fix.

- **Witnesses, and consistency proofs** (format description, section 29),
  in both languages. Whoever keeps a book could show one history to one
  reader and another to another, each sealed. A witness is a party, with
  a key set of its own, that keeps for each book the latest seal it has
  signed for, and signs a statement for a new seal only where the new
  seal extends that one.
  - *Consistency proofs*, exactly as RFC 9162, section 2.1.4, sets out:
    `consistencyProof(leaves, m)` and `verifyConsistency(m, n, rootM,
    rootN, proof)` (Python: `consistency_proof`, `verify_consistency`).
    For m equal to n the proof is empty and the roots must be the same;
    for m of 0 the proof is empty and the earlier root must be that of the
    empty tree. A second implementation, written in the tests from the RFC
    alone, is compared with the library's for every pair of sizes up to 64
    leaves, with every value of every proof changed and left out.
  - *A new kind of record, the witness statement*: label
    `vnd.provared.witness.v0+json`, two signatures (Ed25519 and
    ML-DSA-87), content `type`, `id`, `seal` (the seal's fingerprint),
    `size` and `root` (repeated from the seal), `by` (`{keys, name}`)
    and `when`. `writeWitness(fields, signers)` (Python:
    `write_witness`); signers may be keys or signer objects. There are now
    twenty-six labels.
  - *Beside a seal*: a seal's line may hold `witnesses`, 1 to 4
    statements, none from the same key set twice; and a seal handed over
    beside the book (`seals`, `--seal`) may hold statements that came
    later. A checker checks each: its signatures, that it speaks of that
    very seal (its `seal`, `size` and `root`), and that it is not dated
    more than 300 seconds before the seal. One new code,
    `witness-invalid`; it joins the format's own list of finding codes.
    A statement that does not pass is a problem with its entry, or, handed
    over, with the whole check (the seal it came with is used all the
    same).
  - *Which witnesses count*: the option `witnesses` (the fingerprints of
    the key sets of the witnesses the person trusts), `--witness
    <fingerprint>` on the command line (may be repeated), and a box on the
    checking page. A statement counts only where its witness is named,
    both its signatures were checked on the device, **the book's first
    line is a permission that passed, signed by a passkey the person
    named (`issuerKeys`), the person named the recorders they expect
    (`sealKeys`)**, and its seal passed with its Ed25519 and ML-DSA-87
    signatures checked there (its third, SLH-DSA, may not be: the Python
    version and browsers count on the first two). A witness knows a book
    only by its permission and its recorder's keys, which the recorder
    chooses; without both fixed by the reader, a recorder could start a
    second history with another first line and have the same witness
    sign for it (found by the independent review). Where a statement
    from a trusted witness is not counted for that reason, the answer
    says why. One from a witness not named is shown and not counted.
  - *What the answer says*: each seal entry, and each seal handed over,
    gains `witnesses` (each statement with its fingerprint, its witness's
    key set fingerprint, its name as a label, its `when`, its signatures,
    `state`, `trusted` and `counted`); the summary gains `witnessed`: the
    latest seal for which a statement counts, the entries it covers, the
    witnesses, and every seal witnessed, or null. Where a seal is
    witnessed, the answer's list of what the check does not show says what
    a witness shows and what it does not. Being witnessed excuses nothing,
    is never said of a book with a problem, and is not needed for exit
    code 0. The command-line checker prints "Witnessed by a witness you
    trust?".
  - *The witness itself*, in the library (it needs Node.js, because it
    checks SLH-DSA): `openWitness({ by, signers, state, clock })`, with
    `witness(entry, proof, firstLine)`, `update`, `ready`, `latest(book)`
    and `state()`. It knows a sequence of books by the recorder's key set
    with the passkey and the agent of the permission on the first line
    (`bookIdentity`); ties the first
    line to the seal with an audit path when it first sees a sequence and
    at each new book, and keeps it
    tied with each consistency proof (`witnessProof` makes the proof to
    send); signs only for a seal whose three signatures it checked, which
    names the seal it holds, is not dated before it, extends it, and is
    dated no more than 300 seconds after its clock; never signs two
    different seals of one book at one size (the same seal again gets the
    same statement); checks every signature it makes before it keeps or
    gives out a statement; and hands back its state with each statement,
    to be saved first. Opened from a saved state, it signs nothing until
    it has been brought up to date from a copy of what it gave out
    (`update`) and told so (`ready`). A witness running as a service is
    not part of this change. The Python version has no witness.
  - The check before acting, the stub writer and a checker that is
    carried on read statements as a whole check does; a statement's
    signatures that the device cannot check leave the record not fully
    checked, as for any record.
  - *The books of one permission* (format description, section 21.6): a
    seal may give `book`, its book's number among the books its recorder
    keeps under one permission (2 or more; absent for the first book, so
    every seal written before reads as it did; `1` is refused, and a seal
    with `book` must give `previous`). The first seal of a later book
    names, as `previous`, the last seal of the book before: a checker of
    that book alone does not compare it, says so, and, handed that seal,
    says whether the book follows on from it (`seal-chain-broken` where it
    is by other keys, `time-went-backwards` where it is dated after the
    first seal); a seal of another number is not compared by its place.
    Every seal of a book gives the same number (`seal-chain-broken`).
    `writeSeal` takes `book` (Python: `write_seal`). The recorder beside
    Claude Code does not yet number its books.
  - *The witness keeps every book of one recorder, person and agent as
    one sequence*: it knows a sequence by the recorder's keys with the
    passkey and the agent's key set of the permission on the book's first
    line, so a renewal (another permission from the same passkey to the
    same agent) is the same sequence, and a book that starts with it must
    follow on from the seal the witness holds (found by the second round
    of the review: known by the permission alone, a book that began with
    a renewal forked the history). It keeps no book whose first line is
    not a permission (`slip-missing`; a first line given with its line
    feed is `bad-field`), signs for the first seal of the next book only
    where that seal names the latest seal it holds and its first line is
    tied to it, and never again signs for the book before; a fork across
    books is refused. Its state names each sequence by its passkey and
    agent. One recorder key set keeps one sequence for each person and
    agent: books kept side by side for one agent need recorder keys of
    their own.
  - *Every permission before a witnessed seal must name the first line's
    passkey and agent* (found by the third round of the review: a book
    that started with agent Y's permission, then held agent X's
    permission and stubs with the one over the limit left out, was signed
    as the first book of the person and agent Y and read as witnessed).
    A statement now counts only where every permission among the entries
    its seal covers names the same passkey key and agent key set as the
    first line's; otherwise a note says why. A renewal by the same person
    for the same agent, and each agent's own book under one recorder (as
    the gateway keeps them), are witnessed as before. A Show counts a
    statement only where its pages hold every entry the seal covers, so it
    never counts one the whole book would not. The witness cannot apply
    this itself: it sees a book's first line, not its entries.
  - *A seal held elsewhere that gives another book number than the book
    is not compared with it, and gives no pass* (found by the second
    round of the review: a book cut short and sealed again as "book 2"
    otherwise hid the cut). It is not used; its note says what it shows
    and that this book does not show whether that book was cut short;
    the command-line checker says "Seals held elsewhere compared? NO" and
    does not end with code 0, and the checking page gives no green
    answer.
  - New shared test files: `tree-consistency`, `tree-consistency-checks`,
    `witness-contents`, `witnesses-written`, `witness-books`,
    `witness-shows`, `witness-before`, `seal-books`, `chained-books`,
    `chained-shows`, `renewal-books`, `renewal-shows`, `two-agent-books`
    and `two-agent-shows`. **Every stored answer of a whole
    book, a Show or the stub writer changes**, and only by the new
    members: `summary.witnessed: null`, and `witnesses: []` on every seal
    entry and every seal handed over; `denial-constants` gains
    `witness-invalid`. Eleven files change, each checked case by case to
    differ in those members alone (`books`, `denial-books`,
    `denial-constants`, `denial-scenarios`, `denial-shows`,
    `held-seal-shows`, `held-seals`, `recorder-details-after`,
    `recorder-scenarios`, `shows`, `tool-scenarios`); no record was
    signed again.
  - Section 28's list of finding codes now also names `book-cut-short`
    and `seal-not-in-book`, which the library already gave.
  - **A checker of version 0.5.0 or earlier refuses a seal's line that
    holds `witnesses`** (`unknown-entry`), **and a seal that gives `book`**
    (`bad-field`).
- **A witness that runs as a service, and the recorder beside Claude Code
  numbering its books and asking witnesses** (`integrations/claude-code`:
  `witness.mjs`, the new command `provared-witness`, `witnessed.mjs` and
  `proofs.mjs`). The package now needs `provared` 0.6.0 or later.
  - *The recorder numbers and chains its books* (format description,
    section 21.6). The first seal of a new book gives the book's number
    and names the last seal of the book before; its later seals give the
    same number. "The book before" is the latest kept book whose first
    line is a permission from the same passkey, for the same agent, sealed
    with the recorder's keys, as a witness knows a sequence; it is read
    from the kept files, so the numbers hold across a restart, and a kept
    book that cannot be read stops the seal rather than give it a number
    that may be wrong. A book that begins with another passkey's
    permission begins a sequence of its own, with no number. The first
    book gives no number, so the record so far reads as it did, and a book
    whose seals give no number goes on giving none. Before the book in
    force is first sealed, every kept book a late call could still come
    back to is closed, and sealed again where something came after its
    seal; such a call is then recorded in the book in force. Every seal's
    line is made sure to be on the disk (fsync), and a book is kept as
    `book-<n>.jsonl` only once it is.
  - *`provared-witness`*, a small service on 127.0.0.1 (port 8796 by
    default) around the library's witness (`openWitness`), in a folder of
    its own: its keys (Ed25519 and ML-DSA-87), a token for the recorders
    it serves and another for its operator, its settings (`witness.json`:
    its name, the fingerprints of the recorders it serves, its port and
    limits), a journal, a state and a checkpoint. For each new statement
    the journal line and then the state are made sure to be on the disk
    (fsync) before the statement is given out; what it says it holds
    (`/latest`, `status`) is what it last saved, never what the library's
    witness holds in memory, and once anything cannot be saved it gives
    out nothing more, by any route, until it is started again. Every 256
    journal lines it writes a checkpoint (the latest seal of each sequence,
    with its statement) and begins the journal again; a start reads the
    journal a line at a time, and in full only the lines its state does
    not yet reflect. At every start, the first included, it signs nothing
    (`witness-not-ready`) until its operator says that its folder was not
    put back to an older copy (`ready`, or `start --ready`); `update <book>
    [--seal <file>]` hands it, from a copy, the statements it signed for a
    book's seals, and `forget <sequence>` makes it hold a sequence no more
    (it then signs whatever it is next shown for that sequence). It
    refuses to start where its journal has gone while its keys are there,
    where a journal line is not one it writes or lines are numbered out of
    order, where its state reflects more lines than the journal holds, or
    where the journal follows a checkpoint it does not have; a last journal
    line cut off by a stop is taken off; a lost state is rebuilt from the
    checkpoint and the journal; a stop between the steps of a checkpoint
    is mended at the next start. One witness at a time on a folder
    (`witness.lock`, taken over from a process that has ended under a
    second file only one start can make). Who may ask: a program proves
    that it holds the token, which never travels, as for the recorder's
    feed (a hello, then HMAC-SHA-256 over the question, its body included,
    and over the answer), one question to a conversation; the operator's
    commands (`status`, `ready`, `update`, `forget`, `stop`) take the
    operator's token; it signs only for seals of the recorders named, and
    starts a new sequence only from a permission whose passkey signature
    the library's checker passes. Limits: 120 new statements in any hour
    (shared by every recorder it serves), 64 sequences, 8 questions that
    sign at once, bodies of 1 MiB. Library refusals keep the library's
    codes.
  - *The recorder asks the witnesses named in `witnesses.json`* (at most
    four, each on 127.0.0.1, with the fingerprint of its key set and its
    token; written by the new commands `add-witness`, which checks that the
    witness answers, holds the token and signs with that key set, and
    `remove-witness`). After each seal it asks each witness what it holds
    and whether it signs now, and shows one that does, in order, the seals
    it has not signed for whose lines are on the disk, with the proof RFC
    9162 sets out, made from the book's line fingerprints kept as the book
    grows (`proofs.mjs`, the same proofs as the library's `witnessProof`
    without reading the book again), and the book's first line; a witness
    that holds none of this sequence is shown the latest only. For the
    seal that `seal` makes, the seal's entry is first kept apart on the
    disk (`pending-seal.json`, written at its place at the next start if a
    stop comes first, or let go where its line is in the book or in a book
    kept since; one at a time), the witnesses are asked, and the
    statements that come within five seconds stand beside the seal on its
    line; the wait ends at once when any other request arrives, so no tool
    call waits for a witness. A statement is taken only where the
    library's checker passes it for that seal, as signed by the witness
    named; one that comes later is kept beside the book in
    `witnessed/<seal>.json`, in the form the checker takes with `--seal`,
    and `check` hands those of the book checked over, names the witnesses,
    and says plainly that those copies are the book's own seals from the
    recorder's folder, not seals held elsewhere, and cannot show the book
    cut short. A witness that is down, refuses, could not save, or hands
    back what does not pass never stops recording: `status` shows, for
    each, the seal it holds, whether that is the latest, and why not; one
    that holds a seal of this sequence in none of the recorder's books is
    reported (`witness-holds-another`) and is sent no seal. The record page
    tool, tried on a numbered book with statements, reads the books as
    before (it names no witness, and hands over no statement kept beside
    the book); the application's uploader reads the books through the
    feed, which is unchanged. Measured on a book of 93.5 MB with four
    witnesses: a tool call's two questions took at most 67 and 99
    thousandths of a second after a seal; during any seal a call waits for
    the seal itself, about 3.3 seconds on such a book, with or without
    witnesses.
  - *After its independent review*: a statement that could not be
    journaled was still given out through `/latest`, and after a restart
    the witness signed a different seal at the same size (fixed: only what
    is saved is given out, and nothing once a save has failed); a folder
    put back to a copy taken before the first statement started ready and
    signed a fork (fixed: never ready at a start until told); the journal
    was read whole at each start and could no longer be read at about
    8,000 lines (fixed: checkpoints, and a line at a time); proofs read the
    whole book each time (fixed: line fingerprints kept); and the low
    findings on the seal kept apart, the lock, the agent in the book
    before, `check`'s words and the passkey signature of a new sequence.
  - Stated: on one computer under one user account the agent can reach
    the witness's folder, so a witness means more under another account,
    on another computer through a tunnel, or run by someone else; a
    witness on another computer reached directly is not built; what
    travels is proved, not encrypted; one token serves every recorder the
    witness serves, and each can read what it holds for any of them, fill
    its sequences with permissions signed by passkeys of its own, and use
    up the shared statements; a witness put back to an older copy and told
    it is ready can be made to sign a fork (a test shows it); forgetting a
    sequence a recorder still uses lets that recorder have a second
    history witnessed. 51 new tests in the package (181 in all). Of 61 checks broken in turn, before and after the review, 59 are caught by a test; the two that are not (a stale lock taken without the second file, which only a race between two starts reaches, and the in-time ask kept to a book that passes its check, which no book the recorder holds fails) are stated.
- **The recorder beside Claude Code offers its books to a reader on this
  computer, through a feed on its own port** (`integrations/claude-code`,
  `feed.mjs`), so that no other program need open a book file. On
  11 October 2026 an uploader reading `book.jsonl` made the recorder's
  rename of it fail on Windows, and seven receipts were lost; the
  application's uploader now asks the recorder instead. `GET /books`
  lists the books oldest first (the kept ones by number, the one in force
  last), each named by its file's identity (the volume, the file's number
  and its creation time, which a rename keeps, reckoned as the uploader
  reckons it), with its size; `GET /lines?id=<identity>&from=<n>` (or
  `book=<name>`, or neither for the book in force) answers with up to 500
  lines (and at most 4 MiB) from place n, where each is in the file, the
  line before place n with its fingerprint, the number of lines and the
  fingerprint of the last; `max` asks for fewer, and 0 for none. Lines are
  counted as the uploader and the checker count them (an empty line and a
  carriage return set aside, a line with no line break not yet a line).
  Where the book holds nothing at place n yet, the question waits up to
  25 seconds (`wait`) and is answered as soon as any book is written, a
  late receipt or a seal again in a kept book included; at most 8 wait at
  once, and one more is told to ask again (429). The recorder writes a
  token into its folder at its first start (`feed-token`, 32 random
  bytes, readable by its owner only where the file system keeps such
  rights), and **the token never travels**: a reader opens a conversation
  (`GET /hello`) with a random number; the recorder answers with a random
  number of its own and HMAC-SHA-256 over both, keyed by the token, and
  the reader trusts nothing until that proof checks; each question then
  carries an HMAC under a key both sides work out from the token and the
  two numbers, with a number used once, and each answer an HMAC under the
  same key over the question's number, its code and every byte; every
  proof is compared in constant time, and a question asked twice is
  refused. Each of these 32-byte values is read only in the one way it can
  be written in base64url, so none can be given again under another
  spelling of the same bytes. A hello keeps nothing: the recorder's number for a conversation
  is worked out from the time, the reader's number and a secret only the
  running recorder holds, and a conversation is kept only from its first
  proved question; only proved conversations (at most 16, each ended
  after 10 minutes unused) give way to one another, so a program without
  the token cannot push out one in use. Each question, refused or not,
  still costs the recorder about a thousandth of a second, so very many at
  once slow the hook in proportion. A token file that holds no token is not replaced, and the feed
  then refuses every question and `status` says why. One answer is made
  at a time, with a pause between two, and at most 16 are taken on at
  once (429 beyond). The books the recorder holds open are read from its
  own copy in memory, only as far as it has written them to their files,
  so the feed answers while another program holds `book.jsonl` open with
  no sharing and never gives out a receipt whose save failed; a kept book
  it no longer writes is read from its file, 4 MiB at a time, and closed
  again. Measured on the author's computer with a book of 98 MB: about
  110 thousandths of a second for the first question, 1.8 seconds to read
  the whole book; a hook's two questions took a median of 61 thousandths
  of a second with no reader and of 160 (at most 266) with two readers
  reading the whole book again and again, and a hook's question 971
  thousandths with 1,500 feed questions at once. The service still listens
  on 127.0.0.1 only. Nothing of the record or the format changes.
- **The recorder never replaces its book because it could not read it**
  (`integrations/claude-code`). Where another program held `book.jsonl`
  for a few seconds while a receipt was saved, the recorder took the
  failed read as "no book yet" and replaced the whole file, which then had
  a new identity; an uploader following it stopped for good. Now the
  reading and the adding are tried again for up to ten seconds while the
  file is busy, a read that fails otherwise fails the save and leaves the
  file as it is, and the file is replaced only where it was read and no
  longer holds the book's start. Found by the independent review of the
  feed, with four faults of the feed itself, each fixed and tested: the
  token sent to whatever listened (now never sent); questions that do not
  wait had no limit (on a 98 MB book, 1,500 at once held a hook up for 22
  seconds); a receipt whose save failed could be given out; and a kept
  book of exactly 4 MiB that ended part way through a line lost that
  line's start. A second review found that a hello kept a conversation,
  so that a program without the token could push out the uploader's (now
  a hello keeps nothing). Where a save fails after the ten seconds, the
  hook is now told the truth: the stub is signed and held by the
  recorder, not yet in the book file, and written with the next save, and
  `status` counts it as recorded. A third review found that an ended
  conversation could be begun again under another spelling of its number
  (now refused), and that no test held the refusal of a hello dated ahead
  of the clock (now tested). 37 tests of the feed; the package's 130 pass.
- **Seals held elsewhere, handed over beside the book** (format
  description, section 21.5), in both languages. Whoever keeps a book
  could cut off its end, the last seal with it, and what is left still
  checks. Now anyone who keeps a copy of a seal (the person, an auditor, a
  second copy out of the recorder's reach) can hand up to 64 of them to
  the checker, each as the entry it is in the book: the option `seals`,
  `--seal <file>` on the command line (may be repeated), and a file
  chooser in the checking page's panel "What you were handed with the
  record". A seal at entry n must stand at entry n of the book. Two new
  codes, both problems with the book: `book-cut-short` (the book ends
  before that place) and `seal-not-in-book` (the entry there is not a
  seal with the same content; the same content with other signatures is
  the same seal, and is said). Nothing in a seal names its book, so a
  seal of another book by the same recorder is reported against the book
  being checked. Each seal handed over is checked as any seal is, once
  for a checker that is carried on and for the stub writer; it counts
  only where its recorder is named in `sealKeys` (`--sealer`), and on a
  device without SLH-DSA (the Python version, and browsers that have
  ML-DSA) on its Ed25519 and ML-DSA-87 signatures, which the answer says.
  Seals handed over without `--sealer` give no pass (code 1), and a line
  of their own says why, on the command line and on the checking page. One that does not pass its own check is a problem with
  the whole check. Its own time-stamps are shown, and are not used for the
  entries of the book; where they differ from those the book holds beside
  the same seal, the answer says so. A Show does not use seals held
  elsewhere, and says so. Each one is given in the answer's `held` list,
  after any cancellations, with `kind: "seal"`, `place`, `inBook`,
  `sealer`, `used`, `verified`, its signatures and time-stamps; the
  type declarations give `held` as `(HeldCancellation | HeldSeal)[]`.
  The check before acting and the stub writer take the option too, and a
  seal held elsewhere whose third signature this device cannot check is
  excused there as a seal in the book is. No new kind of record. The two
  codes join the format's own list of finding codes (`FINDING_CODES`).
  New shared test files: `held-seals`, `held-seal-shows` and
  `held-seals-before`; `denial-constants` changes for the two new codes,
  and no other shared file changes.
- **A new kind of record: the denial** (format description, section 28),
  in both languages. It is the agent's own side's signed statement that it
  did not take an action that was asked for, and who said no: the check
  before acting (with the finding codes it gave, from the format's own
  list, now written out in section 28), the person, or a rule of the
  software around the agent. It is signed with the agent's two keys, or a
  helper's under its pass, with the new labels
  `vnd.provared.denial.v0+json` (twenty-four labels in all). In a book it
  comes after its slip, is in no chain and is compared with nothing; a
  checker shows it as the agent's side's own word, counts it
  (`summary.counts.denials`, new in every answer), and never counts it
  against the agent. `writeDenial` (`write_denial`), `denialCodes`,
  `FINDING_CODES` and `DENIAL_SOURCES` are new. The stub writer writes a
  denial whenever `act` does not take an action if it is opened with
  `denials: true` (`more.denial: false` writes none for one call);
  `deny` writes one for a refusal from elsewhere; at most
  `denialsPerHour` (600 by default) are written in any hour of the
  writer's clock, each counted at the clock's time when it joins the
  book (whatever date it states), the answers count those left out, and
  a stub is never kept out. `deny` records what its caller states. `recordTools` and
  `record_function` pass it on (`NotTaken.denial`), and where the person
  may yet approve a call they write none until it is known the call will
  not run, so one call never leaves both a stub and a denial. The
  command-line checker and the checking page show denials. **A checker of
  an earlier version refuses a book that holds a denial** (`unknown-entry`).
  New shared test files: `denial-contents`, `denials-written`,
  `denial-codes`, `denial-constants`, `denial-books`, `denial-shows`,
  `denial-before` and `denial-scenarios`; `books`, `shows`,
  `recorder-scenarios`, `recorder-details-after` and `tool-scenarios`
  gain `denials: 0` in their stored counts, and nothing else changes in
  them.
- **`provared-hermes` 0.1.0, a plugin for Hermes Agent**
  (`python/integrations/provared-hermes/`): every tool call of a Hermes
  agent is checked against the slip before it runs, and a stub is
  written once it has run; a call the slip does not allow is not run,
  and the model is told why. It runs no recorded call on a Hermes it was
  not tested with (0.21.7 and later 0.21 versions) unless told to, and
  it loads on any Hermes so that its own check can refuse. Its commands
  are named by the same reading of the command text as the recorder
  beside Claude Code (below), with shared test rows that both languages
  answer alike. Checked by independent reviewers over eight rounds, the
  last six with the shared reading of commands, the last three clean;
  71 tests. Not on the Python Package Index yet: the README gives the
  command to install it from this repository.
- **The recorder beside Claude Code reads commands more closely**
  (`integrations/claude-code/`, not published), with the same reading
  as the Hermes plugin. A deletion or a publication is now named as one
  where it sits inside `"$( â€¦ )"` or back-quotes in double quotes, with
  quotation marks, `case` choices and comments inside; after a shell,
  `eval`, `ssh`, `watch` or another program that runs a command line;
  in a quoted command after `-c`, `-Command` or `-ArgumentList`; where a
  program is written as a path; or in text piped or handed into a
  shell. More publishing and deleting commands are named (among them
  `gem push`, `helm push`, `dotnet nuget push`, `docker buildx --push`,
  `rsync --delete`, `DELETE FROM` given to a database client and
  `redis-cli FLUSHALL`). Quoted words that run nothing, such as a commit
  message holding `rm`, are no longer named deletions; a back-quoted
  command in double quotes is, because the shell runs it. On a varied
  set of 11,340 deleting and publishing lines, none is named less
  strictly than before; on 109 everyday commands, 2 are named deletions,
  as before. The longest lines tried (about 900,000 characters) are read
  in under a second. The README lists what the reading still misses: a
  command line kept in a file or a variable, `-EncodedCommand`, and
  others. Writing the book file, the slip and the list of trusted
  passkeys is retried for up to ten seconds where Windows holds the file
  busy, and leaves no temporary file behind; a renewal held by a busy
  file can keep the service waiting about 40 seconds, during which calls
  are refused, never let through. Checked by an independent reviewer
  over six rounds, the last three clean; 60 tests.
- **The recorder beside Claude Code starts a new book at 90,000 entries
  or 100 MB** (`integrations/claude-code/`, not published). A book holds
  at most 100,000 entries, and once full every call would be refused. At
  90,000 entries or 100,000,000 bytes of text, whichever comes first, or
  on the command `new-book`, the recorder seals the book, keeps it beside
  the new one as `book-1.jsonl`, then `book-2.jsonl` and so on, and
  starts a new `book.jsonl` that begins with the permission in force,
  with no gap in recording; a call that ends during the switch is written
  into the kept book, which is then sealed again. Every limit is counted
  across the books, from the kept books' receipts and the calls still
  running, so a new book, by command, by size or after a restart, starts
  no limit afresh. A checker given one book still counts limits within
  that book only, so around a switch the record shown to a checker can
  hold up to twice a limit within one period across two books, though the
  agent was held to it. The README states what this does not close: a
  kept book moved, renamed or removed while the recorder is stopped is
  no longer counted, and nothing in the record shows it. The record page
  (`tools/make-record-page.mjs`) lists each kept book with its own
  checker's answer, and points out a gap in their numbers; the site's
  publishing run fetches them from the release "record". Checked by an
  independent reviewer over four rounds; 93 tests.
- **The recorder beside Claude Code numbers its books, chains each new book
  to the last seal of the book before, and asks witnesses; and a local
  witness service, `provared-witness`** (`integrations/claude-code`:
  `recorder.mjs`, `witness.mjs`, `witnessed.mjs`, `proofs.mjs`; live for the
  published record since 24 October 2026, 15:38 UTC). A book's number
  follows the passkey of its first line: a book that holds a seal goes on as
  its first seal says; one that holds none takes the latest kept book's
  number and one, where that book began with a permission from the same
  passkey and its last seal is by this recorder's keys, and its first seal
  names that book's last seal; where there is no such book it gives no
  number, so the record so far reads exactly as it did and its next book is
  book 2. The numbers are read from the kept files, never kept in a file of
  their own. Before the book in force is first sealed, every kept book that
  a late call could still come back to is closed and, where something came
  after its seal, sealed again, so that the first seal of book n names the
  last seal of book n - 1; a kept book that cannot be read when that seal
  needs it stops the seal, and the error says why. Every seal's line is
  made sure to be on the disk, and a witness is shown only such seals. A
  renewal with a new passkey starts no new book; the next book then begins a
  sequence of its own.
  - *Witnesses*: `witnesses.json` names at most four, each
    `{address, key, token}` at `http://127.0.0.1:<port>`, written by
    `add-witness` (which reads the token from the witness's token file and
    checks that the witness answers, holds the token and signs with that key
    set) and `remove-witness`. After the seal that `seal` makes (the
    command, `POST /seal` or the service's own) the recorder keeps the seal
    apart on the disk (`pending-seal.json`) before any witness is asked,
    shows each witness every seal after the one it holds (at first contact,
    the latest only), and waits at most five seconds, and no longer than
    until any tool call arrives; statements that come in time stand on the
    seal's own line, and every other statement is kept beside the book in
    `witnessed/<seal fingerprint>.json`. Each statement is checked with the
    library's own checker before it is kept. It asks again after each seal
    and every minute while a witness is behind; a witness that holds a seal
    of this sequence that is in none of the recorder's books is reported
    (`witness-holds-another`) and asked no more. A seal kept apart that the
    book changed under while the recorder was stopped is moved aside
    (`pending-seal-not-placed-<time>.json`) and `status` says so. `check`
    hands over the kept statements of the seals in the book checked (the
    latest 64) and names the witnesses of `witnesses.json`, unless `--seal`
    or `--witness` is given. `status` gains `witnesses`, `witnessesProblem`
    and `pendingSealProblem`; `seal` answers with `book` and `witnessed`.
  - *The witness service* (`provared-witness`: `init`, `start`, `status`,
    `ready`, `update`, `forget`, `stop`) listens on 127.0.0.1:8796 with a
    folder of its own (`witness-keys.jwk`, two tokens, `witness.json`,
    `journal.jsonl`, `state.json`, `checkpoint.json`, `journal-mark.json`,
    `witness.lock`). One token is for the recorders it serves and one for
    its operator; questions and answers are proved as the feed's are
    (HMAC-SHA-256 under a key worked out from the token and two random
    numbers; one question to a conversation). It signs only for the
    recorders its operator named, by the fingerprint of their key sets, and
    only after the journal line, then the state, then the mark, are on the
    disk; after a save that fails it answers 503 until it is started again;
    at every start it signs nothing until its operator says it is up to date
    (`ready`), after taking its own journal again, and it refuses to start
    where the journal has gone while the keys are there, where a line is not
    one it writes, or where its state reflects more lines than the journal
    holds. Limits: 120 new statements in any hour, 64 sequences, 8 signing
    or updating questions at once, bodies of 1 MiB. There is no background
    start: whoever runs a witness decides how it is kept running. Stated in
    the README: a witness is only as sound as its folder, and whoever can
    change it, or put back an older copy whole, can make it forget a
    sequence.
  - The package depends on `provared` 0.6.0 or later. Three independent
    reviews: the first found one serious fault (a statement given out that
    was never saved, so after a restart the witness could sign a fork) and
    three medium; the second and third found nothing serious or medium.
    189 tests, and the three test fixes of 21 October brought across.
- **`provared-gateway` 0.1.0, a reverse proxy that writes the receipts**
  (`gateway/`, not published). It sits in front of the web interfaces an
  agent acts through, holds the agent's keys (in memory or through
  signers) and each interface's credential, and for every call: checks
  the agent's own secret, names the call from a rules file the company
  writes (paths by the WHATWG URL Pattern standard, amounts by a fixed
  value, a JSON Pointer of RFC 6901 or the length of a list), removes
  the agent's own credentials from the headers and the address, asks the
  stub writer's check before acting, sends the call, and writes a stub
  that names `provared.http-request`, `provared.http-response` or
  `provared.error`, and the upstream's own identifier where it gives one.
  A call that is not allowed is not sent, is answered `403` with the
  checker's words, and is written as a denial; a call that matches no
  rule is refused by default. A call once sent always gets its stub,
  whatever the upstream did. An upstream the company runs may
  countersign. Books are sealed on demand with the recorder's keys
  (`provared-gateway seal`); `provared-gateway check` says what each rule
  maps to and what is wrong. Each book is a file appended line by line;
  the feed to the application is not built. It is the gateway's record
  only, and proves nothing about calls that do not go through it, as its
  README says first. An independent review found one serious point: a
  body naming `hosts` and `HOSTS` was recorded with the first's amount,
  while an upstream that reads names whatever their case acts on the last.
  Now a body whose names some readers take as one (differing only in
  capitals, or in the long s or the Kelvin sign) gives no amount, and the
  call is not sent. Also from the review: method and address override
  headers and `_method` are removed, with every `X-Forwarded-*` and the
  other client-address headers; a `;` in a path is refused unless the
  upstream allows it, and then the rules match each segment without what
  follows its `;`; overlong UTF-8 and full-width `/` or `.` in a path are
  refused; each agent may have only so many calls and bytes waiting; a
  journal beside each book lets a start find a call that was sent when the
  gateway stopped, and stops that agent until the administrator
  acknowledges it (`provared-gateway acknowledge`), when a stub saying the
  outcome is not known is written; header names with `_` and a
  `Connection` header that names other headers are refused; more
  credential headers and query forms are removed; a character set other
  than UTF-8 gives no amount; a credential that cannot be sent as a header
  is refused at start; a stub for a call that never reached the upstream is
  labelled `gateway.not-delivered`; two agents may not share a secret or a
  book file; and the status answers while a call is out. A second review
  found two medium points in the journal: one call could get two receipts
  (a stop between its stub and the journal's "done" line, or an
  acknowledgement tried again after a failure), and any program that could
  write the journal could have the gateway sign stubs of its choosing. Now
  every stub names its call (a label, `gateway.call`), and a start takes a
  call whose stub the book holds as done; each journal line carries an
  HMAC-SHA-256 tag under a journal key of the agent's own, and a line
  whose tag does not check is never acted on; each line is checked against
  the rules before a stub is written from it; the status shows each
  waiting line whole; and the administrator can set aside a line
  (`acknowledge --set-aside`). Also from that review: JSON names are
  folded beyond ASCII (Greek final sigma, the dotless i and others), so an
  unrelated `ID` and `id` in one object now give no amount; an encoded
  character in a path whose NFKC form differs from itself is refused;
  `provared-gateway repair` takes off a book's last line that a stop left
  part-written; and two agents may not share a book, a journal, a journal
  key or a key file. A third review found one medium point: a stub
  written on acknowledgement went under the slip in force at the restart,
  not the one the call was sent under. Now each journal line names its
  slip, and the stub is written under that slip (by a stub writer for it,
  opened on the same book), or, where the book does not hold it, the line
  can only be set aside. Also from that review: two agents' files are also
  compared by each existing file's device and file numbers (a link to
  the file is followed), so, where the file itself exists, a hard link or
  a link to the file counts as the same file; a journal that none of its
  lines checks under the journal key in place stops the start; a
  journal that holds lines and has lost its key stops the start (each of
  these two stops the whole gateway, not that agent alone); a line
  whose rule was taken out can still be acknowledged, with a warning; a
  clock behind the journal's times is said plainly; calls set aside are
  kept in a file a clean start does not empty; the library's own checks of
  a request's fields decide whether a line is usable; the dotted capital
  `Ä°` folds with `i`; `repair` takes its byte count only in digits and can
  put back a lost line ending; and the README lists which honest path
  forms are refused. 68 tests, all on 127.0.0.1, with a file of 145 calls
  and the action, amount and service each must map to.
- **A central sealer** (format description, section 21.7, new; no record
  changes). The recorder's three keys can now sit apart from the agent,
  with a party that never sees the book.
  - *In the library*: `leafFingerprint(line)` (Python:
    `leaf_fingerprint`), the SHA-256 of the byte 0x00 and one line of a
    book, refused where the line is empty, holds a line feed, is not
    well-formed Unicode or is over 131,072 bytes; and `openSealer({by,
    signers, stamp, state, clock, signWithin})`, which takes the leaf
    fingerprints of each book's lines (`extend(book, at, leaves)`, only
    at the place it holds, so a line is never taken twice), keeps the
    same running tree the checker keeps, and signs a seal over its own
    number of entries and top fingerprint (`seal(book, {previous})`),
    through the same keys and signers `writeSeal` takes, each signer
    given 30 seconds. The seal is the one `writeSeal` signs over the same
    book, with the same time and unique number. It signs only where
    `previous`, the seal the caller's book names, is the latest it
    holds of that book (`not-up-to-date`): a sealer whose state is
    behind the book signs nothing until it is brought up to date with
    `update(book, entry, leaves)`, from a later seal it signed and the
    leaf fingerprints since its own latest seal, which must give that
    seal's top fingerprint; it is never moved back. `latest(book)` hands
    back its latest seal, for a book that lost it. A book is known by
    its first line's leaf fingerprint and its number; a later book names
    the book it follows, its first seal names that book's last seal, and
    that book is then closed (also where that first seal is brought in
    with `update`, which waits, `not-up-to-date`, while the sealer holds
    that book at an earlier seal than the one named). Every book with one first line is one chain: a book
    whose first line the sealer holds starts only as the next book after
    the latest with that first line (`not-next-book`). One sealer may
    serve several recorders, through `forRecorder(name)`: a book, and
    every book after it, belongs to the recorder that started it
    (`other-recorder`). A recorder may be given rules,
    `forRecorder(name, {agents, books})`: the fingerprints of the key
    sets of the agents whose permissions it may start books with (an
    agent belongs to one recorder), and the most books it may hold
    (`too-large`). Where any recorder has a list of agents, every book is
    started with its first line itself (`line`, beside `extend`, or
    `update` for a book brought in), which must be a permission for one
    of the caller's own agents (`agent-not-allowed`, `other-recorder`);
    so no recorder can start a book whose first line is a permission for
    another recorder's agent, nor bring another's book in first after a
    lost state. The sealer then learns each first line; it does not check the
    passkey's signature. `releaseUnsealed({recorder})` takes off books
    that hold no seal, for which nothing was signed. A book started
    after a book that another book now follows takes no first seal
    (`book-closed`). Every seal is checked (all three signatures)
    before it is kept; the state is handed back with a seal, a book
    started and `update`, to be saved before the answer is given out. Of
    a seal entry brought in with `update` only the seal, whose three
    signatures it checks, and its time-stamps are kept, the time-stamps
    read for their form only (at most four, each at most 12,288 bytes,
    in base64url, none twice; no time-stamp's signature is checked); its
    witness statements are not, and an entry longer than a line of a
    book is refused (`too-large`), so that no recorder can make the
    state too large to save. The entry is read once, and what is
    measured, checked and kept is that one copy, so a member that gives
    another value at each reading cannot slip past the checks. A
    book is kept in the state at its latest seal, or with none at its
    first line, so a sealer started again asks for the lines since; at
    most 1,000 books, about 52 KB of state for each sealed book. With
    its state kept it never signs two histories of one first line; a
    book from another permission for the same agent that repeats sealed
    lines, and a lost or older state, still need a witness. It sees only
    fingerprints after the first line, so a recorder can start a book
    from a permission for its own agent, copy into it another
    recorder's agent's permissions and stubs with some left out, and
    have it sealed: where one person's passkey signed the permissions
    for both agents,
    the book reads as intact and within its slips, and a witness
    statement on its seal is not counted. A seal of the other
    recorder's own book held elsewhere shows it (`book-cut-short` or
    `seal-not-in-book`; where the two books' numbers differ, it cannot
    be compared, and gives no pass); readers of books from a shared sealer should
    hold each recorder's own seals elsewhere, or run a sealer for each
    recorder. It needs SLH-DSA built in, so
    Node.js; Python has no sealer. `writeSeal` and the sealer share one
    signing path (`sealOver`, not exported). The tree builder gains
    `addLeafHash` and `parts` (Python: `add_leaf_hash`).
  - *A new shared test file*, `sealer-trees.json`: lines or leaf
    fingerprints, and the number of entries and top fingerprint after
    each; both languages give every answer.
  - *`provared-sealer`* (`sealer/`, version 0.1.0, not published): the
    sealer as a program on 127.0.0.1 (port 8797 by default), with its
    keys in a file for its owner alone or reached through signer modules
    named in its settings, a token for each recorder, the agents whose
    permissions each recorder may start books with and the most books
    it may hold (100 unless it says; all recorders' books add up to at
    most 1,000), and one state for every recorder's books, each book
    bound to its recorder; `release-unsealed` takes off, while it is
    stopped, the books that hold no seal. A question proves its
    recorder, and an answer its sealer, with HMAC-SHA-256 under the
    token over a time, a number used once and the body; the token never
    travels; each recorder's numbers used once are kept apart, for as
    long as its question's time could be taken by a clock that never
    goes back; the recorder's name, the time, the number and a first
    proof over the body's declared length are checked before the body
    is read, so no body is read for a program without the token, and at
    most 16 MiB of bodies being read are held for one recorder. A
    question waits for its turn as the bytes of its body only, at most
    16 questions and 32 MiB for one recorder, and its body is read as
    JSON only in its turn, so one read body exists at a time. A body
    must be a JSON object, and may hold only the members its path takes
    (`bad-field`); `connectSealer`, the recorder's side, refuses before
    sending any member of `more` the path does not take (`id` for a
    seal among them), so `more` cannot replace `book`, `at`, `leaves`
    or `entry`, and sends a `when` given as a `Date` as its
    milliseconds. A question
    turned away as `busy` keeps no number. Questions are answered one at a
    time; the state is made sure to be on the disk before an answer to a
    question that changed it; a seal is never given out before the state
    that holds it is saved, and after a failed save every question taken
    up is answered `sealer-stopped` until it is started again. A missing
    state stops the start, and adding a recorder (`--fresh` begins it
    again); `add-recorder` refuses a name that has books in the state
    (a recorder written into `recorders.json` by hand is not checked so); one
    sealer on a folder at a time. It names no time-stamp service and
    asks no witness yet.

## 0.5.0 (17 October 2026)

- **The README's count of review rounds: 50.** The 40 recorded by
  version 0.4.0, and 10 since: five of the Agno package, three of the
  signer interface and two of the stub bound to the platform's own
  record, each listed below.
- **`provared-agno` 0.1.0, an Agno tool hook**
  (`python/integrations/provared-agno/`): every tool call of an Agno
  agent is checked against the slip before it runs, and a stub is
  written once it has run. A call the slip does not allow is not run, and
  the model is told why. Agno's own steering tools cannot carry an action
  past the record: a hand-over, or a task in a team's task mode, goes
  only to a member with the same writer's hooks, read from Agno's own
  list of tasks, not from the session's copy that the model can rewrite.
  A stub is written only once its tool has completed, even where a
  helper agent runs inside the tool, on the same event loop or on one of
  its own; a tool that never completes leaves none, and a cancelled tool
  that completes all the same is recorded. Checked by an independent reviewer
  over five rounds (faults found in the first four, the fifth clean);
  each fault is a test, 68 in all. Not on the Python Package Index yet:
  the README gives the command to install it from this repository.
- **Signers: keys held elsewhere, in both languages.** Wherever a writer
  takes `privateKeys` (`private_keys` in Python), each item may be a key,
  as before, or a signer: an object with `key`, the public key, and
  `sign(data)`, which gives the signature bytes. So a key may live in a
  key service or a hardware module. `signerFromKey` (`signer_from_key`)
  wraps a key held in memory as a signer. A record made through a signer
  is the same record: the same content, labels and Ed25519 signature. A
  signer is not taken on trust: before any signer is asked to sign, its
  key must be plain data, of the method of its place, of a method the
  device can check, and, where the writer knows it, the key the record
  must be signed with (`bad-key`); every signature it gives is checked
  against its key before it is used, and one of the wrong length, one
  that does not check, something other than bytes or an error leaves no
  record (`signature-invalid`), with the method and the key named. The
  stub writer gives a signer 30 seconds for each signature (`signWithin`,
  `sign_within`); after that nothing is written and the writer goes on.
  In Python no seal is written, with keys or signers, as before. Every
  private key that made a correct record before still does, in the same
  way: in JavaScript a private Web Crypto key of the place's method for
  Ed25519 and ML-DSA-87, and for a seal's SLH-DSA-SHA2-256s a Node.js
  KeyObject or what Node.js's own signing call read before (PEM text,
  DER bytes with their format, a JSON Web Key with its format); in Python
  a private key of `cryptography` of the place's method. Refused now
  (`bad-field`), though accepted before: in JavaScript, a private key of
  another kind in a seal's SLH-DSA place, and in Python a private key of
  another method or kind (such as Ed448 in the Ed25519 place); each made
  a record that failed its own check. In Python, an object with only
  `sign` now needs `key` as well: it is a signer. Anything else that is
  neither a key nor a signer (a public key, a key of another method in
  JavaScript's first two places, a value that only looks like a key) is
  refused with `bad-field`, where before it failed with the platform's
  own error. No record and no rule of the format changes. `signWithin`
  must be 1 to 2,147,483,647 milliseconds (`bad-field`). Checked by an
  independent reviewer over three rounds, the third clean; each fault is
  fixed and is now a test.
  Tests: `test/signers.test.mjs`, `test/signers-unavailable.test.mjs` and
  `python/tests/test_signers.py`.
- **A stub bound to the platform's own record of the call, in both
  languages** (format description, section 27). Document names that
  begin `provared.` are now reserved: seven are listed
  (`provared.arguments`, `provared.http-request`,
  `provared.http-response`, `provared.trace-id`, `provared.request-id`,
  `provared.event-id`, `provared.error`), each with the exact text its
  fingerprint is made from, so that someone who holds another system's
  own log can match a stub to it. Only the three identifiers
  (`trace-id`, `request-id`, `event-id`) pick out one call; the others
  show only that the content matches, and the request and answer
  fingerprints cover no header. Any other name that begins `provared.`
  is refused (`bad-field`) in a stub, an approval and the check before
  acting; before, it was a label. So is any of the seven but the three
  identifiers named twice in one record. **A book written before this
  change that holds a stub, or an approval, with such a name now fails
  its check, and the check before acting then refuses every action
  under it** (and a stub writer will not open on it). A checker of
  version 0.4.0 or earlier reads the reserved names as labels.
  `DOCUMENT_NAMES`,
  `httpRequestFingerprint`, `httpResponseFingerprint` and
  `identifierFingerprint` (`http_request_fingerprint` and so on in
  Python) make the fingerprints; an HTTP request or answer is written as
  the signature base of RFC 9421, with the Content-Digest of RFC 9530
  over the body after any content coding, and its address is taken
  exactly as sent; a body of null (None) is no body. The stub writer's `act`
  takes `detailsAfter` (`details_after` in Python): up to four further
  documents, from what the action gave back, such as the identifier a
  platform gave the call. The stub is still checked with the whole book
  before the action; after it, the stub is signed again with them in the
  same call, and keeps the time the action began. If they cannot go in,
  the stub is written without them and `detailsAfter` in the answer says
  why: an action that was taken always gets its stub (where the second
  signing fails, it says so: `details-not-added`). It cannot be used
  with an approval. With it, the request may name at most 28 documents
  (`bad-field`), and an action whose stub would leave no room for four
  more is not taken (`too-large`); `detailsAfter` is given as long as the
  other side is given to countersign. `recordTools` and `record_function` still name the
  arguments `arguments` by default. Shared test files: `stub-contents.json`
  gains cases (made again; its earlier cases are unchanged), and
  `http-fingerprints.json` and `recorder-details-after.json` are new.
  Checked by an independent reviewer in two rounds, the second clean.
  Tests: `test/documents.test.mjs` and `python/tests/test_documents.py`.

## 0.4.0 (14 October 2026)

- **The command-line checker counts the keys it was given.** With two
  passkeys named, its summary said "yes: the passkey you trust"; it now
  says "the passkeys you trust", and "the recorders you expect" where
  more than one recorder is named; the same key named twice counts once.
  Only the words change; tests hold them. The guide gives the fingerprint
  of the checking page built as one file for this version, which changed
  because the checker it holds, and the page itself, changed.
- **The README's count of review rounds is brought up to date: 40.** The
  25 recorded by version 0.3.0, and 15 since: three of the library's
  changes of 11 to 13 October (the seal rule, then a narrow review of four
  commits and a check of its fixes), three of the signing page, six of the
  recorder beside Claude Code, two of the record page's book in a release,
  and one of the asynchronous reads below. Each reviewer is a fresh
  session given the code, the documents and a brief of what to look at;
  the README now says so, and that a fault may be stated as a limit rather
  than fixed.
- **The two framework packages require version 0.4.0**, so that an
  agent behind either goes on after its book is sealed (below).
  `provared-langchain` becomes 0.1.1, which also carries the keywords,
  the homepage and the mark added on 10 and 11 October.
  `pydantic-ai-provared` 0.1.0 is its first version; its README already
  gave the command to install it. Both are published separately, on the
  Python Package Index.
- **The LangChain and Pydantic AI packages read the stub writer safely
  from asynchronous code**: `await middleware.snapshot()` and
  `await capability.snapshot()` give the book and the cancellations the
  writer holds, waiting in a thread of their own. The READMEs said to
  read it with `asyncio.to_thread(writer.snapshot)`; but in the event
  loop's shared threads such a read waits for the action in progress,
  and enough of them at once leave no shared thread for a tool that
  needs one, so the tool and the reads wait for ever. Found while
  building a package for another framework; checked by an independent
  reviewer, and a test in each package fails without it.
- **A proposed action dated by text gets a plain refusal.** The check
  before acting took a time given as text, or a number or a Date that
  gives no time, to the catch-all "the checker met something it did not
  expect" (`check-failed`). It now answers `bad-field`: "when: must be a
  number of milliseconds, or a Date" (the stub writer's own words), or
  "when: does not give a time" (new words, for a number such as Infinity,
  a Date that is not a time, or a Date wrapped in a Proxy). In Python a
  datetime counts as dated only where its time zone gives an offset, as
  Python's own rule for an "aware" time says. Nothing that was allowed is
  refused, and nothing that was refused is allowed. The stub writer
  answers in the same words: its "before" and "act" took a Date wrapped
  in a Proxy to a plain TypeError, and now answer "when: does not give a
  time", as the check before acting does; its "record", which does not
  ask first, took any time that gives none to a plain "Invalid time
  value" error, and now refuses it with `bad-field` in those words. In
  both languages; the shared test file for the check before acting gains
  two cases, and in the stub writer's scenarios the one step that hands in
  a time of Infinity changes its words, and the one step that records an
  action at a time outside the range of times changes its answer. Tests
  in both languages hold a Date in a Proxy and, in Python, a time zone
  that gives no offset.
- **A record's signature of the wrong length is invalid on every
  device.** An Ed25519 signature is 64 bytes, an ML-DSA-87 signature 4,627
  and an SLH-DSA-SHA2-256s signature 29,792 (RFC 8032, FIPS 204, FIPS 205).
  One of another length can never check, and a device that has the method
  already said "invalid"; a device without it said "not checked on this
  device". Now every device says "invalid", for every signature of a
  record, the passkey's Ed25519 signature on a slip among them. So, on a
  device without SLH-DSA, a seal whose third signature is cut short or
  empty is a problem, not something the check before acting goes on
  without. The signature inside a time-stamp from a service is not
  covered: on a device without its method a time-stamp is not checked,
  whatever its length, and is not counted. A third signature of the right
  length that would not check is still not seen on a device without
  SLH-DSA. The format description states the rule in section 3.9 and
  what it means for a seal in section 20; the list of threats says that a
  third signature of the right length is not seen there. In both
  languages; the shared test files for a whole book and for the check
  before acting gain a case each, and tests in both languages hold each
  method's length, shorter and longer, with the method and without it.
- **The check before acting goes on without a seal's third signature, and
  says so** (decision F-106; this changes choice 66 of the draft). Found on
  11 October 2026: a device that cannot check SLH-DSA-SHA2-256s, which is
  every Python stub writer (and so the LangChain and Pydantic AI packages)
  and every browser, was refused every action as soon as its book held a
  seal, because the check allowed nothing unless every signature in the
  record so far had been checked on that device. Now, where the only
  signatures not checked are the third ones of seals whose first two were
  checked there, and nothing else was left unchecked, the check goes on and
  its answer carries `notChecked: ['SLH-DSA-SHA2-256s']`. Any other
  signature left unchecked still refuses everything, and the full checker's
  answers are unchanged. In both languages: the shared test file for the
  check before acting gains seven cases with a seal, besides the one with
  a third signature cut short counted above (found missing by two
  independent reviews, which showed that weaker rules passed every test:
  the last case, a permission and a seal alone on a device without
  ML-DSA-87, holds the rule that the seal's ML-DSA-87 signature must have
  been checked), and the shared test file for the stub writer's scenarios
  is remade. Tests in both languages hold the same rule.
- **The signing page names the agent's keys by the fingerprint of their
  key set** before the passkey is asked, worked out by the library's own
  `keySetFingerprint` (as a recorder's key set is named), and asks the
  person to compare it with the one the agent's software printed when it
  made its keys: a link, or a permission pasted from elsewhere, could
  carry someone else's keys under a familiar name. Keys that are not a
  key set are refused there, in the library's own words. A test holds the
  page's words against the library's fingerprint.
- **The signing page fills itself from a link, and shows everything a
  link could slip in before the passkey is asked.** A link to
  prova.red/sign/ may hold a starting permission after "#"; that part
  stays in the browser and is never sent to a server. A link that cannot
  be read leaves the page's own starting point and says why; a second
  link opened in the same tab fills the page again. Because a link can
  name anything, the page now shows, besides the agent's key-set
  fingerprint (above): each service's keys by the fingerprint of their key
  set, as a checker names them (keys that are not a key set are refused,
  in the library's own words); and the agent's software statement, marked
  as the person's statement and not proof of what runs. Shown inside
  another page, it offers nothing to sign or cancel, since another site
  could frame it filled from a link of its choosing. It now has a content
  security policy that lets it load only its own scripts and style sheet
  and send nothing anywhere; the message of the commit that added the
  link said its policy was unchanged, but the page had none. Tests hold
  each point. Checked by an independent reviewer over three rounds.
- **The recorder beside Claude Code is a package of its own,
  `provared-claude-code` 0.1.0** (published separately, on npm), in
  `integrations/claude-code/`, in place of the recorder of 10 October.
  `init` makes the keys, writes the hooks and prints a link to the signing
  page filled in with a starting permission; `use` puts the signed
  permission in place; `renew` takes a new permission while the recorder
  runs, with no moment in which a call finds it gone. A permission from a
  passkey the recorder has not trusted before is taken only with
  `--new-passkey`, and the passkeys it trusts are kept in
  `trusted-passkeys.json`. The hooks `init` writes match every tool,
  record calls that failed, and refuse a call where the hook itself fails
  (`"onFailure": "block"`). A command is named by reading its line three
  ways (as a shell splits it, from every known program's name, and with
  the first version's patterns), and the strictest name counts; a line
  handed to a shell, to `eval`, `iex` or `Invoke-Expression`, and the
  command `find -exec` runs are read the same way. A call allowed under
  one permission and taken while a renewal switched to the next is
  recorded under the one it was allowed under, and the stub of a call that
  was taken is always written. `keys` and `init` print the fingerprint of
  the agent's key set, which the signing page asks the person to compare;
  `seal` shows the recorder's error. Checked by an independent reviewer in
  six rounds; each fault found is a test (57 in all).
- **The record page's book and the checker's answer are kept in a release
  of the repository, not in the repository itself**: they grow by
  megabytes a day, and GitHub refuses a file over 100 MB.
  `tools/make-record-page.mjs` writes their SHA-256 fingerprints beside
  the page (`site/records/files.sha256`); the site's publishing run
  fetches both from the release "record" and publishes nothing unless each
  matches, and every file the page links is there. Readers see no change.
  The tool now reads the growing book once, into the page's own folder,
  leaving out a last line still being written, so that the page, the
  checker's answer and the fingerprints describe one book (the page of
  14 October said 3,771 receipts above a summary of 3,770 stubs). It
  counts the passkeys that signed the book's permissions from the book,
  and refuses a passkey named to it that signed none. Checked by an
  independent reviewer in two rounds.
- **What browsers check, tried again on 13 October 2026.** Chrome 155,
  Edge 155 and Brave 155 each offer Ed25519 and ML-DSA (all three
  strengths) to a page and check real signatures made with them; none of
  them offers SLH-DSA. The README, the guide, the list of threats, the
  home page, the worked example and the tool that writes the record page
  now say so; they said, from a try on 12 October, that Chrome 154 did
  not check ML-DSA. No code changes.
- **The recorder beside Claude Code appends to the book, and no longer
  loses a receipt while another program reads the file.** It wrote the
  whole book to a temporary file and renamed it over the old one; on
  Windows that is refused while anyone holds the file open (an uploader,
  a virus scanner), and the hook then reported "the action was taken and
  is not in the record". Found on 11 October 2026, when a program that
  uploads the book was reading it every two seconds: 7 of one helper's 23
  tool calls were taken and not recorded. A book only grows, so the
  recorder now appends the new lines; where the file does not match the
  book it is replaced, with retries for up to two seconds. A test holds
  the file open while the recorder saves.

- 2026-10-11: **one mark everywhere**: a permission slip with a
  signature, white on red (#8f000f), as `site/favicon.svg`, in the
  social preview `site/preview.png` beside the word, as inline SVG in the
  header of every page at prova.red, of the checking page and of the
  signing page (no page makes a request for it), and at the top of the
  README and of the three Python packages' READMEs, which the registries
  show with the next published version. The four colours of the parts stay as they are inside the
  pages. The style sheet gains one rule for the mark and a new version
  number. No code changes.
- 2026-10-10: **a real record on prova.red**, `tools/make-record-page.mjs`:
  writes `site/records/` from the book that the recorder beside Claude
  Code keeps. It copies the book and its slip beside the page, runs the
  command-line checker with the passkey and the recorder the reader is
  told to trust, keeps the whole answer as a text file, and writes the
  page from what the checker answered: the slip in the checker's own
  words, the counts by day, by kind of action and by tool, the seals,
  any entry outside the permission, the summary exactly as printed, and
  what the check does not show. The page says that a refused call
  leaves no entry and that every receipt is one-sided. It is run again
  each day while the permission lasts; the home page links to it. A
  test runs the tool on the sample record into a folder of its own.
- 2026-10-10: **the pages at prova.red, the README and the framework
  packages, after the adoption review**: the line under each page's
  title names its reader and then the slogan; "How it is built" on the
  home page is two sentences; the developer page says "the person"
  throughout, names the nearest other projects beside what the
  author found nowhere else, and gives the author's own reason for
  building it; the plain-words page names Article 12 and
  Article 26 of the AI Act, no longer repeats its opening, and asks a
  reader who breaks it to open an issue; every page ends with two
  lines about the author; the README shows the LangChain example; the
  two framework packages gain keywords and a homepage. No code changes.
- 2026-10-10: **a signing page**, `page/sign.html`, served at
  prova.red/sign/: a person writes a permission as JSON (the agent's
  name and two public keys, the actions, limits, conditions, stated
  rules, with whom, from when until when, and why), sees it in words,
  signs it with a passkey made for the website, and saves the signed
  file; the page shows the passkey's thumbprint and the permission's
  fingerprint. It can also sign a cancellation of a permission signed
  with the same passkey. It uses the library's browser part and
  `render.js`, loads nothing from anywhere else and sends nothing. The
  workflow serves it beside the checking page.
- 2026-10-10: **the recorder beside Claude Code**, `integrations/claude-code/`:
  a hook that Claude Code runs before and after each tool call, and a
  small service on 127.0.0.1 that holds the stub writer open on one book
  under a slip the person signed. Before a call, the check before acting
  refuses a call outside the slip and Claude Code is told why; after it,
  a stub is written naming the tool and the SHA-256 fingerprint of its
  arguments; the service seals the book on request with the recorder's
  three keys. Tool calls are named from the shared list by the hook,
  not by the agent (a command that removes something is
  `provared.data.delete`; one that publishes is `provared.code.release`);
  tools that only talk to the person are not recorded. The agent's two
  keys and the recorder's three are kept as JSON Web Keys in files the
  person keeps. If the service is not running, a call is refused: no
  record, no action. The folder names a product, as the framework
  packages do; the library names none, and the npm package does not
  hold it. Five tests run the hook as Claude Code runs it.
- **The tests clean up after themselves.** Nine test files made a
  temporary folder for each run and left it behind; on 13 October 2026
  the computer's temporary folder held about 2,800 of them. A small
  helper, `test/helpers/temp.mjs`, now makes each folder and removes it
  when that test file's tests end. Run with an empty temporary folder,
  the library's tests leave nothing in it.

## 0.3.0 (10 October 2026)

- 2026-10-10: **a development stand-in for a passkey**, `provared/dev`
  in JavaScript and `provared.dev` in Python, so that a first record can
  be made without a browser: `developmentPasskey` (an ES256 key made in
  memory that returns the three values a passkey returns, for the page
  address `http://localhost`), `developmentSlip` (a slip it signed, with
  new keys for the agent, a book holding the slip, and the stand-in's
  thumbprint for a checker) and `developmentRecorder` (the stub writer
  opened under such a slip, in one call). It is not a passkey and no
  person confirms anything through it, so the issuer's name in every
  slip it signs is made to end with " (development)", whatever name is
  given, and the checker prints that name. The library itself (`provared`)
  does not export it, and the checker does not use it. A first record in
  one file: `examples/first-record.mjs` and
  `python/examples/first_record.py`, each run by a test.
- 2026-10-10: `provared-check --sample` checks the sample record that
  comes with the library, naming the stand-in passkey, the recorder and
  the time-stamp service it was made with as trusted, and prints their
  fingerprints; with `--json` the result alone. A file or another option
  given with it is refused.
- 2026-10-10: the README is now a short landing page (install, a first
  record, the four parts, what is only here, what a record does not
  prove, where everything else is), and its former body is
  `docs/guide.md`, unchanged but for the additions above. New:
  `SECURITY.md` (how to report a fault in the security of a record) and
  `CONTRIBUTING.md` (fault reports and other implementations welcome;
  code only under a contributor agreement, whose text is not ready yet).
  `package.json` and `python/pyproject.toml` gain a homepage, keywords
  and a longer description. Version 0.3.0 in both, not yet published.
- 2026-10-10: the pages at prova.red: the home page's first screen now
  shows the checker's summary and the install lines before the four
  parts, with the plain word first and the short name after ("the
  permission (a Slip)"); a first record of your own, in three commands,
  with the file above and the LangChain package; "what the author found
  nowhere else (October 2026)"; the status promises that every published
  version stays on npm and the Python Package Index. The plain-words page
  says that the 25 rounds of review were by AI reviewers and that no
  person other than the author has reviewed the code yet, gives the date
  from which the EU AI Act's logging duty applies (2 December 2027),
  marks its charity example as invented, and uses "flight recorder" only
  as a description. The developer page shows the code that made the
  sample record and says the same about the reviews. All three pages
  gain preview tags, an icon (`favicon.svg`, four coloured squares) and
  a preview image (`preview.png`, drawn from a small page in a headless
  browser), with the content security policy widened by `img-src 'self'`
  only; `robots.txt` and `sitemap.xml` are added, and the workflow copies
  everything in `site/`. Nothing in the library changes for this.
- 2026-10-10: the pages for prova.red, in `site/`: what a record
  proves, the command-line checker's own answer for the sample record
  (run on Node.js 24.19), how to try it, what is only here, how it is
  built, where it is, a worked example for developers ("An agent goes
  over its limit, and the record shows where") and "Provared in plain
  words", three minutes for a reader who does not write code, with two
  drawings that follow the sample record. No script, no font, no image,
  no form: each page loads nothing from anywhere and keeps nothing about
  a reader, and says so. The drawings carry their colours as plain SVG
  attributes as well as through the style sheet, and the pages load the
  style sheet under a versioned address, so a browser that kept an
  earlier copy still draws them right. A workflow, `.github/workflows/pages.yml`,
  publishes them with GitHub Pages from the main branch, with the
  checking page at `/check/` (with the library and the sample it loads,
  copied as they are) and built as one file at `/provared-check.html`.
  The four actions it uses are GitHub's own, each pinned to the commit
  of a released version. The site is not published until the domain
  points at it. Nothing in the library, the checker or the package
  changes.
- 2026-10-08: two small Python packages for agent frameworks, in
  `python/integrations/`, each in a folder of its own, which names its
  framework. Each puts every tool call of an agent behind the stub
  writer with no change to the tools: the check before acting is asked,
  the tool runs only if the slip allows it, and a stub is written; a call
  that is not allowed is not run, and the model is told why. Each checks
  the call as the tool receives it: one must come last among the parts
  that wrap tool calls, and refuses to run otherwise; the other wraps
  each of the agent's own sets of tools, wherever it stands. Each works with ordinary
  and asynchronous agents: the stub writer runs in a thread of its own
  for each call, and cancelling a run cancels a tool that is waiting.
  Each is tested with its framework's own stand-in model, inside the
  examples' guard. An independent review found eight faults in the first
  draft, among them a reviewer's change that got past the slip and
  asynchronous agents that could hang; each is fixed and tested. They use
  only the public interface of the `provared` package, which itself still
  names no product. Not yet published.

## 0.2.0 (8 October 2026)

- 2026-10-08: version 0.2.0, for the npm package and, for the first
  time, the Python package `provared` on the Python Package Index. Both
  give the same answers, as the shared test files in `test-vectors/`
  show. The version rises from 0.1.0 because the format's rules changed:
  the exact rule for a page address in a slip, weak Ed25519 keys and
  signatures refused, and strict keys in a time-stamp service's
  certificate. Version 0.1.0 accepts a forged time-stamp where the
  person checking names as trusted a service whose certificate has an RSA
  public number of 1; 0.2.0 refuses it. The entries below say what
  changed.
- 2026-10-08: fixes from an independent review of `record_function`, the
  examples and the wording for a proposed action. None made a book read
  as intact, or within its slip, when it was not.
  - Python: a whole number in a tool's arguments that JavaScript cannot
    hold exactly (beyond 2^53 - 1, unless a float holds it exactly) is
    refused. Before, `2**60 + 1` and `2**60` left the same fingerprint in
    their stubs, though the tool was handed the exact number. JSON is now
    read as JavaScript reads it here too: a whole number beyond 2^53 - 1
    is the nearest float.
  - Python: a number of a class built on int or float (an Enum of whole
    numbers, say) is written as its value, so its fingerprint is that of
    the same arguments kept as JSON. Before, it was written as its name,
    which is not JSON.
  - A generator function is refused as a tool (`recordTools` and
    `record_tools`) and by `record_function`: calling one does not run
    its body, so its stub was written for an action not yet taken.
  - Python: a dict in a tool's arguments whose names are not all text is
    refused. Before, `{101: 2, "101": 5}` reached the tool as `{"101": 5}`.
  - Python: `record_function` refuses, when it is handed the function, a
    parameter whose type can never be plain data (a class of its own,
    such as a model or a date, a tuple or a set), an object whose
    `__call__` is defined with `async def`, and a function whose name is
    not text, each in words of its own. A call whose arguments are not
    plain data names the argument.
  - Python: the README and the docstring say that the function is run
    with a copy of its arguments, and what the record leaves out (an
    argument bound into a `functools.partial` in place).
  - The check before acting says "the action gives no amount", not "the
    stub gives no amount". The shared file `check-before.json` now holds
    a case for each of the words for a proposed action.
  - Examples: `offline()` also refuses the other kinds of name look-up,
    messages sent without a connection, starting another program, a
    connection made by Python's event loop on Windows (which raises no
    audit event), and a connection to a port on this computer that the
    same program does not hold, such as a proxy's. The tests check that
    nothing was refused while each example ran. Its README says exactly
    what it refuses.
- 2026-10-08: examples for three widely used Python agent frameworks, in
  `python/examples/`, the one folder that names them. Each records an
  agent's tools with `record_function`, runs the agent with the
  framework's own stand-in model (no AI service is called; tracing is
  switched off; any connection outside the program is refused while it
  runs), and checks the book. Each is tested
  (`python/examples/test_examples.py`). The library itself still names no
  product.
- 2026-10-08: the check before acting speaks of an action that is only
  proposed: "With this action the total would be 280 GBP", not "With this
  stub the total is", since no stub exists for an action that is not
  taken. Likewise for a count and a period. The codes are unchanged; the
  checker's words for a stub are unchanged.
- 2026-10-08: the Python version gains `record_function`, which puts one
  ordinary function behind the stub writer and keeps its name, its
  parameters and its description, so that an agent framework describes
  the recorded function to its model as it would the function. Python
  only: a JavaScript tool takes its arguments as one object. Tested
  (`python/tests/test_record_function.py`).
- 2026-10-08: `test-vectors/README.md` says what each shared file holds
  and what must match: Provared's own libraries give every answer
  exactly, words included; another implementation needs to match the
  codes and the shape of each answer. The Python package is made ready
  for the Python Package Index (version 0.1.0, both licence files); it is
  not yet published there.
- 2026-10-08: faults found by a second independent review, of the
  Python stub writer and of the changes above. In 1,183 random
  scenarios (about 79,500 steps) played in both languages, and 140 runs
  with several threads at once, no action was taken after the person's
  cancellation was handed over, and the writer's view of its book always
  equalled a whole check. Each fault is fixed and each is now a test
  (`python/tests/test_review2.py`).
  - **An Ed25519 signature whose first half (R) is a point of small
    order is refused**, in both languages, whatever the key. The holder
    of an honest key could make one for any message; Node.js refused it
    and the OpenSSL beneath the Python version accepted it, so one
    record had two answers (format description, section 3.8).
  - A copy of what the stub writer is handed is refused if it nests more
    than 64 levels deep, in both languages. Before, the JavaScript
    library's limit depended on how much of the stack was in use. The
    depth is measured on the copy, so the caller's value is still read
    once.
  - Python: a cancellation handed to `add` beside a member whose name is
    a number, None or something stranger, or in a read-only mapping, is
    read, and stops the writer, as in JavaScript. An error from the other
    side that is not an `Exception` (such as `SystemExit`) leaves a
    one-sided stub, as any other failure does. `snapshot()` hands back
    the book and the cancellations the writer holds, read together, so
    that another thread's call cannot fall between the two. A number too
    large for a float is no time; options holding objects that cannot be
    copied are kept as they are, as the JavaScript library keeps them;
    the record writers take a datetime with a time zone, as the
    JavaScript ones take a Date.
- 2026-10-08: faults found by an independent review of the Python
  version, which also changed the JavaScript library.
  - **Weak Ed25519 keys are refused.** Under one of the eight Ed25519
    keys of small order, anyone can make a signature that checks.
    Node.js refused such signatures; the OpenSSL beneath the Python
    version accepted them, so with such a key trusted, a slip made by
    someone holding no private key read as sound there. RFC 8032 does
    not say to refuse these keys and libraries differ, so now the
    checker refuses them itself, with any key written in more than one
    way (y not below p): `bad-key` for a key in a record,
    `stamp-invalid` for a time-stamp service's key.
  - **The page address in a slip follows an exact rule.** The checker
    used the URL Standard's own reader of addresses, which for a name
    beginning `xn--` rests on tables of Unicode that differ from one
    version of Node.js to the next, so two checkers could disagree. Now
    `issuer.origin` must be written as a browser writes it, by a rule
    that needs no such tables: `https://` (or `http://localhost`), a
    host of lower-case letters, digits and hyphens in labels, a port
    only where it is not the scheme's own, and nothing more (format
    description, section 4.1). Some addresses the URL Standard allows
    are now refused: underscores and other signs in a host, port 0,
    addresses of numbers.
  - A time-stamp service's key of another kind, or on another curve, is
    refused in words that say so, not as a signature that "does not
    fit".
  - A time is read only from a number of milliseconds or a Date. Text,
    true or a list were read by rules that differ from one device to
    another (text with no time zone was taken as local time).
  - `withoutMethods` that is not a list is set aside when a slip is
    checked, as everywhere else. Before, it made the slip's check fail.
- 2026-10-08: the Python version gains the stub writer beside an agent
  (`open_recorder`) and the connector for an agent's tools
  (`record_tools`, `arguments_fingerprint`, `NotTaken`). So it now does
  everything the JavaScript library does.
  - They are ported one to one and give the same answers: two new
    shared files, `test-vectors/recorder-scenarios.json` (32 scenarios,
    about 1,000 steps) and `test-vectors/tool-scenarios.json` (8
    scenarios), each a world of records made beforehand and a list of
    steps (actions, records, cancellations in every form the writer
    takes, time-stamps, acknowledgements, a clock that fails, writers
    opened again, tools called), with the transcript of what happened.
    The two libraries play each scenario (`test/helpers/scenarios.mjs`
    and `python/tests/scenarios.py`) and must write the same transcript,
    down to the words of every message and how many times the clock was
    read.
  - In Python every call is an ordinary function. The writer's calls
    wait for one another across threads. A call to the writer from
    inside an action it is taking, or from the other side while it
    countersigns, is refused at once, as in Node.js. The other side is
    asked in a thread of its own and given 30 seconds, as before. A
    function handed over that gives a coroutine is refused.
  - `key_set_from_seeds` and `key_set_seeds`: an agent's keys kept
    between runs as their two 32-byte seeds.
  - The Python reading of base64url and the copy of a check's options
    are faster; they give the same answers (a value shared many times in
    the options is now copied once, as the JavaScript library copies it).
  - `test/helpers/world.mjs` can be given the agent's and the service's
    key sets, so that a scenario can hand the same keys to Python.
- 2026-10-08: two faults in the check of a time-stamp from a service,
  found while writing the Python version.
  - An RSA key with the public number 1 in a service's certificate was
    accepted. Under it, anyone can make a signature that checks, so a
    time-stamp could be made without the service's private key. It
    counted only where the person checking had named that certificate as
    trusted. An even public number was accepted too. Now the public
    number must be odd, from 3 to 2^32 - 1 (`stamp-invalid`).
  - The public key inside a certificate was read loosely: a compressed or
    "hybrid" point, RSA numbers with needless or missing sign bytes,
    bytes after the key, any parameters, and unused bits all loaded. Now
    the key must be written exactly as its own standard sets out
    (`stamp-bad-data`), as the rest of a time-stamp already must be, so
    that two checkers cannot disagree about whether it can be read.
  - Each is a shared test (`test-vectors/stamps-strict-keys.json`).
- 2026-10-08: shared test files, and the start of a Python version.
  - `test-vectors/` holds records and values, each with the answer this
    library gives: the canonical form, base64url, times, keys, a
    passkey's signature, the envelope of a record, the content of a stub
    and of a countersignature, page addresses and 170 slips, sound and
    faulty. `tools/make-vectors.mjs` writes them;
    `test/vectors.test.mjs` checks that this library still gives every
    answer. Any other implementation of the format can be tested against
    them.
  - `python/` holds a Python version, built in stages against the same
    files. It is not yet published. It now checks everything the
    JavaScript library checks: slips, stubs, countersignatures, limits,
    approvals, refusals and terms, passes, cancellations and
    acknowledgements, vouching records, seals and their time-stamps,
    block time-stamps, the tree and its proofs, Shows, the chain of
    block headers, and the check before acting. It gives the same answer
    in every one of the 63 shared files, and in 6,091 random books
    compared on this computer. One difference is stated: "cryptography",
    the one package it needs, has no SLH-DSA yet, so a seal's third
    signature is reported as not checked on this device and never as a
    pass. The stub writer and the connector for an agent's tools are
    still to come.
  - A slip whose page address cannot be read, and one whose address is
    not in its plain form, are now refused with the same words. The code
    (`bad-field`) is unchanged.
- 2026-10-07: the README links to the individual Internet-Draft
  `draft-izmaylov-agent-permission-receipts`, which describes the core of
  the format.

## 0.1.0 (6 October 2026)

Draft version 0 of the format, published and not frozen.

- 2026-10-05: `provared-headers` is marked as experimental, in the
  README and in what the command prints.
- 2026-10-05: faults found by an independent review of the chain of
  block headers. It found no way to have a block counted unless real
  work made it: no chain file and no answer from a node did. Each fault
  is fixed and each is now a test (`test/headers.test.mjs`).
  - The second node did not have to show anything: an empty answer
    counted as agreeing, a node behind could agree, and other nodes could
    cut the end of the chain or swap it for a branch with no more work,
    after which the file was written shorter. Now the second node is
    asked for the latest six blocks on a copy of the chain and must hand
    them back itself; it must be on a network apart from every node that
    gave headers, judged by the address reached, not the name given; a
    branch near the end is taken on only if it carries more work; and a
    chain file is never written shorter than it was.
  - A node could keep `provared-headers` waiting for ever with messages
    of its own, and grow its memory with requests to answer. Now a node
    is given fifteen minutes at most, only answers to what was asked keep
    a session open, and answers to its own messages stop while it does
    not read them.
  - The list of threats said that a branch after the last known block
    must carry the real chain's work for every block. The rules on
    difficulty let a branch with dates pushed forward ease its targets at
    each change. Now, after the last known block, no target may be more
    than four times easier than that block's, and the list of threats
    states what a false block then costs, and that a chain file someone
    else hands over is only as good as they are.
  - With `--headers`, the checker said that a block found in the chain
    was one "you named as trusted", and that a block named with
    `--block` was not counted. It now says why each block counts, and
    `--json` gives what the chain showed beside the result.
  - A file that could not be written ended the command with an error of
    its own, and a run that fetched nothing wrote the first block alone.
    Now both are said plainly, nothing is written, and a chain file is
    made sure to be on the disk before it takes the old one's place.
  - Also: the lowest header version after the upgrades of 2013 and 2015,
    and a target of zero, are refused, as nodes refuse them; node
    addresses are read strictly, and lines of a file of nodes that are
    not addresses are counted and said.

- 2026-10-05: a block time-stamp can be checked with no node of your
  own. A new command, `provared-headers`, fetches the chain of Bitcoin
  block headers from nodes the person names, and from no one else, and
  keeps it in a file; a second node on another network must hold the same
  latest block. `provared-check --headers <file>` checks that file on the
  device, from the chain's first block, by the rules every Bitcoin node
  applies to headers, and against ten blocks known to be part of the
  chain; a block time-stamp then counts if its block is in the chain with
  at least six blocks after it. In the library: `checkHeaderChain` and
  `blocksInChain`. The network code sits apart, in `net/`, and only the
  new command uses it: the library and the checker still make no
  request. New code: `headers-invalid`. Tried once against the real
  network: the whole chain, 970,076 headers checked from the first
  block, in about six minutes, the same headers as the test against real
  proofs fetched; a second run fetched only what was new. Built from the
  script of that test.

- 2026-10-05: faults found by a broad final review of the package as it
  is to be published. It found nothing that made a changed record read
  as intact, nothing that crashed the checker, and no request made by
  the checking page built as one file. Each fault is fixed and each is
  now a test (`test/review20.test.mjs`).
  - **Exit code 0, and the checking page's green answer, now need the
    keys you named:** the passkey you trust and, where the record has a
    seal, the recorder you expect. Before, a stranger's record, or a book
    cut short and sealed again with other recorder keys, gave code 0
    with nothing trusted named. The command-line checker now says
    whether the check rests on keys you named. The library's own answer
    is unchanged.
  - The command-line checker refuses a trust value that is not a
    fingerprint (a typing error had left a time-stamp quietly not
    counted), refuses an option given twice where it may be given once,
    ends with code 0 for `--help`, and does not repeat Node.js's warning
    that its ML-DSA and SLH-DSA are experimental.
  - A run of more than three marks drawn on one letter (accents, for
    one) is shown as three and one visible mark, on the page and in the
    terminal, and each value on the page stays inside its own box. A
    purpose of one letter and 999 such marks had been drawn over the
    page's answer.
  - Checking the sample on the page no longer leaves the sample's
    fingerprints in the boxes, where they made the next record chosen
    read as signed by a passkey not trusted.
  - A stub whose slip fails is no longer counted as one-sided: its
    countersignature, not checked, is `unchecked`.
  - In a browser, a slip can now be cancelled with its passkey
    (`cancelWithPasskey`), and anything prepared for a passkey, such as
    a slip with covered fields, signed (`signChallengeWithPasskey`).
  - A line that ends with a carriage return before its line feed, a
    byte-order mark, or an empty line is now named as such. The codes
    are unchanged.
  - The README says how to install and import the package, and which
    commands need a copy of the repository. Two of its claims went
    further than the code: the check before acting refuses more than a
    checker reports in one case, and a seal fixes what is before it only
    for a recorder you named. Both now say so. `package.json` names both
    licences and the repository. Out-of-date sentences in the list of
    threats and the format description are corrected, and a time-stamp
    shows that entries "existed by" a time, for both kinds.

- 2026-10-05: faults found by a nineteenth independent review, of the
  eighteenth review's fixes. Each is fixed and each is now a test
  (`test/review19.test.mjs`). In 3,900 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - The entry below for the eighteenth review says that a value too
    large to be a line of a book is refused before it is written out.
    The limit counted values, not their length, and each member of an
    entry by itself. So a long text met many times, or one long list
    named by many members, could make `add` use gigabytes of memory, or
    end the process, before the call waited its turn. The copy is now
    measured by the length its text would have: each of the three
    members of a cancellation has room for a line, and the other
    members share one line's room. Past that, the entry is not written
    as it was handed over, and the cancellation in it still stops the
    writer. Anything but an object, such as a list, is no longer written
    out, and one that cannot even be looked into is refused through the
    answer, not thrown.
  - A list whose length is not a whole number (a Proxy can say
    anything) was copied as a list that held that value. A list of
    trusted passkeys whose length was a passkey's thumbprint then
    trusted that passkey, and in `add` a list of time-stamps whose
    length was a time-stamp put it into the book. In the options such a
    list is now kept as it was handed over; in `add` it is not plain
    data.
  - An option for the signing methods to treat as not built in that
    could not be read made a whole check and a carried checker throw.
    It is now a problem with the whole check (`check-failed`).
  - A value more than 16 levels down in the options was kept as it was
    handed over. Through a value met twice it could appear near the top
    of a carried checker's options, so that a change made afterwards
    changed its answer. Nothing past that depth is kept now: it cannot
    be read.
  - The stub writer copied the passkeys it trusts with the platform's
    own copy, which refuses a list wrapped in a Proxy. They are now read
    through the same fixed copy as the other options.
  - The check before acting no longer copies its options twice, and a
    gap at the end of a list in the options is now held by a test.

- 2026-10-05: the block time-stamp checked once against real proofs.
  Two complete proofs that others had published, one made by hand and
  one made by public calendar services, were read with this library's
  reader against the headers of the real blocks they name: each led to
  its blocks (five in all), and each was refused with another block's
  header or with its file changed by one bit. The headers came from the
  whole chain of headers, checked from its first block. The proofs and
  their files are not copied into the repository, and the tests still
  use made-up blocks. The README and the list of threats say so.

- 2026-10-05: faults found by an eighteenth independent review, of the
  seventeenth review's fixes. Each is fixed and each is now a test
  (`test/review18.test.mjs`). In 18,000 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - Since the seventeenth review's fixes, a whole check, a Show and the
    check before acting read their options through a fixed copy. Options
    that shared values many times over, or that held themselves, then
    took more than twenty seconds to copy, or used up the memory. A
    value met twice is now copied once, so the copy costs no more than
    the options hold.
  - An option that cannot even be looked into (a revoked Proxy) made a
    whole check, a carried checker and the stub writer throw an error of
    the platform's own, where they should answer. It is now a problem
    with the whole check (`check-failed`), and the stub writer refuses it
    when it is opened (`bad-field`).
  - What is handed to `add` was copied in two steps where it could not
    be copied at once (a Proxy beside it), so a member could be read
    twice, and a member that changed between the two readings could let
    the writer act after the person's cancellation was handed over. It
    is now copied in one pass, each member and each place read once. In
    the same way, a sound time-stamp beside a gap or a faulty item, in a
    list wrapped in a Proxy, is no longer lost. A value too large to be a
    line of a book is refused before it is written out.
  - An acknowledgement that waits, carried by a copy given at opening,
    was the first to give way where more than sixteen were held. The
    acknowledgements that wait now give way newest first.
  - A copy of a cancellation given at opening that could not be copied
    as plain data was kept as the caller's own object, and a later `add`
    could then fail on it. It is now refused when the writer is opened.
  - The check before acting read the passkeys it trusts once for the
    book and again for its decision. It now reads its options once.
  - Three fixes of the seventeenth review are now held by tests. The
    list of threats said that an entry which does not fit made the
    stub writer read its book again from the start; it costs one line's
    check, and the list now says so.

- 2026-10-04: faults found by a seventeenth independent review, of the
  sixteenth review's fixes. Each is fixed and each is now a test
  (`test/review17.test.mjs`). In 25,800 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - A sound cancellation handed to `add` wrapped in a Proxy (as some
    user-interface libraries wrap objects) could not be copied, was taken
    as unreadable, and did not stop the writer. This came from the
    sixteenth review's fixes. What cannot be copied as it stands is now
    copied through its canonical text, still read once.
  - An acknowledgement that waits, carried by a copy given at opening,
    was counted neither in the room the writer keeps nor among the
    waiting ones, and could be cut off. It now counts with the waiting
    ones.
  - With the clock failing, an acknowledgement of the agent's own handed
    over with a cancellation the book holds was taken but neither
    written nor handed back. It now waits, and is handed back and
    written as one that could not be written at once.
  - Opening the stub writer with a very long, nearly empty list of
    cancellations took time in proportion to its length. It no longer
    does.
  - A whole check and a carried checker could still read some unusual
    lists in the options differently (a list with its own way of
    walking through itself, or its own `includes`, or of a class). A
    whole check now reads its options through the same fixed copy, and
    a copy's acknowledgements and a slip's disclosures are read place by
    place.
  - A Show said that cancellations were handed over beside it where the
    list was empty. An empty list is now none, as for a whole book.
  - Tests now hold in place the room kept for the writer's own
    cancellations given at opening, and the limit of 100,000 trusted
    blocks.

- 2026-10-04: preparing the first publication. The package version is
  0.1.0. The package holds the library, the command-line checker, the
  format description, the list of threats, the sample record, the
  checking page, the licences, the README and this change log; the
  tests and the demonstration stay in the repository. The README now
  says, as the list of threats did, that no complete block time-stamp
  from a real service has been checked yet.

- 2026-10-04: faults found by a sixteenth independent review, of the
  fifteenth review's fixes. Each is fixed and each is now a test
  (`test/review16.test.mjs`). In 9,600 random steps the review found no
  action taken after the person's cancellation was handed over (but for
  the case below of a member whose value changes), no line written that
  made the book fail its check, and no difference between the stub
  writer's view of its book and a whole check.
  - An acknowledgement that waits to follow its cancellation into the
    book could be cut off by cancellations kept after it, and copies of
    other slips' cancellations given at opening could crowd out the
    writer's own. The writer now holds its own slip's cancellations
    first, then the acknowledgements that wait, then the other copies,
    which give way.
  - `add` read what it was handed more than once: a member whose value
    changed from one reading to the next could leave the writer
    unstopped. It is now read once, member by member.
  - An option, or a place in a list, that cannot be read made a carried
    checker and the stub writer crash where a whole check answers. It
    now fails exactly where a whole check reads it; the stub writer
    refuses such options when it is opened.
  - The list of blocks and a copy's time-stamps were read through a
    list's own way of walking through itself; they are now read place
    by place. A very long list with no items in it made a carried
    checker hang; only the places that hold an item are now copied, and
    the list of blocks holds at most 100,000.
  - A copy of a cancellation given at opening as an object of a class
    was changed by the writer, and one that was frozen made every `add`
    fail. Such a copy is now copied as plain data.
  - A writer opened from a book with two acknowledgements of its own
    agent handed back the second; a copy given at opening could end up
    with two. The first is taken, and a copy takes no second one.
  - The empty list that a writer holding no cancellation hands back was
    refused when it was handed in again. An empty list of cancellations
    is now accepted as none.
  - Of the time-stamps the writer counts on a cancellation it holds, the
    earliest are now kept.
  - The documents now say that a writer keeps every cancellation of its
    slip, and that where the clock fails the error is the clock's own.

- 2026-10-04: the checking page tried again in current browsers: three
  test builds and two installed desktop browsers at version 154, with
  and without experimental features. None has ML-DSA or SLH-DSA built
  in; each says plainly that the check is not complete, and none shows
  a pass. No horizontal scrolling at phone width. The page built as one
  file refused every request made from inside it. One fault, fixed: in
  the page built as one file, a record chosen before the page's script
  had started was ignored without a word (seen in one browser build). A
  record already chosen when the script starts is now checked.

- 2026-10-04: faults found by a fifteenth independent review, of the
  fourteenth review's fixes. Each is fixed and each is now a test
  (`test/review15.test.mjs`). In 2,500 random calls the review found no
  action taken after the person's cancellation was handed over, no line
  written that made the book fail its check, and no difference between
  the stub writer's view of its book and a whole check.
  - A list with a gap in it, beside a cancellation, was written as text
    that is not JSON. With the clock failing, the cancellation was then
    lost: a writer opened again took actions. A list with a gap is now
    refused as not JSON (`payload-not-canonical`), and the sound
    time-stamps in such a list are still kept.
  - A time-stamp from a service the writer was not told to trust, kept
    with a cancellation, kept out a trusted one handed over later; so
    did a trusted one that was late. The writer now merges the
    time-stamps it holds with those handed over: each is judged by
    itself, the ones it counts come first, four at most. Of a list with
    a faulty time-stamp in it, the sound ones are kept.
  - With the clock failing, the acknowledgements handed over with a
    cancellation were dropped, and a writer signed a second one later. A
    copy could hold two acknowledgements of the writer's own agent, and
    a writer opened again took the last of them where `add` took the
    first. They are now kept on a clock failure; only the first of the
    agent's own is taken, everywhere; the agent's own is found among more
    than four.
  - A copy of a cancellation given at opening with a member that is not
    enumerable was checked with it and handed back without it. Such a
    copy is now made plain data before it is checked.
  - The copy of the options read a member that a whole check never
    reads, and turned a gap in a list into an empty place. A member that
    cannot be read is now kept as it is, and a gap stays a gap; a gap in
    the list of blocks, or of a copy's time-stamps, is refused.
  - Where a kept cancellation was written into the book in the same
    call, the error said it was not added. It now says what was done.
  - An acknowledgement still waiting to follow its cancellation into the
    book was not handed back, and was lost to a writer opened again. It
    is now handed back with the cancellation, and written by a writer
    opened again.
  - With the clock failing, the error for a cancellation that cannot be
    kept, because the writer already holds 16, now says so.
  - Tests now hold in place nine fixes of the fourteenth review that
    could be undone without any test failing. Each fix of this review,
    and each of those nine, was then undone in turn in a copy of the
    code: a test caught every one.

- 2026-10-04: faults found by a fourteenth independent review, of the
  thirteenth review's fixes. Each is fixed and each is now a test
  (`test/review14.test.mjs`). In 3,000 random calls the review found no
  action taken after the person's cancellation was handed over, no line
  written that made the book fail its check, and no difference between
  the stub writer's view of its book and a whole check.
  - `add`, handed a cancellation with several acknowledgements, could
    take one that does not check (signed with other keys, or given for
    another cancellation) as its own agent's, hand it back, and keep it
    with the cancellation, so that nothing more could be added to the
    book. Each acknowledgement is now checked by itself, and only one
    that checks is taken.
  - A sound time-stamp on a cancellation was lost where the clock
    failed, and where it was handed over only after the date of a kept
    cancellation had come. The writer now keeps the cancellation with
    its sound time-stamps, and takes a time-stamp into a kept
    cancellation before it writes anything into the book.
  - Where a copy already held four acknowledgements of helper agents,
    the writer's own was handed back and not kept, and a writer opened
    again signed a second one. The writer's own is now always kept; the
    last of the others gives way. Sound acknowledgements of other agents
    that come with a cancellation stay with the kept copy.
  - A member that is not enumerable, one level down in the options, was
    made enumerable by a carried checker, which then refused what a
    whole check does not see. It now stays as it was.
  - A tool's function that kept the object it gave as `amount`, or the
    list it gave as `details`, could change it before the second try,
    after the person's approval. What these functions give is now
    copied. Each member of a tool's description is read once.
  - The error for a cancellation that cannot be kept, because the writer
    already holds 16, now says so.

- 2026-10-04: faults found by a thirteenth independent review, of the
  eleventh and twelfth reviews' fixes. Each is fixed, or stated, and
  each is now a test (`test/review13.test.mjs`). The review found no way
  to make a whole book or a Show read as intact, or as within its slip,
  when it is not, and no way to make the stub writer's view of its book
  differ from a whole check.
  - The stub writer could date its acknowledgement before a pass that
    its agent had handed on (a pass may be dated up to 300 seconds
    ahead of the clock), so that an honest pass, and the stubs under
    it, read as made after the agent was told. It no longer does.
  - A tool's own function could change what the tool was recorded as,
    through `this`. Each function is now called by itself, and the
    description is frozen.
  - A cancellation given when the writer was opened was handed back
    without the acknowledgement signed for it, and did not take a
    time-stamp handed over later. It now does both, and stops the
    writer from the start.
  - `add`, handed the form that `cancellations()` gives back, dropped a
    sound time-stamp. It now adds the cancellation with its
    time-stamps, and goes on handing back an acknowledgement of its own
    agent that came with it.
  - A clock that failed while the person's cancellation was handed over
    lost the cancellation, and the writer acted on. The writer is now
    stopped, and keeps the cancellation, before the clock is read.
  - A clock that gave no time (`NaN`) switched off the rule that
    nothing is written dated ahead of the clock. It now counts as a
    clock that failed.
  - An acknowledgement dated ahead of the clock was never written into
    the book. It is now tried again.
  - The words a stub was given depended on the order of the
    acknowledgements in one copy. They no longer do.
  - A member of the options that is not enumerable was dropped by a
    carried checker and read by a whole check. Both now read it.
  - `argumentsFingerprint` threw at once for arguments that are not
    JSON; it now refuses through its promise. Stated: `0` and `-0`
    share a fingerprint, as RFC 8785 sets out.

- 2026-10-04: the author is named in the format description's copyright
  line, in the README and in `package.json`.

- 2026-10-04: faults found by a twelfth independent review, of the
  acknowledgement and of the connector for an agent's tools. Each is
  fixed and each is now a test (`test/review12.test.mjs`). The review
  found no way to have an acknowledgement counted that the agent's side
  did not sign, to have a stub excused through one, or to run a tool
  that the slip does not allow.
  - The stub writer could date its acknowledgement before its own last
    stub (a stub may be dated up to 300 seconds ahead of the clock), so
    that an honest stub read as made after the agent was told. It no
    longer does.
  - Different arguments could share one fingerprint: a list with a gap
    in it, or with a named member, was written as if it had neither. It
    is now refused as not JSON, and the tool is not run.
  - What a tool is was copied one level deep, and one object went to
    all of a tool's functions and then to the tool. Each now gets a copy
    of its own, and a tool's description is fixed through and through.
  - The person was asked to approve an action that could not be taken
    anyway (the slip also asks for a countersignature, and the tool has
    no way to ask for one). They are no longer asked, and the stub
    writer's answer names both things that are missing.
  - An acknowledgement in a book still passed after the cancellation it
    names had failed its check further on in the book. It no longer
    does (`cancellation-not-found`).
  - Which words a stub was given depended on the order in which copies
    were handed over. The time-stamp rule is now applied first, for
    every copy; a stub it reports keeps that finding, and is told in
    addition where it is also dated after the acknowledgement.
  - An acknowledgement was given as confirmed where the device could
    not confirm the slip or the copy. It is now given as not checked.
    The command-line checker no longer shows what such a copy says.
  - Changed after the reviewer's design remarks: a pass handed on after
    the agent's side acknowledged, every pass handed on from it, and
    every stub under them, are reported; an acknowledgement that does
    not check is still a problem with the whole check, but the person's
    copy of the cancellation is used all the same; a stub writer opened
    with keys that are not the agent's hands back no acknowledgement.
  - The type declarations said that `cancellations()` hands back
    cancellations with their time-stamps only. They now say that each
    comes with the acknowledgement the writer signed.

- 2026-10-04: faults found by an eleventh independent review, of the
  checker that can be carried on, of the stub writer that carries its
  book on, and of the tenth review's fixes. Each is fixed, or stated as
  a limit, and each is now a test (`test/review11.test.mjs`). In 240
  random books the reviewer's carried checker never differed from a
  whole check, and in 2,483 random calls the stub writer never differed
  from a whole check of its book.
  - A clock that failed part of the way through `add` left the stub
    writer's reader holding a line that its book did not. Every line is
    now tried on a reader split off the book's own, which takes the
    book's place only if the line is written. An entry that does not
    fit now costs one line's check, where it cost a reading of the
    whole book.
  - Options that were inherited, worked out when asked for, or objects
    of a class were dropped or changed when a carried checker or the
    stub writer copied them, so that the answer could differ from a
    whole check's. They are now read once, as a whole check reads them.
  - A new rule: a seal dated more than 300 seconds before a time-stamp
    that it covers (a service's time-stamp on a seal before it) is
    reported (`time-went-backwards`). Stated beside it: what a Show
    cannot show where the earlier seal is left out of its pages.
  - A cancellation given when the stub writer is opened is now written
    into the book once its date has come; every cancellation of its
    slip that the writer is handed is kept, not only the first; one
    kept without a time-stamp takes the time-stamp it is handed over
    with later; and `cancellations()` hands each back with the
    acknowledgement the writer signed, so that a writer opened again
    hands back the same one.

- 2026-10-04: the checking page as one file. `node
  tools/make-single-page.mjs` writes `provared-check.html`: the page, its
  style, the checker and the sample record in one file, copied in
  unchanged, which opens in a browser from the disk with no server. Its
  content security policy allows no request of any kind. Tests:
  `test/single-page.test.mjs`. Tried in three browser builds.

- 2026-10-04: a connector between an agent's tools and the stub writer.
  `recordTools(recorder, tools)` puts each tool behind the stub writer:
  a call asks first, runs the tool only if the slip allows the action,
  and writes the stub. A call that is not allowed throws `NotTaken`.
  Where the slip asks for the person's approval, the tool's `approve`
  function is asked for it once. By default the stub names one
  document, `arguments`: the fingerprint of the call's arguments,
  written in the one form of RFC 8785 (`argumentsFingerprint`). It
  names no agent software. Tests: `test/tools.test.mjs`.

- 2026-10-04: the acknowledgement, a new kind of record (format
  description, section 26). The agent's side states, with the agent's
  own keys, that it was handed the person's cancellation of a slip, and
  when. A cancellation shows when the person signed it; until now
  nothing showed that the agent's side was told.
  - The record: `provared.acknowledgement.v0`, with the label
    `vnd.provared.acknowledgement.v0+json`, signed with the two keys of
    the slip's agent, or of a helper agent under its pass.
    `writeAcknowledgement` writes one.
  - In a book it is an entry of its own, `{"acknowledgement": ...}`,
    after the cancellation it names. A new code:
    `cancellation-not-found`.
  - The person hands it to a checker with their own copy of the
    cancellation (`acknowledgements`, up to four). Every stub of that
    agent dated after the acknowledgement is then reported, in words of
    its own, even where the copy has no time-stamp. Where the book
    leaves the cancellation out, the checker says that the agent's side
    had acknowledged it. A new code: `acknowledgement-mismatch`.
  - The stub writer signs an acknowledgement whenever the person's
    cancellation of its slip is handed to `add`, writes it into the book
    after the cancellation, and hands it back: in the answer of `add`,
    or in the `acknowledgement` member of the error where `add` fails.
  - The checker's answer: a new kind of entry, `acknowledgement`; a new
    count, `summary.counts.acknowledgements`; and `acknowledgements` on
    each cancellation handed over beside the book. The command-line
    checker and the checking page show them.
  - Tests: `test/acknowledgement.test.mjs`, and the two new codes in
    `test/refusals.test.mjs`.

- 2026-10-04: a checker that can be carried on. No record and no rule of
  the format changes: only how fast the free library works.
  - `openChecker(book, options)` reads a book once and then takes more
    lines (`add`), without reading the earlier ones again. Its answer
    (`result`) is the answer `checkBook` gives for the same text. A
    whole check is now: start, read every line, give the answer; there
    is one way of reading a line.
  - The stub writer carries its book on. One action no longer checks
    every signature in the book twice. Measured on one computer, with
    countersigned stubs: 9, 14 and 23 thousandths of a second for one
    action after 400, 1,600 and 6,400 stubs, where it took 2.0 seconds
    after 400 and 7.7 after 1,600.
  - `recorder.check()` gives the checker's answer for the writer's book
    as it stands. `recorder.before()` now waits its turn with the other
    calls.
  - What can be found only once every stub has been read (a limit "in
    any period", what a cancellation handed over beside the book shows)
    is worked out afresh for each answer, and is no longer written into
    what the checker keeps while it reads.
  - New tests (`test/carried.test.mjs`): the carried checker against a
    whole check after every line of a book with every kind of entry;
    trying a stub leaves the book's reader as it was; the stub writer's
    view of its book against a whole check after every call.

- 2026-10-04: faults found by a tenth independent review, of the ninth
  review's fixes. Each is fixed, or stated as a limit, and each is now a
  test (`test/review10.test.mjs`). With time-stamps that tell the truth,
  the review found no way to make a whole book or a Show read as intact,
  or as within its slip, when it is not, apart from the two narrow cases
  below (the seal of a Show, and a rare kind of block).
  - The stub writer lost a cancellation that the person had signed when
    something beside it could not be written as a line of a book
    (`stamps: undefined`, for example), and went on taking actions.
    `add` now adds the cancellation by itself where what stands beside
    it is at fault, and the call still fails and says what was done.
  - A cancellation that the stub writer kept, because it was dated ahead
    of the clock, was never written into the book, and a writer opened
    again from the book took actions again. The writer now writes it
    into the book once its clock has reached that date, whole, with the
    person's time-stamps. Until then `cancellations()` hands back what
    the writer holds, to be kept with the book. Stated as a limit: a
    writer opened from the book alone knows nothing of it.
  - A cancellation with no counted time-stamp of its own was shown as
    "counts as cancelled at" the time of a later seal. The checker's
    answer now keeps two times apart: `existedBy`, the time by which a
    later seal shows that an entry existed, and `stampedAt`, the time
    that a seal's or a cancellation's own time-stamps give it. **This
    changes the answer's shape:** for a slip, a stub and the other kinds
    of entry, what was `stampedAt` is now `existedBy`.
  - The seal that comes with a Show was not held to the rule that no
    unique number appears twice. It now is, against the pages.
  - A block time-stamp beside a later seal that stated a time before a
    service's time-stamp on an earlier seal was credited, and could
    excuse a stub made after a cancellation. It is now set aside, and
    the checker says so. It needs a block that states a time far behind
    the true time.
  - A seal or a cancellation that did not pass its check no longer shows
    a time of its own.
  - A date was reported against the time-stamp of a cancellation whose
    passkey signature the device could not check. It no longer is, as
    for a seal.
  - The format description and the list of threats said that a page
    dated after a seal's time-stamp is the page reported in a Show. The
    seal is.

- 2026-10-03: faults found by a ninth independent review, of the eighth
  review's fixes. Each is fixed, or stated as a limit, and each is now a
  test (`test/review9.test.mjs`). The review found no way to make a
  whole book read as intact, or as within its slip, when it is not.
  - A cancellation dated ahead, put into a block at once and
    time-stamped by a service on its date, counted from the block's
    time: days before the date the person signed. Honest stubs were then
    reported. A cancellation is now never taken to have been made before
    its own date, and the checker says that the two time-stamps do not
    agree.
  - A seal with an early block time-stamp and a later one from a service
    counted from the later. Every counted time-stamp of a seal is now
    taken, and the earliest counts. A block that states a time long
    before the seal's own date, beside a service's time-stamp, is still
    set aside, and the checker says so.
  - In a Show, an old seal that did not belong to the book marked the
    honest page before it. The finding is now given for the seal.
  - In a Show, a seal was not held to the chain of seals. It now is, as
    far as the pages show the chain.
  - The stub writer wrote an approval dated up to 600 seconds ahead of
    its clock. It now writes none dated more than 300 seconds ahead.
  - The stub writer kept at most 16 cancellations that it could not add,
    of any slip in the book, and dropped the next: its own slip's
    cancellation could be the one dropped. It now keeps one, of its own
    slip.
  - Stated as limits in the documents: the time-stamps beside the seal
    of a Show, and beside the last seal of a book, can be swapped for
    later ones (the gain is at most 300 seconds); a person can keep a
    cancellation back and hand it over later; only a late time, not a
    late time-stamp beside a prompt one, is pointed out on a
    cancellation.

- 2026-10-03: the checking page takes what the command-line checker
  takes. A fifth box names the blocks you trust. A second panel takes the
  person's own copies of cancellations (up to 16 files) and one file of
  disclosures for covered fields; each handed-over cancellation is shown
  as a card, saying whether the book holds it. A file that is not JSON
  stops the check. The sample record is checked without those files.
  Tried in three browser builds at phone width.

- 2026-10-03: faults found by an eighth independent review, of the stub
  writer, of which time-stamps give a record its time, and of ten passes
  in a row. Each is fixed and each is now a test
  (`test/review8.test.mjs`). Passing on up to ten times was found sound.
  - A later time-stamp from a service, put beside an earlier block
    time-stamp on a cancellation, moved the cancellation's time later,
    and excused stubs made after the person cancelled; in the person's
    own copy too. Every counted time-stamp beside a cancellation is now
    taken, and the earliest counts.
  - A block time-stamp on a cancellation is no longer taken as earlier
    than the date the person signed in the cancellation. Before, a stub
    that an outside time-stamp showed to have existed before that date
    could still be reported.
  - Where a service's time-stamp and a block time-stamp beside one seal
    do not agree, the checker now says so.
  - A service's time-stamps could step backwards without end, 300 seconds
    at a time. Each is now compared with the latest before it.
  - A Show under a later seal passed where the whole book failed, even
    with the earlier seal among its pages. A seal among the pages is now
    held against the pages and the seals before it. With that seal left
    out of the pages a Show cannot show it, and the documents now say so.
  - The stub writer wrote its line from the caller's own objects after it
    had checked them, so a later change could put a line into the book
    that failed the book's check. What it is handed is now copied when it
    is handed over.
  - `record` handed the stub to the other side before the check of the
    whole book, so the other side could hold two signed stubs for one
    place in the chain. It now checks first.
  - `act` accepted a date in the past, so an action could be taken after
    the slip had ended and dated inside it. A date handed to `act` must
    now be within 300 seconds of the writer's clock.
  - After an other side that never answered, a later call that stemmed
    from that request was refused as "from inside an action". The mark
    now ends when the time to countersign runs out.
  - A countersignature dated up to 598 seconds ahead of the clock was
    written. It is now compared with the clock alone: 300 seconds.
  - The check before acting refuses an action that would add to a period
    which a later-dated stub already overfills, though a checker reports
    nothing new for it. That stays, and the format description now says
    so, where it said the two agree exactly.

- 2026-10-03: a slip may allow up to ten passes in a row (`passes`: 1 to
  10); an eleventh is refused. It was three. Ten is the upper number
  commonly set for chains of delegated access between services, and is a
  first-draft number.
- 2026-10-03: faults found by a seventh independent review, of how
  time-stamps are credited and of the stub writer. Each is fixed and
  each is now a test (`test/review7.test.mjs`). The review found no way
  to make a whole book read as intact, or as within its slip, when it is
  not.
  - A Show under a seal passed where the whole book failed: the seal's
    own date was not compared with the pages. It is now.
  - The stub writer refused a cancellation it could not add (a faulty
    time-stamp beside it, a date ahead of the clock) and went on allowing
    actions. A cancellation the person signed now stops it either way.
  - `act` wrote its line without the whole-book check that `record`
    makes. The stub is now written and checked with the whole book
    before the action is taken; the other side is handed a copy of the
    stub; a stub added through `add` moves the writer's place on.
  - An approval that was not a record let the action be taken and then
    lost its stub. It now stops the action before it is taken.
  - The stub writer accepted its own stub dated ahead of its clock. It
    writes nothing dated ahead of it.
  - A call made after an action had ended could be refused as "from
    inside the action". The mark now holds only while the action runs.
  - A later seal was reported because of an entry that had already
    failed its own check, and one misdated entry excused a seal from
    every other. Each entry is now looked at by itself.
  - A date was reported against a time-stamp that the device could not
    count. It no longer is, and the seal says that the time-stamp was
    not counted.
  - Where a service states the time, its time-stamps now give the time,
    and a block time-stamp beside them is a second witness. A block that
    states a time far behind no longer makes such a seal fail.
  - A time limit of "for ever" for the other side became one
    millisecond; it is now refused. An empty list of documents is the
    same as none in `act` as in `record`.

- 2026-10-03: faults found by a sixth independent review, of the block
  time-stamp and the stub writer. Each is fixed and each is now a test
  (`test/review6.test.mjs`). The review found no way to have a block
  time-stamp counted without a proof that leads to a block the reader
  named, and nothing that crashed or hung the checker.
  - On a cancellation, a block time-stamp's two hours of looseness were
    taken the unsafe way, so a stub made after the cancellation could
    escape. A cancellation now counts from two hours before the time the
    block states, and the time used is shown.
  - A seal dated before an entry it covers was not reported once any
    counted time-stamp existed, even one that settled nothing. It is now.
  - An entry kept the time of the first seal after it, even where a later
    seal showed an earlier time; naming a true block could then turn an
    honest stub into one "after the cancellation". An entry now has the
    earliest time that any seal after it shows.
  - The stub writer accepted a countersignature, or an entry, dated years
    ahead, after which its book could not be sealed. Both are refused.
  - The stub writer could be blocked for good by an other side that never
    answered, or by a call from inside its own action. The other side now
    has a set time; such a call is refused at once (in Node.js).
  - The stub writer relied on an approval's fingerprint as handed over.
    It now works it out from the approval itself.
  - `record` could write a stub that made the book fail its check. It
    now writes nothing unless the book still passes with it.
  - The check before acting ignored the longest line a book may hold. An
    action whose record would not fit is not allowed.
  - `act` took an action that was certain to be outside the slip, where
    the slip asks for a countersignature and no way to ask for one was
    given. It no longer does.
  - Disclosures handed over beside a Show were ignored where the page
    carried its own. Both are now used together.
  - The note about a late time-stamp on a cancellation appeared for
    almost every block time-stamp. It now goes by the earliest time the
    time-stamp allows.
  - A block's number above about four thousand million was refused,
    against the format description; a header of the wrong length had two
    codes. Both follow the description now, which allows 255 steps in a
    row, as the format's own reader does.
  - Where two passes above a stub both set a limit within a period, the
    checker and the check before acting named different passes. Both now
    name the nearer one.
  - A unit could hold spaces and capitals and be read as the checker's
    own words. A unit is now 1 to 16 characters with no spaces.
  - On a device that cannot check all three signatures of a seal, the
    seal now says that its time-stamp was not counted.

- 2026-10-03: the block time-stamp, a second kind of time-stamp beside a
  seal or a cancellation. It is a proof, in the open format
  OpenTimestamps, that the fingerprint was written into a block of the
  Bitcoin blockchain, with the block's header beside it. The chain is
  used purely as a clock: no coin, wallet, account or payment. It rests
  on SHA-256 only, not on a signature. The person checking names the
  blocks they trust by fingerprint (`blocks`, `--block`); a block's time
  counts as right to within two hours. The library sends nothing
  anywhere and names no service. Tested with made-up blocks; published
  sample proofs of the format were read with the reader, and no complete
  proof from a real service has been checked yet.

- 2026-10-03: faults found by a fifth independent review, of the fixes
  below and of the person's own copy of a cancellation. Each is fixed and
  each is now a test (`test/review5.test.mjs`). The review found no way
  to make a book or a Show read as intact, or as within its slip, when it
  is not, and nothing that crashed or hung.
  - The stub writer let two actions asked for at the same moment both
    pass the check before acting. Its calls now wait for one another.
  - The stub writer put the other side's countersignature into the book
    unchecked; one made with other keys made the whole book fail. It is
    now checked first, and left out if it does not check. `add` adds an
    entry only if the book still passes its check with it.
  - The check before acting allowed an action that could never be
    countersigned where the slip asks for a countersignature. It no
    longer does.
  - A name padded with the blank Braille pattern could draw a line that
    looked like the checker's own, a variation selector passed unmarked,
    and a name could carry the checker's words. Every character that is
    not drawn is now marked, a name or a purpose is shown in quotation
    marks, and the page folds runs of spaces as the command line does.
  - The signer of a slip could cover a name with a value a slip may not
    hold, so that the slip was sound only while the name stayed covered.
    Disclosures that do not pass are now refused and reported apart, and
    the slip is checked as it would be without them.
  - A finding about a period was given twice on a helper's stub where the
    slip and the pass both set such a limit. It is given once.
  - Only four passes were compared for one stub, so two checkers could
    differ on the totals of a pass far up. A fourth pass in a row is now
    refused (`pass-too-deep`), and a stub is compared with every pass
    above its own.
  - Any text was accepted in the place of a covered field. It must now be
    a SHA-256 fingerprint in base64url.
  - Disclosures handed over in the wrong form were ignored without a
    word. They are now refused.
  - The format description said an action may not be dated before the
    last stub "under the slip"; the code, rightly, uses the last stub of
    its own chain. The description is corrected.
  - The notes about the person's own copy of a cancellation said the book
    left it out where the book held it with a broken time-stamp, and did
    not point out a late time-stamp on the copy. Both are corrected.
  - A finding about a period may be given for a stub of another chain
    than the one written last. That is as the format sets out; it is now
    stated.

- 2026-10-03: the person's own copy of a cancellation. The checker takes
  it beside the book (`cancellations`, `--cancellation`). It counts even
  where whoever keeps the book left the cancellation out, or holds it
  with a later time-stamp: every stub that no outside time-stamp shows
  to have existed before it is reported, and the check before acting
  allows nothing under the slip. A copy that does not pass its check is
  a problem, never set aside. The answer has a new member, `held`.

- 2026-10-03: faults found by a fourth independent review, of
  cancelling, vouching, covered fields and passing on. Each is fixed and
  each is now a test (`test/review4.test.mjs`). The review found no way
  to crash the checker, and found the checks of who signed a
  cancellation, a vouching record, a withdrawal and a pass sound.
  - A slip could cover an item of a list: a limit, a condition, an
    action, a service or a key. One signed slip then read differently to
    different readers, and the check before acting allowed anything. An
    item of a list can no longer be covered in a slip.
  - A member named `__proto__` in a slip was accepted, hidden from every
    check, and what it held was inherited unchecked: software names sent
    to the terminal as they were, keys for a service that nobody had
    checked, a stand-in for a covered name. It is now a member like any
    other, and is refused as unknown.
  - A limit "within any period" could be emptied by a later-dated stub in
    a helper's chain. A period now goes by the times the stubs state, in
    whichever chain and at whichever place in the book, and is worked out
    once every stub has been read. The check before acting counts the
    periods of later-dated stubs too.
  - Where the person cancelled twice, only the first cancellation in the
    book counted, and whoever kept the book chose the order. Every
    cancellation now counts.
  - A time-stamp beside a cancellation can be swapped for a later one.
    No check can show that; the checker now points out a time-stamp dated
    more than 300 seconds after the cancellation's own date, and the
    documents state the limit.
  - A helper could pass on and so escape the limits, actions and times of
    its own pass. A stub is now compared with every pass above its own,
    and so is an action in the check before acting.
  - A Show applied the strict rule for a time-stamped cancellation, which
    single pages cannot settle, and reported a stub that the whole book
    clears. It now uses only the place of each page, and says so.
  - A Show did not say that a cancellation or a withdrawal may be on a
    page that is not shown. It does now.
  - A vouching record that had run out still stood behind a slip that
    began inside its time. It must now be in force for the whole of the
    slip's time, and for a seal at the time-stamped time too.
  - A pass that the device could not check, with no stub under it, still
    gave "within its slip". It no longer does.
  - Looking up who vouches took time that grew with the number of
    vouching records multiplied by the number of names. It no longer does:
    a book of 45 megabytes that took 46 seconds takes 4.
  - A service whose id is `constructor` was shown as vouched for by
    "undefined". Every service now has a place of its own in the answer.
  - An empty list of covered fields let a name be absent and shown as
    covered. A list now holds exactly one fingerprint, the fingerprint
    method is named exactly where something is covered, and a decoy is
    not accepted.
  - Disclosures handed over with a page that is not a slip were ignored.
    They are now refused; disclosures for a slip that is not there are
    pointed out.
  - The command-line checker and the page did not show how often a slip
    may be passed on. They do now.
  - The type declarations said a covered name is always text, and left
    out the pass on a helper's stub. Both are corrected.
  - Also: a disclosure for a slip must be JSON in the canonical form, so
    that two checkers cannot read one disclosure in two ways.

- 2026-10-03: `openRecorder`, the stub writer beside an agent. It keeps the
  agent's place in its chain, asks the check before acting, takes the
  action only if the answer is yes, and writes the stub.
- 2026-10-03: faults found by a third independent review, of the seal
  and the time-stamp. Each is fixed and each is now a test
  (`test/review3.test.mjs`). The review found no way to have a time-stamp
  counted without the trusted service's key, and nothing that crashed.
  - A Show under a seal did not report a page dated after the time-stamp
    that covers it. It does now, for a countersignature's and an
    approval's date too.
  - A seal shown as a single page was compared with nothing. Its place is
    now checked, the page says it could not be compared, and its
    time-stamp is credited to no other page.
  - On the checking page, a line that was not a fingerprint was dropped,
    which switched the check off. It now stops the check and says which
    box.
  - A time-stamp from a service nobody named could make a sound record
    fail. It is now compared with nothing.
  - A time-stamp is now read in full and must be strict DER, laid out as
    its standards set out. It must name the certificate that signed it,
    in its signed part; that certificate, wherever it sits, is the one
    that counts. A time-stamp that states its time too loosely, or carries
    an extension it insists on, is refused.
  - A seal dated before an entry it covers, and a later seal time-stamped
    before an earlier one, are reported.
  - A time-stamp is credited only when all three signatures of the seal
    were checked.
  - A name padded with spaces could wrap into a line that looked like the
    checker's own. Runs of spaces are now shown as one.
  - Smaller: the same time-stamp twice is refused; checking a time-stamp
    no longer changes the caller's copy; a small file can no longer cost
    much work.
- 2026-10-03: passing a slip on. A slip can allow its agent to hand part
  of its permission to a helper agent, up to three times in a row. The
  pass is a new record, signed by the agent that passes on. A helper's
  stubs form a chain of their own and are compared with the pass and with
  the slip; the slip's totals take in the agent and every helper
  together. New codes: `pass-missing`, `pass-mismatch` (refused);
  `pass-not-allowed`, `pass-wider` (reported).
- 2026-10-03: covered fields. A slip can be written with its names and
  its purpose covered, by the standard "Selective Disclosure for JSON Web
  Tokens" (RFC 9901) as it stands. A reader sees a covered field only if
  handed its disclosure; the signature, the chain and the tree check
  either way. The standard's worked example is a test, with every case
  the standard says must be rejected. New: `prepareSlip(fields, { cover })`,
  the `disclosures` option, disclosures on a page of a Show,
  `--disclosures`, and the code `cover-invalid`.
- 2026-10-03: type declarations for the whole library, for the checker
  alone and for the browser's passkey part. Checked once with a type
  checker against a developer's use of the library; a test keeps them in
  step with what the library exports.
- 2026-10-03: cancelling a slip, and vouching for a name.
  - The person who signed a slip can cancel it with the same passkey, and
    have the cancellation time-stamped at once. Stubs after it are
    reported (`after-cancellation`). With a time-stamp on the
    cancellation, a stub counts as earlier only if an outside time-stamp
    shows that it existed by then.
  - A vouching record: an organisation states that a key belongs to a
    name, for a person, an agent, a service or a recorder. The person
    checking says which organisations they trust (`vouchers`,
    `--voucher`), and a name those vouch for is shown as vouched for.
    The organisation can withdraw the record.
  - A slip may state the fingerprints of the agent's program and
    settings. It is shown as a statement, not as proof of what ran.
  - Three new records, with their own labels: the cancellation, the
    vouching record and the withdrawal.
- 2026-10-03: faults found by a second independent review, of the
  framework of limits. Each is fixed and each is now a test. The review
  found no way to make a whole book read as intact, or as within its
  slip, when it was not.
  - The check before acting allowed an action dated before the last stub,
    which then broke the book. It allowed an action on a device that
    could check only one signature of two. It allowed an action under a
    slip signed by any key. It now refuses all three, must be told whose
    passkey it trusts, and where the slip asks for the person's approval
    allows the action only with the signed approval in hand.
  - A Show did not say that single pages cannot show an approval used
    twice. It now says so.
  - A stub or a refusal under a slip that the device could not confirm
    was shown as if it were evidence. It is now hidden.
  - A service's terms signed by a stranger, under the service's name,
    were shown with nothing to tell them apart. Terms and refusals now
    show the fingerprint of the keys that signed them.
  - An approval's own date was compared with nothing and shown nowhere.
    It is now shown, and an approval dated later than its stub is
    refused (`approval-dated-after-stub`).
  - Characters that cannot be seen (zero-width characters, soft hyphens,
    line separators) passed through to the screen. They are now shown as
    a mark, as control characters already were.
  - The name of an unknown field was copied into the message about it.
    No word from a record goes into a message now.
  - The format description said less than the code about which letters a
    unit and an action name may hold. It now says the same.
  - Smaller: an approval whose number equals another record's number was
    called "reused"; terms could accept what they forbid; a service could
    not write down a refused request for an unlisted reserved name; a
    period kept everything it had ever counted in memory.
- 2026-10-03: the Seal and the outside time-stamp.
  - A seal is a new record: whoever keeps a book signs its top
    fingerprint and its number of entries, with three signatures
    (Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s). Each seal names the one
    before it.
  - A seal may carry up to four time-stamps in the standard form of RFC
    3161. The checker reads them offline with a small strict reader of
    its own, and trusts a service only by the fingerprint of its
    certificate, which the person checking gives. No service is named
    anywhere.
  - The latest stubs before a seal can no longer be removed unnoticed. An
    entry dated later than the time-stamp that covers it is reported.
  - A Show can be made under a seal, and then proves when its pages
    existed with no other copy of the top fingerprint.
  - New options: `sealKeys`, `stampServices`, `--sealer`,
    `--stamp-service`. The checking page has boxes for what the person
    trusts.
  - Tested against time-stamps made by the OpenSSL program.
  - What is still open: the last seal, with everything after it, can be
    removed unnoticed, unless someone else holds a copy.
- 2026-10-03: a framework of limits, in five layers.
  - Amounts: besides a total, a slip can limit each single action, the
    number of actions, and a total or a number within any period.
  - Boundaries: a slip can ask that the other side countersign an action.
  - Approvals: a slip can ask for the person's own approval of an action,
    always or above an amount. The approval is a new record, signed with
    the same passkey as the slip, for exactly one action.
  - Stated rules: a slip can name kinds of action the agent must never
    do, which a checker compares with the stubs, and rules of conduct,
    which are the person's signed instruction.
  - The other side's records: a service can sign a refusal, and its terms
    for agents. Both are new records.
  - A shared list of 30 action names in 8 kinds, a first draft. Names
    that begin `provared.` are reserved for it.
  - `checkBefore`: would this action be outside the slip? It uses the
    checker's own comparison.
  - The demonstration and the sample record show all of these. The
    person approves one order with the passkey.
  - Every slip now holds `requires` and `never`, so a draft slip written
    before this change no longer checks.
- 2026-10-03: the quantum-safe method for agents and services is now
  ML-DSA-87, the strongest of the three strengths of FIPS 204, in place
  of ML-DSA-65. The test uses the ML-DSA-87 worked example of RFC 9964.
  The sample record was made again. A key set is larger, so one slip now
  holds about a dozen services with keys at most.
- 2026-10-03: the checking page marks the agent's name and the services'
  names as labels that are not checked, as it already did for the
  person's name.
- 2026-10-03: faults found by an independent review, each fixed and each
  now a test.
  - A small record made with no key crashed the checker (content whose
    "type" was not text). Nothing from a record is put into a message
    unchecked any more, and anything the checker does not expect is
    reported as the problem `check-failed`, never as a pass.
  - "Intact" was reported on a device that could check no signature. It
    is now said only when no problem was found and every signature was
    checked; `summary.problemFound` says whether a problem was found. An
    entry none of whose signatures could be checked is not shown and not
    compared with its slip.
  - A Show reported "within its slip" for a single stub over the limit.
  - "Every signature checked" was reported when nothing was checked.
  - A flood of line feeds could end the process. Lines are now counted as
    they are split.
  - A trusted top fingerprint was ignored for a book, and a trusted number
    of entries could not be given: `expectedRoot`, `expectedSize`,
    `--root`, `--size`.
  - The writers could make a slip too large for the checker.
  - `--json` printed characters that can disturb a terminal; the page did
    not neutralise characters that reorder text.
  - Smaller: an RSA key of 2,041 bits was accepted; lengths were counted
    in a way that differs between languages; the threat model said only
    "the end" of a book could be removed.
- 2026-10-03: a damaged record no longer reads as "every signature
  checked"; what a failed entry says is no longer shown.
- 2026-10-03: the pages no longer scroll sideways on a phone; times are
  shown in words.
- 2026-10-03: the first build.
  - `docs/threat-model.md`: who might attack a record, what each part
    protects and what it does not, written before the code.
  - `spec/provared-format.md`: the format, draft version 0: the Slip, the
    Stub, the countersignature, the chain, the book, the tree and the
    Show.
  - `src/`: the checker (`checkBook`, `checkShow`, `checkSlip`) and the
    writers (`prepareSlip`, `assembleSlip`, `writeStub`, `countersign`,
    `writeBook`, `makeShow`), with no dependencies. Agents and services
    sign with Ed25519 and ML-DSA-65 together; a person signs a slip with
    a passkey.
  - `bin/provared-check.mjs`: the checker for the command line.
  - `page/`: the checking page and the demonstration page.
  - `demo/`: the demonstration, an invented office agent that orders
    supplies within a limit, with a local server.
  - `samples/`: a sample record written once, and what a checker must
    find in it.
  - `test/`: the tests, including the worked examples of RFC 8032, RFC
    8037, RFC 9964 and the test trees of RFC 6962, and one test for every
    refusal the threat model lists.
  - Licences: Apache License 2.0 for the code, Creative Commons
    Attribution 4.0 for the documents.
- 2026-10-03: the folder created; no code yet.
- 2026-10-03: named Provared.
