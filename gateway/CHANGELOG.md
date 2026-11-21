# Changelog of provared-gateway

## Unreleased

Version 0.1.0 has not been published. What it holds, as it stands:

- **The gateway's own countersignature.** A new setting, `gateway`
  (`keys`, the gateway's own key file of Ed25519 and ML-DSA-87; `name`;
  in a program, `privateKeys` and `keySet`). Where an agent's slip names
  that key set in the `with` entry of an upstream's service, the gateway
  countersigns each call of that agent to that upstream which it lets
  through, with the library's `countersign` (the countersignature of the
  format description, section 6; no new kind of record). It is made after
  the answer, over the stub that names the answer's or the error's
  fingerprint. A stub written when the administrator acknowledges a call is
  countersigned then, where the slip the call was sent under names the
  gateway's keys for its service. For that agent and service the upstream
  is not asked to countersign. The gateway does not start where a slip
  names the gateway's keys as the agent's. It warns, at start (a `warning`
  event in the log) and in `check`, where a slip names the gateway's keys
  for no service, where it does not require a countersignature for every
  action, where an upstream's calls are not countersigned by anyone, and
  where an upstream's `countersign` is not used. `check` lists the
  services each agent's calls are countersigned for. The `taken` event
  says whether the stub was countersigned; `status` gives `countersigner`
  and, for each agent, `countersigns` and `copy`. (`gateway.mjs`,
  `files.mjs`.)
- **The gateway's own copy** (`copy.mjs`). Where the gateway has its own
  keys, it keeps for each agent a copy apart from the book, in the form of
  the MCP executor's copy: numbered lines, each tagged with HMAC-SHA-256
  of the agent's name and the line under the agent's copy key, of the
  kinds `sending` (on the disk before the call is sent), `done`, `refused`,
  `set-aside` and `withdrawn`. New per-agent settings `copy` and `copyKey`
  (default `copies/<agent>.jsonl` and the same with `.key`). A copy line
  that cannot be written stops the agent (`503`, `agent-stopped`); the
  gateway does not start on a copy that has lines and no key, ends part-way
  through a line, has no line that checks, or is not whole. At a start, a
  call the copy shows as sent whose stub the book holds is noted `done`
  (`found-in-book`), and one with no line in the journal is noted
  `withdrawn`. Two agents may not share a copy or a copy key.
- **`provared-gateway compare`** (`compare.mjs`, exported as
  `provared-gateway/compare`): holds an agent's copy against its book, as
  the MCP executor's `compare` does, and ends with 0, 3 or 1.
- **`provared-gateway keys --gateway`** makes the gateway's key file and
  prints the slip's `with` entries that name its keys, with `"requires":
  [{"need": "countersignature"}]`. It refuses a path that is the recorder's
  or an agent's key file.
- **Getting ready to publish.** `package.json` lists `copy.mjs`,
  `compare.mjs` and `CHANGELOG.md` among its files, exports `./compare`, and
  asks for `provared` 0.9.0 exactly, as the MCP executor does (it asked for
  `>=0.9.0 <0.10.0`). The version stays 0.1.0. `gateway.example.json`
  names the gateway's own key file. The README says how to try the gateway,
  what the countersignature and the copy are and are not, and how
  `compare` reads.
- **Tests** (`test/countersign.test.mjs`, 10): the countersignature, its
  absence for other services, the copy's lines, refusals, the comparison
  (matched, missing, not in the copy, a changed line), the refusals at
  start, a copy that something else wrote to, a call never sent, `check`,
  and the commands `keys --gateway`, `acknowledge` after a stop without
  warning, and `compare`.

### After the review of the countersignature (21 November 2026)

These change what the entries above describe.

- **The gateway has a `with` entry of its own** (H2). The settings give it
  an id, `gateway.id` (`gateway` if left out; the form of a service's id;
  no upstream's `service` may be it). Where an agent's slip names that id
  in `with` with the gateway's keys, every stub and denial of that agent
  names the gateway's id, and the gateway countersigns every call of the
  agent it lets through. The gateway no longer countersigns under an
  upstream's service, so its countersignature no longer reads as the
  upstream's, and the upstreams' own entries are left for their own keys.
  It warns where a slip gives its keys under another id, or names its id
  with other keys. `keys --gateway` prints the one entry, with the
  gateway's id and name. `status` gives `id`, and `countersigns` is now true
  or false. `check` no longer warns that a slip naming the gateway does not
  name an upstream's service. (`gateway.mjs`, `bin.mjs`.)
- **The copy decides, not the journal** (H1, H3). Where the gateway keeps
  a copy, a call with a `sending` line and no receipt is never noted
  `withdrawn` at a start: it stops the agent and waits for the
  administrator, whatever the journal holds, and the stub written for it on
  acknowledgement is written from the copy's own line (`journal-line-missing`
  in the log where the journal has no line for it). A journal line is taken
  only where the copy holds a `sending` line for the same call with the same
  slip, action, amount, service and documents; one for a call the copy does
  not hold can only be set aside, and is never given a stub or a
  countersignature (`journal-line-not-in-copy`); one that names a call of
  the copy and says otherwise is not acted on (`journal-line-differs`).
  (`gateway.mjs`, `copy.mjs`.)
- **A stub found in the book at a start** (M1) settles a call only where it
  is the only stub for the call, it is the call the copy's `sending` line
  shows, and, where the slip names the gateway, it carries a valid
  countersignature of the gateway. Its `found-in-book` line now records
  whether it was countersigned and the countersignature's fingerprint. Any
  other such stub stops the agent (`receipt-not-matching`), and its call
  can only be set aside. (`gateway.mjs`.)
- **`compare`** (M2, L6, L7) holds each receipt it matches against the
  copy's `sending` line (and the documents of its `done` line), and the
  countersignature against the one the copy records (`differs` with `why`;
  `countersignatures`); reports more than one receipt for a call
  (`moreThanOne`); lists withdrawn calls by name (`withdrawn` is a list);
  and says in its summary whether the copy has a problem and whether the
  book was fully checked and is within its slips, agreeing only where it
  is. It takes the gateway's id, not its public keys, and reads no key file
  of the gateway. The command refuses an option it does not know.
  (`compare.mjs`, `bin.mjs`.)
- **Settings** (L1, L3, L5). A setting the gateway does not know, at the
  top or in an agent's entry, and a `copy` or `copyKey` that is not a path,
  are problems: the gateway does not start, and `check` says so. Key sets
  are the same keys whatever the order of their members. An agent's copy
  and copy key may not be any other file of the same agent (its book, its
  journal, its journal key, its key file). `"unlisted": "forward"` with the
  gateway's own keys is warned of at start and in `check`, and `compare`
  says what it cannot see. (`gateway.mjs`, `rules.mjs`.)
- **At a start** (L2) the gateway warns where the book holds receipts
  naming the gateway that the copy does not know. (`gateway.mjs`.)
- **Documents** (L4, M4). The README states the exact bytes of the copy's
  tag, gives the checker's command as `npx --package=provared@0.9.0
  provared-check …` (the checker is the library's command), and says no
  more of the countersignature than the checker shows.
- **Tests** (`test/review4.test.mjs`, 20; `test/countersign.test.mjs`
  changed to the gateway's own entry, and its test of a call noted
  `withdrawn` replaced): the copy deciding at a start, with the journal's
  line there, spoiled or gone; a call set aside; a journal line the copy
  does not hold, or that differs from it; a stub found in the book that is
  not the call, or is one-sided, and one that is; a countersignature taken
  off or swapped; a receipt that is not the call sent, or another; more than
  one receipt for a call; a copy line that does not check, put twice, taken
  out, or a cut copy; a fixed vector of the tag; a denial the book lacks; a
  book with a problem, or not within its slips; the upstream countersigning
  where the slip does not name the gateway; the gateway's keys under an
  upstream's service; the gateway's id; unknown settings; key sets in
  another order; an agent's files that are one file; a copy taken away;
  `"unlisted": "forward"`; and the commands `keys --gateway` and `compare`.
- **No test waits for ever** (`test/limits.mjs`, new). A call to the
  gateway in a test fails after 120 seconds without a whole answer; a
  command fails after 60; a gateway started as a program must listen, and
  stop, within 30. A gateway a test opened, or a program it started, that
  a failing test left running is closed or stopped when the file's tests
  end; a start that should be refused and is not closes the gateway it
  opened. Before, a test that failed while a gateway program it had
  started was running left the test file waiting with no end.
- **Tests and the system clock.** Each wait's limit is measured on the
  monotonic clock (`test/limits.mjs`, `test/review1.test.mjs`), so a system
  clock put forward or back no longer ends a wait at once or stretches it;
  and a test's slip lasts a day, not an hour (`test/world.mjs`), so a clock
  put forward by more than an hour no longer ends it under a running test.
