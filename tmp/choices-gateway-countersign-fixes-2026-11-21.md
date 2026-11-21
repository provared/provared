# Gateway and guard choices after review 3.4 (21 November 2026)

The decisions taken by the lead specialist (H1, H2, H3, M1 to M4, the lows, the guard's M1, M2 and L7) are not repeated here. These are the smaller choices made in carrying them out, each the plainest option, with its reason. X371 and X378 in `choices-gateway-countersign-2026-11-21.md` are marked as replaced or changed.

## The gateway's own `with` entry (H2)

- **X390.** The gateway's id is the setting `gateway.id`, `gateway` if left out, of the form of a service's id; an upstream whose `service` is that id stops the start. Why: as the guard's `service`, whose default is `executor`; one id may not stand for two parties. Other: a fixed id.
- **X391.** Where the slip in force names the gateway, every stub and every denial of that agent names the gateway's id, whichever upstream the call is for, and no upstream is asked to countersign for that agent (a warning says so where an upstream has `countersign`). Why: "exactly as the guard does": every record of the guard names the executor; a stub carries one countersignature. Other: the upstream countersigns where it can and the gateway otherwise, which would give two kinds of stub for one agent.
- **X392.** A slip names the gateway only by an entry with the gateway's id and the gateway's keys (compared member by member). Otherwise the gateway does not countersign, the stubs name the upstream's service as before, and the start and `check` warn where the slip gives the gateway's keys under another id or the gateway's id with other keys. Why: a countersignature under other keys would not check; one under an upstream's id would read as the upstream's.
- **X393.** A stub that names the gateway no longer names the upstream; the copy's `sending` line does (`upstream`). No new document is added for the upstream. Why: no label is invented; the guard's stubs do not name the tool server either. (Listed as an open question in the report.)
- **X394.** `keys --gateway` prints one `with` entry, `{id, name, keys}`, and the `requires`. `status` gains `id`, and each agent's `countersigns` is true or false. `copyOf()` gives `service` (the id) in place of the public keys. Why: what the new entry needs; nothing else.

## The copy decides (H1, H3, M1)

- **X395.** Where a copy is kept, a call with a `sending` line, no settling line and no stub is listed for the administrator from the copy's own line (in the form of a journal line), with the checks a journal line gets (`unusableLine`), and stops the agent; it is not given a late stub at the start by itself, as the guard does under the slip in force. Why: decision 2 says the agent is stopped and the call listed. A rule is held against the upstream the copy names.
- **X396.** A journal line matches a copy line where the call, slip, action, amount, service and documents (in order) are the same; its time is not compared, since the copy and the journal take their times one after the other. Why: the fields decision 2 names.
- **X397.** A journal line that names a call of the copy and does not match is not listed separately: the copy's entry for the call stands, and the log says `journal-line-differs`. Why: two waiting entries with one call identifier could not be told apart by `setAside`.
- **X398.** New log events: `journal-line-missing` (a copy call with no matching journal line), `journal-line-not-in-copy`, `journal-line-differs`, `receipt-not-matching`. Why: each start decision is said in the log, as `receipt-found` is.
- **X399.** A stub found in the book at a start settles a copy call only where it is the only stub naming the call, it is the call the `sending` line shows (slip, action, amount and service the same; the line's documents first, in order; after them only `provared.http-response`, `provared.event-id`, `provared.error` or `gateway.not-delivered`), and, where the slip names the gateway, its countersignature is valid. Any other is listed for the administrator with the reason, and can only be set aside. Why: set aside is the one way the administrator already has to settle a call that gets no stub of the gateway's.
- **X400.** A `found-in-book` line records `countersigned` and the countersignature's fingerprint, as a `done` line of the gateway's own does. Why: so that `compare` holds it as any other.
- **X401.** A journal line from before the gateway kept a copy can only be set aside. Why: decision 2; such a line has no copy line to match. Said in the README.

## `compare` (M2, L6, L7)

- **X402.** A matched receipt is held against the `sending` line, and, where the `done` line holds `documents`, against exactly those after them; a receipt that does not match goes to `differs` with `why: "not the call sent"` (a receipt that is another stub: `why: "another stub"`). Why: one list for "the book's receipt is not the gateway's".
- **X403.** Where the `done` line says `countersigned: true`, the book's receipt must carry a valid countersignature, and, where the line holds its fingerprint, that one. A failure goes to a new list `countersignatures`, with `problem` `missing`, the checker's state, or `another`. Why: decision 3, kept apart from `differs` because the receipt itself is the gateway's.
- **X404.** Every receipt naming a call is kept; more than one goes to `moreThanOne`; the one the copy names is the one matched. Why: L7.
- **X405.** `withdrawn` is a list (call, time, upstream, action, when withdrawn, reason), with the count in the summary. Why: decision 3. The gateway writes no `withdrawn` line now; the list reads copies of the build before.
- **X406.** `agree` also requires the book to be fully checked and within its slips; the summary gains `copyProblem`, `bookFullyChecked` and `bookWithinSlips`, and counts for the new lists. Why: L6: "agree ignores fullyChecked and findings".
- **X407.** `compare` takes the gateway's id (`service`), not its public keys; the command reads no key file of the gateway. Why: L6; as the guard's `compare`; the book's own check holds each countersignature against the keys the slip gives.
- **X408.** The command refuses any option but `--config`, `--agent`, `--book` and `--sealer`. Why: as the guard's commands.

## Settings and start (L1, L2, L3, L5)

- **X409.** A setting the gateway does not know, at the top of the settings or in an agent's entry, is a problem (no start; `check` lists it), as for upstreams and rules already. The lists are what the code reads. Why: L5.
- **X410.** A `copy` or `copyKey` that is not text is a problem. Why: L5; the guard reports these.
- **X411.** Key sets are the same keys where each key has the same members with the same values, in any order. Why: L5; only the gateway's comparisons change, not the guard's.
- **X412.** Within one agent, no two of its files may be one file (book, journal, list of calls set aside, journal key, key file, copy, copy key). Why: L3, first half.
- **X413.** At a start, a warning (not a refusal) where the book holds receipts naming the gateway whose `gateway.call` no `sending` line of the copy names. Why: L2 says "warn"; such a copy's journal lines are refused anyway (X401).
- **X414.** `"unlisted": "forward"` with `gateway` is warned of at start and in `check`, and `compare` says it cannot see such calls; they still get no copy line. Why: L1's suggestion; a copy line for a call with no receipt would read as a receipt missing.

## Documents and tests

- **X415.** The README gives the checker as `npx --package=provared@0.9.0 provared-check …`. Why: M4; the exact library the gateway asks for.
- **X416.** The new tests are in `gateway/test/review4.test.mjs`, as the earlier reviews' were.

## The guard (M1, M2, L7)

- **X417.** At a start, and when the administrator acknowledges, the guard settles a copy call by a stub found in the book only where it is the only stub naming the call, it is the call the `sending` line shows (its documents first, then only `provared.tool-result`, `provared.error`, `executor.written-late` or `executor.acknowledged`), and it carries a valid countersignature where the permission the call was sent under names the executor with keys. Any other stops the start (stdio, with a sentence of its own naming `--set-aside`) or the agent (HTTP), and the call is listed for the administrator, with `inBook`, to be set aside. Why: decision 7, as the gateway.
- **X418.** The guard's `compare` gains `countersignatures` and `moreThanOne`, and `differs` gains `why`, as the gateway's. Its `withdrawn` stays a count: the guard writes real `withdrawn` lines (a call cancelled before it was sent), the review asked nothing of it, and a published result field is not changed without need. Why: decision 7 names M1, M2 and L7 only.
- **X419.** The executor's changes are recorded in the repository's own `CHANGELOG.md`, under "Not yet released", and not in a new `mcp-executor/CHANGELOG.md`. Why: the executor's releases up to 0.5.0 are all recorded there, its README points there, and it has no change log of its own; a second file would split its record, and listing it in the package would change the published package. The version is not raised.
