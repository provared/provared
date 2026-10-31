# The conformance kit

A way to test your own implementation of the Provared format, in any
programming language, against Provared's shared test files
(`test-vectors/`, about 14,700 cases in 95 files). The kit hands each
case to your code, reads your answer, compares it with the answer stored
in the file, and prints which cases match.

It needs Node.js 24.7 or later and a copy of this repository. It uses
only Node.js's own modules: nothing is installed.

## What "match" means

Each case in a file has an `expected` answer, `{"ok": value}` or
`{"refused": {"code": ..., "message": ...}}` (see `test-vectors/README.md`).
By default the kit compares the **codes and the shape** of your answer,
as that README sets out for another implementation:

- every member must be there, with no member added, and every value must
  be the same: codes, numbers, fingerprints, true or false, the length of
  every list;
- except the words meant for people. The text of each member named
  `message` need only be a text. In a list named `notes` or `limits`, the
  sentences are neither compared nor counted: you may give more or fewer
  of them, or none, in your own words or in another language. The items
  of those lists that are not texts (a slip's limits, for example) are
  compared in full, with their number and their order;
- the lists of findings, `problems`, `breaches` and `disclosureProblems`,
  are compared **in any order**: the format description says that the
  order in which a checker reports several findings for one entry is not
  part of the format, and two checkers agree if they report the same set
  (`spec/provared-format.md`, section 8). Each finding must still be
  there as often as it is stored, and no other may be added;
- an entry's own `problems` (an entry of a book or a Show: an object with
  an `index` and a `kind`) may hold **some** of the stored problems, at
  least one where any is stored. The format says that where an entry
  fails its own check in several ways, a checker MUST report at least one
  of them, and MAY stop at the first (section 8). Where the stored entry
  reports a fault in its countersignature and your answer reports none,
  because your checker stopped before it, a countersignature of
  `{"state": "unchecked", "signatures": []}` is taken in place of the
  stored one. In every stored case where an entry has more than one
  problem, nothing else in the answer (no count, no summary) depends on
  the problems left out. `breaches` are not cut this way: they are
  judgements about the agent, and every checker must report them all.

With `--words`, every value is compared, words included, in the stored
order, and so is the number of sentences in each list and of findings in
each entry. Provared's own libraries must pass this way; another
implementation need not.

The order of members in an object does not matter; the order of items in
any other list does.

## Running it

From the top folder of the repository:

```
node conformance/run.mjs -- <the command that starts your adapter>
```

For example, against Provared's own JavaScript library, word for word:

```
node conformance/run.mjs --words -- node --disable-warning=ExperimentalWarning conformance/adapters/provared.mjs
```

Options:

| Option | What it does |
|---|---|
| `--words` | compare every value, words included, findings in their stored order |
| `--no-skip` | count every case the adapter skips as a failure (exit code 1) |
| `--file <name>` | only this file of `test-vectors/`; may be given more than once |
| `--vectors <folder>` | another folder of test files (default: `test-vectors/`) |
| `--timeout <seconds>` | the longest wait for one answer (default: 60) |
| `--show-all` | list every failure, not only the first 20 |
| `--report <file>` | also write the whole report as JSON |
| `--quiet` | print only the totals and the verdict (and why the kit stopped early, where it did) |

The kit prints, for each file, how many cases passed, failed, were
skipped and were not run; then each failure, with the case's name and the
first place where the answers differ, such as
`answer.refused.code: expected "bad-base64url", got "bad-field"`; then
the functions none of whose cases was compared, because the adapter
skipped every one; then the totals and a verdict that names the skips,
such as:

```
3,099 case(s) compared, all matched; 11,643 skipped and not tested. This shows agreement on these cases only; it is not a certificate.
```

A skipped case is **not tested**: a run that skips most cases and
matches the rest says so, and passes only what it compared. Give
`--no-skip` where every case must be answered.

It ends with **exit code 0** only where at least one case was compared
and every case compared matched (and, with `--no-skip`, none was
skipped); **1** where any case failed or was not run, none was compared,
or `--no-skip` was given and a case was skipped; **2** where the command
itself was wrong (an unknown option, a file that does not exist, no
adapter given).

## Writing an adapter

An adapter is a small program of yours that stands between the kit and
your implementation. The kit starts it once, with the command you give
after `--` (run directly, not through a shell: on Windows, start a `.cmd`
or `.bat` file with `cmd /c`). It keeps it running, and talks to it in
JSON Lines: one JSON object to a line, each line ending with a line feed.

For each case, the kit writes one line to the adapter's **standard
input**:

```json
{"id": 17, "file": "base64url.json", "function": "fromBase64url", "case": {"name": "an impossible length", "text": "A"}}
```

- `id` is the number of the request: 1, 2, 3 and so on.
- `function` names what the case tests: the function of Provared's
  JavaScript library that answers it (`test-vectors/README.md`). One
  function may be used by several files. The table below says what each
  one tests.
- `case` is the case exactly as it is in the file, without `expected`.
- Every character outside ASCII is written as a JSON escape (an e with
  an acute accent is written `\u00e9`), so a line holds no character that
  some readers take as the end of a line.

The adapter writes one line back to its **standard output**, for each
request, in the order asked:

```json
{"id": 17, "answer": {"refused": {"code": "bad-base64url", "message": "Your words."}}}
```

or, for a case it does not handle:

```json
{"id": 17, "skip": "this implementation has no DER reader"}
```

Rules:

- Answer every request with exactly one line, with the same `id`, holding
  either `answer` or `skip`, never both.
- Write nothing else to standard output. Messages for yourself go to
  standard error; the kit keeps the last few lines and shows them when
  the adapter stops.
- Skip whole functions that test parts only an implementation built like
  Provared's has (the rows marked "internal" in the table below). A
  skipped case counts as neither passed nor failed, and is not tested.
- Stop when standard input ends.

What counts against a case:

- an answer that does not match;
- a line that holds both `answer` and `skip`;
- no answer within the time limit: the kit stops the adapter and starts
  it again for the next case;
- the adapter stopping, a line that is not JSON, or an answer with
  another `id`: the same.

If the adapter fails this way four times in a row, the kit stops asking
it, and the cases left are reported as not run.

`adapters/provared.mjs` is a complete adapter for Provared's own
JavaScript library, in about 40 lines. It answers through
`test/helpers/vectors.mjs`, the same table the library's own tests use,
which shows what each `function` takes and gives.

## What each function tests

One row for each `function` the shared test files name. "Format" marks
a rule of the format description that every implementation is meant to
follow; "internal" marks a part of Provared's own library (or of an
optional tool) that another implementation may skip. Where the answer's
shape is declared in the type declarations (`src/types.d.ts`; the
checker alone in `src/check.d.ts`), the row says so; otherwise the helper
named in the row, in `test/helpers/`, shows how the case is read and the
answer built. Sections are those of `spec/provared-format.md`.

Ways of writing a case that recur:

- **hexadecimal**: bytes are written as hexadecimal text (`bytes`,
  `der`, `header`, `proof`, `leaf`, `leaves`, `root`, `path`, `stamped`,
  `seed`, `key`, `signature`, `message`, `authenticatorData`,
  `clientDataJSON`); a time-stamp `token` is base64url.
- **`change`** (and `headerChange` for a header): the bytes after they are
  changed: `flip: [place, mask]` turns over the bits of the mask in the
  byte at that place, `cut: n` keeps the first n bytes, `append` adds
  bytes (hexadecimal) at the end, in that order.
- **`...Value`** (`tokenValue`, `stampedValue`, `proofValue`,
  `headerValue`, `bytesValue`): a JSON value handed over as it is, in
  place of the bytes, to test what is not bytes at all.
- **`options.withoutMethods`**: signing methods the checker treats as not
  built into the device (section 3.9). The cases for whole books, Shows
  and the check before acting all name SLH-DSA-SHA2-256s here.
- **`seed`** (records written by an agent's keys): the 32 bytes of an
  Ed25519 private key, with a fresh ML-DSA-87 key beside it; the answer
  gives the Ed25519 signature exactly, and for ML-DSA-87 only whether it
  checks (`"check": "valid"` or `"invalid"`), since that signature is
  made afresh each time.
- **`fields`**: the members a writer or a passkey's preparation is given.

| Function | Section | Kind | Answer shape | How a case is written |
|---|---|---|---|---|
| `fromBase64url` | 3.3 | format | `src/types.d.ts` | `text`; the bytes as hexadecimal |
| `parseCanonical` | 3.4 | format | not declared; `vectors.mjs` | `text` |
| `parseTime` | 3.6 | format | not declared; `vectors.mjs` | `text`; milliseconds since 1970, or null |
| `countCharacters` | 3.4 (lengths in code points) | internal | not declared; `vectors.mjs` | `text` |
| `parseRecord` | 3.1 to 3.5 | format | not declared; `vectors.mjs` | `record`, `kind`; answer gives the number of signatures |
| `checkKey` | 3.8 | format | not declared; `vectors.mjs` | `key` (a JSON Web Key), `allowed` methods; answer gives the method and the thumbprint |
| `checkEd25519Signature` | 3.8 | format | not declared; `vectors.mjs` | `key`, `signature`, `message` in hexadecimal; `without`: methods treated as not built in |
| `checkOrigin` | 4.1 | format | not declared; `vectors.mjs` (through `checkOriginForTests`, not exported) | `text` (the page address), `rpId` |
| `checkSlip` | 4.4 | format | `src/types.d.ts`, `src/check.d.ts` | `record`, `options`, `disclosures` |
| `validateStubContent` | 5.1 | format (reached inside whole books) | not declared; `vectors.mjs` | `content`; answer is `true` |
| `validateCountersignatureContent` | 6 | format (reached inside whole books) | not declared; `vectors.mjs` | `content` |
| `checkBook` | 7 to 11, 17 to 29 | format | `src/types.d.ts`, `src/check.d.ts` | `text` (the book), `options` (with `withoutMethods`) |
| `checkShow` | 11, with 21.5, 21.6, 28, 29 | format | `src/types.d.ts`, `src/check.d.ts` | `show`, `options` |
| `makeShow` | 10, 11 | format | `src/types.d.ts` | `text`, `indexes`, `showOptions` |
| `inclusionPath` | 10 (RFC 6962, 2.1.1) | format | `src/types.d.ts` | `leaves` in hexadecimal, `index`; the path in hexadecimal |
| `verifyInclusion` | 10 (RFC 9162, 2.1.3.2) | format | `src/types.d.ts`, `src/check.d.ts` | `index`, `size`, `leaf`, `path`, `root` in hexadecimal |
| `leafHash` | 10 (RFC 6962, 2.1) | internal | not declared; `vectors-stamps.mjs` | `leaf` in hexadecimal |
| `treeRoot` | 10 (RFC 6962, 2.1) | internal | not declared; `vectors-stamps.mjs` | `leaves` in hexadecimal |
| `treeBuilder` | 10 | internal | not declared; `vectors-stamps.mjs` | `leaves`, `forkAt`, `forkLeaves` |
| `validateApprovalContent` | 17 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `requestOf` | 17 | internal | not declared; `vectors-records.mjs` | `content` |
| `prepareApproval` | 17 | format | `src/types.d.ts` | `fields`; the bytes in the answer in hexadecimal |
| `assembleApproval` | 17 | format | `src/types.d.ts` | `prepared`, and the passkey's three values in hexadecimal |
| `validateRefusalContent` | 18 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeRefusal` | 18 | format | `src/types.d.ts` | `seed`, `fields` |
| `validateTermsContent` | 19 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeTerms` | 19 | format | `src/types.d.ts` | `seed`, `fields` |
| `checkBefore` | 20, with 21.5, 28, 29 | format | `src/types.d.ts` | `text`, `proposal`, `options` |
| `validateSealContent` | 21.1, 21.6 | format (reached inside whole books) | not declared; `vectors-stamps.mjs` | `content` |
| `keySetFingerprint` | 21.1 | format | `src/types.d.ts`, `src/check.d.ts` | `keys` |
| `checkStamp` | 21.2 (RFC 3161) | format | not declared; `vectors-stamps.mjs` | `token` (base64url) with `change` or `tokenValue`; `stamped` or `stampedValue`; `options` |
| `decodeStamps` | 21.2 | internal | not declared; `vectors-stamps.mjs` | `stamps`; the bytes in the answer in hexadecimal |
| `readElement` | 21.2 (DER) | internal | not declared; `vectors-stamps.mjs` | `bytes`, `at`, `end` |
| `children` | 21.2 (DER) | internal | not declared; `vectors-stamps.mjs` | `bytes`, `most` |
| `validateDer` | 21.2 (DER) | internal | not declared; `vectors-stamps.mjs` | `bytes` |
| `timeOf` | 21.2 (DER) | internal | not declared; `vectors-stamps.mjs` | `bytes` |
| `ecdsaToRaw` | 21.2 | internal | not declared; `vectors-stamps.mjs` | `der`, `size` |
| `ecdsaDerToRaw` | 4.4 | internal | not declared; `vectors.mjs` | `der` |
| `checkBlockStamp` | 21.4 | format | not declared; `vectors-stamps.mjs` | `proof`, `header`, `stamped` with `change`, `headerChange` or the `...Value` forms; `trusted` |
| `blockFingerprint` | 21.4 | format | `src/types.d.ts`, `src/check.d.ts` | `header` in hexadecimal |
| `blockStampItem` | 21.4 | format | `src/types.d.ts` | `proof`, `header`, or `proofValue`, `headerValue` |
| `checkHeaderChain` | 21.4 (an optional tool) | internal | `src/types.d.ts`, `src/check.d.ts` | `bytes` with `change`, or `bytesValue`; `now` |
| `blocksInChain` | 21.4 (an optional tool) | internal | `src/types.d.ts`, `src/check.d.ts` | `result`, and `chain`: a table from block fingerprint to its place |
| `readHeaderChain` | 21.4 (an optional tool) | internal | not declared; `vectors-stamps.mjs` | `bytes`, `change`, `now`, `rules`, `lookups`, `workAfter`, `partial` |
| `headerChainSteps` | 21.4 (an optional tool) | internal | not declared; `vectors-stamps.mjs` | `rules`, `steps` (`add`, `keepTo`, `copy`, `adopt`) |
| `nextBits` | 21.4 (an optional tool) | internal | not declared; `vectors-stamps.mjs` | `bits`, `firstTime`, `lastTime`, `rules` |
| `answerFor` | 21.4 (an optional tool) | internal | not declared; `vectors-stamps.mjs` | `bytes`, `now`, `rules`, `lookups` |
| `sealerTree` | 21.7 | format | not declared; `vectors-sealer.mjs` | `lines` (fingerprinted as lines of a book) or `leaves` in hexadecimal |
| `validateCancellationContent` | 22 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `prepareCancellation` | 22 | format | `src/types.d.ts` | `fields` |
| `assembleCancellation` | 22 | format | `src/types.d.ts` | `prepared`, and the passkey's three values in hexadecimal |
| `validateVouchingContent` | 23 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `validateWithdrawalContent` | 23 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeVouching` | 23 | format | `src/types.d.ts` | `seed`, `fields` |
| `writeWithdrawal` | 23 | format | `src/types.d.ts` | `seed`, `fields` |
| `validatePassContent` | 25 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writePass` | 25 | format | `src/types.d.ts` | `seed`, `fields` |
| `recordConstants` | 18, 23, 25 | internal | not declared; `vectors-records.mjs` | no members; see "Answers particular to Provared's library" |
| `validateAcknowledgementContent` | 26 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeAcknowledgement` | 26 | format | `src/types.d.ts` | `seed`, `fields` |
| `documentFingerprint` | 27 (RFC 9421, 2.5) | format | `src/types.d.ts` (`DOCUMENT_NAMES`, `identifierFingerprint`, the request and answer fingerprints) | `kind` (`names`, `identifier`, `request`, `response`), `input`; a body as `bodyHex` or `bodyText`; the answer for a request or answer also gives the text its fingerprint is made from |
| `validateDenialContent` | 28 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeDenial` | 28 | format | `src/types.d.ts` | `seed`, `fields` |
| `denialCodes` | 28 | format | `src/types.d.ts` | `answer` (an answer of the check before acting) |
| `denialConstants` | 28 | internal | not declared; `vectors-records.mjs` | no members; see "Answers particular to Provared's library" |
| `recorderScenario` | 27, 28 (the stub writer) | internal | not declared; `vectors-recorder.mjs` and `scenarios.mjs` | `world` (start, keys, records) and `steps`, played by the repository's own test code |
| `consistencyProof` | 29.1 (RFC 9162, 2.1.4.1) | format | `src/types.d.ts` | `leaves` in hexadecimal, `ms`; for each, the proof and whether it checks against the two roots |
| `verifyConsistency` | 29.1 (RFC 9162, 2.1.4.2) | format | `src/types.d.ts`, `src/check.d.ts` | `m`, `n`, `rootM`, `rootN`, `proof` in hexadecimal |
| `validateWitnessContent` | 29.2 | format (reached inside whole books) | not declared; `vectors-records.mjs` | `content` |
| `writeWitness` | 29.2 | format | `src/types.d.ts` | `seed`, `fields` |

## Answers particular to Provared's library

Some stored values are Provared's own choices, not rules of the format.
By codes and shape, the kit still compares them, so another
implementation that wants to pass those cases must give them as stored,
or skip them:

- the text of `signature.method` in a slip's answer, such as
  `"passkey (ES256)"`;
- the descriptions in `record-constants.json` and
  `denial-constants.json`, and the description of each reserved document
  name in the `names` case of `http-fingerprints.json` (the names
  themselves are the format's, section 27);
- the code `check-failed` where the library refuses an argument outside
  what a function takes. The stored answer is `check-failed`, the
  library's catch-all, in 22 cases: `approval-requests.json` (1),
  `approvals-prepared.json` (1), `cancellations-prepared.json` (1),
  `make-show.json` (1), `tree-consistency.json` (8) and
  `tree-paths.json` (10). These answers are particular to the JavaScript
  library: another implementation may rightly refuse such an argument
  with a code of its own, or in its own way, and may skip these cases.

### An example adapter on public functions only

`adapters/provared-public.mjs` is a second adapter for the same library,
written as an outside developer would write one: it uses only the
functions the npm package offers (`import ... from 'provared'` and
`'provared/check'`), never a file inside the library. It is the better
model for your own adapter: it shows how each case is decoded (bytes
written in hexadecimal, changed bytes, keys made from a seed), which
function answers it, and how the answer is put in the stored shape.

```
node conformance/run.mjs -- node --disable-warning=ExperimentalWarning conformance/adapters/provared-public.mjs
```

It loads the library through the `exports` list of the package's
`package.json`, from this repository by default. Add `--package <folder>`
after the adapter's name to test an installed copy of the npm package
instead, such as `node_modules/provared`.

Where the library refuses with its own error (a `Refusal`, with a code),
the adapter answers with that code. Where it refuses an argument with a
`RangeError`, the adapter answers `check-failed`, as the stored answer is
in 13 of the cases above that it answers. Any other error is a fault, and
the adapter reports it as one: it writes what it met to standard error
and stops, and the kit counts that case as failed.

On 31 October 2026 it answered **3,099 of the 14,742 cases**, every one
matching word for word, and skipped the other 11,643. Those are:

- the functions marked "internal" in the table above, which test parts
  of the library that are not offered to other programs (DER, the inner
  steps of the tree and of the chain of block headers, the stub writer's
  scenarios, and so on);
- the checks of each kind of record's content (`validate...Content`), of
  a page address (`checkOrigin`), and of keys, signatures, records, times
  and the canonical form on their own (`checkKey`,
  `checkEd25519Signature`, `parseRecord`, `parseTime`, `parseCanonical`):
  rules of the format, but not offered as functions of their own;
  whole books, Shows and slips reach them all the same;
- time-stamps from a service and block time-stamps on their own
  (`checkStamp`, `checkBlockStamp`), and the sealer's tree
  (`sealerTree`), which are not offered as functions of their own;
- `consistencyProof`, which is exported, but whose cases also ask whether
  each proof checks against the roots of the two trees, and no public
  function gives the root of a tree of leaves; and, of
  `documentFingerprint`, the cases for a web request or answer, which
  also ask for the text its fingerprint is made from, which no public
  function gives;
- two lists of fixed values that hold a number the package does not
  offer (`recordConstants`, `denialConstants`).

Each skip gives its reason to the kit, and the kit lists the functions it
skipped entirely.

## What it does not prove

Passing the kit is **not a certificate**, and the kit gives no seal or
badge. It shows that your implementation gives the same answers as
Provared's own library **on these cases only**, as far as the kit
compares them. It does not show that your implementation is secure, that
it refuses everything it should refuse outside these cases, that its
words mean what Provared's words mean, or that it agrees on cases you
skipped. The cases are those Provared's author wrote; they are not a
complete list of what can go wrong.

Cases for whole books, Shows and the check before acting are answered as
on a device without SLH-DSA, so an implementation without it can still
be held to them (`test-vectors/README.md`).

## Tests

`npm test` in this folder runs the kit's own tests (`test/`): the kit
passes Provared's own library on every file, word for word, through
`adapters/provared.mjs`; the example adapter imports nothing but
Node.js's own modules and the package's public entry points, and matches
every case it answers, word for word, while it skips 11,643; and the kit
reports rightly an adapter that answers wrongly, gives other sentences,
reorders its findings or stops at an entry's first problem (both of
which pass by codes and shape), leaves a finding out or adds one, skips,
holds both an answer and a skip, stops, hangs or prints what is not JSON
(`test/adapters/faulty.mjs`, `test/adapters/skip-one-file.mjs`).

Under the Apache License 2.0, as the rest of the code; this guide under
Creative Commons Attribution 4.0.
