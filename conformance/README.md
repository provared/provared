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
  compared in full, with their number and their order.

With `--words`, every value is compared, words included, and so is the
number of sentences in each list. Provared's own libraries must pass this
way; another implementation need not.

The order of members in an object does not matter; the order of items in
a list does.

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
| `--words` | compare every value, words included |
| `--file <name>` | only this file of `test-vectors/`; may be given more than once |
| `--vectors <folder>` | another folder of test files (default: `test-vectors/`) |
| `--timeout <seconds>` | the longest wait for one answer (default: 60) |
| `--show-all` | list every failure, not only the first 20 |
| `--report <file>` | also write the whole report as JSON |
| `--quiet` | print only the totals and the verdict |

The kit prints, for each file, how many cases passed, failed, were
skipped and were not run; then each failure, with the case's name and the
first place where the answers differ, such as
`answer.refused.code: expected "bad-base64url", got "bad-field"`.

It ends with **exit code 0** only where at least one case was compared
and every case compared matched; **1** where any case failed or was not
run, or none was compared; **2** where the command itself was wrong (an
unknown option, a file that does not exist, no adapter given).

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
  function may be used by several files.
- `case` is the case exactly as it is in the file, without `expected`.
- Every character outside ASCII is written as a JSON escape (`é`),
  so a line holds no character that some readers take as the end of a
  line.

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

- Answer every request with exactly one line, with the same `id`.
- Write nothing else to standard output. Messages for yourself go to
  standard error; the kit keeps the last few lines and shows them when
  the adapter stops.
- Skip whole functions that test parts only an implementation built like
  Provared's has (reading DER, the stub writer's scenarios, and so on).
  A skipped case counts as neither passed nor failed.
- Stop when standard input ends.

What counts against a case:

- an answer that does not match;
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

On 28 October 2026 it answered **3,099 of the 14,742 cases**, every one
matching word for word, and skipped the other 11,643. Those test parts
of the library that are not offered to other programs, and that the
public functions therefore cannot answer:

- the checks of each kind of record's content (`validate...Content`) and
  of a page address (`checkOrigin`);
- reading DER, time-stamps from a service and block time-stamps on their
  own (`readElement`, `children`, `validateDer`, `timeOf`, `ecdsaToRaw`,
  `ecdsaDerToRaw`, `checkStamp`, `checkBlockStamp`, `decodeStamps`);
- the inner steps of the tree and of the chain of block headers
  (`leafHash`, `treeRoot`, `treeBuilder`, `consistencyProof`,
  `sealerTree`, `nextBits`, `readHeaderChain`, `headerChainSteps`,
  `answerFor`);
- reading keys, signatures, records, times and the canonical form on
  their own (`checkKey`, `checkEd25519Signature`, `parseRecord`,
  `parseTime`, `countCharacters`, `parseCanonical`, `requestOf`);
- two lists of fixed values that hold a number the package does not
  offer (`recordConstants`, `denialConstants`);
- the stub writer's scenarios, which are played by the repository's own
  test code (`recorderScenario`);
- of `documentFingerprint`, the cases for a web request or answer, which
  also ask for the text its fingerprint is made from.

Each skip gives its reason to the kit. Many of these parts are still
reached through the public functions, inside whole books, Shows and
slips; what the skips lose is the cases that test each part on its own.

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
both adapters; the example adapter imports nothing but Node.js's own
modules and the package's public entry points; and the kit reports
rightly an adapter that answers wrongly, gives other sentences, stops,
hangs or prints what is not JSON (`test/adapters/faulty.mjs`).

Under the Apache License 2.0, as the rest of the code; this guide under
Creative Commons Attribution 4.0.
