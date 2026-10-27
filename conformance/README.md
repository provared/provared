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
- except the words meant for people: the text of each member named
  `message`, and each text in a list named `notes` or `limits`, need only
  be a text. You may say the same thing in your own words, or in another
  language. Items of those lists that are not texts (a slip's limits, for
  example) are compared in full.

With `--words`, every value is compared, words included. Provared's own
libraries must pass this way; another implementation need not.

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
passes Provared's own library on every file, word for word, and it
reports rightly an adapter that answers wrongly, stops, hangs or prints
what is not JSON (`test/adapters/faulty.mjs`).

Under the Apache License 2.0, as the rest of the code; this guide under
Creative Commons Attribution 4.0.
