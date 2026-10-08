# Shared test files

Records and values, each with the answer the JavaScript library in
`src/` gives for it. They show what a checker of the Provared format
must say, case by case. The JavaScript library checks them
(`test/vectors.test.mjs`), and so does the Python version in `python/`.
Another implementation of the format can be tested against them.

## What a file holds

Each file is one set of cases:

```json
{
 "about": "What the set tests, and the section of the format description",
 "function": "checkSlip",
 "cases": [
  { "name": "an end before the start", "record": { ... }, "expected": { "ok": { ... } } }
 ]
}
```

- `function` names the JavaScript function that answers the cases.
  Its inputs are the other members of each case (`record`, `options`,
  `text`, and so on), as that function takes them. Some sets test parts
  that only an implementation built like this one has (such as reading
  DER, or the stub writer's scenarios); another implementation may set
  those aside.
- `expected` is `{"ok": value}` where the function answers, or
  `{"refused": {"code": ..., "message": ...}}` where it refuses.
- Bytes are written in hexadecimal or in base64url, as each set says.

## What must match

- **Provared's own libraries** (JavaScript and Python) must give every
  answer exactly, words included.
- **Another implementation** needs to match the codes and the shape of
  each answer: every member and every value, except the words meant for
  people. Those are the text of each member named `message`, and the
  sentences in the lists named `notes` and `limits`. They are this
  library's own words, and another implementation may say the same
  thing in its own words, or in another language.

## Two things to know

- The cases for whole books, Shows and the check before acting are
  answered as on a device without SLH-DSA (the method of a seal's third
  signature), so that an implementation without it can be held to them.
  There, a seal's time-stamp never counts.
- The files are made by `node tools/make-vectors.mjs`, which signs the
  records afresh each time. A set is made again only when its cases, or
  the library's answers, change.

Under the Apache License 2.0, as the rest of the code.
