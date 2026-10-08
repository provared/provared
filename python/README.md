# Provared for Python

Proof of what an AI agent was allowed to do, and what it then did.

*Evidence, not a verdict.*

This is the Python version of Provared. The format, the reasons for it
and what a record does and does not prove are described in the
repository's own [README](../README.md), the
[format description](../spec/provared-format.md) and the
[list of threats](../docs/threat-model.md). This page says only what is
particular to Python.

## Status

**Not yet published.** It is built in stages from the JavaScript
library, and gives the same answer, case for case, as the shared test
files in [`test-vectors/`](../test-vectors) show: the same result, the
same codes and the same words. Every shared file passes in both
languages.

One difference is stated, not hidden. The one package this version
needs, `cryptography`, does not yet have SLH-DSA (FIPS 205), the method
of a seal's third signature. So a seal's third signature is reported as
"not checked on this device", and never as a pass, as the checking page
in a browser reports it. Seals are checked in full by the JavaScript
command-line checker.

## Install

From a copy of the repository:

```
pip install ./python
```

You need Python 3.11 or later. The one dependency is `cryptography`,
version 48 or later: Python has no signatures built in, and version 48
is the first whose ready-built packages hold ML-DSA (FIPS 204).

## Use

```python
from provared import check_book

with open('record.jsonl', encoding='utf-8') as f:
    result = check_book(f.read(), issuer_keys=['<the thumbprint of the passkey you trust>'])

summary = result['summary']
print(summary['intact'], summary['withinSlips'], summary['firstBreach'])
```

The answer is the same JSON as the JavaScript library gives (see "What
the checker returns" in the repository's README).

Before an agent acts:

```python
from provared import check_before

answer = check_before(book_text, {
    'slip': slip_fingerprint,
    'action': 'supplies.order',
    'amount': {'unit': 'GBP', 'value': 20},
    'with': 'supplier',
}, issuer_keys=[passkey_thumbprint])

if not answer['allowed']:
    print(answer['problems'], answer['breaches'])
```

Names follow Python's way (`check_book`, `write_stub`). Options may be
given as keyword arguments (`issuer_keys`, `expected_root`,
`stamp_services`, `seal_keys`, `vouchers`, `disclosures`,
`cancellations`, `without_methods`), or as one dict with the names the
JavaScript library uses (`issuerKeys` and so on). Records and answers
are dicts and lists, with the same member names as in the format.

`provared.check` holds the checker alone, for anyone who audits the
checking.

## Tests

From the `python` folder:

```
python -m venv .venv
.venv/bin/pip install "cryptography>=48"        # on Windows: .venv\Scripts\pip
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests
```

The tests read the shared test files in `../test-vectors/`, which the
JavaScript library writes (`node tools/make-vectors.mjs`) and checks
(`node --test test/vectors.test.mjs`).

## Licences

As for the rest of the repository: the Apache License 2.0 for the code,
and Creative Commons Attribution 4.0 for the documents.
