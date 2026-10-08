# Provared for Python

Proof of what an AI agent was allowed to do, and what it then did.

*Evidence, not a verdict.*

This is the Python version of Provared. The format, the reasons for it
and what a record does and does not prove are described in the
repository's own [README](https://github.com/provared/provared/blob/main/README.md), the
[format description](https://github.com/provared/provared/blob/main/spec/provared-format.md) and the
[list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md). This page says only what is
particular to Python.

## Status

**Not yet published.** It is built in stages from the JavaScript
library, and gives the same answer, case for case, as the shared test
files in [`test-vectors/`](https://github.com/provared/provared/tree/main/test-vectors) show: the same result, the
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

Beside an agent, the stub writer asks the check before acting, takes the
action only if the answer is yes, and writes the stub (see "Beside an
agent" in the repository's README):

```python
from provared import open_recorder

writer = open_recorder(book_text, slip_fingerprint, private_keys, issuer_keys=[passkey_thumbprint])
result = writer.act(
    {'action': 'supplies.order', 'amount': {'unit': 'GBP', 'value': 20}, 'with': 'supplier'},
    lambda: place_the_order(),
)
book_text, held = writer.snapshot()   # keep both together, with the book
```

Every call is an ordinary function. A writer's calls wait for one
another, also across threads. The other side is asked in a thread of
its own and given 30 seconds. An asynchronous agent calls the writer
through `asyncio.to_thread`. A call to the writer from inside an action
it is taking is refused at once, from the same thread or from a thread
that carries the action's context; from a new thread that the action
starts without it, the call waits until the action ends, so an action
must not wait for such a call. `record_tools` puts an agent's tools
behind the writer. `record_function` puts one ordinary function behind
it and keeps the function's name, parameters and description, so that an
agent framework describes it to its model as it would the function:

```python
from provared import record_function

def place_order(item: str, value: int) -> str:
    """Order supplies from the supplier."""
    ...

place_order = record_function(writer, place_order, 'supplies.order', with_='supplier',
                              amount=lambda args: {'unit': 'GBP', 'value': args['value']})
```

A call that the slip does not allow raises `NotTaken`, and the function
is not run. The folder
[`examples/`](https://github.com/provared/provared/tree/main/python/examples)
shows this with three agent frameworks: LangChain, the OpenAI Agents SDK
and Pydantic AI. `key_set_from_seeds` and `key_set_seeds` keep an
agent's keys between runs as two 32-byte seeds.

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
