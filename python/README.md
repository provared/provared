# <img src="https://prova.red/favicon.svg" alt="" width="36"> Provared for Python

Proof of what an AI agent was allowed to do, and what it then did.

*Evidence, not a verdict.*

This is the Python version of Provared. The format, the reasons for it
and what a record does and does not prove are described in the
repository's own [README](https://github.com/provared/provared/blob/main/README.md), the
[format description](https://github.com/provared/provared/blob/main/spec/provared-format.md) and the
[list of threats](https://github.com/provared/provared/blob/main/docs/threat-model.md). This page says only what is
particular to Python.

## Status

**Version 0.5.0, a draft**, the same version as the JavaScript library.
Published as it is, by one author in their own time; fixes as time
allows. It gives the same answer, case for case, as the shared test
files in [`test-vectors/`](https://github.com/provared/provared/tree/main/test-vectors) show: the same result, the
same codes and the same words. Every shared file passes in both
languages.

One difference is stated, not hidden. The one package this version
needs, `cryptography`, does not yet have SLH-DSA (FIPS 205), the method
of a seal's third signature. So a seal's third signature is reported as
"not checked on this device", and never as a pass, as the checking page
in a browser reports it. Seals are checked in full by the JavaScript
command-line checker. The check before acting, and so the stub writer,
goes on after a seal whose Ed25519 and ML-DSA-87 signatures were checked
here, and its answer says what was not checked (`notChecked`); any
other signature left unchecked still allows nothing.

## Install

```
pip install provared
```

Or, from a copy of the repository, `pip install ./python`.

You need Python 3.11 or later. The one dependency is `cryptography`,
version 48 or later: Python has no signatures built in, and version 48
is the first whose ready-built packages hold ML-DSA (FIPS 204).

## A first record

The permission is signed with a **development stand-in for a passkey**
(`provared.dev`): a key made in memory, which no person confirmed. Every
permission it signs says so in its issuer's name, and a checker shows
that name. A real permission is signed by a person, in a browser, with a
real passkey (the browser part of the JavaScript library, and the
checking page).

```python
from provared import check_book
from provared.dev import development_recorder

SEND = 'provared.message.send'

# A permission: the agent may send messages, at most two.
made = development_recorder({'actions': [SEND], 'limits': [{'action': SEND, 'count': 2}]})

# Each action is asked for first, taken only if the permission allows it,
# and receipted after. The third message is outside it, so it is not sent.
for i in range(1, 4):
    outcome = made.writer.act({'action': SEND}, lambda i=i: print(f'message {i} sent'))
    if not outcome['done']:
        print(f"message {i} not sent: {outcome['answer']['breaches'][0]['message']}")

book = made.writer.book()                                    # the record, one entry to a line
summary = check_book(book, issuer_keys=made.issuer_keys)['summary']
print(summary['intact'], summary['withinSlips'])             # True True
```

The whole file is [`examples/first_record.py`](https://github.com/provared/provared/blob/main/python/examples/first_record.py).
`development_slip(fields)` gives the signed slip, its fingerprint, a
book holding it, the stand-in's thumbprint (`issuer_keys`) and the
agent's keys without opening the writer; `development_passkey()` gives
the stand-in alone, whose `sign(challenge)` signs a prepared slip,
approval or cancellation. The issuer's name always ends with
" (development)", whatever name is given.

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
is not run. The arguments must be plain data (text, numbers, lists,
dicts with text for names, True, False, None). A function with a
parameter whose type can never be plain data (a class of its own, such
as a model or a date, a tuple or a set) is refused when it is recorded,
and so is a generator function. A whole number that JavaScript cannot
hold exactly (beyond 2^53 - 1, unless a float holds it exactly) is
refused, since two such numbers could share one fingerprint. The
function is run with a copy of the arguments: a change it makes to a
list or a dict it was handed does not reach the caller, and a default
that is a list or a dict is a fresh copy at each call. The record holds the
arguments the recorded function is called with: an argument bound in
place into a `functools.partial` is no longer a parameter, so it is not
in the record, and nor is any change that a decorator inside makes. The
folder
[`examples/`](https://github.com/provared/provared/tree/main/python/examples)
shows this with three widely used agent frameworks, and the folder
[`integrations/`](https://github.com/provared/provared/tree/main/python/integrations)
holds small packages for two of them, each of which puts every tool call
of an agent behind the writer in one line. `key_set_from_seeds` and `key_set_seeds` keep an
agent's keys between runs as two 32-byte seeds.

Names follow Python's way (`check_book`, `write_stub`). Options may be
given as keyword arguments (`issuer_keys`, `expected_root`,
`stamp_services`, `seal_keys`, `vouchers`, `witnesses`, `disclosures`,
`cancellations`, `seals`, `without_methods`), or as one dict with the names the
JavaScript library uses (`issuerKeys` and so on). Records and answers
are dicts and lists, with the same member names as in the format.

A seal of the book that someone holds elsewhere (the person, an auditor,
a copy kept apart) can be handed to the checker beside the book, as the
entry it is in the book: `check_book(text, seals=[entry], seal_keys=[...])`,
up to 64. A book that ends before the place the seal states is reported
as cut short (`book-cut-short`); one that holds another line there, as
changed (`seal-not-in-book`). This version cannot check a seal's third
signature (SLH-DSA), so such a seal counts on its Ed25519 and ML-DSA-87
signatures, and the answer says so (format description, section 21.5).
Hand over only seals of the book being checked: nothing in a seal names
its book.

A seal's line may hold witness statements, and statements that came
later may be handed over with a copy of the seal (`{"seal": ..., "witnesses": [...]}`).
Name the witnesses you trust with `witnesses` (the fingerprints of their
key sets): `summary["witnessed"]` then gives the latest seal witnessed
(format description, section 29). `write_witness` writes a statement,
and `consistency_proof` and `verify_consistency` make and check the proof
that one tree extends another (RFC 9162, section 2.1.4). There is no
witness program in this version: a witness checks a seal's three
signatures, and this version cannot check SLH-DSA.

`provared.check` holds the checker alone, for anyone who audits the
checking.

Where the other side will not countersign, a stub can name the
fingerprint of the other system's own identifier for the call, so that
someone who holds that system's log can match the two. Document names
that begin `provared.` are reserved for this (`DOCUMENT_NAMES`; format
description, section 27), and any other such name is refused.
`identifier_fingerprint`, `http_request_fingerprint` and
`http_response_fingerprint` make the fingerprints (a body is bytes, a
bytearray or a memoryview, after any content coding such as gzip; None
is no body; a status may be an int, or a float equal to a whole number;
no header is covered; a trace-id's form is not checked). Only
`provared.trace-id`, `provared.request-id` and `provared.event-id` may
be named more than once in a stub. An identifier that the platform gives only
in its answer goes in through `details_after` (the JavaScript name
`detailsAfter` is taken too):

```python
from provared import identifier_fingerprint

result = writer.act(
    {'action': 'provared.data.change', 'with': 'tickets'},
    lambda: update_the_ticket(),
    {'details_after': lambda answer: [{'name': 'provared.event-id', 'sha256': identifier_fingerprint(answer['request_id'])}]},
)
result['detailsAfter']   # {'added': 1, 'problem': None}
```

The stub is checked with the whole book before the action, and signed
again after it with up to four further documents, in the same call; it
keeps the time the action began. `details_after` is asked in a thread
of its own, must be an ordinary function, and is given as long as the
other side is given to countersign. If it fails, gives no answer in
time, or gives what cannot go in, the stub is written without the
further documents and `result['detailsAfter']['problem']` says why. It
cannot be used with an approval. A matching identifier shows that the
two records speak of one call, not that the call did what either says;
a fingerprint of a request, an answer, the arguments or an error shows
only that the content matches, not that it was the same call.
`record_tools` and `record_function` still name the arguments
`arguments` by default.

Opened with `denials=True`, the writer also writes a **denial**
whenever `act` does not take an action: the agent's side's own signed
statement that it did not take it, and why (format description, section
28). `writer.deny(request, {'source': 'person'})` writes one for a
refusal that came from elsewhere (`'person'`, or `'rule'` for a rule
of the software around the agent; `'check'` with `'codes'` where
`act` was asked to write none with `{'denial': False}`). A denial names
the action, the amount and the service, with documents as fingerprints
only; arguments are never written into it. At most `denials_per_hour`
(600 by default) are written in any hour of the writer's clock: each
denial it writes, or is handed through `add`, counts at the clock's time
when it joins the book, whatever date it states, and those the book held
when the writer was opened count at the dates they state. The answer's
`notWritten` counts those left out, and a stub is never kept out. At 600
an hour a book's 100,000 entries still fill in about a week. A writer
opened again on a book counts the book's denials at their stated dates,
so a caller who dates denials back and then opens the writer again can
get a second burst (5 and then 5 more within 3,302 seconds, at a limit
of 5). `deny`
records what its caller states, and raises only for a malformed call (a
request that is text, a number or None, or that is not plain data,
`codes` that cannot be copied, a `when` that is not a time, or a call from
inside an action). `record_tools` and
`record_function` pass it on: a call that is not run leaves a denial,
which `NotTaken.denial` describes, and a call where the person may yet
approve leaves one only once it is known that it will not run. A checker
counts denials (`summary.counts.denials`) and never counts one against
the agent. An agent can simply not write one, so a book without denials
shows nothing about refusals.

## Keys held elsewhere: signers

The keys of an agent, a service or an organisation need not sit in the
memory of the program that writes the records. Wherever a writer takes
`private_keys` (`open_recorder`, `write_stub`, `countersign`,
`write_refusal`, `write_terms`, `write_pass`, `write_acknowledgement`,
`write_vouching` and `write_withdrawal`), each item may be a key of the
package `cryptography`, as before, or a **signer**: any object with a
`key` attribute, the public key as a dict in one of the shapes the format
allows (format description, section 3.8), and a `sign(data)` method that
gives the signature over exactly those bytes (`bytes`, `bytearray` or
`memoryview`). `provared.Signer` describes it for type checkers. Keys and
signers may be mixed. `signer_from_key(alg, private_key, key)` wraps a
key held in memory as a signer.

```python
from provared import open_recorder, signer_from_key

class HeldSigner:
    """The agent's ML-DSA-87 key, held in a key service."""
    key = agent_keys[1]                      # the public key, as the slip names it
    def sign(self, data):
        return key_service.sign('agent-ml-dsa-87', data)   # the bytes themselves, not a fingerprint of them

writer = open_recorder(book_text, slip_fingerprint,
                       [signer_from_key('Ed25519', ed25519_private_key, agent_keys[0]), HeldSigner()],
                       issuer_keys=[passkey_thumbprint], sign_within=10000)
```

A record made through a signer is the same record as one made with the
key: the same content, labels and Ed25519 signature (an ML-DSA-87
signature is made afresh each time, either way). A signer is not taken
on trust. Its two members are read once, and its key must be exactly a
key of the method of its place, as plain data: a `dict` whose names and
values are plain `str`, not a kind derived from them. A signer for
SLH-DSA is refused before any signer is asked, as `cryptography` cannot
check SLH-DSA, so no seal is written in Python, with keys or with
signers. Where the writer knows the key the record must be signed with
(the agent's keys, or a helper's, in the stub writer; the keys `by`
names in `write_refusal`, `write_terms` and `write_vouching`), a signer
for another key is refused (`bad-key`) before any signer is asked. The
stub writer compares when it is opened, with the slip, or the pass it
acts under, as its book holds it; opened with a pass that its book does
not yet hold, it compares nothing then, and refuses each action
(`pass-missing`). `write_stub`, `countersign`, `write_pass`,
`write_acknowledgement` and `write_withdrawal`, used by themselves,
cannot know the key: there a signer for another key gives a record that
fails its own check, as a wrong key always did. Every signature is
checked against the signer's key before it is used: one of the wrong
length, one that does not check, something other than bytes, a
coroutine, or an error raised leaves no record (`signature-invalid`),
and the error names the place, the method and the key's thumbprint. In
the stub writer a signer is asked in a thread of its own and given
`sign_within` milliseconds (30,000 by default) for each signature; after
that the action is not taken, nothing is written, and a late answer is
not used. The other writers set no time of their own: give the signer's
own connection a time limit. Where no record is made, signers earlier in
the list may already have signed, and a signer that ran out of time may
still sign later: a key service's own log may hold signatures that match
no record. A private key of `cryptography` of another method than its
place's, or anything else that is neither a key nor a signer, is refused
(`bad-field`).

The library cannot know how a key held elsewhere is kept, or whether
the service keeps it safe; it checks only that each signature fits the
key the signer names. A record does not say where a key was kept. Each
signature costs one more check (under a thousandth of a second for
Ed25519 and ML-DSA-87 on one computer).

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
