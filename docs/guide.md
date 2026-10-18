# The Provared guide

Everything about the format, the library, the checker, the stub writer beside an agent and what a record does and does not prove, in one document. The [README](../README.md) is the short version: install, a first record, and where things are.

*Evidence, not a verdict.* A record shows what was signed and by which keys. People decide what it means.

## Status

**Version 0.5.0, a draft.** Published as it is, by one author in their
own time; fixes as time allows. The format may still change, so do not
rely on a draft record staying checkable.

The core of the format is also written as an individual Internet-Draft
at the IETF:
[draft-izmaylov-agent-permission-receipts](https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/).
An Internet-Draft is a working document, not a standard.

## The four parts

| Part | What it is | In this draft |
|---|---|---|
| **Slip** | A short permission a person signs with a passkey: which agent, which actions, what limits and conditions, with whom, from when until when, and why | Built |
| **Stub** | A signed receipt for each action, pointing back to its slip, countersigned by the other side where possible, and approved by the person where the slip asks for it | Built |
| **Seal** | The stubs chained together and gathered under one top fingerprint, signed by whoever keeps the book, time-stamped by an outside service, and signed for by witnesses | Built, with the part of a witness that decides and signs. A public place where seals are kept is not |
| **Show** | One page shown to a checker with proof that it is in the book, and when the book was sealed, with the names it does not need kept covered | Built. Only a slip's names and purpose can be covered so far |

## What is here

| Folder | What it holds |
|---|---|
| `spec/provared-format.md` | The format, described exactly |
| `docs/threat-model.md` | Who might attack a record, what each part protects, and what it does not |
| `src/` | The library: the checker, the writers for every kind of record, the stub writer beside an agent and the connector for an agent's tools. No outside code |
| `bin/provared-check.mjs` | The checker for the command line |
| `bin/provared-headers.mjs`, `net/` | A command that fetches the chain of Bitcoin block headers from nodes you name, so that a block time-stamp can be checked with no node of your own. The only code here that makes a network request. Experimental |
| `page/` | The checking page and the demonstration page |
| `demo/` | The demonstration: an invented office agent works under a permission and goes outside it four times |
| `samples/` | A sample record, written once, that the tests keep checking |
| `tools/` | Three small tools: one wrote the sample record, one writes the checking page as a single file, one writes the shared test files |
| `test/` | The tests |
| `test-vectors/` | Shared test files: records and values, each with the answer this library gives. Another implementation of the format can be tested against them |
| `python/` | The Python version, `pip install provared`, which gives the same answers. See its own [README](../python/README.md), and its examples with three agent frameworks in `python/examples/`, and small packages for two of them in `python/integrations/` |
| `site/` | The pages at [prova.red](https://prova.red/): what a record proves, with the checker's answer for the sample record, and a worked example. Published with GitHub Pages by `.github/workflows/pages.yml`, which also serves the checking page at `prova.red/check/` and as one file. The pages load nothing from anywhere and keep nothing about a reader |

The npm package holds `src/`, `bin/`, `net/`, `spec/`, `docs/`,
`samples/` and the checking page. The tests, the shared test files, the
demonstration, the tools and the Python version are in the repository
only.

## Install

```
npm install provared
```

You need Node.js 24.7 or later. There are no dependencies. Node.js marks
its ML-DSA and SLH-DSA as experimental and may print a warning about
them; the command-line checker does not repeat it.

```js
import { checkBook, openRecorder } from 'provared';               // the whole library
import { checkBook } from 'provared/check';                       // the checker alone, as a page uses it
import { createPasskey } from 'provared/passkey-browser';          // a passkey, in a browser
import { developmentRecorder } from 'provared/dev';               // a stand-in for a passkey, for development only
```

The checker for the command line is `provared-check`:

```
npx provared-check record.jsonl --issuer <the thumbprint of the passkey you trust>
npx provared-check --sample     # the sample record, naming the stand-ins it was made with as trusted
```

The examples below import from the package by name. In a copy of the
repository, import from `./src/index.js`, `./src/check.js`,
`./src/passkey-browser.js` and `./src/dev.js` instead.

## A stand-in for a passkey, for development

A slip is signed by a person with a passkey, in a browser. To try the
library without one, `provared/dev` gives a **development stand-in**: an
ordinary key made in this process's memory that returns the same three
values a passkey returns, so that every record it signs checks exactly
as a real one would. It is not a passkey, and no person confirmed
anything. So that such a record is never mistaken for a person's, the
issuer's name in every slip it signs ends with " (development)",
whatever name you give, and its page address is `http://localhost`,
which the format allows for development only. The checker prints that
name beside the slip.

```js
import { developmentPasskey, developmentRecorder, developmentSlip } from 'provared/dev';

const { recorder, issuerKeys } = await developmentRecorder({ actions: ['provared.message.send'] });
// the stub writer, opened under a slip signed by the stand-in; issuerKeys is its thumbprint, for a checker

const made = await developmentSlip({ actions: ['supplies.order'], limits: [{ action: 'supplies.order', max: 200, unit: 'GBP' }] });
// made.slip, made.slipFingerprint, made.book (the slip alone), made.issuerKeys, made.agent (keys and privateKeys), made.passkey

const passkey = await developmentPasskey();
// passkey.key, and passkey.sign(challenge) for a prepared slip, approval or cancellation
```

`developmentSlip` takes the members of a slip as `prepareSlip` does, and
fills in the issuer (its key, page address and marked name) and the
agent's keys; by default the slip runs from a minute ago for one day,
holds no limits and names no other party, and its purpose says that it
is for development. [examples/first-record.mjs](../examples/first-record.mjs)
is a whole first record in one file. In Python the same is
`provared.dev` (`development_passkey`, `development_slip`,
`development_recorder`), with the writer as `.writer`.

## Try it

These need a copy of the repository. You need Node.js 24.7 or later.
Nothing is installed: there are no dependencies.

**Run the tests.**

```
npm test
```

**Check the sample record from the command line.**

```
npm run check -- samples/office-supplies.jsonl
```

It prints each entry, then its answers: is the record intact, was
everything checked on this device, did the agent stay within its slip, is
it time-stamped in a way you trust, and was it checked against keys you
named. Here you named none, so it is not a pass, whatever else it shows;
the fingerprints that come with the sample are given below.
In the sample the agent goes outside its slip four times: an order the
supplier never confirmed, an order above 60 pounds that the person was
not asked to approve, a total of 230 against a limit of 200, and a
deletion that the slip forbids. The checker says where.

**Make the checking page as one file.**

```
node tools/make-single-page.mjs
```

It writes `provared-check.html`: the checking page, its style, the
checker and the sample record in one file, copied in unchanged. Open it
in a browser straight from the disk; it needs no server. The file allows
itself no request of any kind: its content security policy lets nothing
be loaded from anywhere. The tool prints the file's SHA-256 fingerprint,
so that a copy can be compared with it. (Tried on 8 October 2026 in the
three browser builds this repository is tested with, and on 13 October
2026 in Chrome 155, Edge 155 and Brave 155.) The file for
version 0.5.0 is attached to the release on GitHub. Its SHA-256
fingerprint is
`cec1b8d5e6e7a11c00478c6e83d9f9b5963340ec656657ea0ac84f32e8e52bda`.

**Run the demonstration in a browser.**

```
npm run demo
```

Then open `http://localhost:8787`. You sign a permission with a passkey,
the agent works and stops once to ask your approval of one order, and the
page shows where the agent went outside the permission. Everything in it
is invented: nothing is bought, sent or deleted. The checking
page on its own is at `http://localhost:8787/check`. It takes a record
file, the fingerprints you already trust (keys, time-stamp services,
blocks), and what you were handed with the record: the person's own
copies of cancellations, seals of the book held elsewhere, and
disclosures for covered fields. All of it is read in the browser and
sent nowhere.

## What a slip can say

- **What the agent may do**: a list of action names. Use names of your
  own, or names from the shared list in the format description, section
  16, such as `provared.order.place`, so that another organisation's
  checker knows what is meant.
- **Limits**: a total, a limit on each single action, a number of
  actions, and a total or a number within any period.
- **Conditions**: that the other side must countersign an action, and
  that the person must approve an action with their passkey, always or
  above an amount.
- **Stated rules**: kinds of action the agent must never do, such as
  `destroys`, and rules of conduct, such as "never claim to be a human
  being". A checker compares the first with the stubs. The second is the
  person's signed instruction: no check can show that the agent kept it.
- **With whom**: the services the agent may deal with, and their keys.

The other side has a voice of its own. A service can sign a **refusal**
("this agent asked for something outside its slip, and we refused") and
its **terms for agents** (which actions it accepts). Both are shown as
what the service said.

## The seal and the outside time-stamp

Whoever keeps the book seals it from time to time: they sign its top
fingerprint and its number of entries, with three signatures (Ed25519,
ML-DSA-87 and SLH-DSA-SHA2-256s). An outside time-stamp service then
states when that seal existed, in the standard form of RFC 3161.

- After a seal by a recorder you named (`--sealer`, or `sealKeys`),
  nothing before it can be changed, added or removed without the seal no
  longer fitting. A seal by keys you did not name shows only that someone
  sealed the book as it now stands.
- With a time-stamp from a service you trust, the entries before the seal
  existed by the time the service states. An entry dated later than that
  is reported.
- **You say whom you trust.** This format names no time-stamp service.
  You give the checker the fingerprint of the certificate of each service
  you trust; a time-stamp from any other service is shown, and not
  counted. In the same way you can give the fingerprint of the key set of
  the recorder you expect.

- **A second clock that rests on no signature.** Beside a time-stamp
  from a service, a seal can carry a **block time-stamp**: proof that
  its fingerprint was written into a block of a public blockchain (the
  open proof format OpenTimestamps, and the Bitcoin blockchain). The
  chain is used purely as a clock: no coin, no wallet, no account and no
  payment is involved. It stays good even if every signing method of
  today is broken. You name the blocks you trust by their fingerprints
  (`--block`, or `blocks`). A block's time is right only to within about
  two hours, and the checker says so. The tests use made-up blocks. Two
  complete proofs that others had published, one made by hand and one
  made by public calendar services, were checked once with this reader
  against the real blocks they name (5 October 2026): each led to its
  blocks, and each was refused with another block or with its file
  changed by one bit.

```
npm run check -- samples/office-supplies.jsonl --stamp-service <fingerprint> --sealer <fingerprint>
```

The fingerprints for the sample are in
`samples/office-supplies.expected.json`. The sample's time-stamp service
is made up, as its passkey is.

### Seals held elsewhere

Whoever keeps the book can cut off its end, with the last seal, and what
is left still checks. Anyone who keeps a copy of a seal elsewhere (the
person, an auditor, a second copy out of the recorder's reach) can hand
it to the checker beside the book, as the entry it is in the book:

```
provared-check record.jsonl --seal seal.json --sealer <fingerprint> --issuer <thumbprint>
```

In the library: `seals`, up to 64. A seal at entry n covers the n
entries before it, so the book must hold that very seal at entry n. A
book that ends before it is reported as cut short (`book-cut-short`); a
book that holds another line there, as changed (`seal-not-in-book`).
Both are problems with the book. A seal handed over is checked as any
seal is, and counts only where you named its recorder (`--sealer`, or
`sealKeys`); one that does not pass its own check is a problem with the
whole check. On a device without SLH-DSA (the Python version, and
browsers that have ML-DSA, such as Edge and Brave 155 when tested) it
counts on its Ed25519 and ML-DSA-87 signatures, and says so; on a device
without ML-DSA it is not used. The seal is compared with the book by its
content: the same content with other signatures is the same seal, and
the answer says that the signatures differ. Nothing in a seal names its
book, so hand over only seals of the book being checked: a seal of
another book by the same recorder (for example the book it kept before
it started a new one) is reported as `seal-not-in-book` or
`book-cut-short`. Without `--sealer`, the seals handed over are not
compared with the book, and the command-line checker says so on a line
of its own and gives no pass.
Its own time-stamps are shown but are not used for the entries of the
book. The answer lists each one in `held`, after any cancellations. A
Show does not use one. What it does not catch: a book cut back after the
latest seal anyone holds, or a book never shown to anyone who holds one.

### Witnesses

A witness is a party, with a key set of its own, that keeps for each
book the latest seal it has signed for, and signs a short statement for
a new seal only where the new seal extends that one (format
description, section 29). The recorder sends it the seal and a
consistency proof (RFC 9162, section 2.1.4); the statement goes beside
the seal on its line, in `witnesses`, up to four, or is handed to the
checker later with a copy of the seal (`--seal` with a file of
`{"seal": ..., "witnesses": [...]}`). Name the witnesses you trust by
the fingerprints of their key sets:

```
provared-check record.jsonl --witness <fingerprint> --sealer <fingerprint> --issuer <thumbprint>
```

In the library: `witnesses`. The answer's `summary.witnessed` gives the
latest seal for which a statement from a witness you trust counts, the
entries it covers, those witnesses, and every seal witnessed; the
command-line checker prints it as "Witnessed by a witness you trust?".
A statement that does not check, or that speaks of another seal, is a
problem (`witness-invalid`). A statement counts only where you also
named the passkey you trust (`--issuer`) and the recorder you expect
(`--sealer`), the book starts with a permission signed by that passkey,
and every permission before the seal is from that passkey for the same
agent (a Show must hold every page the seal covers): a witness knows a book only by the passkey and the agent of
the permission it starts from and its recorder's keys, and the recorder
chooses the first line and its keys. Being witnessed excuses nothing
and is not needed for a pass. What it adds: a second history of the
entries before a witnessed seal, sealed by the same recorder and
starting from any permission that passkey gave that agent (a renewal
included), shown to someone else, would need that witness to sign for it
too. What it does not: a history sealed with other keys, even keys you
also named, or one that starts from a permission for another agent;
anything never shown to the witness; or the time. To see whether the end
of the book is missing, ask the witness for the latest seal it holds for
this recorder, passkey and agent, and hand that seal over beside the book
it is of. One recorder key set keeps one sequence for each person and
agent: books kept side by side for one agent need recorder keys of
their own.

A recorder may keep the record of one permission in several books: a
seal says which in `book` (2, 3 and so on; the first book has no
number), and the first seal of a later book names the last seal of the
book before. `writeSeal` takes `book`. A witness treats every book of one
recorder, person and agent as one sequence: it signs for a new book only
where its first seal starts from the latest seal it holds, and never
again for the book before. A checker of one book does not see the book
before; handed that book's last seal, it says whether this book follows
on from it (format description, section 21.6). A seal handed over that
gives another book number than the book is not compared with it, and
gives no pass: the command-line checker says "Seals held elsewhere
compared? NO" and does not end with code 0, even for an honest book.
To check book n − 1 against the seal book n starts from, check book
n − 1 with that seal handed over beside it.

The library holds a witness: `openWitness({ by, signers, state })`, with
`witness(entry, proof, firstLine)`, which signs only for a seal whose
three signatures it checked and that extends the seal it holds, and
hands back its state with each statement, to be saved before the
statement is given out; `update`, `ready`, `latest` and `state`.
`witnessProof(book, size, from)` makes the proof to send it (`from`:
the size of the seal the witness holds of the same book, or none for a
first seal and for the first seal of the next book), and `bookIdentity`
names a sequence as a witness knows it: by the recorder's keys with the
passkey and the agent of the permission on the book's first line. Whoever can change a witness's
state can make it forget a sequence: keep it as safely as its keys. A
witness needs SLH-DSA, so it needs Node.js; the Python version has none.

### Knowing that a block is part of the chain

**Experimental.** `provared-headers` is new in version 0.1.0 and may
change. It is the only part of Provared that connects to the internet,
and it does so only when you run it.

A block time-stamp counts only for a block you trust to be part of the
Bitcoin blockchain. You need not run a Bitcoin node of your own, or trust
anyone who lists blocks, to know that:

```
provared-headers --node <host:port> --node <host:port>
provared-check record.jsonl --headers block-headers.bin --issuer <thumbprint> --sealer <fingerprint>
```

`provared-headers` fetches the chain of block headers (about 78 MB, a
few minutes the first time) from the Bitcoin nodes you name, and from no
one else, and keeps it in a file. It checks every header on your device,
by the rules every Bitcoin node applies, from the chain's first block:
each names the block before it, carries the work its target asks for,
follows the rule for the difficulty, and states a time that the rules
allow. The chain must also hold, at their places, ten blocks known to be
part of it, which are written into the library, and after the last of
them no target may be more than four times easier than that block's. A
second node, on another network, must hand back the latest six blocks
itself. A node can refuse to answer, but cannot have a false header
kept. A chain file someone else hands you is only as good as they are:
fetch your own. Run it again later and it
fetches only the newer headers. Name your own node if you have one
(`127.0.0.1:8333`); a file of nodes, one `host:port` to a line, can be
given with `--nodes-file`. The nodes you name see your device's address,
and a node named by its name is looked up by your device's own name
service.

`provared-check --headers` checks that file again, in full, on your
device, and makes no request. A block time-stamp then counts if its block
is in the chain with at least six blocks after it. The checker says, for
each block time-stamp, what the chain shows. In the library:
`checkHeaderChain` and `blocksInChain`.

## Cancelling a slip

The person who signed a slip can end it early with the same passkey, and
have the cancellation time-stamped at once. Every stub after it is then
reported as outside the slip. With a time-stamp on the cancellation, a
stub counts as made before it only if an outside time-stamp shows that
it existed by then: an agent cannot escape a cancellation by writing an
earlier time into a stub. If the person cancelled more than once, every
cancellation counts, in whichever order they stand in the book.

The person should keep their own copy of a cancellation, with its
time-stamp. Whoever keeps the book could leave the cancellation out, or
put a later time-stamp in its place. Handed to the checker beside the
book (`--cancellation <file>`, or `cancellations`), the person's copy
counts all the same: the checker says whether the book holds it, and
reports every stub that no outside time-stamp shows to have existed
before it.

A cancellation shows when the person signed it, not that the agent's
side was told. So the agent's side can **acknowledge** it: a short
record, signed with the agent's own keys, that says "this cancellation
was handed to us at this time". The stub writer signs one whenever the
person's cancellation of its slip is handed to its `add`, once for each
cancellation, writes it into the book after the cancellation, and hands
it back for the person to keep. Handed to the checker with the person's
copy (as `acknowledgements` in the same file), it shows which stubs the
agent made after it was told, which passes it handed on after it was
told, and whether a cancellation that the book leaves out had been
handed over. Both dates in that comparison are the agent's own word. An
acknowledgement that does not check is reported, and the cancellation
itself is still used.

## Who stands behind a name

A name in a record is a label. An organisation can stand behind one with
a **vouching record**: "this key belongs to this name". It can vouch for
a person's passkey, an agent's keys, a service's keys and a recorder's
keys, and can later **withdraw** the statement. You tell the checker
which organisations you trust (`--voucher`, or `vouchers`), and it then
shows a name as "vouched for by" that organisation instead of "a label,
not checked". The vouching record must be in force for the whole of the
slip's time. Provared does not decide who anyone is: it records who
vouched.

A slip can also state the fingerprints of the agent's program and
settings, as the person approved them. That is a statement, not proof of
what ran.

## Covered fields

A slip can be written with its names and its purpose covered: the person's
name, the agent's name, the services' names and the purpose. What is
signed then holds a fingerprint in place of each. To let a reader see a
field, hand over its **disclosure**; to keep it hidden, do not. The
signature, the chain and the tree check either way, and a disclosure
cannot be made for a value that was not signed. A disclosure that does
not fit is refused and said to be, and the slip is checked as it would
be without it: what a slip is does not depend on what is handed over
with it. Nothing that a checker
compares can be covered: not an action, a limit, a condition, a service
or a key. So every reader checks the same slip.

```js
const prepared = await prepareSlip(fields, { cover: ['issuer.name', 'purpose'] });
prepared.disclosures; // keep these beside the slip

await checkBook(book, { disclosures: { [fingerprintOfTheSlip]: theDisclosuresYouWereHanded } });
await makeShow(book, [0, 3], { disclosures: { 0: theOnesThisReaderMaySee } });
```

The method is the standard "Selective Disclosure for JSON Web Tokens"
(RFC 9901), which digital identity wallets also use. The standard's own
worked example is one of the tests. A slip uses less than the standard
allows: no covered item of a list, no decoy fingerprints, and
disclosures written in one canonical form.

## Passing a slip on

A slip can say that its agent may hand part of its permission to a helper
agent, and how many times in a row (`passes`: from 1 to 10). The agent then
signs a **pass** that names the helper's keys, what the helper may do,
its limits and its times. A helper's stubs name the pass, are signed with
the helper's keys, and are compared with the pass, with every pass above
it, and with the slip the person signed. The totals of the slip, and of
each pass, take in everything done under them, so passing on cannot
widen a permission. A pass the slip does
not allow is reported, with every stub under it.

## The check before acting

`checkBefore` answers, before an action: would this be outside the slip?
It uses the same comparison as the checker, so it refuses everything the
checker would report afterwards. In one case it refuses more: an action
that would add to a period which a stub dated after it already
overfills; the checker reports that against the later stub. The software
around an agent can call it and stop the action.

```js
import { checkBefore } from 'provared';

const answer = await checkBefore(
  textOfTheBookSoFar,
  {
    slip: fingerprintOfTheSlip,
    action: 'provared.order.place',
    amount: { unit: 'GBP', value: 80 },
    with: 'supplier',
    approval: theSignedApprovalIfTheSlipAsksForOne,
  },
  { issuerKeys: ['the thumbprint of the passkey you trust'] },
);

answer.allowed;   // true only if the record so far is sound, fully checked (but for a seal's third signature, below), and the action is inside the slip
answer.notChecked; // present only where the device went on without checking a seal's third signature (SLH-DSA)
answer.breaches;  // why not, in the checker's own codes
answer.problems;  // why the question could not be answered with a yes
answer.needs;     // what the slip asks to go with it: 'approval', 'countersignature'
```

It must be told whose passkey it trusts: a slip signed by any other key
allows nothing. Where the slip asks for the person's approval, the action
is allowed only if the signed approval is handed over. Where the slip
asks for a countersignature, `needs` says so: the action is inside the
slip only if the other side then countersigns it.

It is a help, not evidence: nothing in a record shows that it was called.

## Beside an agent

`openRecorder` puts the two things an agent's software must do into one
call: ask first, and write the receipt after.

```js
import { openRecorder } from 'provared';

const recorder = await openRecorder({ book, slip, privateKeys, issuerKeys });

const outcome = await recorder.act(
  { action: 'provared.order.place', amount: { unit: 'GBP', value: 45 }, with: 'supplier' },
  async () => placeTheOrder(),            // taken only if the answer is yes
  { countersign: askTheSupplierToCountersign },
);

outcome.done;      // false: the action was outside the slip, was not taken, and nothing was written
recorder.book();   // the book, with the new stub in the agent's chain
await recorder.check();   // what the record shows as it stands, as checkBook would answer
```

If taking the action fails with an error, no stub is written; the caller
must deal with whatever part of the action did happen. `record` writes a
stub without asking, for an action that was taken some other way: the
record is of what happened, inside the slip or not.

The writer's calls wait for one another, so two actions asked for at the
same moment are taken one after the other, each against the book as the
one before left it. A countersignature that the other side hands back is
checked before it goes into the book; one that does not check is left
out, the stub stands one-sided, and `stub.countersignature.problem` says
why. `add` puts an entry that someone else made (a seal, a cancellation,
a refusal) into the book only if the book still passes its check with
it, and it is not dated ahead of the clock. The other side is given 30
seconds to countersign (`countersignWithin`); after that the stub is
written one-sided. Where the slip asks for a countersignature, `act`
takes the action only if it is given a way to ask for one. Before an
action is taken, its stub is written and checked with the whole book, so
that the receipt is known to fit. `act` takes an action now: a date
handed to it must be within 300 seconds of the writer's clock (`now`).
Nothing is written that is dated more than 300 seconds ahead of that
clock. What the writer is handed (the request, an approval, what the
other side hands back) is copied when it is handed over, and the copy is
what is checked and written. `record` hands a stub to the other side
only once it has passed the check of the whole book. The function
that takes the action must not call the writer. Use one writer for one
chain: two writers on two copies of a book know nothing of each other.

The writer reads its book once, when it is opened, and then carries it
on: each new line is read by itself, and no signature is checked twice.
So the time an action takes grows only slowly with the length of the
book. Measured on one computer on 4 October 2026, with countersigned
stubs: 9, 14 and 23 thousandths of a second for one action after 400,
1,600 and 6,400 stubs. (Before the book was carried on: 2.0 seconds
after 400 stubs and 7.7 after 1,600.) Opening the writer still reads
the whole book: about one second for every 450 stubs. Every line
is tried on a reader split off the book's own before it joins the book,
so an entry that does not fit, or an error part of the way through a
call, leaves the writer's view of its book exact. `recorder.check()`
gives the checker's answer for the book as it stands, without reading
it again. `before` waits its turn with the other calls. What the writer
is told to trust (`options`) is read once, when it is opened, and
fixed.

A cancellation that the person signed is never lost in `add`. If it
cannot be added as it was handed over (a faulty time-stamp beside it, a
member that cannot be written as a line, such as a list with a gap in
it), the writer adds the cancellation with its time-stamps, or with
those of them that pass their check, or by itself. If it cannot be added even so (it is dated ahead
of the clock), the writer keeps it, allows nothing more under the slip,
and writes it into the book, at its next call, once the clock has
reached its date. In both cases `add` fails, and the error says what was
done. (Where the clock fails, the error is the clock's own; the
cancellation is held all the same, as `cancellations()` shows.) A
cancellation that the writer keeps lives only in that writer:
`recorder.cancellations()` hands back what it holds, each with the
acknowledgement the writer signed for it, and so does an acknowledgement
that still waits to follow its cancellation into the book. Keep that
with the book, and hand it in again (`options.cancellations`, an empty
list included) when you open a writer again; a writer opened from the
book alone knows nothing of it. Read `recorder.book()` and
`recorder.cancellations()` together, with nothing awaited in between,
so that the two you keep belong to the same moment. A cancellation given in that way is written into the book once
its date has come, and stops the writer from the start. A copy that
the writer holds takes the time-stamps handed over with it later: each
is judged by itself, those the writer counts come first, and a copy
holds four at most. The writer is stopped before it reads its clock, so
a clock that fails then does not lose the cancellation, nor the sound
time-stamps, nor the acknowledgements handed over with it. A clock that
gives anything but a time counts as a clock that failed. An
acknowledgement that is handed over with a cancellation is taken as the
agent's own only if it checks by itself, and only the first such one is
taken: the writer never puts a second one of the agent's own with a
copy (a copy given at opening that already holds two is handed back as
it was given). A copy holds four
acknowledgements at most; the writer's own is always among them, and
where the copy already holds four, the last of the others gives way to
it. A writer that is stopped
takes no action, but `record` still writes the stub of an action that
was taken all the same: the record is of what happened, and a checker
reports such a stub.

### The agent's tools

An agent acts by calling tools: functions that its software offers it.
`recordTools` puts each tool behind the stub writer, so that no call is
forgotten. The agent's software calls the tools as before.

```js
import { openRecorder, recordTools } from 'provared';

const recorder = await openRecorder({ book, slip, privateKeys, issuerKeys });
const tools = recordTools(recorder, {
  placeOrder: {
    action: 'provared.order.place',          // the name the slip uses for it
    with: 'supplier',
    amount: (order) => ({ unit: 'GBP', value: order.total }),
    run: (order) => sendTheOrder(order),     // run only if the slip allows it
    countersign: (stub) => askTheSupplierToCountersign(stub),
  },
  readStock: { action: 'provared.data.read', run: (query) => lookUpStock(query) },
});

await tools.placeOrder({ item: 'paper', boxes: 5, total: 45 });
```

A call that the slip does not allow throws `NotTaken`, with the answer
of the check before acting, and the tool is not run. Where the slip asks
for the person's own approval, a tool's `approve` function is asked for
it once. By default the stub of a call names one document,
`arguments`: the fingerprint of the call's arguments, written in one
form (RFC 8785). So the record fixes exactly what was asked for without
holding it; `argumentsFingerprint` works the same fingerprint out again.
The arguments must be JSON: a list with a gap in it, or with a named
member, or a member that is `undefined`, is refused, and the tool is
not run. A fingerprint of arguments
that are few and easy to guess can be guessed. What a tool is, and what
it is called with, is copied when it is handed over; each function a
tool is described by gets a copy of the arguments of its own, and is
called by itself, without `this`: it is not handed the description and
cannot change it. What `amount`, `with` and `details` give is
copied too, so a function that keeps what it gave cannot change it
afterwards. `amount` and `with` must give their value at once,
not a promise. The numbers `0` and `-0` share a fingerprint, as RFC
8785 writes both as `0`. If `onStub` fails, its error is passed on,
though the tool has run and its stub is in the book. `recordTools`
names no agent software, and works with any function.

### Denials: the calls the agent's side refused

A book shows what the agent did, not how often it was stopped. Opened
with `denials: true`, the stub writer also writes a **denial** whenever
`act` does not take an action: the agent's side's own signed statement
that it did not take it, and why (format description, section 28).

```js
const recorder = await openRecorder({ book, slip, privateKeys, issuerKeys, denials: true });

const outcome = await recorder.act({ action: 'provared.data.delete' }, async () => removeTheFiles());
outcome.done;              // false: the slip does not allow it
outcome.denial.written;    // true: the book now holds a denial, by "check", with the reason "action-not-allowed"

// A refusal that came from elsewhere: the person said no, or a rule of the software around the agent did.
await recorder.deny({ action: 'provared.order.place', amount: { unit: 'GBP', value: 900 } }, { source: 'person' });
```

A denial names what was asked for (its action, amount and service) and
who said no: `check` (the check before acting, with the codes it gave),
`person` or `rule`. Its documents are fingerprints only; arguments are
never written into it. `more.denial: false` asks `act` to write none
for one call. A writer writes at most `denialsPerHour` (600 by default)
in any hour by its clock. Each denial it writes, or is handed through
`add`, counts at the clock's time when it joins the book, whatever date
it states; those of its own chain that the book already held when it
was opened count at the dates they state. Past that it writes none, and
each answer's `notWritten` says how many it left out since it was
opened. A writer opened again on a book counts the book's denials at
their stated dates, so a caller who dates denials back and then opens
the writer again can get a second burst (5 and then 5 more within 3,302
seconds, at a limit of 5). At 600 an hour, an agent that is refused again and again still
fills a book's 100,000 entries in about a week: the limit slows that,
it does not stop it. A stub is never kept out by that limit, and
nothing that goes wrong in writing a denial makes `act` or `deny` fail:
the answer says what was done. `deny` does throw where the call itself
is malformed: a request that is not an object, or that cannot be copied
as plain data, a `when` that is neither
a number nor a date, `codes` that cannot be copied, or a call from
inside an action, which is refused as every call from there is. It
writes nothing for a writer opened without `denials: true`, and takes a
`when` within 300 seconds of the clock. It records what its caller
states: it does not check that the action was not taken, so a caller
can write a denial for a request that also has a stub.

`recordTools` passes it on: with a writer that writes denials, a call
that is not run leaves one, and `NotTaken` holds what was done
(`denial`). Where a tool can ask the person for approval, no denial is
written until it is known that the call will not run: so one call
leaves a stub or a denial, never both. A checker shows each denial as
the agent's side's own word, counts it (`summary.counts.denials`), and
never counts it against the agent. An agent can simply not write one,
so a book without denials shows nothing about refusals.

### Binding a stub to the platform's own record

Where the other side will not countersign, a stub can still be matched
with the other system's own log of the call: name, among its documents,
the fingerprint of an identifier that both records hold. Document names
that begin `provared.` are reserved for this (format description,
section 27); any other such name is refused.

| Name | The fingerprint of | Made with |
|---|---|---|
| `provared.arguments` | The call's arguments, in the one form of RFC 8785 | `argumentsFingerprint` |
| `provared.http-request` | The request: its method, its address exactly as sent, and its body where it has one; no header | `httpRequestFingerprint` |
| `provared.http-response` | The answer: its status code, and its body where it has one; no header | `httpResponseFingerprint` |
| `provared.trace-id` | The trace-id of the W3C Trace Context `traceparent` header the agent's side sent (its form is not checked) | `identifierFingerprint` |
| `provared.request-id` | An identifier the agent's side chose and sent with the call | `identifierFingerprint` |
| `provared.event-id` | An identifier the platform gave for the call | `identifierFingerprint` |
| `provared.error` | The error text the agent's software was given | `identifierFingerprint` |

`DOCUMENT_NAMES` lists them, each with the exact text it stands for. An
HTTP request or answer is written as the signature base of RFC 9421
(nothing is signed with it): the address is taken exactly as it was
sent, never rewritten, so give it in the form that was sent. A body is
the bytes RFC 9530 digests: after any content coding (such as gzip),
before any transfer coding; a body of `null` is no body. The three
identifiers may be named more than once in a stub; every other reserved
name once at most. A trace-id is fingerprinted as given: its form (32
lower-case hexadecimal characters in the W3C standard) is not checked.

An identifier that the platform gives only in its answer cannot be in a
stub signed before the action. `act` takes `detailsAfter` for it:

```js
import { identifierFingerprint } from 'provared';

const outcome = await recorder.act(
  { action: 'provared.data.change', with: 'tickets' },
  async () => updateTheTicket(),               // gives the platform's answer
  { detailsAfter: async (answer) => [{ name: 'provared.event-id', sha256: await identifierFingerprint(answer.requestId) }] },
);
outcome.detailsAfter;   // { added: 1, problem: null }
```

The stub is still written and checked with the whole book before the
action, so it is known to fit. After the action it is signed again with
up to four further documents, within the same call, so that no other
call comes between; it keeps the time the action began. If
`detailsAfter` fails, gives no answer in the time the other side is
given to countersign (`countersignWithin`), gives more than four
documents, or gives one that would be refused, the stub is written
without them, and `outcome.detailsAfter.problem` says why: an action
that was taken always gets its stub. The request may then name at most
28 documents of its own, and no approval may be given, because an
approval covers exactly the documents the person saw. `detailsAfter`
must not call the writer.

A matching identifier shows that the two records speak of one call, not
that the call did what either says: the platform's identifier is the
platform's word. It binds the two only where the platform writes the
same identifier into its own log; which one a platform keeps is for you
to find out, so record both one you sent and one you were given where
you can. Only an identifier picks out one call: a fingerprint of a
request, an answer, the arguments or an error shows only that the
content matches, since identical requests, and identical answers (many a
`200` with the body `{}`), share one fingerprint. A platform that logs
the decoded body of a compressed message will not match the body's
fingerprint. An identifier that is short or easy to guess can be guessed
from its fingerprint.

`recordTools` still names the arguments `arguments` by default; a tool
can name them `provared.arguments` through its own `details` function.

## How signing works

- **The person** signs a slip with a passkey. A passkey signs a short
  value handed to it; that value is the SHA-256 fingerprint of the slip's
  exact signed bytes, so the signature covers the whole slip.
- **The agent and the service** each sign with two keys at once: Ed25519,
  which is today's kind, and ML-DSA-87, which is quantum-safe. A record
  counts only if both signatures check. A forger must break both.
- **The passkey signature is of today's kind only**, because no device
  offers a quantum-safe passkey yet.
- **Whoever keeps the book** signs each seal with three keys: the same
  two, and SLH-DSA-SHA2-256s, which rests only on fingerprint functions.
- **The browsers tried have ML-DSA; none has SLH-DSA.** Tried on the
  author's computer on 13 October 2026: Chrome 155, Edge 155 and
  Brave 155 each offer Ed25519 and ML-DSA (all three strengths) to a
  page, and check real signatures made with them. None of the three
  offers SLH-DSA. So in these browsers the checking page checks every
  signature of a slip, a stub, a countersignature and the other records,
  but not a seal's third signature: a book with a seal reads "not
  complete" there, and the time-stamp beside the seal is not counted.
  Where a browser lacks a method, the checking page says that those
  signatures were not checked, and does not show a pass. Node.js checks
  all of them.

### Keys held elsewhere: signers

The keys of an agent, a service, an organisation or a recorder need not
sit in the memory of the program that writes the records. Wherever a
writer takes `privateKeys` (`openRecorder`, `writeStub`, `countersign`,
`writeRefusal`, `writeTerms`, `writePass`, `writeAcknowledgement`,
`writeVouching`, `writeWithdrawal` and `writeSeal`), each item may be a
key, as before, or a **signer**: an object with two members.

- `key`: the public key, as a JSON Web Key in one of the shapes the
  format allows (format description, section 3.8).
- `sign(data)`: a promise of the signature over exactly those bytes, as a
  `Uint8Array` or an `ArrayBuffer`.

A signer lets a key live in a key service or a hardware module. Keys and
signers may be mixed: an agent may keep its ML-DSA-87 key in a key
service and its Ed25519 key elsewhere. `signerFromKey(alg, privateKey,
key)` wraps a key held in memory as a signer, so that both take one path.

```js
import { openRecorder, signerFromKey } from 'provared';

// "keyService.sign" stands for the service's own call. It must sign the
// bytes themselves, not a fingerprint of them.
const held = {
  key: agentKeys[1],                       // the agent's ML-DSA-87 public key, as the slip names it
  sign: (data) => keyService.sign('agent-ml-dsa-87', data),
};
const recorder = await openRecorder({
  book, slip, issuerKeys,
  privateKeys: [signerFromKey('Ed25519', ed25519PrivateKey, agentKeys[0]), held],
  signWithin: 10000,                       // milliseconds for each signature; 30,000 by default
});
```

A record made through a signer is the same record as one made with the
key itself: the same content, the same labels and the same Ed25519
signature. ML-DSA-87 and SLH-DSA signatures are made afresh each time,
with a key or through a signer, so those differ between any two
signings, as they always did.

A signer is not taken on trust:

- Its two members are read once. Its key must be exactly a key of the
  method of its place in the list, as plain data.
- A signer for a method this device does not have built in is refused
  before any signer is asked to sign, since its signatures could not be
  checked here.
- Where the writer knows the key the record must be signed with, the
  signer's key must be that key: the agent's keys as the slip names them,
  or a helper's as its pass names them, in the stub writer; the keys
  `by` names in `writeSeal`, `writeRefusal`, `writeTerms` and
  `writeVouching`. A signer for another key is refused (`bad-key`)
  before any signer is asked to sign. This catches the most likely
  fault of a key held elsewhere: a mistyped key name in its settings.
  The stub writer compares when it is opened, with the slip, or the
  pass it acts under, as its book holds it. Opened with a pass that its
  book does not yet hold, it compares nothing then, and refuses each
  action (`pass-missing`), as it always did.
- `writeStub`, `countersign`, `writePass`, `writeAcknowledgement` and
  `writeWithdrawal`, used by themselves, cannot know which key the
  record must be signed with. There a signer for another key gives a
  record that fails its own check, as a wrong key in memory always did.
- Every signature it gives is checked against its key before it is
  used. A signature of the wrong length, one that does not check
  (another key used, or other bytes signed, such as a fingerprint of
  them), something other than bytes, or a `sign` that throws: no record
  is made (`signature-invalid`), nothing is written to a book, and the
  error names the place in the list, the method and the key's
  thumbprint.
- In the stub writer, a signer is given `signWithin` milliseconds for
  each signature (30,000 by default). After that the action is not
  taken, nothing is written, the writer goes on to its next call, and a
  late answer is not used. A signer that calls the writer is refused at
  once, as an action that does so is. The other writers set no time of
  their own: a signer that never answers leaves the call waiting, so give
  the signer's own connection a time limit.

Where no record is made, signers earlier in the list may already have
signed, and a signer that ran out of time may still sign later. So a key
service's own log may hold signatures that match no record.

A key given as before is used exactly as before: a private Web Crypto
`CryptoKey` of the method of its place and, in a seal's SLH-DSA place, a
private Node.js `KeyObject`, or what Node.js reads as one (PEM text, DER
bytes with their format, or a JSON Web Key with its format). Anything
else that is not a signer (a public key, a key of another method or
kind, a value that only looks like a key) is refused (`bad-field`).

What a signer does not change:

- **The library cannot know how a key held elsewhere is kept**, who else
  can ask for signatures with it, or whether the service keeps it safe.
  It checks only that each signature fits the key the signer names.
- **A record does not say where a key was kept.** A record signed
  through a key service reads the same as one signed with a key in
  memory, and a key set split between two places reads as one agent.
- **Each signature costs one more check.** Measured on one computer on
  15 October 2026: about 0.3 thousandths of a second for Ed25519, 0.6
  for ML-DSA-87 and 2 for SLH-DSA-SHA2-256s.

## Using the library

```js
import { checkBook } from 'provared/check';

const result = await checkBook(textOfTheBook, {
  issuerKeys: ['the thumbprint of an issuer key you already trust'],
});

result.summary.intact;        // no problem found, and every signature checked
result.summary.problemFound;  // was a problem found in the record?
result.summary.fullyChecked;  // was every signature checked on this device?
result.summary.withinSlips;   // every stub compared with its slip, none outside it
result.summary.firstBreach;   // the first entry that shows the agent outside its slip
```

Type declarations come with the library (`src/types.d.ts`), so an editor
can check how it is called.

**A book that grows.** `checkBook` reads a whole book each time. To
follow a book as lines are added to it, open a checker once and carry it
on. It reads each new line against what it worked out from the lines
before it, and checks no signature twice. Its answer is the answer
`checkBook` gives for the same text; a test compares the two at every
length of a book that holds every kind of entry.

```js
import { openChecker } from 'provared/check';

const checker = await openChecker(textOfTheBookSoFar, { issuerKeys });
await checker.add(newLines);            // whole lines, each ending with a line feed
const result = await checker.result();  // the same shape as checkBook returns
```

What the checker is told to trust is fixed when it is opened. Each answer
is a copy of its own.

The checker never throws for a bad record. A failed check is a normal
answer with a named reason. It keeps two things apart:

- **problems**: reasons the record cannot be relied on (a changed entry, a
  signature that does not fit, a broken chain);
- **breaches**: what a sound record shows about the agent (an action the
  slip does not allow, a limit passed).

### What the checker returns

| Member | Meaning |
|---|---|
| `size`, `root` | How many entries the book holds, and its top fingerprint |
| `problems` | Problems with the book as a whole |
| `entries` | One for each line: `index`, `kind` (`slip`, `stub`, `refusal`, `terms`, `seal`, `cancellation`, `acknowledgement`, `vouching`, `withdrawal`, `pass`, `denial` or `unreadable`), `fingerprint`, `verified` (`all`, `some` or `none` of its signatures confirmed here), `problems`, `breaches`, `notes`, the signature states, and `content`. Where a time-stamp you trust on a later seal covers the entry: `existedBy`, the time by which it is shown to have existed. On a seal or a cancellation that passed its check: `stampedAt`, the time its own time-stamps give it |
| `held` | One for each cancellation handed over beside the book (`kind` `cancellation`): whether it passed its check and was used, whether the book holds it (`inBook`), the time its time-stamp gives, and the acknowledgements handed over with it (`acknowledgements`: who acknowledged, and when by their own word). Then one for each seal held elsewhere (`kind` `seal`): whether it passed its check and was used, the entry it stands at (`place`), whether the book holds it there (`inBook`), its recorder's key set (`sealer`), its signatures and time-stamps |
| `summary.problemFound` | A problem was found somewhere in the record |
| `summary.fullyChecked` | Every signature was checked on this device |
| `summary.intact` | No problem was found **and** every signature was checked. The only answer that is a pass |
| `summary.methodsMissing` | The signing methods this device lacks, if any, for example `ML-DSA-87` |
| `summary.withinSlips` | Every stub was compared with its slip, and none is outside it |
| `summary.firstBreach` | The first entry that shows the agent outside its slip, if any |
| `summary.counts` | Slips, stubs, countersigned stubs (the countersignature confirmed on this device), one-sided stubs (no countersignature; a stub that was not checked, because its slip failed, is neither), stubs the person approved, refusals, sets of terms, denials (the agent's side's own word, never counted against it), and the other kinds of entry |
| `summary.sealed` | How far the last time-stamp you trust reaches: how many entries, the time they existed by, and whether a service or a block (`by`) gave it. Otherwise nothing |
| `summary.limits` | What no check can show, in plain sentences |

A signature state is `valid`, `invalid`, `unavailable` (this device
lacks the method; never a pass), or `unchecked` (not checked, because
what it rests on failed its check). Each problem and each breach has a `code`
in plain words and a `message`. The codes are listed in
`docs/threat-model.md`, section 8.

The `content` of an entry that has problems, or whose `verified` is
`none`, is unverified. It is there for whoever must find out what went
wrong. Never show it as fact: the checking page and the command-line
checker do not.

Options: `issuerKeys` (the thumbprints of issuer keys you trust),
`sealKeys` (the fingerprints of the key sets of the recorders you
expect), `stampServices` (the fingerprints of the certificates of the
time-stamp services you trust), `blocks` (the fingerprints of the
blocks of a public blockchain you trust), `vouchers` (the fingerprints of the key
sets of the organisations whose vouching you trust), `witnesses` (the
fingerprints of the key sets of the witnesses you trust), `disclosures` (the
disclosures of covered fields that you were handed), `cancellations`
(the person's own copies of cancellations), `seals` (seals of the book
held elsewhere), `expectedRoot` and
`expectedSize` (a top fingerprint and a number of entries you already
hold a copy of). Give
them whenever you have them.

The checker reads a whole book into memory. A book of several hundred
megabytes may be too large for a browser or for Node.js to hold as one
text.

The command-line checker ends with code 0 (intact, nothing outside the
slip, and checked against keys you named: the passkey you trust and,
where the record has a seal, the recorder you expect), 1 (no problem
found, but the agent is outside its slip, not every signature could be
checked, or you did not name whom you trust) or 2 (a problem was found,
or what you gave on the command line could not be used). A value that
is not a fingerprint is refused, never set aside. The checking page
gives its green answer on the same terms.

Writing records: `prepareSlip` and `assembleSlip`, `prepareApproval` and
`assembleApproval` (the person), `writeStub` (the agent), `countersign`,
`prepareCancellation` and `assembleCancellation` (the person),
`writeRefusal` and `writeTerms` (the service), `writeVouching` and
`writeWithdrawal` (an organisation), `writePass` (an agent, to a helper
agent), `writeSeal` (whoever keeps
the book; it needs Node.js), `writeWitness` and `openWitness` (a
witness; `openWitness` needs Node.js), `consistencyProof`, `writeBook` and `makeShow`, all from
`provared`. The library asks no time-stamp service itself: you send
the seal's fingerprint to the service you choose and put its answer
beside the seal. In a browser, `createPasskey`, `signSlipWithPasskey`,
`approveWithPasskey` and `cancelWithPasskey` from
`provared/passkey-browser`. For a slip with covered fields in a browser:
`prepareSlip` with `cover`, then `signChallengeWithPasskey` with what it
prepared, then `assembleSlip`; keep the disclosures it prepared.

## What a record does not prove

- It proves what was recorded, not what was left out. An agent that acts
  and writes no stub leaves no trace.
- A one-sided stub (one with no countersignature) proves what the agent's
  side said, not what the other side did.
- A refusal proves what the service's side said, not what the agent did.
- A rule of conduct in a slip is the person's signed instruction. No
  check can show that the agent kept it.
- An approval proves that the passkey approved that one action, not that
  the person read what they approved.
- It does not show that an action was wise, lawful or wanted.
- A badly written slip is faithfully recorded as a badly written slip.
- It does not prove who was holding the device when the passkey signed.
- A name in a record is a label. Only keys are checked. A vouching
  record shows which organisation stood behind a name, not how well it
  checked.
- An identifier of another system's, named in a stub, shows that the
  two records speak of one call, not that the call did what either
  says. A fingerprint of a request, an answer, the arguments or an error
  shows only that the content matches, not that it was the same call.

And about time:

- only an outside time-stamp you trust, from a service or a block you
  named, proves when entries existed. The times inside records are the signer's own word,
  so a limit within a period rests on the agent's word;
- after the last seal, the latest stubs under a slip or a pass, or a
  slip or a pass with all its stubs, can be removed unnoticed, which can hide a stub that shows
  the agent outside its slip;
- the last seal, with everything after it, can itself be removed. Only a
  copy of it, or of its top fingerprint and number of entries, held by
  someone else shows that: hand such a copy of a seal to the checker
  (`--seal`, or `seals`), such as the latest seal a witness holds;
- a witness statement is the witness's own word for when it saw the
  seal, and is not used as a time-stamp;
- time-stamp services sign with methods of today's kind, which are not
  quantum-safe.

## What it never does

It never holds money, never starts a payment and issues no token. It
reports nothing back from the machine it runs on. The checker makes no
network request. Only `provared-headers`, which you run yourself,
connects to anything: to the Bitcoin nodes you name, for block headers.

## Not built yet

A public place where seals are kept, which gathers the seals of many
books; a witness that runs as a service (the library holds the part that
decides and signs); covering fields other than a slip's
names and purpose; connectors for particular agent software (the
general one, `recordTools`, is built); a compact binary form; the
recorder service. The checking page cannot yet take a chain of block
headers: use the command-line checker.

## Licences

Copyright 2026 Pavel Izmaylov.

The code, the pages and the sample files: Apache License 2.0
(`LICENSE`). The format description and the other documents: Creative
Commons Attribution 4.0 International (`LICENSE-CC-BY-4.0.txt`).
