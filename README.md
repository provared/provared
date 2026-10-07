# Provared

Proof of what an AI agent was allowed to do, and what it then did.

*Evidence, not a verdict.* A record shows what was signed and by which
keys. People decide what it means.

## Status

**Version 0.1.0, a draft.** Published as it is, by one author in their
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
| **Seal** | The stubs chained together and gathered under one top fingerprint, signed by whoever keeps the book and time-stamped by an outside service | Built. A public place where seals are kept is not |
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
| `tools/` | Two small tools: one wrote the sample record, one writes the checking page as a single file |
| `test/` | The tests |

The npm package holds `src/`, `bin/`, `net/`, `spec/`, `docs/`,
`samples/` and the checking page. The tests, the demonstration and the tools are in the
repository only.

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
```

The checker for the command line is `provared-check`:

```
npx provared-check record.jsonl --issuer <the thumbprint of the passkey you trust>
```

The examples below import from the package by name. In a copy of the
repository, import from `./src/index.js`, `./src/check.js` and
`./src/passkey-browser.js` instead.

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
so that a copy can be compared with it. (Tried on 4 October 2026 in the
three browser builds this repository is tested with.) The file for
version 0.1.0 is attached to the release on GitHub. Its SHA-256
fingerprint is `ca4a15f820c9c715907952c2e7577717ffca92d87bcf633cc9a92f6dd5242746`.

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
copies of cancellations, and disclosures for covered fields. All of it is
read in the browser and sent nowhere.

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

answer.allowed;   // true only if the record so far is sound, fully checked, and the action is inside the slip
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
- **Browsers are only now adding ML-DSA, and have no SLH-DSA.** Where a
  browser lacks a method, the checking page says that those signatures
  were not checked, and does not show a pass. Node.js checks all of them.

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
| `entries` | One for each line: `index`, `kind` (`slip`, `stub`, `refusal`, `terms`, `seal`, `cancellation`, `acknowledgement`, `vouching`, `withdrawal`, `pass` or `unreadable`), `fingerprint`, `verified` (`all`, `some` or `none` of its signatures confirmed here), `problems`, `breaches`, `notes`, the signature states, and `content`. Where a time-stamp you trust on a later seal covers the entry: `existedBy`, the time by which it is shown to have existed. On a seal or a cancellation that passed its check: `stampedAt`, the time its own time-stamps give it |
| `held` | One for each cancellation handed over beside the book: whether it passed its check and was used, whether the book holds it (`inBook`), the time its time-stamp gives, and the acknowledgements handed over with it (`acknowledgements`: who acknowledged, and when by their own word) |
| `summary.problemFound` | A problem was found somewhere in the record |
| `summary.fullyChecked` | Every signature was checked on this device |
| `summary.intact` | No problem was found **and** every signature was checked. The only answer that is a pass |
| `summary.methodsMissing` | The signing methods this device lacks, if any, for example `ML-DSA-87` |
| `summary.withinSlips` | Every stub was compared with its slip, and none is outside it |
| `summary.firstBreach` | The first entry that shows the agent outside its slip, if any |
| `summary.counts` | Slips, stubs, countersigned stubs (the countersignature confirmed on this device), one-sided stubs (no countersignature; a stub that was not checked, because its slip failed, is neither), stubs the person approved, refusals, sets of terms, and the other kinds of entry |
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
sets of the organisations whose vouching you trust), `disclosures` (the
disclosures of covered fields that you were handed), `cancellations`
(the person's own copies of cancellations), `expectedRoot` and
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
the book; it needs Node.js), `writeBook` and `makeShow`, all from
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

And about time:

- only an outside time-stamp you trust, from a service or a block you
  named, proves when entries existed. The times inside records are the signer's own word,
  so a limit within a period rests on the agent's word;
- after the last seal, the latest stubs under a slip or a pass, or a
  slip or a pass with all its stubs, can be removed unnoticed, which can hide a stub that shows
  the agent outside its slip;
- the last seal, with everything after it, can itself be removed. Only a
  copy of it, or of its top fingerprint and number of entries, held by
  someone else shows that;
- time-stamp services sign with methods of today's kind, which are not
  quantum-safe.

## What it never does

It never holds money, never starts a payment and issues no token. It
reports nothing back from the machine it runs on. The checker makes no
network request. Only `provared-headers`, which you run yourself,
connects to anything: to the Bitcoin nodes you name, for block headers.

## Not built yet

A public place where seals are kept; covering fields other than a slip's
names and purpose; connectors for particular agent software (the
general one, `recordTools`, is built); a compact binary form; the
recorder service. The checking page cannot yet take a chain of block
headers: use the command-line checker.

## Licences

Copyright 2026 Pavel Izmaylov.

The code, the pages and the sample files: Apache License 2.0
(`LICENSE`). The format description and the other documents: Creative
Commons Attribution 4.0 International (`LICENSE-CC-BY-4.0.txt`).
