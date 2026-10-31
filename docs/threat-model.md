# Threat model — Provared, draft version 0

This document lists who might attack a Provared record, what each part
protects, and what it does not protect. It was written before the code,
and it is kept in step with the code: every refusal in section 8 names the
test that proves it.

It covers what is built in draft version 0: the Slip (the permission a
person signs), with its limits, conditions and stated rules; the Stub
(the receipt for one action); the countersignature; the person's approval
of one action; a service's refusal and its terms for agents; the chain of
stubs; the book; the tree of fingerprints; the Seal, with outside
time-stamps from a service and from a block of a public blockchain; the
one-page proof; cancelling a slip, and the agent's acknowledgement of a
cancellation; vouching for a name; covered fields; passing a slip on to a
helper agent; the check before acting; and the stub writer beside an
agent. It does not cover parts that are not built: the recorder service,
and a public place where seals are kept.

*Evidence, not a verdict.* A record shows what was signed and by which
keys. People decide what it means.

## 1. Who might attack

| Name | Who | What they can do | What they want |
|---|---|---|---|
| A1 | An insider at the organisation that runs the agent | Reads and edits the book; may hold the agent's keys | To change or remove history |
| A2 | A holder of a copy of the book (later: the recorder's operator) | Reads everything in the book; can drop, reorder, cut short or swap entries | To change history, or to learn what the records say |
| A3 | The agent itself, faulty or taken over | Signs anything with the agent's keys | To act outside its slip, or to hide that it did |
| A4 | The service the agent deals with | Signs with its own keys; may refuse to countersign | To deny what happened, or to claim what did not |
| A5 | A thief of the agent's keys | Signs as the agent | To act as the agent |
| A6 | A forger with no passkey | Writes any bytes they like | To make a slip the person never signed, or to widen one |
| A7 | A stranger who feeds records to a checker | Chooses every byte of the record | To crash the checker, to make it show a pass, or to run a script in the checking page |
| A8 | A future attacker with a large quantum computer | Forges signatures made with today's common methods (Ed25519, ECDSA, RSA) | To forge old records |
| A9 | A taken-over device or signing page | Shows the person one thing and asks the passkey to sign another | To get a slip signed that the person did not mean |

## 2. Limits that are true of every part

- **A9 wins.** If the person's device or the signing page is taken over,
  the person can be made to sign a slip they did not mean. A passkey
  proves that the device signed and that it confirmed someone by
  fingerprint, face or PIN. It does not prove who was holding the device,
  nor that they read what they signed.
- **The record shows what was recorded, not what was left out.** An agent
  that acts and writes no stub leaves no trace here. The gap may show
  against the other side's own records.
- **Times inside records are the signer's own word.** Only an outside
  time-stamp, from a service the person checking has named as trusted,
  proves that entries existed by a time. Entries after the last such
  time-stamp have no proven time. See sections 5 and 6a.
- **Names are labels.** The name of a person, an agent or a service in a
  record is text chosen by whoever wrote it. Only keys are checked. A
  checker must compare the issuer's key with one it already trusts, or
  name an organisation whose vouching record stands behind the name
  (section 6b).
- **The passkey signature is of today's kind.** No device offers a
  quantum-safe passkey. Against A8, a slip is protected once it sits
  under a seal, whose three signatures include two quantum-safe ones.
  The outside time-stamps themselves are of today's kind.
- **A signature that cannot be checked is not a pass.** Where a device
  has no built-in ML-DSA, or no SLH-DSA for a seal, the checker says
  so, and never reports the record as intact. An entry none of whose
  signatures the device could check is not treated as evidence: what it
  says is not shown, and it is not compared with its slip.
- **A record does not show that an action was wise, lawful or wanted.**
- **A badly written slip is faithfully recorded as a badly written slip.**

## 3. The Slip

**Protects.** That the permission was signed by the passkey whose public
key the slip names, on the website the slip names, with the person
confirmed by the device, and that nothing in it has changed since.

**From whom.** A6 (cannot make or widen a slip without the passkey), A3
and A5 (cannot change the agent's own permission), A2 (cannot alter a
slip in the book).

**How.** The passkey signs a challenge that is the SHA-256 fingerprint of
the slip's exact signed bytes. Those bytes begin with a label that says
"this is a Provared slip", so a signature made for a slip can never pass
as a signature on a stub, a countersignature or a sign-in. The checker
follows the checking steps of the Web Authentication standard.

**Does not protect.**

- Against A9, as above.
- Against a person who signs a slip that is wider than they meant.
- Against A8, until the slip sits under a seal (section 2, and section
  6a).
- Against a cancellation that never reaches the agent or the book: see
  section 6b. Slips should still be short-lived.
- Who the issuer is. The slip proves which key signed, not whose key it
  is.
- Against a page that has the passkey sign a record dressed as a sign-in,
  where the passkey's website name (its `rpId`) serves anything but the
  signing page. A passkey signs only a challenge, and the challenge for a
  slip, an approval or a cancellation is the fingerprint of the record,
  which the person cannot read on the device's prompt. Any page at an
  origin under the slip's `rpId` (the website's own operator, a script
  running on one of its pages, or the operator of any subdomain) can hand
  the device the fingerprint of a record it wrote as an ordinary sign-in
  challenge: the client data of a sign-in and of a record have the same
  shape, and the person sees a sign-in prompt. No device and no page need
  be broken into. The checker compares the origin and the rpId with what
  the slip itself says; and, where the reader names the address they
  expect the person to sign at (`issuerOrigins`, `--origin`, or the box
  on the checking page; format description, section 4.4), with that
  address too, refusing a slip signed anywhere else
  (`issuer-origin-not-expected`). What each measure does:
  - A passkey made for a name that serves only the signing page closes
    this for that passkey: the device lets it sign only for pages under
    that name, so no other page can have it sign anything. Provared's own
    signing page is served at sign.prova.red, a name that serves nothing
    else.
  - A reader who names the address is protected by naming alone, whatever
    name the passkey was made for: the client data the passkey signs must
    say that address, so a record signed at any other page under the
    `rpId` is refused.
  - A page that shows the record before it asks for the signature helps
    only against a page that asks openly for a record to be signed. It
    does nothing against a prompt dressed as a sign-in, which shows no
    record.
  - Naming an address protects only the reader who names it. It does not
    stop the passkey signing records at other pages, which readers who
    name no address, or name another one, accept.

  What stays open: a reader who names no address is protected only by
  which passkey they trust; whoever serves the named address (the host of
  the site, or whoever holds its domain name) can serve another page
  there, and a reader's naming does not tell that page from the real one;
  and a passkey made for a name that serves other pages stays exposed to
  every reader who does not name the address.

## 4. The Stub and the countersignature

**Protects.** That the agent's keys signed this exact statement of what
was done, under this exact slip, at this place in the chain. With a
countersignature: that the service's keys signed "it happened with me"
for this exact stub.

**From whom.** A2 and A6 (cannot make or change a stub without the
agent's keys). A4 cannot deny a countersigned stub, and cannot forge the
agent's half. A3 cannot forge the service's half. A8 must break both
Ed25519 and ML-DSA-87: each stub and each countersignature carries both,
and counts only if both check.

**How.** Each signature covers a label that names the kind of record, so
a stub cannot pass as a countersignature. The stub names the slip's
fingerprint, the fingerprint of the stub before it, the service dealt
with and its own unique number. The countersignature names the stub's
fingerprint.

**Does not protect.**

- A one-sided stub (no countersignature) proves what the agent's side
  said. It is weaker evidence of what the other side did, and it is
  always shown as one-sided.
- Against A5 before the theft is noticed: stubs signed with stolen keys
  check as the agent's. Short-lived slips limit the harm.
- Against A1 or A3 writing a false stub with the agent's own keys. A
  countersignature is what makes a stub more than one side's word.
- The documents themselves. A stub holds fingerprints of documents, not
  the documents. Whoever keeps the documents must keep them.

**A stub bound to the other system's own record of the call.** Where the
other side will not countersign, a stub may name, under a reserved name
(format description, section 27), the fingerprint of the identifier the
platform gave the call (`provared.event-id`), of one the agent's side
chose and sent (`provared.trace-id`, `provared.request-id`), of part
of the request and the answer (`provared.http-request`: the method, the
address and the body; `provared.http-response`: the status and the
body; no header is covered), or of the error the agent was given
(`provared.error`).

- *What it shows.* Someone who holds the platform's own log can work the
  fingerprint out again and match the two records, without either
  side's help. For an identifier, the two speak of one call. An agent's
  side that later claims another identifier for the call, or a platform
  that later shows another, is caught by the mismatch.
- *Only an identifier picks out one call.* A request, an answer, the
  arguments or an error shows only that the content matches: identical
  requests, and identical answers (many a `200` with the body `{}`),
  share one fingerprint, so a match with one of them does not show that
  it was the same call. Only `provared.trace-id`, `provared.request-id`
  and `provared.event-id` are meant to pick out one call, and only they
  may be named more than once in a stub.
- *The body's bytes* are what RFC 9530 digests: the content after any
  content coding (such as gzip) and before any transfer coding. A
  platform that logs the decoded body of a message sent compressed will
  not match.
- *A trace-id's form is not checked.* The W3C standard writes it as 32
  lower-case hexadecimal characters, but any text is fingerprinted as
  given.
- *What it does not show.* That the call did what either record says:
  the platform's identifier is the platform's word, and the stub is
  still the agent's side's word. That the platform keeps the identifier
  at all: which one a platform writes into its log differs from one
  platform to another, and is for whoever relies on it to find out. That
  the fingerprint was made from the text the name says: a checker cannot
  tell; only someone who holds that text can. An identifier that is
  short or easy to guess gives no privacy through its fingerprint.
- *Against A1 and A3* (the agent's own side). The binding is written by
  the agent's side, so a dishonest one can leave it out, or name a
  wrong identifier; only the match with the platform's log, made later,
  catches the second. It adds nothing against an agent that writes no
  stub.
- *Two spellings of one address.* An HTTP address is taken exactly as it
  was sent and never rewritten, so that two programs fingerprint the
  same request the same way. A program that records a rewritten address
  (`%2f` for `%2F`, a host in capitals) makes a fingerprint that will not
  match: whoever writes the stub must give the address as sent.
- *A reserved name not on the list* is refused (`bad-field`), so that a
  name that may be given a meaning later cannot be used now with another;
  so is one of the four once-only names named twice (two `provared.arguments`
  fingerprints in one stub would leave unclear which was the call's). A
  book written before this rule that holds such a name no longer passes
  its check.

## 4a. Limits, conditions, approvals and the other side's records

**Protects.** That what the person allowed is stated exactly, and that a
checker compares every stub with it in one fixed way: totals, the size of
each action, counts, periods, a countersignature or the person's own
approval where the slip asks for one, and the kinds of action the slip
forbids. That an approval was signed by the passkey the slip names, for
exactly one action. That a refusal or a set of terms was signed by the
keys it gives.

**From whom.** A3 cannot make an approval: only the person's passkey can.
An approval for one action cannot be moved to another action, another
amount, another service, another document or another slip. In a whole
book it cannot be used twice; single pages of a Show cannot show a second
use, and say so. A3 cannot forge a countersignature, so where the slip asks
for one, an action the other side did not confirm shows as outside the
slip. A4 cannot be made to seem to have refused or to have stated terms:
both need its keys.

**How.** Each kind of record has its own label, so an approval cannot
pass as a slip, nor a refusal as a countersignature. An approval names
the slip and repeats the action, the amount, the service and the
documents; the stub names the approval's fingerprint; a checker compares
all of them. A period is counted backwards from each stub in whole
seconds, so there are no calendar days or time zones for two checkers to
disagree about. Totals are added as whole numbers of any size.

**Does not protect.**

- **A rule of conduct is not checked.** "Never claim to be a human being"
  is the person's signed instruction. Nothing in a record can show that
  the agent kept it. Only a kind of action ("never destroys") is compared
  with stubs, and only for actions named from the shared list.
- **An agent that names its action falsely.** A stub says what the agent
  says it did. An agent that deletes data and writes "read" is caught
  only by the other side's records.
- **Periods rest on the times in stubs**, which are the agent's own word
  unless an outside time-stamp you trust covers them. An agent can write a false time to
  stay inside a period. A total over the whole life of the slip does not
  have this weakness.
- **An approval shows that the passkey approved.** It does not show that
  the person read what they approved, and against A9 it shows nothing.
  An approval can be signed after the action: only an outside
  time-stamp you trust, on a seal after the action, bounds it.
- **A refusal is one side's word**, as a one-sided stub is. A4 can write
  a refusal for a request that was never made. A checker shows it as the
  service's statement and never counts it against the agent.
- **A refusal can be left out.** Whoever keeps the book can leave a
  refusal out of it. It is strongest in the service's own book.
- **Terms do not show consent to one action.** They show what the service
  said it accepts. Only a countersignature shows that the service
  confirmed this action.
- **A stub or a refusal under a slip that this device could not
  confirm** is not shown and not compared, whatever its own signatures
  say: the keys it was checked against came from that slip.
- **The check before acting is not evidence.** It helps whoever runs the
  agent to stop an action. A taken-over agent does not ask. Nothing in a
  record shows whether the check was made.
- **Two stub writers on copies of one book.** One stub writer takes its
  actions one after the other, each against the book as the one before
  left it. Two writers on two copies know nothing of each other: both
  may be allowed an action that together passes a limit, and their stubs
  will not fit one chain. Keeping one writer to a chain is the business
  of whoever runs the agent.
- **An action that never ends.** The stub writer waits for an action it
  is taking, because it cannot know what happened. The other side is
  given a set time to countersign (30 seconds unless told otherwise),
  after which the stub is written one-sided. In Node.js a call to the
  writer made by its own action, while that action runs, is refused at
  once. A browser cannot tell, and neither can Node.js where the action
  waits for some other part of the program that calls the writer: such a
  call waits for ever.
- **The stub writer's clock.** `act` takes an action at the time its
  clock gives, and refuses a date handed to it that is more than 300
  seconds from that clock either way; nothing is written that is dated
  more than 300 seconds ahead of it. The clock is the device's own, or
  the one the caller gives. A wrong clock gives wrong dates, and `record`
  writes any earlier date the caller states: until an outside time-stamp
  covers a stub, its date is the agent's own word.
- **What the stub writer is handed** (the request, an approval, what the
  other side hands back) is copied when it is handed over, and the copy
  is what is checked and written. `record` hands a stub to the other
  side only once it has passed the check of the whole book, so the other
  side is never left holding a stub that the writer then refused.
- **An approval dated ahead of the clock.** The stub writer writes no
  approval dated more than 300 seconds ahead of its clock, as it writes
  no stub and no countersignature dated so.
- **Cancellations the stub writer keeps.** A writer serves one slip. Of
  the cancellations it cannot add to its book, it keeps every one of its
  own slip; any one is enough to stop it. A cancellation of another slip
  that is handed to `add` is nothing to this writer and is not kept.
  Copies of other slips' cancellations, or of cancellations the book
  already holds, that were given when the writer was opened give way to
  one that matters, so no number of them can crowd it out.
- **The agent's tools behind the stub writer** (`recordTools`). Each
  call asks first, runs the tool only if the slip allows the action, and
  writes the stub; a call that is not allowed throws, and the tool is
  not run. The arguments are copied when the call is made: the copy is
  what the fingerprint in the stub is made from, and what the tool is
  run with. Each function a tool is described by is handed a copy of
  its own and is called without the description, and what a tool is,
  is fixed when it is put behind the writer, so nothing done
  afterwards, by the caller or by the tool's own functions, changes
  what is recorded or run. A
  list with a gap in it, or with a named member, is not JSON: such
  arguments have no fingerprint, and the tool is not run with them. The
  person is asked to approve only where their approval is the one thing
  missing. It protects only the tools that are put behind it: an agent
  that can reach a tool some other way leaves no stub. The fingerprint
  of the arguments fixes what was asked for without holding it; where
  the arguments are few and easy to guess, the fingerprint can be
  guessed.
- **Documents named after the action** (`detailsAfter` in the stub
  writer's `act`). The stub is first written and checked with the whole
  book before the action, as always; after the action, it is signed
  again with up to four further documents, still within the same call,
  so that no other call comes between, and keeps the time the action
  began. The room for them is kept beforehand: with today's limits the
  largest stub, with 32 documents of the longest names, and a
  countersignature still fits a line, and the writer checks this again
  for each such call. If what `detailsAfter` gives cannot go in (it
  fails, gives no answer within the time the other side is given to
  countersign, gives more than four, or gives a document that would be
  refused), the stub made before the action is written without them,
  and the answer says why: an action that was taken always gets its
  stub. What it gives is copied when it is read, so a later change to
  it changes nothing. A call to the writer from inside it is refused at
  once. It cannot be used with an approval, because an approval covers
  exactly the documents the person saw. The stub is signed twice for
  such an action, and only one of the two is written: a signer kept
  elsewhere is asked once more.
- **The check before acting refuses more in one case.** An action that
  would add to a period which a stub dated after it already overfills is
  refused, though a checker would report nothing new for it.
- **A cancellation the stub writer cannot add to its book as it was
  handed over** is not lost, if the person signed it. Where what stands
  beside it is at fault (a faulty time-stamp, a member that cannot be
  written as a line of a book, such as a list with a gap in it), the
  writer adds the cancellation with the time-stamps that pass their
  check, or by itself, and the book holds it. Where it cannot be added even so (a
  date ahead of the clock), the writer keeps it as the person's own copy
  and allows nothing more under the slip; it writes it into the book, at
  its next call, once its clock has reached that date. In both cases the
  call fails, and the error says what was done. Every such cancellation
  of the writer's slip is kept, not only the first; one that was kept
  takes the time-stamps it is handed over with later, merged with those
  it holds: each is judged by itself, those the writer counts come
  first, four at most. So a time-stamp from a service the writer was not
  told to trust never keeps out one it counts. A cancellation that was given when the writer was opened, and
  that the book does not hold, is written into the book in the same
  way, takes a time-stamp in the same way, and stops the writer from the
  start. One that the book already holds without a time-stamp stays as
  it is: a line of a book is not changed. The writer is stopped before
  it reads its clock, so a clock that fails while a cancellation is
  handed over does not lose it, nor the sound time-stamps or the
  acknowledgements handed over with it; a clock that gives anything but
  a time counts as a clock that failed. A time-stamp handed over for a cancellation that the
  writer holds is taken before anything is written into the book, so it
  is not lost where the cancellation's date has come in the meantime.
- **A cancellation the stub writer keeps lives only in that writer**
  until it is written into the book. A writer opened again from the book
  alone knows nothing of it, and takes actions again. This is a stated
  limit. The writer hands back what it holds (`cancellations()`), each
  with the acknowledgement it signed: whoever runs the agent keeps that
  with the book, and hands it in again when a writer is opened. The
  writer opened again then hands back the same acknowledgement, not a
  second one; an acknowledgement that still waits to follow its
  cancellation into the book is handed back too, and the writer opened
  again writes it. An acknowledgement handed over with a cancellation is
  taken as the agent's own only if it checks by itself: one that does
  not check is never handed back or kept. Only the first of the agent's
  own is taken, so the writer never puts a second one with a copy. A
  copy given when a writer is opened is made plain data before it is
  checked, so what is handed back is what was checked; one given already
  holding two of the agent's own is handed back with both, and the
  first is the one the writer goes on handing back. A copy that cannot
  be made plain data is refused when the writer is opened. A copy holds four
  acknowledgements at most; the writer's own is always among them, and
  where the copy already holds four, the last of the others gives way. What is not a cancellation record at all (a record with a
  member added to it, for example) is refused and stops nothing. What
  is handed to `add` is read once, member by member, so a member whose
  value changes from one reading to the next cannot make the writer
  read two different entries. A check may be handed 16 cancellations at
  most. The writer holds, in this order: its own slip's cancellations
  that the book does not hold; acknowledgements that wait, in the order
  in which they began to wait, so that the newest gives way first; then
  the other copies given at opening, which give way. Where it already holds
  16 of the first two kinds, a further cancellation of its slip that
  cannot be written into the book still stops that writer, and is not
  kept or handed back; the error says so, also where the clock fails.
  An acknowledgement that begins to wait while the writer holds 16 of
  its own slip's cancellations is not handed back, and a writer opened
  again signs a second one; both are genuine. A copy given at opening
  that carries a waiting acknowledgement counts with the waiting ones. A
  copy that gives way is no longer handed to the writer's own check: one
  that carried a time-stamp the book's line lacks then no longer marks
  the stubs it marked, in the writer's answer. Whoever handed it over
  keeps it, and a check of the book with it still marks them. What is
  handed to `add` wrapped in a Proxy is read once, as plain data, like
  anything else: each member and each place is read once and copied as
  it is read, and a gap or a faulty item in a list of time-stamps
  leaves a sound one beside it as it is. The copy is measured by the
  length its text would have: each of the three members of a
  cancellation may be as long as a line, and all the other members
  together as long as one more. Past that, the entry is not written as
  it was handed over and the rest of it is not read, but the
  cancellation in it still stops the writer. So what is handed over
  beside a cancellation cannot make the writer use memory or time out
  of proportion. A list whose length is not a whole number is not plain
  data, and anything but an object (a list, for one) is not written out
  at all. Acknowledgements of other
  agents that stay with a kept copy are not written into the book with
  it: once the copy is written, the writer no longer hands them back.
  Whoever handed them over keeps them.
- **Every line is tried before it joins the book.** The stub writer
  reads each new line on a reader split off the book's own, which takes
  the book's place only if the line is written. So an error part of the
  way through a call (a clock that fails, an action that fails, an entry
  that does not fit) leaves the writer's view of its book exact: a test
  compares it with a whole check. An entry that does not fit costs one
  line's check, not a reading of the whole book.
- **What the stub writer is told to trust** is read once, when it is
  opened, as a whole check reads it, and copied where it is plain data;
  the passkeys it trusts (`issuerKeys`) as well. The same holds for a
  checker that is carried on. An option that is an object of a class,
  or a function, is kept as it was handed over: a check refuses or
  ignores it as a whole check does, and it is not fixed. So is a list
  whose length is not a whole number. So is a value that cannot even be
  looked into (a revoked Proxy); one of those given as an option is a
  problem with the whole check (`check-failed`), and the stub writer
  refuses it when it is opened. A value more than 16 levels down in the
  options cannot be read: no option nests so deep, and nothing past
  that depth is kept as it was handed over. A value met twice is copied
  once, so options that share values, or that hold themselves, cost no
  more to copy than they hold values. The list of signing methods to
  treat as not built in is read with every line, so one that cannot be
  read is a problem with the whole check from its start. A whole check reads its options through the same fixed copy,
  so the two cannot read them differently: a list is read as the plain
  list of what it holds, whatever kind of list it is. An option, a
  member or a place in a list that cannot be read fails, with the same
  error, wherever a check reads it, and nowhere else; the stub writer
  refuses an option that cannot be read at all when it is opened.
  A gap in a list stays a gap, and a gap in the list of blocks or of a
  copy's time-stamps is refused. Lists are read place by place, never
  through a list's own way of walking through itself, and a very long
  list with few items in it costs little. The list of blocks holds at
  most 100,000. A copy of a cancellation given at opening is copied as
  plain data, whatever kind of object it is, so the writer never
  changes the caller's own object.
- **A finding about a period may be given for another chain's stub.** A
  period goes by the times the stubs state. A helper's stub written
  later and dated earlier can put an earlier, honest stub of the agent
  over the limit, and that stub is then the one marked. The record still
  shows the limit was passed, and by which stubs together.
- **The shared list is a first draft.** A name on it means what the list
  says only if those who use it agree.

## 5. The chain and the book

**Protects.** That stubs under one slip are in an unbroken order: each
names the one before, and each is numbered. A stub cannot be changed,
removed from the middle or moved without the break showing.

**From whom.** A2 (cannot edit, reorder or remove from the middle
unnoticed).

**Does not protect, by itself.**

- **A block that is not part of the chain.** A block time-stamp comes
  with the header of its block, and the checker cannot tell a real block
  from a made-up one. It counts only for a block whose fingerprint the
  person checking named, having compared it with sources they trust.
  Naming a block that someone else supplied, unchecked, is trusting them.
- **A block's time is loose.** It is right only to within about two
  hours. The looseness is always taken against whoever is being checked:
  for a seal a block time-stamp counts as "existed by the stated time and
  two hours"; for a cancellation it counts from two hours before the
  stated time, so that no stub made after the person cancelled escapes,
  but not from before the date the person signed in the cancellation
  itself.
  A proof is complete only hours after it is asked for. A block that
  states a time more than two hours behind the true time, which the
  chain's rules allow in rare cases, would make an honest seal read as
  dated after its time-stamp.
- **Checked once against real proofs, not in the tests.** The tests use
  made-up blocks. On 5 October 2026 two complete proofs that others had
  published, one made by hand from a transaction and one made by public
  calendar services, were checked with this reader against the headers
  of the real blocks they name, taken from the whole chain of headers
  and checked from its first block: each led to its blocks (five in
  all), and each was refused with another block's header or with its
  file changed by one bit. Older published sample proofs of the format
  were read with this reader too: the incomplete ones are read to their
  end; the complete ones among them are old, and use a step this reader
  does not
  accept.
- **Removing the latest stubs.** In a book with no seal, or after its
  last seal, whoever holds the book can remove the latest stubs under any
  slip or any pass, or a slip or a pass together with all its stubs, and
  what is left still checks. This can hide the very stub that shows the agent outside its
  slip. A seal closes this for everything before it (section 6a). After
  the last seal, only a copy of a top fingerprint, with its number of
  entries, or a copy of a later seal, held by someone else would show it
  (section 6a, "Seals held elsewhere").
- **Writing a different history with the agent's keys.** A1, A3 or A5
  can sign a second, different chain under the same slip. Countersigned
  stubs resist this, because the service's keys are needed. One-sided
  stubs do not.
- **When.** Without an outside time-stamp from a service the checker
  trusts, a whole book could have been written yesterday. Section 6a.

## 6. The tree and the one-page proof

**Protects.** That one entry is part of a book with a given top
fingerprint, without showing the rest of the book. Built exactly as RFC
6962 (Certificate Transparency), section 2.1, sets out.

**From whom.** A2 and A6 (cannot make a proof for an entry that is not in
the book; cannot change an entry and keep the proof).

**Does not protect.**

- The top fingerprint itself. A proof is worth as much as the checker's
  reason to trust the top fingerprint: a seal with a time-stamp that
  comes with the Show (section 6a), or their own earlier copy.
- The number of entries. The top fingerprint does not by itself fix how
  many entries the book holds. Keep the number with every copy of a top
  fingerprint.
- Limits. One page cannot show whether a limit was kept: that needs every
  stub under the slip.

## 6a. The Seal and the outside time-stamp

**Protects.** That the entries before a seal are exactly the entries the
recorder sealed: none changed, added or removed. With a time-stamp from a
service the checker trusts: that those entries existed by the time the
service states, whatever the recorder says later.

**From whom.** A1 and A2 can no longer remove the latest stubs under a
slip, or a slip with its stubs, from before a seal: the seal after them
no longer fits. They cannot back-date an entry into a sealed part, nor
date an entry, a countersignature or an approval later than the
time-stamp that covers it, in a book or in a Show under a seal (to
within 5 minutes for a time-stamp from a service, and to within 2 hours
and 5 minutes for a block time-stamp). A6 cannot make a
seal: it needs the recorder's three keys. A8 must break Ed25519, ML-DSA-87
and SLH-DSA together to forge a seal; the third rests only on fingerprint
functions. One exception, stated: the check before acting on a device
without SLH-DSA (the Python version, every browser) goes on after a seal
whose first two signatures check there, so on that device a seal rests on
Ed25519 and ML-DSA-87 alone, and a third signature of the right length
that would not check is not seen. A device with SLH-DSA, such as the
command-line checker, sees it. Nobody can move a time-stamp to another seal: it is made over
the seal's fingerprint.

A block time-stamp is a second witness of the time, which rests on no
signature at all: only on SHA-256, and on the block being part of a
public blockchain that the person checking named. A8 gains nothing
against it by breaking every signing method of today.

**How.** The seal names the number of entries before it and their top
fingerprint, and the seal before it. A checker that holds the book works
both out again. The time-stamp follows RFC 3161 and is checked offline:
its statement, the signed attributes that name the statement, the
signature, and the time against the certificate's dates. The checker
trusts a service only by the fingerprint of its certificate, which the
person checking gives.

**Does not protect.**

- **The end of the book.** The last seal, with everything after it, can
  be removed, and what is left still checks. Only a copy of that seal, or
  of its top fingerprint and number of entries, held by someone else
  shows it. A seal held elsewhere can be handed to the checker beside the
  book (below), and a witness that signs for each seal (section 6f)
  holds the latest one it signed for. A public place where seals are
  kept, which gathers the seals of many books, is not built.
- **Seals held elsewhere.** The person, an auditor, or any copy kept out
  of the recorder's reach can hand the checker, beside the book, up to 64
  seal entries it holds (option `seals`, `--seal` on the command line, files on
  the checking page). A seal at entry n stands at entry n of the
  book, so the checker reports a book that ends before that place
  (`book-cut-short`) and a book that holds another line there
  (`seal-not-in-book`). This closes the end of a book cut off after a seal
  someone else holds, back to any place before that seal, and a second
  history shown to someone who holds a seal of the first. What it does
  not close: a book cut back after the latest seal anyone holds; a book,
  or a part of one, never shown to anyone who keeps a seal; and a holder
  who keeps no seal at all. A seal handed over counts only where the
  person named its recorder (`sealKeys`), and only where the device checked
  its Ed25519 and ML-DSA-87 signatures; on a device without SLH-DSA (the
  Python version, and browsers that have ML-DSA, such as Edge and Brave
  155 when tested) it counts on those two, and says so; on a device
  without ML-DSA it is not used. It is compared with the book by its
  content: the same content with other signatures is the same seal, and
  is said, not reported against the book. It can only show a problem
  with the book, never excuse one, so this widens nothing. Nothing in a
  seal names its book, so a seal of another book by the same recorder
  (one it kept before, when it started a new book) is reported against
  the book being checked: hand over only that book's seals. A seal handed over that does not pass its own check is a
  problem with the whole check, never set aside. Its time-stamps are
  checked and shown, but are not used for the entries of the book: where
  they differ from those beside the same seal in the book, the checker
  says so. A Show does not use a seal held elsewhere, and says so: single
  pages cannot show what the book holds at the place the seal states.
- **Entries after the last time-stamp.** They are not time-stamped.
- **A recorder who seals a false book.** A1 holding the agent's keys and
  the recorder's keys can write another history and seal it. A time-stamp
  then proves only when that was done: a book sealed long after the times
  its stubs claim deserves doubt. Countersignatures and the other side's
  own book are what tie a history to someone else.
- **A time-stamp service that lies, or whose key is stolen.** Its time is
  then wrong. Time-stamps from several services, which a seal may carry,
  limit the harm.
- **A8 against the time-stamp.** Time-stamp services sign with methods of
  today's kind. A forger with a large quantum computer could make a
  time-stamp. The seal's own signatures would still have to be forged.
- **A certificate is not judged.** The checker does not follow a chain of
  certificates, does not ask whether a certificate was withdrawn, and
  does not read what a certificate says its key is for. It checks that
  the stated time lies within the certificate's dates, and leaves the
  rest to the person who chose to trust it.
- **A browser.** Tried on the author's computer on 13 October 2026:
  Chrome 155, Edge 155 and Brave 155 offer ML-DSA to a page; none of the
  three offers SLH-DSA. So a checker in a browser
  reports a seal as not fully checked, never as a pass, and counts no
  time-stamp beside it. In a browser without ML-DSA, every record signed
  with ML-DSA is reported as not fully checked too.
- **A few bytes of a time-stamp's wrapper** are not covered by the
  service's signature (the list of fingerprint methods, and the lines
  that name the certificate by its issuer). Changing them changes nothing
  the time-stamp says: which certificate signed is taken from the signed
  part, and every part must still be well formed.
- **A time-stamp from a service the checker did not name** is compared
  with nothing. Anyone can make one, so it must not be able to make a
  sound record fail, any more than pass.
- **A seal shown as a single page of a Show** cannot be compared with the
  entries before it. The page says so, and its time-stamp is credited to
  no other page. Its dates are still held against the pages that come
  before it in the book, and it is held to the dates and the chain of
  the other seals of the Show. Where they do not fit, the finding is
  given for the seal and never for the page before it: the seal may not
  belong to the book at that place, and single pages cannot show which
  of the two is at fault. A Show made under a seal is the form that
  proves a time.
- **The time-stamps beside the last seal.** Nothing fixes the
  time-stamps beside the last seal of a book, or beside the seal that
  comes with a Show: whoever hands the record over can put a later
  time-stamp in the place of an earlier one. A later time-stamp shows
  less, never more, and the entries are still held against the seal's
  own date, so the gain is at most 300 seconds.
- **A Show under a later seal.** Whoever hands over a Show chooses its
  pages and its seal. Where a page is dated after the time-stamp of a
  seal that comes after it in the book, that is reported only if the
  seal is among the pages, and the seal is the page reported. With that
  seal left out, the Show passes where the whole book fails. Only the
  whole book shows it in every case. The same holds for a unique number
  used twice: the seal that comes with a Show is held to the pages, and
  a record left out of the pages cannot be compared.
- **A seal dated before a time-stamp that it covers.** A seal covers
  the lines of the seals before it, time-stamps included. One dated more
  than 300 seconds before the latest time a service gave any of them is
  reported: it cannot have been made by then. In a Show this is seen
  only for seals among the pages.
- **What a Show cannot show about an earlier seal.** The two rules that
  rest on a seal earlier in the book (the one above and the one below)
  are applied in a Show only for seals among its pages. With such a seal
  left out, a Show may pass where the whole book fails; it may show its
  pages as having existed earlier than the whole book shows; and, with a
  block that states a time far behind the true time, it may fail where
  the whole book passes. Only the whole book shows it in every case.
- **A block that states a time before an earlier seal's time-stamp.** A
  later seal covers the earlier seal's line, time-stamp included, so it
  cannot have existed before the time a service gave the earlier seal.
  A block time-stamp beside the later seal that states an earlier time,
  even with its two hours, is set aside, and the checker says so.
  Without this, such a block (the chain's rules allow one in rare cases)
  would show entries to have existed earlier than they did, and a stub
  made after a cancellation would be excused.
- **Two times of an entry are kept apart.** The time by which a later
  seal shows that an entry existed (`existedBy`) is one thing. The time
  that a seal's or a cancellation's own time-stamps give it
  (`stampedAt`) is another: a cancellation does not count from the time
  of a seal after it, and is never shown as if it did. A seal or a
  cancellation that did not pass its check shows no time of its own.
- **A time-stamp on a cancellation this device could not confirm.**
  Where the device lacks the passkey's signing method, no date is
  reported against the cancellation's time-stamp, as for a seal. The
  record is then not a pass in any case.
- **Two time-stamps that do not agree.** Every counted time-stamp of a
  seal is taken, and the earliest shows when its entries existed. One
  case is set apart: beside a time-stamp from a service, a block
  time-stamp that states a time more than two hours before the seal's
  own date is set aside, and does not make the seal fail. A block may
  state a time far behind the true time. The checker says that the two
  do not agree. The other reading is that the seal existed before the
  date it gives. The same holds for a cancellation: it is never taken to
  have been made before the date the person signed in it, so nobody can
  move a cancellation back in time by having it put into a block before
  that date.
- **Cost.** A time-stamp is read only if the seal's own signatures did
  not fail, only the one certificate it names is tried, and an RSA key
  must have a small public number, so that a small file cannot cost much
  work.
- **A key under which anyone can sign.** An RSA key with the public
  number 1 lets anyone make a signature that checks. Such a key, and one
  with an even public number, is refused, even in a certificate the
  person named as trusted. So is an Ed25519 key of small order, there and
  in every record (a passkey, an agent, a service, a recorder, an
  organisation): libraries differ in whether they accept signatures under
  such a key, so the checker refuses the key itself. For the same reason
  it refuses an Ed25519 signature whose point R is of small order, under
  any key: the key's own holder could make one for any message, which one
  library accepts and another refuses. It also refuses, itself, an
  Ed25519 signature whose number S is not below the order L, which RFC
  8032 requires and some libraries do not check, and an ES256 passkey key
  that is not a point on its curve (`bad-key`), which can check nothing
  and which libraries report in different ways. A time-stamp signed with
  Ed25519 must name SHA-512 as its fingerprint method, with no
  parameters, as RFC 8419 requires, and may name the certificate that
  signed it only once in each form (RFC 5035, sections 3 and 5): two
  checkers could otherwise pick different certificates. A time-stamp is
  read as strict DER throughout, every set it holds in the order DER
  requires, so that two checkers cannot read one time-stamp in two ways. The key in a
  certificate must be written exactly as its standard sets out, so that
  two checkers cannot disagree about whether it can be read.

**Knowing that a block is part of the chain.** The person checking can
name the blocks they trust, or hand the checker a chain of block headers
(`--headers`), which `provared-headers` fetches from Bitcoin nodes the
person names.

- **Protects.** Every header is checked on the device, from the chain's
  first block, by the rules every node applies to headers: the link to
  the block before, the work, the difficulty rule, the rules on times,
  and the lowest version a block may have after the upgrades of 2013 and
  2015. The chain must hold ten blocks known to be part of it, at their
  places, and must reach the last of them (block 969,696). A chain that
  branches off before that block cannot hold them. After it, no target
  may be more than four times easier than that block's, a rule of this
  checker's own: the real chain's difficulty has never eased by more
  than one and a half times at one change. So every block of a branch made after the last
  known block carries at least a quarter of the work a real block
  carried in October 2026, and a block counts only with at least six
  blocks after it. When headers are fetched, a second node, on a network
  apart from every node that gave headers, must hand back the latest six
  blocks itself, checked on a copy of the chain; a branch near the end is
  taken on only if it carries more work; and a chain file is never
  written shorter than it was, or half written. So a node can refuse,
  fall silent or hold back the newest blocks, but cannot have a false
  header kept.
- **Does not protect.**
  - The ten known blocks are written into the library. They were read on
    5 October 2026 from the whole chain, checked by these rules from the
    first block, which a second node on another network agreed with.
    Whoever trusts the library trusts them. A later release may add newer
    ones.
  - Someone with mining equipment could make a branch of their own after
    the last known block, with a block that holds what they choose. The
    rules on difficulty let them push the dates of a branch forward to
    ease its targets at each change; the rule above stops that at four
    times. A false block with six blocks after it then costs at least the
    work of about two real blocks of October 2026. A chain file that
    someone else hands over could hold such a branch: a chain fetched
    from nodes the person chooses, with a second node agreeing, could
    not, unless every node named was in on it. Fetch your own, or name
    the blocks you trust.
  - If every node named holds back the newest blocks, the chain ends
    early, and a recent block is not found. Nothing false is counted.
  - The nodes named see the device's address, and that headers were
    asked for. A node named by its name is looked up by the device's own
    name service. The connection is not encrypted; nothing secret is
    sent.
  - A node is given fifteen minutes at most, and must answer what is
    asked within a minute; its own messages do not keep a session open.
  - A device whose clock is far behind refuses the newest headers, whose
    times are then more than two hours ahead of it.
  - The checking page cannot yet take a chain of headers.

## 6b. Cancelling, vouching and withdrawing

**Protects.** That a slip was ended by the person who signed it, and
from when. That a name in a record had an organisation standing behind
it, which the person checking chose to trust. That such a statement was
ended only by the organisation that made it.

**From whom.** A3 and A6 cannot cancel a slip, or undo a cancellation:
only the passkey that signed the slip can cancel it. A3 cannot escape a
time-stamped cancellation by writing an earlier time into a stub: a stub
counts as earlier only if an outside time-stamp shows it. Where the
person cancelled more than once, A6 gains nothing by the order the
cancellations stand in: every one counts, and the earliest time-stamped
time is used. A6 cannot make a vouching record count: it must be signed
by an organisation the checker named. Nobody but that organisation can
withdraw it. A vouching record that has run out does not stand behind a
slip whose time runs past it. Where the person kept their own copy of a
cancellation, with its time-stamp, A6 can neither make it disappear from
a check nor move it later in time: the checker takes the copy beside the
book.

**Does not protect.**

- **A cancellation the recorder leaves out, where the person kept no
  copy.** Whoever keeps the book can keep a cancellation out of it. The
  person should keep their own copy, with its time-stamp, and hand it to
  the checker beside the book: it then counts as if it were there. A copy
  with no time-stamp from a service the reader trusts cannot be placed in
  time: it stops the agent's software that is handed it, and marks no
  stub.
- **A cancellation with no time-stamp.** Only its place in the book says
  when it took effect, and the recorder chose that place.
- **A cancellation the person keeps back.** A cancellation shows when
  the person signed it and had it time-stamped. It does not show that
  the agent, or whoever keeps the book, was told. A person can sign and
  time-stamp a cancellation, tell nobody, and hand it over later: every
  stub made in between is then reported as after the cancellation,
  though the check before acting allowed each. Where the book does not
  hold a cancellation that is handed over beside it, the checker says
  that the keeper left it out or was never given it. It cannot show
  which, unless the person was given an acknowledgement (below).
- **An acknowledgement is the agent's side's own word.** It shows that
  the agent's software stated, with the agent's keys, that it was handed
  the cancellation at a time. Handed over with the person's copy, it
  tells the two cases apart: a stub of that agent dated after it was, by
  the agent's own dates, made after the agent's side was told, and is
  reported in words of its own. So is a pass that the agent handed on
  after it was told, every pass handed on from it, and every stub under
  them: an agent that was told cannot go on through a helper. It does
  not show when the person cancelled, nor that a helper agent which held
  its pass before then was told. An agent that writes earlier dates into
  its stubs escapes this rule, and is caught only by the time-stamp
  rule, which is applied first and whose findings are kept. Nothing
  obliges an agent's side to acknowledge; this library's stub writer
  does, for every cancellation of its slip that is handed to `add`, and
  never dates an acknowledgement before its own last stub or a pass it
  handed on. An acknowledgement that is dated ahead of the clock for
  that reason follows its cancellation into the book once the clock has
  reached its date. A writer that
  was opened with keys that are not the agent's hands back no
  acknowledgement: one it signed would not check.
- **An acknowledgement that does not check**, handed over with the
  person's copy, is a problem with the whole check and is never set
  aside silently. The cancellation itself is still used: the agent's
  side cannot spoil the person's copy by handing them an acknowledgement
  that does not check. An acknowledgement in a book does not pass once
  the cancellation it names has failed its check, even where that shows
  only later in the book.
- **A time-stamp on a cancellation that is swapped for a later one.**
  The time-stamps stand beside the cancellation, not inside what the
  passkey signed. Whoever keeps the book can put a later time-stamp from
  the same service in the place of the person's own; a stub sealed in
  between then counts as earlier. No check of the book alone can show the
  swap. The checker points out a time-stamp dated more than 300 seconds
  after the cancellation's own date. The person's own copy, with its
  time-stamp, handed to the checker beside the book, overrules it. A
  later time-stamp put beside an earlier one, in the book or in the
  person's copy, changes nothing: the earliest that any counted
  time-stamp gives is the time used.
- **A slip written late, with early dates.** A slip's times are its
  issuer's own word. A slip written after a vouching record ran out, with
  times inside the old window, is caught only where an outside
  time-stamp shows when it was written.
- **Single pages.** A Show cannot show that a slip was not cancelled, or
  a vouching record not withdrawn, on a page that is not shown; the
  checker says so with every Show.
- **A withdrawal has only its place in the book.** A slip that sits
  before the withdrawal keeps the vouching, even if it was signed after
  the organisation decided to withdraw. Seals and time-stamps bound how
  far a book can be rearranged.
- **A stub made honestly just before a cancellation**, and not yet under
  a time-stamped seal, is reported as not shown to have been made in
  time. That is what the record can show. A recorder that seals often
  keeps it rare.
- **What the organisation did to check.** A vouching record shows that
  the organisation stood behind a name. It does not show how well it
  checked, nor that the organisation is who its own name says.
- **The agent's software.** The fingerprints in a slip are a statement
  of what the person approved. Nothing shows which program signed with
  the agent's keys.

## 6c. Covered fields

**Protects.** That a slip can be shown with its names and its purpose
hidden, while its signature, its place in the book and every comparison
of stubs with it still check. That a revealed field is exactly the field
that was signed: nobody can reveal a different name or purpose.

**From whom.** A reader who is handed a slip without its disclosures
learns no covered name and no purpose: each is replaced, in what was
signed, by the fingerprint of the field mixed with 128 random bits, so it
cannot be guessed. A2 and A6 cannot make a disclosure for a value that
was not signed. A disclosure cannot be moved to another slip. Nobody can
write a slip that shows one reader different limits, conditions,
actions, services or keys from another: only a name or the purpose can
be covered, an item of a list never, and a field is absent only where
exactly its one fingerprint stands in its place.

**How.** The method is the standard "Selective Disclosure for JSON Web
Tokens" (RFC 9901), with its own checking steps: a fingerprint may appear
once; a disclosure must belong to the record; a revealed name may not
replace a field that is there. The standard's worked example is a test.

**Does not protect.**

- **Only a slip's names and purpose can be covered.** The actions, the
  limits, the keys and the times cannot: a checker needs them. Stubs and
  other records cannot hold covered fields in this draft, so the names of
  documents in a stub are visible to whoever holds the stub.
- **That a field is covered is visible.** A reader sees that something is
  hidden, and how many fields.
- **A disclosure, once handed over, cannot be taken back.**
- **Whoever keeps the disclosures can read the fields.** Covering limits
  what a reader of a record learns, not what its keeper knows.
- **A covered name cannot be vouched for** to a reader who cannot see it.
- **A covered name may be visible in another record.** A vouching record
  states the name it vouches for, and a service's terms and refusals
  state the service's name. Covering a name in a slip does not cover it
  there.
- **A disclosure that does not fit.** The signer of a slip can cover a
  name with a value that a slip may not hold. The slip is sound while the
  name stays covered. Handed the disclosure, the checker refuses the
  disclosure, says so, and checks the slip as before: what a slip is does
  not depend on what is handed over with it. The check as a whole is then
  not a pass, and the reader should check again without that disclosure.
- **A slip uses less than the standard allows.** No covered item of a
  list, no decoy fingerprints, disclosures in the canonical form only.
  Software written for the standard alone must be told so.
- **The person signs the covered form.** What they are shown on the
  signing page is up to that page: A9 still wins.

## 6d. Passing a slip on

**Protects.** That a helper agent acted under a pass signed by the agent
that held the permission, that the slip allowed passing on, and that
everything the helper did is compared with the slip the person signed.

**From whom.** A3 cannot widen its permission by passing it on: a
helper's stubs are compared with the slip itself, and the slip's totals
take in the agent and every helper together. A helper cannot widen its
own by passing on either: a stub is compared with every pass above its
own, and the totals of each take in what is done further down. A stub
in one chain, dated later, cannot empty a limit "within a period" for
another chain: periods go by the times the stubs state, wherever the
stubs stand in the book. A helper cannot act under
another slip's pass, nor write into the first agent's chain. A6 cannot
make a pass: it needs the keys of the agent that passes on.

**Does not protect.**

- **An agent that hands over its own keys** instead of writing a pass.
  The helper's actions then look like the agent's own.
- **Who the helper is.** Its name in a pass is a label, unless a
  vouching record stands behind it.
- **A pass the slip does not allow** is not refused: it is reported, with
  every stub under it, as outside the slip. The record is still sound.
  Only an eleventh pass in a row, which no slip can allow, is refused.

## 6e. The denial

A denial (format description, section 28) is the agent's side's signed
statement that it did not take an action that was asked for, and who
said no: the check before acting, the person, or a rule of the software
around the agent.

**Protects.** That a denial in the book was signed by the agent the slip
names, or by the helper its pass names, under a slip that is earlier in
the book (`slip-missing`, `pass-missing`, `pass-mismatch`,
`signature-invalid`). A6 cannot make one. A7 cannot use one to change
any other answer: a denial is in no chain, adds to no total, and is never
counted against the agent, so a flood of denials, or a denial that names
an action far outside the slip, makes no stub read as outside it. A
denial changed after it was signed, or under another kind of record's
labels, is refused like any record. In this library, `act` writes a
denial only where it did not take the action, so one call through `act`,
`recordTools` or `record_function` leaves a stub or a denial, never both
(the connector for an agent's tools asks for no denial until it knows
the person will not approve). `deny` is different: it records whatever
its caller states, and a caller can write a denial for a request that
also has a stub; the checker shows both. The writer keeps to a set
number of denials an hour of its own clock (600 by default), counting
each it writes at the clock's time, so that an agent that asks again and
again cannot fill its book quickly: at 600 an hour a book's 100,000
entries still fill in about a week. A stub is never kept out by that
limit.

**Does not protect.**

- **It is the agent's side's own word.** A3 can write a denial for an
  action it then took some other way, or a false reason. Only the other
  side's records, or the service's own refusal, can show otherwise.
- **An agent can simply not write one.** A book with no denial shows
  nothing about how often the agent was stopped. A1 or A2 can also leave
  denials out of a copy of the book after the last seal, as any entry.
- **What was asked for is in clear.** A denial names the action, the
  amount and the service. Its documents are fingerprints only, and the
  library never writes arguments into it; but a fingerprint of a short
  or guessable value can be guessed.
- **The source is not checked.** Nothing shows that the person, or a
  rule, said no: `person` and `rule` are the agent's side's statement.
  A denial by the check before acting names the codes the check gave,
  and nothing in the record shows that the check was made.
- **Older checkers** refuse a book that holds a denial (`unknown-entry`).

## 6f. Witnesses, and a book shown two ways

A recorder that keeps a book (A1, A2) can show one history to one reader
and another to another (a "split view"): each copy checks, and each is
sealed, so a reader who holds one copy cannot see the other. A witness
(format description, section 29) is a party with a key set of its own
that keeps, for each recorder, person and agent, the latest seal it
signed for, and signs a statement for a new seal only where the new seal
extends that one: in the same book, by a consistency proof (RFC 9162,
section 2.1.4), or as the first seal of the next book (section 21.6). The
person and the agent are those the permission on a book's first line
names: its passkey and the agent's key set. So every permission one
person gives one agent under one recorder, renewals included, is one
sequence: the independent review showed that a sequence known by the
permission alone let a book that started with a renewal fork the
history, and a witness now refuses it. The statement sits beside the seal on its line, or is
handed to a checker later with a copy of the seal.

**Protects.** That a statement a checker counts was signed by a witness
the person named, by the fingerprint of its key set, and speaks of that
very seal: its `seal`, `size` and `root` must be the seal's, both its
signatures must check, and it may not be dated more than 300 seconds
before the seal (`witness-invalid`). A6 and A7 cannot make one, and a
statement from a witness nobody named is shown and not counted. A
statement that does not pass is a problem; one handed over beside the
book is a problem with the whole check, and the seal it came with is
used all the same. Being witnessed excuses nothing: it changes no other
answer, and a book with a problem is never said to be witnessed.

A witness knows which books are one sequence only by the passkey and the
agent of the permission on their first line and the keys of their
recorder, and the recorder (A1, A2) chooses the first line and its keys: it can start a history with another first line, or
seal it with new keys, and the same honest witness signs for it as
another sequence. So a statement counts only where the person fixed
both: the book's first line is a permission that passed its check,
signed by a passkey the person named (`issuerKeys`), and the person
named the recorders they expect (`sealKeys`). The independent review of
this step showed a history that began with made-up terms, then the
permission, signed by the same witness and read as witnessed; it now
reads as not witnessed, and the witness itself no longer keeps a book
whose first line is not a permission.

And every permission among the entries a seal covers must name the same
passkey and agent as the first line's. The third round of the review
showed a fork through a second agent of the same person under the same
recorder, the gateway's own set-up: a book that started with agent Y's
permission, then held agent X's permission and X's stubs without the
one over its limit, was signed by the witness as the first book of the
person and agent Y, and read as witnessed. It now reads as not
witnessed, with a note saying why; so does one that starts with a
second passkey's permission for X. A witness cannot refuse such a book
itself: it sees a book's first line, not its entries. A Show counts a
statement only where its pages hold every entry the seal covers, so it
never counts one that the whole book would not.

What it narrows, where the witness keeps section 29.3 and the person
fixed the start: a second history sealed by the same recorder and
starting from any permission that passkey gave the same agent needs that
witness to sign for it too, which it does not do. So two readers who name that witness, the
same passkey and the same recorder cannot be shown two such histories
that both carry its statements and that disagree before the earlier of
the two seals it signed for. A new book cannot start from an earlier
seal than the latest the witness holds, so the books of one permission
cannot fork either. Two witnesses need two to fail. The latest seal a
witness holds, handed over beside the book it is of as a seal held
elsewhere (section 6a), shows that book cut back to before that seal
(`book-cut-short`, `seal-not-in-book`). The witness program in the
library (`openWitness`) checks a seal's three signatures, signs nothing
on a device that cannot check SLH-DSA (so there is none in the Python
version), ties the first line to the seal with an audit path at first
contact and at each new book, keeps it tied with each consistency proof,
never signs two different seals of one book at one size, never again
signs for a book once it has signed for the next, and hands back what it
holds with each statement, to be kept before the statement is given
out.

**Does not protect.**

- **Other recorder keys, or another agent.** A history sealed with
  another key set, even one the person also named, or that starts from a
  permission for another agent, is another sequence to a witness, and a
  fork made that way is not caught. A person who names two recorders
  should know that a fork sealed with the second reads as witnessed. One
  recorder key set keeps one sequence for each person and agent, so books
  kept side by side for one agent need recorder keys of their own, and
  are then other sequences.
- **What a later book holds.** A later book can repeat, or leave out,
  what an earlier book holds: each book is checked on its own.
- **A book sealed again under another number.** A book cut short can be
  sealed again with another book number. A seal held elsewhere is then of
  another number than the book, is not compared with it, and gives no
  pass: the command-line checker says "Seals held elsewhere compared?
  NO" and does not end with code 0, and the checking page gives no green
  answer. The reader learns that their seal was not compared, not where
  the book was cut.
- **What is never shown to a witness.** A recorder can keep a book, or
  the end of one, from every witness. Nothing in a book obliges it to be
  witnessed, and a checker that is not handed the witness's latest seal
  does not know of later seals. Where that latest seal is of a later
  book, a checker of an earlier book cannot use it to show that earlier
  book cut short: it cannot tell whether a seal of the next book is that
  book's first (section 21.6).
- **A witness that fails.** A witness that signs for two histories, or
  that loses what it holds or is put back to an older copy of it, can
  sign a fork, and nothing in either history shows it. The library's
  witness, opened again from what it kept, signs nothing until it is
  brought up to date (`update`) and told so (`ready`); it cannot tell
  whether what it was given is the latest it gave out. Whoever can change
  what it keeps can make it forget a sequence, which it then signs for
  again from any seal: its state must be kept as safely as its keys.
- **The entries.** A witness sees a seal's size and top fingerprint,
  not the entries: it shows that the entries existed in that form when
  it saw the seal, not that they are true.
- **Time.** A statement's `when` is the witness's own word, and is not
  used as a time-stamp.
- **Limits across books.** A checker counts a limit within the book it
  checks, not across the books of a permission.
- **A device that cannot check both of a statement's signatures**
  counts nothing, and the record is not fully checked there.
- **Older checkers** refuse a seal's line that holds `witnesses`
  (`unknown-entry`), and a seal that gives `book` (`bad-field`).

## 7. The checker and the checking page

**Protects.** A7 cannot crash the checker, make it run a script, or make
it show a pass for a record that does not check.

**How.**

- A failed check is a normal answer with a named reason, never a crash.
  If the checker itself meets something it did not expect, that too is
  reported as a problem, never as a pass.
- What an entry says is shown only if the entry passed its check. Text
  from a record is shown with control characters, characters that cannot
  be seen (every character that Unicode says is left out when text is
  drawn, and the blank Braille pattern), and characters that change the
  direction of text, replaced by a visible mark. Runs of spaces are
  shown as one. A name or a purpose is shown inside quotation marks, and
  a quotation mark inside it as an apostrophe, so that a reader can see
  where the record's words end and the checker's begin. No word a record contains is copied into a message
  about a problem.
- A flood of empty lines is refused as soon as there are too many, before
  any is read.
- Every field of a record is treated as untrusted text. The checking
  page writes it as text and never as markup.
- Every member name in a record is treated as a plain name. A member
  named `__proto__` is a member like any other: it is refused where it
  is unknown, and nothing is inherited from it. What is looked up by a
  name that came from a record, such as a service's id, finds only what
  the checker itself put there.
- "Within its slip" is said only if every stub and every pass was
  compared on this device.
- Records over a fixed size, or nested too deeply, are refused. A book
  may hold 100,000 lines of 131,072 bytes, about 13 gigabytes in all;
  this library takes a book as one text, so it can check no book larger
  than one text the device can hold, and a checker should bound the size
  it accepts (format description, section 9).
- The content of a record must be written in one canonical form (RFC
  8785). A record with a repeated field name, stray spaces or an unusual
  number form is refused, so two checkers cannot read the same record in
  two ways.
- The checker makes no network request. Nobody learns which record was
  checked. Only `provared-headers`, which the person runs, connects to
  anything: to the Bitcoin nodes the person names, for block headers.
  It asks for every header from the first block onwards, so a node does
  not learn which blocks matter to the person.
- What the person hands the checking page beside a record (their own
  copies of cancellations, disclosures for covered fields, the blocks,
  the fingerprints and the signing page's address they trust) is read in
  the browser and sent nowhere. A file that is not JSON, or a line that
  is not a fingerprint or a page address in its plain form, stops the
  check and says so: it is never set aside silently. The sample record
  is checked without the files handed over.
- The checker depends on no outside code. It uses only the cryptography
  built into the browser or Node.js.
- **The checking page as one file** (`tools/make-single-page.mjs`) holds
  the page, its style, the checker and the sample record, copied in
  unchanged; a test compares each with the file it was copied from. Its
  content security policy lets nothing be loaded from anywhere, and lets
  only the one script and the one style in the file run, named by their
  fingerprints. So the file can make no request, whatever a record
  holds. Whoever is handed the file should compare its SHA-256
  fingerprint with one obtained from a place they trust: a changed copy
  is a changed checker.
- **A checker that is carried on** (`openChecker`, and the stub writer)
  reads a book once and then takes more lines without reading the
  earlier ones again. There is one way of reading a line, and a whole
  check is: start, read every line, give the answer. So a book that is
  carried on gets the answer a whole check gives. A test compares the
  two after every line of a book that holds every kind of entry, sound
  and unsound. What can be found only once every stub has been read (a
  limit "in any period", what a cancellation handed over beside the
  book shows) is worked out afresh for each answer and never written
  into what the checker keeps. Each answer handed out is a copy, and
  what the checker is told to trust is copied when it is opened, so
  nothing done outside changes what it keeps.
- **Trying a line.** The stub writer tries each new line on a reader
  split off the book's own. For a stub that reader is a light copy: a
  stub is the one kind of entry that changes nothing read before it, and
  the light copy refuses any other kind. For an entry that someone else
  made it is a full copy. If the line is not written after all (it does
  not fit, the action fails, the clock fails), that reader is thrown
  away, and the book's own reader is as it was: a test compares it with
  a whole check after every try. An entry that does not fit costs one
  line's check, never a reading of the whole book.

**Does not protect.**

- A checker run on a taken-over device.
- A checker that is itself altered. Use a copy you obtained from a place
  you trust.
- A carried checker against a book that is changed behind it. It knows
  the lines it was handed. If the text of the book is changed elsewhere
  (by a second stub writer, or by hand), its answer is for the lines it
  read. Check the whole book again where that may have happened.
- A book too large for memory. The checker reads the whole book at once.
  A book of several hundred megabytes may be more than a browser or
  Node.js will hold as one text; the check then fails, and says so.

## 8. What is refused, and the test that proves it

Each row is one test in `test/refusals.test.mjs`, named by its code. A
further test reads this table and fails if a code here has no test. This
table is also the format's own list of finding codes, from which a denial
names its reasons (format description, section 28); `test/denial.test.mjs`
fails if the two differ.

| Code | What is refused or reported |
|---|---|
| `not-json` | A record that is not JSON text |
| `bad-envelope` | A record that is not laid out as a JSON Web Signature with exactly the expected members |
| `bad-base64url` | A value that is not strict base64url |
| `too-large` | A record over the size limit |
| `unknown-type` | A signature whose label is not one of the exact known labels |
| `bad-signatures-layout` | The wrong number or order of signatures, including a quantum-safe signature that has been stripped off |
| `payload-not-canonical` | Content that is not in the canonical form, including a repeated field name |
| `payload-type-mismatch` | Content of one kind under the label of another, for example a stub presented as a countersignature |
| `bad-field` | A missing, extra or wrongly typed field |
| `bad-key` | A public key that is not exactly of an accepted kind, an Ed25519 key of small order or written in more than one way, or an ES256 key that is not a point on its curve |
| `signature-invalid` | A signature that does not fit the key, or an Ed25519 signature whose R is a point of small order or whose S is not below the order L |
| `passkey-wrong-type` | A passkey answer that was made for creating a passkey, not for signing |
| `passkey-challenge-mismatch` | A passkey signature made for other content |
| `passkey-origin-mismatch` | A passkey used on a website other than the one the slip names |
| `passkey-rpid-mismatch` | A passkey that belongs to a website other than the one the slip names |
| `passkey-user-not-present` | A passkey signature with no sign that a person was there |
| `passkey-user-not-verified` | A passkey signature where the device did not confirm the person |
| `passkey-bad-data` | Passkey values that are cut short or malformed |
| `issuer-not-expected` | A slip signed by a key other than the ones the checker was told to expect |
| `issuer-origin-not-expected` | A slip signed at a page address other than the ones the checker was told to expect (section 3) |
| `slip-missing` | A stub whose slip is not earlier in the book |
| `slip-unusable` | A stub whose slip failed its own check |
| `chain-broken` | A stub that is missing, moved, repeated or changed |
| `time-went-backwards` | A stub dated before the stub ahead of it |
| `duplicate-id` | Two records with the same unique number |
| `duplicate-slip` | The same slip twice in one book |
| `countersignature-invalid` | A countersignature that does not fit the service's keys |
| `countersignature-wrong-stub` | A countersignature made for a different stub |
| `countersignature-not-possible` | A countersignature from a service for which the slip names no keys |
| `line-not-canonical` | A line of a book that is not in the canonical form |
| `unknown-entry` | A line of a book that is not one of the known kinds of entry |
| `approval-mismatch` | An approval put with a stub it was not given for: another action, amount, service, document or slip |
| `approval-reused` | One approval put with a second stub |
| `approval-invalid` | An approval that was not signed with the passkey the slip names, or whose passkey values do not check |
| `approval-not-found` | A stub that names an approval which is not with it |
| `approval-dated-after-stub` | An approval dated later than the stub that carries it |
| `terms-not-found` | A stub that relies on terms which are not earlier in the book |
| `terms-unusable` | A stub that relies on terms which failed their own check |
| `terms-mismatch` | A stub that relies on terms not signed with the keys the slip gives for the service it names |
| `pass-missing` | A stub, or a further pass, that relies on a pass which is not earlier in the book, or which failed its own check |
| `pass-mismatch` | A pass given under one slip, used under another |
| `pass-too-deep` | An eleventh pass in a row: a permission may be passed on at most ten times |
| `cover-invalid` | A disclosure of a covered field that does not belong to the record, was changed, is handed over twice, is not as its standard sets out, or is not in the canonical form; a covered item of a list in a slip; disclosures handed over with a page that is not a slip |
| `cancellation-invalid` | A cancellation that was not signed with the passkey the slip names |
| `cancellation-not-found` | An acknowledgement that names a cancellation which is not earlier in the book, did not pass its check, or cancels another slip |
| `acknowledgement-mismatch` | An acknowledgement handed over with the person's own copy of a cancellation that was given for another cancellation |
| `vouching-missing` | A withdrawal of a vouching record that is not earlier in the book |
| `seal-mismatch` | A seal that does not fit the entries before it: an entry was changed, added or removed after the seal was made. In a Show: a seal for another book, or for another length of this one |
| `seal-chain-broken` | A seal that does not name the seal before it: a seal is missing, moved or changed |
| `sealer-not-expected` | A seal signed with keys other than the ones the checker was told to expect |
| `book-cut-short` | A book that ends before the place of a seal held elsewhere and handed over beside it: its end was cut off after that seal was made |
| `seal-not-in-book` | A book that holds another line at the place of a seal held elsewhere and handed over beside it: it was changed after that seal was made, or the seal is of another book |
| `witness-invalid` | A witness statement, beside a seal in the book or handed over with a seal held elsewhere, whose signatures do not fit the keys it gives, that speaks of another seal, or that is dated more than 300 seconds before its seal |
| `dated-after-stamp` | An entry dated later than the outside time-stamp that covers it, or a seal dated later than its own time-stamp |
| `stamp-bad-data` | A time-stamp that is not laid out as its standard sets out |
| `stamp-wrong-data` | A time-stamp made for something other than this seal |
| `stamp-invalid` | A time-stamp whose signature does not check, that names the certificate that signed it twice in one form, that is signed with Ed25519 and names a fingerprint method other than SHA-512, or that is dated outside the time its service's certificate was in force |
| `headers-invalid` | A chain of block headers in which a header breaks a rule that every Bitcoin node applies, that does not hold the known blocks at their places, or that ends before the last of them (tested in `test/headers.test.mjs`) |
| `record-not-sound` | The check before acting: the record so far has a problem, or could not be checked on this device, so no action is allowed |
| `proof-invalid` | A one-page proof that does not lead to the top fingerprint |
| `root-mismatch` | A top fingerprint, or a number of entries, other than the one the checker was told to expect |
| `check-failed` | Anything the checker itself did not expect: reported as a problem, never as a pass |
| `action-not-allowed` | Reported, not refused: the agent did something the slip does not allow |
| `party-not-allowed` | Reported: the agent dealt with someone the slip does not name |
| `outside-valid-time` | Reported: the action is dated outside the slip's time |
| `amount-missing` | Reported: the slip sets a limit and the stub gives no amount in that unit |
| `over-limit` | Reported: the running total passes the slip's limit, and at which stub. In a Show: a single stub that passes the limit by itself |
| `over-each-limit` | Reported: one action is larger than the slip allows for a single action |
| `over-count-limit` | Reported: more actions of one kind than the slip allows |
| `over-period-limit` | Reported: the total, or the number of actions, within a period is more than the slip allows |
| `countersignature-missing` | Reported: the slip asks for the other side to countersign the action, and the stub is one-sided |
| `approval-missing` | Reported: the slip asks for the person's own approval of the action, and there is none |
| `prohibited` | Reported: an action of a kind the slip says the agent must never do |
| `pass-not-allowed` | Reported: the permission was passed on though the slip does not allow it, or more times than it allows; and every stub written under such a pass |
| `pass-wider` | Reported: a pass that hands on an action, or a time, that its writer does not itself hold |
| `after-cancellation` | Reported: a stub that comes after the person cancelled the slip, or that no outside time-stamp shows to have existed before a time-stamped cancellation |
| `outside-terms` | Reported: an action the service's terms for agents do not accept, or dated outside the time they were in force |

The last fifteen are what a sound record can show about the agent. They are
not faults in the record. The checker keeps three questions apart: "was a
problem found in the record?", "was every signature checked on this
device?" and "did the agent stay within its slip?". It calls a record
intact only when no problem was found and every signature was checked.

## 9. When this document must be reviewed

- Before any change to a label, a field or the bytes that are signed.
- Before the first publication, when draft version 0 is frozen.
- When a public place for seals is added, when more fields may be
  covered, when passing on changes, or when the way a time-stamp or a vouching
  record is trusted changes.
- When a kind of limit, a condition, a rule of conduct or a shared action
  is added, removed or changes its meaning.
- When a browser or Node.js changes how it offers ML-DSA or SLH-DSA.
- When the proof format of the block time-stamp changes, or a second
  chain or a further kind of step is accepted.
- When a fault is found: the fault becomes a test and a row here. (Twenty
  independent reviews from 3 to 5 October 2026 found the faults the
  change log lists; each is now a test.)
- A gap between what this document claims and what the code does is a
  defect of the highest priority.
