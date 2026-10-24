# provared-sealer

**A central sealer signs seals over what it was sent. It proves that the
book it sealed had those lines at that time, as far as the recorder sent
their fingerprints; it does not check that the lines are true, and it sees
none of them but each book's first line, its permission.** What it adds: the recorder's keys are no longer on the
agent's computer, and, with its state kept, the sealer never signs two
different histories of one first line: each line is taken once at its
place, and every book that starts with the same first line follows the
one before. Each recorder starts books only from permissions for its
own agents, so no recorder can have a book sealed whose first line is a
permission for another recorder's agent. What it cannot tell from
fingerprints: that a book repeats lines of another book, its own
recorder's or another's. So a recorder can start a book from a
permission for its own agent, copy into it another recorder's agent's
permissions and stubs with some left out, and have it sealed (see "What
it does not do, and what it does not prove"); a seal of the other
recorder's own book held elsewhere (format description, section 21.5)
shows it; a witness statement on its seal is not counted, but nothing
says why. A sealer whose state was lost or put
back can also be made to sign a second history; witnesses (section 29)
are the outside check for that.

A small program, run by a team other than the one that runs the agent,
that holds the recorder's three keys (Ed25519, ML-DSA-87 and
SLH-DSA-SHA2-256s) and seals books it never sees:

1. a recorder sends it the leaf fingerprint of each new line of its book
   (the SHA-256 of the byte 0x00 and the line, as RFC 6962, section 2.1,
   sets out), never the line, except that a book is started with its
   first line itself, the permission it starts with;
2. the sealer builds, for each book, the same tree a checker builds from
   the lines, extended only by what it was sent, each line taken once, at
   its place;
3. asked for a seal, it signs one over its own number of entries and its
   own top fingerprint, naming its own latest seal of that book, checks
   its three signatures, saves its state (made sure to be on the disk),
   and only then hands the seal's entry back;
4. the recorder adds the entry to its book with the stub writer's `add`,
   which checks it against the whole book: a sealer sent a wrong
   fingerprint signs a seal the book refuses (`seal-mismatch`).

It is the library's `openSealer` (format description, section 21.7) with
a folder and a port around it. Evidence, not a verdict.

## Install

```
npm install provared-sealer
```

It needs Node.js 24.7 or later: SLH-DSA is built into Node.js, and a
sealer checks every seal it signs.

## Set it up

```
provared-sealer init --folder /srv/sealer --name "Example Ltd central sealer"
provared-sealer add-recorder --folder /srv/sealer --agent <fingerprint> agent-one
provared-sealer start --folder /srv/sealer
```

`init` writes the settings (`sealer.json`) and the key file
(`sealer-keys.jwk`, for its owner alone; never replaced), and prints the
public keys and the fingerprint of the key set. Give that fingerprint to
whoever checks the books: it is what they name as the recorder they
expect (`--sealer` on the command-line checker, `sealKeys` in the
library). `add-recorder` gives a recorder a token, printed once, and
names the agents whose permissions it may start books with (see "The
recorders"); the first one added also writes the empty state. `start`
listens on 127.0.0.1, port 8797 unless the settings or `--port` say
otherwise.

## The settings

`sealer.json`:

| Member | What it is |
|---|---|
| `name` | The name the seals give (`by.name`): a label, 1 to 200 characters |
| `port` | The port on 127.0.0.1; 8797 by default |
| `signers` | Optional. For any of `Ed25519`, `ML-DSA-87` and `SLH-DSA-SHA2-256s`, the path of a module (from the folder) whose default export is an async function that gives a signer for that method: an object with `key`, the public key, and `sign(data)`, which gives the signature bytes. It takes the place of the key file's key for that method |

A signer is how a key held in a key service or a hardware module is
reached (the library's guide, "Keys held elsewhere: signers"). Every
signature a signer gives is checked against its key before it is used.
Few key services sign SLH-DSA-SHA2-256s today, so the third key will
usually stay in the key file, on the machine the sealing team runs; keep
that file protected at rest (an encrypted disk). `init` makes keys only
for the methods the settings name no module for.

## The recorders

`recorders.json` (for its owner alone) names, for each recorder:

| Member | What it is |
|---|---|
| `token` | 32 random bytes in base64url, made by `add-recorder` |
| `agents` | 1 to 64 fingerprints of the key sets of the agents whose permissions the recorder may start books with: the SHA-256 of the agent's list of keys in the canonical form (format description, section 21.1), as for a recorder's key set |
| `books` | The most books the recorder may hold, sealed or not: 1 to 1,000; 100 by default |

```
provared-sealer add-recorder --folder /srv/sealer --agent <fingerprint> [--agent <fingerprint> ...] [--books <n>] <name>
```

An agent belongs to one recorder: a list that names one agent for two
recorders stops the start, and `add-recorder` refuses it. The books the
recorders in `recorders.json` may hold add up to at most 1,000, the most
the sealer keeps. Books already in the state count towards the 1,000
too, those of a recorder taken off the list included: a book with no
seal until it is released (`release-unsealed`), a sealed book for good.
So, where such books are kept, the recorders on the list can be refused
(`too-large`) before each reaches its own number. To change a recorder's
agents or its number of books, stop the sealer and change
`recorders.json`; to add a recorder, use `add-recorder` (see "What it
keeps").

Every book is started with its first line itself (`line` beside
`/extend`, or `/update` for a book brought in): the sealer reads it as a
permission (format description, section 4) and starts the book only
where the permission's agent is one of the recorder's own
(`agent-not-allowed`; `other-recorder` for another recorder's agent; a
line that is not a permission gets the checker's own codes, such as
`slip-missing`). It does not check the passkey's signature: that is the
book's own check. So the sealer learns each book's permission, its names
and purpose included, except fields covered as section 24 of the format
description sets out. A recorder past its number of books is refused
(`too-large`).

A book that holds no seal had nothing signed for it, and can be taken
off the state while the sealer is stopped:

```
provared-sealer release-unsealed --folder /srv/sealer [<name>]
```

It frees the book's place in the recorder's number of books, its place
as the next book after another, and its first line. Only one recorder's
books are released where a name is given.

## What it keeps

In its folder: `sealer.json`; `sealer-keys.jwk`; `recorders.json`;
`state.json`, one state for the
books of every recorder: for each book, the leaf fingerprint of its
first line, its number, the recorder it belongs to, the book it follows,
whether a later book follows it, and its latest seal with the tree at
that seal (the seal and its time-stamps, at most four; never witness
statements, which the sealer does not check); a book with no seal yet is kept at its first line's leaf
fingerprint. No line of any book is kept, the first included, and no
fingerprint of a line that no seal covers. The state is replaced
whole through a temporary file made sure to be on the disk, when a book
is started, sealed or brought up to date, before the answer is given;
lines added to a book are not saved by themselves, so after a start the
sealer stands at each book's latest seal (or first line) and asks for
the lines since (`out-of-step` gives the place). It keeps at most 1,000
books, and each recorder at most its own number (see "The recorders").
Each sealed book takes about 52 KB of the state, most of it the
latest seal's three signatures; the seal's entry, time-stamps included,
is never longer than a line of a book (131,072 bytes). A state of 1,000
sealed books is about 52 MB, and well under 140 MB at most, written whole at each of those changes (about a fifth of a second
on the computer it was measured on, before the disk), and it takes about
five seconds to open, since each latest seal is checked again.
`sealer.lock` keeps a second sealer off the same folder (one left by a
process that has ended is taken over).

A book, and every book that follows it, belongs to the recorder that
started it. Another recorder can neither send lines for it, seal it,
bring it up to date, start a book after it, nor start a book with its
first line (`other-recorder`); asked about it (`/latest`, `/held`), the
sealer answers as for a book it does not hold. Nor can another recorder
start a book from any permission for this recorder's agents, such as a
renewed permission that stands inside one of its books, nor bring such a
book in first after a lost state; so it cannot hold back the permission
this recorder starts its next book with. A recorder taken off
`recorders.json` keeps its books in the state. `add-recorder` refuses a
new recorder whose name has books in the state; the program does not
check this when it starts, so a recorder written into `recorders.json`
by hand under an old name takes over that name's books. Add recorders
with `add-recorder`. Every recorder's seals are signed with the same key
set. Run one sealer, with one state, for one key set: two states kept
with one key set are two sealers, and each signs its own history.

## What a recorder asks

Every question is a `POST` with a JSON body, its length declared
(`Content-Length`; a body sent in pieces of unknown length is refused),
and five headers: `Provared-Sealer-Recorder` (its name),
`Provared-Sealer-Time` (the time, in milliseconds since 1970),
`Provared-Sealer-Nonce` (32 random bytes in base64url, used once), and
two proofs, each HMAC-SHA-256 (RFC 2104) under the token over a label
and parts, each after a line break, in base64url:
`Provared-Sealer-Head`, over the label `provared sealer v1: a
recorder's question, before its body`, the name, the path, the time,
the nonce and the declared length, as written in `Content-Length`; and
`Provared-Sealer-Proof`, over the label `provared sealer v1: a
recorder's question`, the name, the path, the time, the nonce and the
SHA-256 of the body. The sealer refuses (`401`) a question whose proofs
do not check; whose time is written other than
in digits, is more than 60 seconds from its clock, or is more than 60
seconds before the latest time its clock has given (a clock set back
never lets a question be taken twice; until the clock is there again,
the questions it dates are refused); or whose nonce that recorder has
used while the question could still be taken (until 60 seconds after
the later of the question's time and the latest time the clock has
given). The name, the time, the nonce, the second proof's form, the
declared length and the first proof are checked before the body is read,
so no body is read for a program that does not hold the token; a
question that fails them is answered at once, its body never read. A
client that is still sending its body when such an answer comes may see
the connection closed rather than the answer, depending on the client
(`connectSealer` was seen to receive an early `503`); either way nothing
was acted on, and the question may be sent again. The sealer's answer
carries `Provared-Sealer-Proof` too:
HMAC-SHA-256 under the token over `provared sealer v1: the sealer's
answer`, the question's proof, the status and the SHA-256 of the
answer's body. So the token never travels, a program that listens in the
sealer's place learns nothing it can use, and the recorder can tell an
answer from the sealer from any other.
`connectSealer({ address, recorder, token })` in `sealer.mjs` does all
this. Its calls take the library's arguments, with one difference: the
last argument of `extend`, `seal` and `update` (`more`) may hold only
what the table below gives for that path beside the call's own members
(`follows` and `line` for `extend`; `previous`, which must be given, and
`when` for `seal`; `line` for `update`). Any other member is refused
(`bad-field`) and nothing is sent. Among them is `id`: the library's
`seal` takes one, the program does not, and the sealer makes the seal's
id itself. A `when` given as a `Date` is sent as its milliseconds.

| Path | Body | Answer |
|---|---|---|
| `/about` | `{}` | `{name, keys, sealer}`: the key set and its fingerprint |
| `/extend` | `{book, at, leaves, follows?, line?}` | `{size}`, or `{refused, size}` where `at` is not the number of lines the sealer holds |
| `/seal` | `{book, previous, when?}` | `{entry, line, fingerprint}`; `stampProblem` where a time-stamp was asked for and failed |
| `/update` | `{book, entry, leaves, line?}` | `{size}` |
| `/latest` | `{book}` | `{latest}`: the latest seal it holds of the book, or null |
| `/held` | `{book}` | `{held}`: how many lines, the latest seal's fingerprint, whether the book is closed, or null |

`book` is the leaf fingerprint of the book's first line, in base64url, or
`{first, number}` for a book after the first; `leaves` are leaf
fingerprints in base64url; `line` is the book's first line itself, needed
to start a book. A book whose first line the sealer holds
already starts only as the next book after the latest with that first
line, following it (`not-next-book`). A body may hold only the members
its path takes, as in the table; any other is refused (`bad-field`),
never set aside. `/update` takes the seal's `entry` as the book holds
it, but keeps only the seal, whose three signatures it checks, and its
time-stamps, read for their form only (at most four, each at most
12,288 bytes, in base64url, none twice): it checks no time-stamp's
signature and trusts no time-stamp service, so a time-stamp that
`/latest` gives back has not been checked by the sealer. An `entry`
longer than
a line of a book may be (131,072 bytes) is refused (`too-large`), so
that no recorder can make the state too large to save. `/latest` gives
the seal with its time-stamps. A refusal is
`{refused: {code, message}}` with status `200`; `400` with `bad-field`
for a body that is not JSON (found in its turn); `503` with
`sealer-stopped` or `busy`; `413`, and the connection closed, where a
body is declared or found larger than 8 MiB. The codes and their words
are the library's (`openSealer`).

`busy` is given, with a proof, where one recorder has 16 questions
waiting, has 32 MiB of bodies waiting (four whole bodies), or has asked
100,000 questions in the time their numbers are kept: each recorder
keeps its own count, bytes and numbers, so one recorder's questions do
not take another's places. A question turned away as `busy` is not
acted on and its number is not kept, so the same question may be sent
again; every call is guarded by its place or its seal, so a question
taken twice changes nothing the second time. `busy` is also given,
before the body is read and so with no proof, where the bodies being
read for one recorder (each question's first proof checked, its body
not yet) add up to more than 16 MiB; only a program that holds that
recorder's token can fill them. `connectSealer` reports such an answer
as `busy`, and uses nothing in it.

What the bodies cost in memory. While a question waits for its turn its
body is kept as its bytes only; it is read as JSON in its turn, so one
read body exists at a time for the whole sealer. For each recorder, at
most 16 MiB of bodies being read and 32 MiB of bodies waiting are held;
and, at any moment, the one body in its turn as read JSON, which for an
8 MiB body can take up to about 250 MB (about 230 MB was measured for
one of lists nested about 4.2 million deep, and about 170 MB for one of
2.8 million empty objects). A recorder
that sends many such bodies is turned away as `busy`, and holds the
others back while each of its own is read in its turn; the memory it can
take is bounded as above, whatever number of questions it sends. (In a
test with a heap of 700 MB, 16 such questions of 8 MiB sent at once
while a long question held the queue: three waited and were answered,
thirteen were turned away, and the heap grew by about 180 MB at most.)

The questions of every recorder are answered one at a time, so one
recorder's long question holds the others back (100,000 leaf
fingerprints in one `/extend` took about five seconds). Once the state
cannot be saved, every question taken up after that, by any recorder, is
answered `sealer-stopped` until the program is started again; an answer
worked out and saved before the failure may still be sent. A seal is
never given out before the state that holds it is saved.

## After a restore, or a lost state

A seal names, in `previous`, the seal before it as the recorder's book
shows it, and the sealer signs only where that is the latest seal it
holds. So a sealer whose state was put back from an older copy signs
nothing for a book whose seals are ahead of it (`not-up-to-date`) until
the recorder brings it up to date: `/update` with the book's latest seal
and the leaf fingerprints from the latest seal the sealer holds to that
one; they must give that seal's top fingerprint. Where that seal is the
first seal of a later book, and names the latest seal of a book the
sealer holds, that book is closed. Bring the books up to date in their
order, the earliest first: where the sealer holds the book a later book
was started after at an earlier seal than the one the later book's
first seal names, that first seal is refused (`not-up-to-date`) until
the book before is brought up to date. A book behind the sealer (a seal
given out and never added) takes the seal back from `/latest`. A book
that was started after a book that is then closed by another book (a
state put back can leave one waiting so) takes no first seal
(`book-closed`); nothing was signed for it, and `release-unsealed`
takes it off.

A state that is missing stops the start, and no recorder is added
meanwhile. Put back the latest copy; or start with `--fresh` to begin
with no state, and then bring each book up to date, with its first
line, before it is sealed again. `--fresh` is refused where there is a
state. A book brought in is held to the same rules as one started line
by line, so no recorder can bring in first a book whose permission is
for another recorder's agent.

## What it does not do, and what it does not prove

- It sees no line but each book's first, and does not check that a
  fingerprint is of a real line. The book's own check does that, when
  the seal is added.
- It cannot tell that a book which starts from another permission for
  the same agent repeats lines of a book it has sealed, nor that a later
  book repeats lines of the book before: a recorder can do this with its
  own agents' permissions. A reader who asks that seals be witnessed is
  the check for that.
- **It cannot tell that a recorder copied another recorder's agent's
  lines into a book of its own.** With only its own token, a recorder
  can start a book from a permission for one of its own agents (the
  sealer checks only that first line), then send the fingerprints of
  permissions and stubs taken from a book of another recorder's agent,
  leaving out any it likes (a stub over a limit, say), and have the
  book sealed. Where one person's passkey signed the permissions for
  agents of both recorders, as is ordinary in a company, a reader who
  names that passkey and this sealer's key set finds the book intact
  and within its slips, with nothing reported. What catches it: a seal
  of the other recorder's own book, held elsewhere (format description,
  section 21.5) and handed to the checker with this book, shows a
  problem (`book-cut-short` or `seal-not-in-book`), because the two
  books differ; or, where the two books' numbers differ (the copied
  lines came from book 2 and the copy is book 1, say), the seal held
  elsewhere cannot be compared, and the checker says so ("compared?
  NO") and gives no pass. A witness may sign such a seal, but its statement is not
  counted for a reader, because the seal covers a permission for an
  agent other than the first line's (format description, section 29.2,
  "When a statement counts"): the seal reads as not witnessed,
  and nothing reports why. So readers of books from a sealer that
  serves recorders which do not trust each other should hold each
  recorder's own seals elsewhere and hand them to the checker, or the
  organisation should run a sealer, with its own key set, for each
  recorder.
- It trusts its operator's `recorders.json`: an agent named for the
  wrong recorder lets that recorder start books from that agent's
  permissions. Changing a recorder's agents does not move the books it
  already holds.
- Each recorder may have up to 16 MiB of bodies being read and 32 MiB of
  bodies waiting, so the memory used for them grows with the number of
  recorders (see "What the bodies cost in memory").
- The numbers used once, and the latest time the clock has given, are
  kept in memory only. After a start, a question sent in the minute
  before it could be taken once more; every call is guarded by its place
  or its seal, so this changes nothing the second time.
- It names no time-stamp service: a program that embeds it may give the
  library's `stamp` function to `startSealer`. It asks no witness yet.
- A state put back from an older copy, with a recorder that hides the
  seals made since, can be made to sign a second history of the lines
  after the latest seal that state holds. A later book brought in with
  `/update`, whose first seal names a seal the sealer does not hold as
  the latest of any book, does not know which book it follows: it closes
  only the earlier books with its own first line, and a book before it
  with another first line stays open until it too is brought up to date.
  Keep the state as safely as the keys, and back it up often;
  witnesses (format description, section 29) are the outside check.
- It listens on 127.0.0.1 only, with no TLS. Any program on that computer
  can ask it questions; only those that hold a token are answered.
- A checker cannot tell a seal made by a central sealer from one made
  beside the agent: who holds the keys is not in the record. Bind the
  sealer's key set to the organisation with a vouching record (format
  description, section 23).

## Working from a copy of the repository

The program names its library `provared`, as it is named when installed
from npm. The tests always run against the repository's own library,
whatever `node_modules` holds (`test/local-library.mjs`):

```
cd sealer
node --disable-warning=ExperimentalWarning --test test/*.test.mjs
```

To run the command on the repository's own library:

```
node --import ./sealer/test/local-library.mjs sealer/bin.mjs init --folder <folder> --name <name>
```

## Licences

The code is under the Apache License 2.0; this file is under the Creative
Commons Attribution 4.0 International licence. Copyright 2026 Pavel
Izmaylov.
