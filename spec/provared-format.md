# The Provared format — draft version 0

A way to write down what an AI agent was allowed to do, and what it then
did, so that someone else can check it later with free tools.

*Evidence, not a verdict.* A record shows what was signed and by which
keys. People decide what it means.

## 1. Status

This is **draft version 0**. Nothing in it is frozen. Every label below
ends in `v0` so that a frozen version can never be confused with this
draft. Do not rely on a draft record staying checkable.

Built in this draft: the Slip, with its limits, conditions and stated
rules; the Stub; the countersignature; the person's approval of one
action; a service's refusal and its terms for agents; the chain; the
book; the tree of fingerprints; the Seal, with outside time-stamps; the
one-page proof; cancelling a slip, and the agent's acknowledgement of a
cancellation; the block time-stamp; vouching for a name; covered fields
in a slip; and passing a slip on to a helper agent.

What is not in this draft is listed in section 12.

The words MUST, MUST NOT and MAY are used as RFC 2119 defines them.

## 2. Words used

| Word | Meaning |
|---|---|
| Slip | A permission that a person signs with a passkey: which agent, which actions, what limits, with whom, from when until when, and why |
| Stub | A signed receipt for one action, pointing back to its slip |
| Countersignature | The other side's signed statement that the action happened with it |
| Approval | The person's own yes to one action, signed with the same passkey as the slip |
| Refusal | A service's signed statement that an agent asked for something and was refused |
| Terms | A service's signed statement of which actions it accepts from agents |
| Seal | The signed statement, by whoever keeps a book, of its top fingerprint and its number of entries at one moment |
| Recorder | Whoever keeps a book and seals it |
| Time-stamp | A signed statement by an outside service that a fingerprint existed by a time (RFC 3161); a block time-stamp is the like, from a block of a public blockchain (section 21.4) |
| Cancellation | The person's signed statement that a slip is ended early |
| Vouching record | An organisation's signed statement that a key belongs to a name |
| Withdrawal | The organisation's signed statement that a vouching record is ended |
| Pass | An agent's signed statement that it hands part of its permission to a helper agent |
| Chain | The stubs under one slip, each naming the one before |
| Book | A list of entries, one to a line: slips, stubs and the other records of this format |
| Top fingerprint | One fingerprint that stands for the whole book (the root of a Merkle tree) |
| Show | One or more entries of a book, each with proof that it is in the book |
| Issuer | The person who signs a slip |
| Agent | The software that acts, and signs stubs |
| Service | Whoever the agent deals with; it may countersign |
| Checker | Anyone who verifies a record, or the software they use |
| Fingerprint | The SHA-256 hash of some bytes, written in base64url (43 characters) |
| Passkey | A private key held in a phone, laptop or security key and unlocked by fingerprint, face or PIN (the W3C Web Authentication standard) |
| Hybrid | Two signatures on one record, one of today's kind and one quantum-safe; the record counts only if both check |

## 3. Rules common to every record

### 3.1 The signed envelope

Every record is a JSON Web Signature (RFC 7515) in the **general JSON
serialisation** (RFC 7515, section 7.2.1):

```json
{
  "payload": "<base64url of the content>",
  "signatures": [
    { "protected": "<base64url of the protected header>", "signature": "<base64url>" }
  ]
}
```

- The top level MUST hold exactly `payload` and `signatures`.
- Each entry of `signatures` MUST hold exactly `protected` and
  `signature`, and, for a record signed with a passkey (a slip, an
  approval or a cancellation), `header` (section 4.3).
- The bytes each signature covers are the JSON Web Signature signing
  input (RFC 7515, section 5.1): the ASCII text of `protected`, a full
  stop, and the ASCII text of `payload`.
- A record MUST NOT be larger than 65,536 characters, measured as the
  lengths of its `payload` and of every text value in its signature
  entries, added up. A writer MUST NOT make a larger record.

### 3.2 Labels: the protected header

The protected header says what kind of record this is and which signing
method was used. Because it is part of the signed bytes, a signature made
for one kind of record can never pass as another kind.

In this draft the protected header, once decoded, MUST be **exactly** one
of these twenty-two texts, byte for byte. A checker compares the bytes and does
not interpret anything else.

| Record | Method | Protected header |
|---|---|---|
| Slip | Passkey | `{"typ":"vnd.provared.slip.v0+json","alg":"prova.red/webauthn/v0"}` |
| Stub | Ed25519 | `{"typ":"vnd.provared.stub.v0+json","alg":"Ed25519"}` |
| Stub | ML-DSA-87 | `{"typ":"vnd.provared.stub.v0+json","alg":"ML-DSA-87"}` |
| Countersignature | Ed25519 | `{"typ":"vnd.provared.countersignature.v0+json","alg":"Ed25519"}` |
| Countersignature | ML-DSA-87 | `{"typ":"vnd.provared.countersignature.v0+json","alg":"ML-DSA-87"}` |
| Approval | Passkey | `{"typ":"vnd.provared.approval.v0+json","alg":"prova.red/webauthn/v0"}` |
| Refusal | Ed25519 | `{"typ":"vnd.provared.refusal.v0+json","alg":"Ed25519"}` |
| Refusal | ML-DSA-87 | `{"typ":"vnd.provared.refusal.v0+json","alg":"ML-DSA-87"}` |
| Terms | Ed25519 | `{"typ":"vnd.provared.terms.v0+json","alg":"Ed25519"}` |
| Terms | ML-DSA-87 | `{"typ":"vnd.provared.terms.v0+json","alg":"ML-DSA-87"}` |
| Seal | Ed25519 | `{"typ":"vnd.provared.seal.v0+json","alg":"Ed25519"}` |
| Seal | ML-DSA-87 | `{"typ":"vnd.provared.seal.v0+json","alg":"ML-DSA-87"}` |
| Seal | SLH-DSA-SHA2-256s | `{"typ":"vnd.provared.seal.v0+json","alg":"SLH-DSA-SHA2-256s"}` |
| Cancellation | Passkey | `{"typ":"vnd.provared.cancellation.v0+json","alg":"prova.red/webauthn/v0"}` |
| Acknowledgement | Ed25519 | `{"typ":"vnd.provared.acknowledgement.v0+json","alg":"Ed25519"}` |
| Acknowledgement | ML-DSA-87 | `{"typ":"vnd.provared.acknowledgement.v0+json","alg":"ML-DSA-87"}` |
| Vouching record | Ed25519 | `{"typ":"vnd.provared.vouching.v0+json","alg":"Ed25519"}` |
| Vouching record | ML-DSA-87 | `{"typ":"vnd.provared.vouching.v0+json","alg":"ML-DSA-87"}` |
| Withdrawal | Ed25519 | `{"typ":"vnd.provared.withdrawal.v0+json","alg":"Ed25519"}` |
| Withdrawal | ML-DSA-87 | `{"typ":"vnd.provared.withdrawal.v0+json","alg":"ML-DSA-87"}` |
| Pass | Ed25519 | `{"typ":"vnd.provared.pass.v0+json","alg":"Ed25519"}` |
| Pass | ML-DSA-87 | `{"typ":"vnd.provared.pass.v0+json","alg":"ML-DSA-87"}` |

`typ` is the media type of the record (RFC 7515, section 4.1.9), used as
explicit typing (RFC 8725, section 3.11). `alg` names the signing method
(RFC 7515, section 4.1.1). `Ed25519` is the name RFC 9864 registers;
`ML-DSA-87` is the name RFC 9964 registers. `SLH-DSA-SHA2-256s` is the
name FIPS 205 gives that method; no registered name for it in this
envelope was found when this draft was written. `prova.red/webauthn/v0` is
not a registered name: it is a collision-resistant name under a domain
the format's author controls, which RFC 7515 section 4.1.1 allows.

### 3.3 Base64url

Base64url is as RFC 4648, section 5, with no padding (RFC 7515, section
2). A checker MUST refuse a value that holds any other character, has
padding, has an impossible length, or has stray bits set in its last
character.

### 3.4 The content, and its canonical form

The content of a record (the decoded `payload`) is a JSON object in
UTF-8. It MUST be written in the JSON Canonicalization Scheme (RFC 8785):
no spaces or line breaks, the members of every object sorted by name, and
strings and numbers written in the one form that standard gives.

This draft narrows what the content may hold: objects, lists, strings,
whole numbers from 0 to 9,007,199,254,740,991, and nothing else. There
are no fractions, no negative numbers, no `null`, no `true` or `false`.
Strings MUST be well-formed Unicode. Nesting MUST NOT go deeper than 8
levels.

A checker MUST read the content, write it again in the canonical form,
and refuse the record if the two differ by a single byte. This refuses a
repeated member name, stray spaces and unusual number forms, so that two
checkers cannot read one record in two ways.

The signed bytes are always kept and checked exactly as they were signed.
The canonical form is a test the bytes must pass; it is never used to
rewrite them.

Every content object has a `type` member: `provared.slip.v0`,
`provared.stub.v0`, `provared.countersignature.v0`,
`provared.approval.v0`, `provared.refusal.v0`, `provared.terms.v0`,
`provared.seal.v0`, `provared.cancellation.v0`,
`provared.acknowledgement.v0`, `provared.vouching.v0`,
`provared.withdrawal.v0` or `provared.pass.v0`. It MUST match the `typ`
label of every signature on the record.

An object MUST hold exactly the members this document lists for it. A
checker MUST refuse an unknown member.

Wherever this document limits the length of a text, the length is counted
in characters (Unicode code points).

### 3.5 Fingerprints

The **fingerprint of a record** is the SHA-256 hash (FIPS 180-4) of its
content bytes (the decoded `payload`), written in base64url. It is how a
stub names its slip, how a stub names the stub before it, and how a
countersignature names its stub.

### 3.6 Times

A time is written as `YYYY-MM-DDTHH:MM:SSZ` (RFC 3339, in UTC, to the
second, with the letter Z). No other form is accepted.

### 3.7 Unique numbers

An `id` is 16 random bytes written in base64url (22 characters).

### 3.8 Keys

Public keys are written as JSON Web Keys (RFC 7517). Each MUST be exactly
one of these shapes, with no other member:

| Used by | Shape |
|---|---|
| Agent, service | `{"alg":"Ed25519","crv":"Ed25519","kty":"OKP","x":"…"}` (RFC 8037; `x` is 32 bytes) |
| Agent, service | `{"alg":"ML-DSA-87","kty":"AKP","pub":"…"}` (RFC 9964; `pub` is 2,592 bytes) |
| Recorder, third key | `{"alg":"SLH-DSA-SHA2-256s","kty":"AKP","pub":"…"}` (FIPS 205; `pub` is 64 bytes) |
| Issuer's passkey | `{"alg":"ES256","crv":"P-256","kty":"EC","x":"…","y":"…"}` (RFC 7518, section 6.2; 32 bytes each) |
| Issuer's passkey | `{"alg":"RS256","e":"AQAB","kty":"RSA","n":"…"}` (RFC 7518, section 6.3; `n` is 2,048 to 8,192 bits) |
| Issuer's passkey | `{"alg":"Ed25519","crv":"Ed25519","kty":"OKP","x":"…"}` |

A key is named for people by its **thumbprint**: the JSON Web Key
Thumbprint with SHA-256 (RFC 7638; for ML-DSA keys, RFC 9964 section 6).

### 3.9 A key set: the hybrid

An agent or a service is known by a **key set**: a list of exactly two
keys, the Ed25519 key first and the ML-DSA-87 key second.

A stub, a countersignature, a refusal, a set of terms, a vouching record,
a withdrawal or a pass MUST carry exactly two signatures, in the same order: Ed25519 (RFC 8032), then ML-DSA-87 (FIPS 204, the plain
method with an empty context, as RFC 9964 section 5 requires). Both cover
the same content. The record counts as signed **only if both signatures
check**. The two signatures stand side by side as two entries of the
`signatures` list, as RFC 7515 already allows. Nothing is combined by a
method of this format's own.

Because the slip names both keys, taking the quantum-safe signature off a
stub does not leave a valid stub.

A checker on a device with no built-in ML-DSA MUST report that the
quantum-safe signature could not be checked, and MUST NOT report the
record as intact. An entry none of whose signatures the device could
check MUST NOT be treated as evidence: what it says is not shown as fact,
and it is not compared with its slip.

A recorder is known by a key set of exactly three keys: Ed25519,
ML-DSA-87, then SLH-DSA-SHA2-256s (FIPS 205, the plain method with an
empty context). A seal MUST carry exactly three signatures, in that
order, and counts as signed only if all three check. The third rests only
on fingerprint functions, so it would stand even if the mathematics
behind ML-DSA were broken. When this draft was written, no browser
offered it to a page, and Node.js offered it outside the standard
interface: a checker in a browser reports it as not checked, which is
never a pass.

The issuer's passkey signature on a slip is of today's kind only. No
device offers a quantum-safe passkey.

## 4. The Slip

### 4.1 Content

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.slip.v0` |
| `id` | Unique number | Section 3.7 |
| `issuer` | Who gives permission | An object, below |
| `agent` | Which agent may act | `{"name": text, "keys": key set}`, and optionally `"software"`, below |
| `actions` | What it may do | A list of 1 to 64 action names, none repeated |
| `limits` | How much | A list of 0 to 64 limits, below |
| `requires` | What must go with an action | A list of 0 to 64 conditions, below |
| `never` | Stated rules | A list of 0 to 16 names, below, none repeated |
| `with` | With whom it may deal | A list of 0 to 64 services, below |
| `passes` | How many times the permission may be passed on. Optional | A whole number from 1 to 10. Absent: it may not be passed on (section 25) |
| `validFrom` | From when | A time |
| `validUntil` | Until when | A time, later than `validFrom` |
| `purpose` | Why | Text, 1 to 1,000 characters |

`issuer` is `{"name": text, "key": passkey public key, "rpId": text,
"origin": text}`. `rpId` is the website the passkey belongs to (the
"relying party identifier" of the Web Authentication standard). `origin`
is the address of the page the slip was signed on, for example
`https://sign.example.org`. The host in `origin` MUST be `rpId` or end
with a full stop and `rpId`. `origin` MUST use `https`, or be
`http://localhost` with or without a port number. It holds nothing after
the host and the port.

A **name** is text of 1 to 200 characters. It is a label chosen by
whoever wrote the slip. It is not checked against anything, unless a
vouching record stands behind it (section 23).

`agent.software`, where present, is a list of 1 to 16 of `{"name": text,
"sha256": fingerprint}`: the agent's program and settings as the person
approved them. It is a statement. Nothing in a record proves which
program signed with the agent's keys, and a checker MUST show it as a
statement.

An **action name** is 1 to 64 characters: the lower-case letters a to z,
digits, full stops, hyphens and underscores, beginning with a letter or digit,
for example `supplies.order`. The issuer chooses the names. A checker
compares them exactly. Names that begin `provared.` are reserved for the
shared list of section 16: such a name MUST be on that list.

A **limit** names an `action`, which MUST be one of `actions`, and holds
exactly one of `max`, `each` and `count`, each a whole number:

| Limit | Meaning |
|---|---|
| `{"action", "max", "unit"}` | The amounts of all stubs under this slip for this action, added up, must not pass `max` |
| `{"action", "each", "unit"}` | No single stub for this action may have an amount above `each` |
| `{"action", "count"}` | There must not be more than `count` stubs for this action. `count` is 1 or more |
| `{"action", "max", "per", "unit"}` | As `max`, within any period of `per` seconds |
| `{"action", "count", "per"}` | As `count`, within any period of `per` seconds |

`unit` is 1 to 16 characters: the letters a to z and A to Z, digits,
full stops, hyphens and underscores, with no spaces, beginning with a
letter or a digit, for example `items` or `hours`. (A unit is shown
beside the checker's own words, so it is kept too short and too plain to
be mistaken for them.) A `count` has no
unit, and `each` has no period. `per` is from 1 to 31,622,400 (366 days).
A period is counted backwards from each stub, by the times the stubs
state. It holds every stub under the slip for the action, in whichever
chain (section 25) and at whichever place in the book, whose `when` is
later than this stub's `when` less `per` seconds and earlier than this
stub's `when`; every such stub with the same `when` that stands earlier
in the book; and this stub. There are no calendar days and no time
zones. A stub further on in the book, in another chain, may state an
earlier time, so a checker works these limits out once it has read every
stub under the slip. The finding is given for the stub whose period
holds too much, which may be a stub of another chain than the one that
was written last. A slip MUST NOT hold two limits with the same action, the same one
of `max`, `each` and `count`, and the same `per`.

A **condition** is `{"need": "countersignature"}` or `{"need":
"approval"}`, with these optional members: `action` (one of `actions`;
without it the condition applies to every action), and `above` with
`unit` (the condition applies only to a stub whose amount is more than
`above`; these two come together and need an `action`).
`countersignature` means the stub must carry the countersignature of the
service it names (section 6). `approval` means the stub must carry the
person's approval (section 17). A slip MUST NOT hold two conditions with
the same `need` and the same `action`.

Every `unit` named for one action, in its limits and its conditions, MUST
be the same, because a stub gives one amount.

A name in **`never`** is a kind of action or a rule of conduct from
section 16, for example `destroys` or `impersonate`. A slip MUST NOT
allow, in `actions`, a shared action of a kind that its `never` forbids.
A rule of conduct is the person's signed instruction to the agent. No
check of a record can show that the agent kept it (section 13).

A **service** is `{"id": text, "name": text}` or `{"id": text, "keys":
key set, "name": text}`. `id` has the form of an action name and MUST NOT
repeat within the slip. A service with no `keys` cannot countersign.

### 4.2 How a passkey signs a slip

A passkey does not sign a document. It signs a short value the web page
hands to it (the challenge), together with the address of the website.

1. Write the content in the canonical form. Build the signing input
   (section 3.1) with the slip's protected header (section 3.2).
2. The challenge is the SHA-256 hash of the signing input.
3. Ask the passkey to sign with that challenge, with the person confirmed
   by the device ("user verification: required").
4. The passkey returns three values: the authenticator data, the client
   data, and the signature. Store all three exactly as returned.

### 4.3 The signed slip

A slip has exactly one signature entry:

```json
{
  "protected": "<the slip's protected header>",
  "header": { "authenticatorData": "<base64url>", "clientDataJSON": "<base64url>" },
  "signature": "<base64url of the signature as the passkey returned it>"
}
```

`header` MUST hold exactly those two members.

### 4.4 Checking a slip

A checker follows the checking steps of the Web Authentication standard
(W3C Web Authentication Level 3, section 7.2), as far as they apply to a
check made later and offline. It MUST confirm all of these:

1. The envelope, the label, the canonical form and every member are as
   sections 3 and 4.1 require.
2. The client data is JSON whose `type` is `webauthn.get`.
3. The client data's `challenge` is the base64url of the SHA-256 hash of
   the signing input.
4. The client data's `origin` equals `issuer.origin`, and `crossOrigin`
   is not true.
5. The authenticator data is at least 37 bytes. Its first 32 bytes equal
   the SHA-256 hash of `issuer.rpId`.
6. In the flags byte, "user present" (bit 0) and "user verified" (bit 2)
   are both set. "Attested credential data" (bit 6) is not set. If
   "extension data" (bit 7) is not set, the authenticator data is exactly
   37 bytes.
7. The signature fits `issuer.key`, over the authenticator data followed
   by the SHA-256 hash of the client data. For an `ES256` key the stored
   signature is in ASN.1 DER form and MUST be strictly encoded.

If the checker was given the thumbprints of the issuer keys it expects,
it MUST also confirm that `issuer.key` is one of them. If it was given
none, it MUST say that the issuer's key was not compared with a known
key.

The signature counter in the authenticator data is not used: an offline
checker keeps no state.

## 5. The Stub

### 5.1 Content

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.stub.v0` |
| `id` | Unique number | Section 3.7 |
| `slip` | The slip relied on | The slip's fingerprint |
| `seq` | Place in the chain | A whole number: 0 for the first stub under the slip, then 1, 2, … |
| `previous` | The stub before | The fingerprint of the stub with the number before. Present unless `seq` is 0 |
| `action` | What was done | An action name |
| `amount` | How much. Optional | `{"unit": text, "value": whole number}` |
| `with` | With whom. Optional | The `id` of a service in the slip |
| `details` | The documents involved. Optional | A list of 1 to 32 of `{"name": text, "sha256": fingerprint of the document}` |
| `approval` | The person's approval of this action. Optional | The fingerprint of the approval (section 17) |
| `terms` | The service's terms the agent relied on. Optional; needs `with` | The fingerprint of the terms (section 19) |
| `pass` | For a helper agent: the pass it acts under. Optional | The fingerprint of the pass (section 25) |
| `when` | When it was done | A time |

A stub holds fingerprints of documents, never the documents.

### 5.2 Signing and checking

A stub is signed by the agent's key set (section 3.9), with the stub
labels of section 3.2.

A checker MUST confirm that both signatures check against the two keys
the slip gives for the agent.

## 6. The countersignature

Content: `{"stub": fingerprint of the stub, "type":
"provared.countersignature.v0", "when": a time}`. It means: "this action
happened with me".

It is signed by the service's key set, with the countersignature labels
of section 3.2. A checker MUST confirm that `stub` is the fingerprint of
the stub it accompanies, and that both signatures check against the keys
the slip gives for the service named in the stub's `with`.

A stub with no countersignature is **one-sided**. It is a named state,
not a failure. It proves what the agent's side said. A checker MUST show
it as one-sided.

## 7. The chain

There is one chain for the stubs of the slip's own agent, and one for the
stubs under each pass (section 25). For the stubs of one chain, taken in
the order they appear in a book, a checker MUST confirm:

- the first has `seq` 0 and no `previous`;
- each later one has the next number, and `previous` equal to the
  fingerprint of the one before;
- `when` never goes backwards;
- no `id` appears twice in the book, among records of every kind
  (`duplicate-id`).

## 8. What a stub shows about the agent

These are not faults in the record. A sound record can show that the
agent went outside its slip. A checker reports each of them, and at which
stub:

| Code | Shown when |
|---|---|
| `action-not-allowed` | `action` is not in the slip's `actions` |
| `party-not-allowed` | `with` is not the `id` of a service in the slip |
| `outside-valid-time` | `when` is before `validFrom`, or not before `validUntil` |
| `amount-missing` | The slip has a limit or a condition with a `unit` for this action, and the stub has no amount in that unit. Reported once for a stub |
| `over-limit` | The running total for this action, with this stub added, is more than a limit's `max` |
| `over-each-limit` | The stub's amount is more than a limit's `each` |
| `over-count-limit` | With this stub there are more stubs for this action than a limit's `count` |
| `over-period-limit` | Within the period that ends at this stub, the total is more than `max`, or the number of stubs is more than `count` |
| `countersignature-missing` | A condition asks for a countersignature, and the stub has none |
| `approval-missing` | A condition asks for the person's approval, and the stub has none |
| `prohibited` | `action` is a shared action of a kind the slip's `never` forbids |
| `after-cancellation` | The person cancelled the slip before this stub (section 22) |
| `pass-not-allowed` | The stub was written under a pass that the slip does not allow (section 25) |
| `outside-terms` | The stub relies on a service's terms (section 19), and the terms do not accept `action`, or `when` is before their `validFrom` or not before their `validUntil` |

A stub is compared with its slip only if the stub passed its own check.
Totals, counts and periods take in only the stubs that were compared. A
pass that hands on more than its writer holds is reported on the pass
(`pass-wider`, section 25).

The order in which a checker reports several findings for one entry is
not part of this format: two checkers agree if they report the same set.
Where an entry fails its own check in several ways, a checker MUST report
at least one of them, and MAY stop at the first.

A checker answers three questions and keeps them apart: was a problem
found in the record; was every signature checked on this device; and what
do the stubs show about the agent. It MUST call a record intact only if no
problem was found and every signature was checked. It MUST say that the
agent stayed within its slip only if every stub was compared with its slip
and none was outside it. If the checker itself meets something it did not
expect, it MUST report a problem, never a pass.

## 9. The book

A book is UTF-8 text. Each line is one entry, ended by a line feed (the
line feed after the last line may be missing). An
entry is a JSON object in the canonical form (section 3.4, with records
in place of the narrowed content), and is one of:

- `{"slip": slip record}`
- `{"stub": stub record}`, which MAY also hold `"countersignature":
  countersignature record` and `"approval": approval record`
- `{"refusal": refusal record}`
- `{"terms": terms record}`
- `{"seal": seal record}`, which MAY also hold `"stamps": list of 1 to 4
  time-stamps` (section 21)
- `{"cancellation": cancellation record}`, which MAY also hold `"stamps"`
  (section 22)
- `{"acknowledgement": acknowledgement record}` (section 26)
- `{"vouching": vouching record}` and `{"withdrawal": withdrawal record}`
  (section 23)
- `{"pass": pass record}` (section 25)

A slip MUST come before the entries that rely on it, and a set of terms
before the stubs that rely on it. A book MUST NOT hold
the same slip twice, nor more than 100,000 entries. A line MUST NOT be
longer than 131,072 bytes.

## 10. The tree and the top fingerprint

The entries of a book are the leaves of a Merkle tree built exactly as
RFC 6962 (Certificate Transparency), section 2.1, sets out, with SHA-256.
The data of a leaf is the bytes of its line, without the line feed. The
root of the tree is the book's **top fingerprint**.

A top fingerprint is signed, with the number of entries, by a seal
(section 21), and an outside time-stamp on the seal states when. Without
a seal that the checker has reason to trust, a top fingerprint is worth
as much as the checker's other reason to trust it, for example a copy
they took earlier.

The top fingerprint does not by itself fix how many entries the book
holds: that is a property of this kind of tree. Whoever keeps a copy of a
top fingerprint MUST keep the number of entries with it, and a later
signature or time-stamp MUST cover both, as RFC 6962 section 3.5 does. A
checker that is given a top fingerprint or a number of entries to expect
MUST compare it.

## 11. The Show: one page, with proof

A Show hands a checker some entries of a book and, for each, the few
fingerprints needed to work out the top fingerprint again (the audit path
of RFC 6962, section 2.1.1).

```json
{
  "type": "provared.show.v0",
  "size": 12,
  "root": "<the top fingerprint>",
  "pages": [
    { "index": 3, "entry": "<the line, exactly>", "path": ["<fingerprint>", "…"] }
  ]
}
```

A Show MAY also hold `"seal"`: an entry of the form `{"seal": seal
record}`, with or without `"stamps"`. The Show is then of the book as it
stood when that seal was made: the seal's `size` and `root` MUST equal the
Show's (`seal-mismatch`), and a checker checks the seal and its
time-stamps as section 21 sets out. Its `id` MUST NOT be that of a
record on any page (`duplicate-id`), as in a whole book (section 7).
Such a Show proves that its pages existed by the time the time-stamp
states, with no other copy of the top fingerprint.

A Show holds 1 to 64 pages, none repeated. It is not itself signed. A checker
MUST confirm each page with the checking steps of RFC 9162, section
2.1.3.2, then check each entry as above. A stub can be checked only if
its slip is among the pages, and a stub that relies on a service's terms
only if those terms are among the pages. A Show can show a stub outside
its slip, including a single stub that passes a limit by itself, and a
stub that lacks a countersignature or an approval the slip asks for. It
cannot show a count, that a limit was kept, or that an approval was used
only once: those need every stub under the slip. Nor can it show that a
slip was not cancelled (section 22), or that a vouching record was not
withdrawn (section 23), on a page that is not among its pages. A checker
MUST say both with every Show.

Whoever hands over a Show chooses its pages and its seal. So a Show does
not show what a seal that was left out of it would show. Where a page is
dated after the time-stamp of a seal that comes after it in the book,
that is reported only if the seal is among the pages, and the seal is
the page reported (section 21.3). Only the whole book shows it in every
case.

The same holds for the rules that rest on a seal earlier in the book
(section 21.1, rule 4, and section 21.3, the second case): a Show
applies them only for seals that are among its pages. With such a seal
left out, a Show may pass where the whole book reports a seal as dated
before a time-stamp it covers; it may count a block time-stamp that the
whole book sets aside, and so show its pages as having existed earlier
than the whole book shows; and it may report a seal as dated after its
block time-stamp where the whole book sets that time-stamp aside and
passes. The last two need a block that states a time far behind the
true time.

Nothing fixes the time-stamps beside the seal that comes with a Show.
They stand outside the tree and outside the seal's signatures, so
whoever hands the Show over can put a later time-stamp in the place of
an earlier one. The same holds for the last seal of a book. A later
time-stamp shows less, never more, and the pages are still held against
the seal's own date (section 21.1, rule 4).

## 12. Not in draft version 0

| Missing | What follows |
|---|---|
| A public place where seals are kept | The last seal of a book, with everything after it, can be removed unnoticed, unless someone else holds a copy of that seal or of its top fingerprint and number of entries |
| A quantum-safe time-stamp | Time-stamp services sign with methods of today's kind |
| Covered fields outside a slip's names and purpose | Every other field of an entry is visible to whoever holds it |
| A compact binary form | Records are JSON text only |

## 13. What a record does not prove

- It proves what was recorded, not what was left out. An agent that acts
  and writes no stub leaves no trace.
- A one-sided stub proves what the agent's side said, not what the other
  side did.
- A refusal proves what the service's side said, not what the agent did.
- A rule of conduct in a slip, such as "never claim to be a human being",
  is the person's signed instruction. No check can show that the agent
  kept it.
- An approval proves that the passkey approved that one action. It does
  not prove that the person read what they approved.
- It does not show that an action was wise, lawful or wanted.
- A badly written slip is faithfully recorded as a badly written slip.
- It does not prove who was holding the device when the passkey signed.
- A name in a record is a label. Only keys are checked. A vouching
  record shows which organisation stood behind a name; it does not prove
  that the organisation checked well.
- The fingerprints of an agent's software in a slip are a statement of
  what the person approved, not proof of what ran.

## 14. Standards used

| Standard | Used for |
|---|---|
| RFC 8259 (JSON); RFC 8785 (JSON Canonicalization Scheme) | Writing the content |
| RFC 7515 (JSON Web Signature), sections 5.1 and 7.2.1 | The signed envelope |
| RFC 7517 (JSON Web Key); RFC 7638 (thumbprints) | Keys and their names |
| RFC 8725, section 3.11 | Labels (explicit typing) |
| RFC 8032; RFC 8037; RFC 9864 | Ed25519 and its names |
| FIPS 204; RFC 9964 | ML-DSA-87 and its names |
| FIPS 180-4 | SHA-256 |
| W3C Web Authentication Level 3, section 7.2 | Passkey signatures |
| FIPS 186-5; RFC 7518; RFC 8017 | The signing methods passkeys use (ES256, RS256) |
| RFC 4648, section 5 | Base64url |
| RFC 3339 | Times |
| RFC 6962, section 2.1; RFC 9162, section 2.1.3.2 | The tree and its proofs |
| FIPS 205 | SLH-DSA-SHA2-256s, the third signature on a seal |
| RFC 3161; RFC 5652; RFC 5280; ITU-T X.690 | Time-stamps: the statement, its signed wrapper, the certificate, and the byte layout (DER) |
| The OpenTimestamps proof file, version 1 (an open format; not the work of a standards body) | Block time-stamps: the steps from a fingerprint to the Merkle root of a block |
| RFC 9901 (Selective Disclosure for JSON Web Tokens) | Covered fields |

## 15. Choices that go beyond the standards

Each of these is a choice of this draft, to be reviewed before the format
is frozen.

1. The method name `prova.red/webauthn/v0`: a passkey signature wrapped
   as a JSON Web Signature. No registered name exists for it.
2. The media types of section 3.2 (`vnd.provared.slip.v0+json` and
   the others, each ending in `.v0+json`) are not registered.
3. Protected headers are fixed texts, compared byte for byte.
4. The hybrid is two signatures side by side with the rule "both must
   check", not a combined signature.
5. The content is narrowed to whole numbers, strings, lists and objects.
6. A fingerprint covers the content only, not the signatures.
7. The kinds of limit, the conditions and the `never` list of section 4.1.
8. A period is counted backwards from each stub, in seconds, with no
   calendar days and no time zones.
9. The shared list of actions, the kinds of action and the rules of
   conduct of section 16. They are a first draft, written before real
   agents have used them.
10. The approval, the refusal and the terms for agents of sections 17 to
    19, and the labels `vnd.provared.approval.v0+json`,
    `vnd.provared.refusal.v0+json` and `vnd.provared.terms.v0+json`.

11. The seal of section 21, its label `vnd.provared.seal.v0+json`, and
    its three signatures side by side. The name `SLH-DSA-SHA2-256s` is
    used as FIPS 205 gives it.
12. A checker trusts a time-stamp service by the fingerprint of the
    service's certificate, given by the person checking. It follows no
    chain of certificates.
13. A time-stamp is made over the seal's fingerprint. The allowance
    between clocks is 300 seconds. A time-stamp that states its own time
    more loosely than that is refused.
13a. The block time-stamp of section 21.4: the proof read strictly, with
    three kinds of step only; the block's header kept beside the proof; a
    block trusted by its fingerprint, given by the person checking, or
    found in a chain of block headers the checker checks itself, with
    known blocks and six blocks after it; a block's time taken as right
    to within 7,200 seconds.

14. The cancellation, the vouching record and the withdrawal of sections
    22 and 23, and their labels.
15. A stub counts as made before a time-stamped cancellation only if an
    outside time-stamp shows that it existed by then.

16. Covered fields follow RFC 9901, narrowed as section 24 sets out: only
    a slip's names and purpose; never an item of a list; exactly one
    fingerprint where a field is covered, with no decoys; disclosures in
    the canonical form; SHA-256 only; disclosures kept beside the record,
    not inside a line of the book.

17. The pass of section 25, its label, and one chain of stubs for each
    pass.
18. The acknowledgement of section 26 and its label
    `vnd.provared.acknowledgement.v0+json`.

## 16. The shared list: actions, kinds of action, rules of conduct

Anyone may use action names of their own. So that one organisation's slip
can be read by another, this format also keeps a shared list. Every name
on it begins `provared.`, and belongs to exactly one kind of action.

The kinds of action:

| Kind | Meaning |
|---|---|
| `reads` | Looks at data without changing it. |
| `changes` | Creates or changes data in a way that can be put back. |
| `destroys` | Removes data or a resource in a way that may not be put back. |
| `sends` | Sends a message or data to a person, to the public or to another system. |
| `commits` | Binds the person to something: an order, a booking, an agreement, an account. |
| `grants` | Gives someone or something access or permission. |
| `runs` | Runs a program or a command. |
| `enters` | Signs in to a system or an account. |

The shared actions:

| Action | Kind | Meaning |
|---|---|---|
| `provared.data.read` | `reads` | Read stored data or a file. |
| `provared.data.search` | `reads` | Search stored data. |
| `provared.data.create` | `changes` | Create a new item of data or a new file. |
| `provared.data.change` | `changes` | Change an item of data or a file that exists. |
| `provared.data.delete` | `destroys` | Delete data or a file. |
| `provared.data.export` | `sends` | Copy data out of the system that keeps it. |
| `provared.message.read` | `reads` | Read messages. |
| `provared.message.draft` | `changes` | Write a message without sending it. |
| `provared.message.send` | `sends` | Send a message to a person. |
| `provared.post.publish` | `sends` | Publish something where the public can see it. |
| `provared.calendar.read` | `reads` | Read a calendar. |
| `provared.calendar.change` | `changes` | Add, move or remove an entry in a calendar. |
| `provared.booking.make` | `commits` | Book a place, a time or a service. |
| `provared.booking.cancel` | `commits` | Cancel a booking. |
| `provared.order.place` | `commits` | Place an order for goods or services. |
| `provared.order.cancel` | `commits` | Cancel an order. |
| `provared.terms.accept` | `commits` | Accept terms, or sign an agreement. |
| `provared.form.submit` | `commits` | Submit a form or an application. |
| `provared.account.create` | `commits` | Open an account. |
| `provared.account.sign-in` | `enters` | Sign in to an account or a system. |
| `provared.access.grant` | `grants` | Give a person or a program access. |
| `provared.access.remove` | `changes` | Take access away from a person or a program. |
| `provared.key.create` | `grants` | Make a key or a password that gives access. |
| `provared.code.read` | `reads` | Read the source of a program. |
| `provared.code.change` | `changes` | Change the source of a program. |
| `provared.code.run` | `runs` | Run a program or a command. |
| `provared.code.release` | `runs` | Put a program into live use. |
| `provared.system.configure` | `changes` | Change the settings of a system. |
| `provared.web.read` | `reads` | Read a public web page. |
| `provared.agent.instruct` | `sends` | Hand a task to another agent. |

The rules of conduct that a slip's `never`, or a service's terms, may
state:

| Rule | Meaning |
|---|---|
| `impersonate` | Never claim to be a human being, or to be anyone other than the agent of the person who signed the slip. |
| `bypass` | Never go around an access control, a block or a refusal. |
| `escalate` | Never obtain or use access that it was not given. |
| `conceal` | Never hide, alter or leave out its own records. |
| `deceive` | Never state what it has reason to believe is false, and never make up a record or a result. |
| `harass` | Never threaten, pressure or attack a person. |
| `disclose` | Never pass information that is not public to anyone the slip does not name. |
| `continue-after-stop` | Never carry on after being told to stop. |

A `never` list MAY hold the name of any kind of action and of any rule of
conduct above.

## 17. The approval

A slip may ask for the person's own approval of an action (section 4.1).
The person gives it with the same passkey that signed the slip.

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.approval.v0` |
| `id` | Unique number | Section 3.7 |
| `slip` | The slip | The slip's fingerprint |
| `action` | What is approved | An action name |
| `amount`, `with`, `details` | Optional | As in a stub (section 5.1) |
| `when` | When it was given | A time |

It is signed as a slip is (sections 4.2 and 4.3), with the approval label
of section 3.2. An approval is for exactly one action. The stub names it
by its fingerprint, in `approval`, and the approval is kept on the same
line of the book as the stub.

A checker MUST confirm all of these, and otherwise report a problem:

1. The approval's fingerprint is the one the stub names
   (`approval-mismatch`; a stub that names an approval which is not with
   it: `approval-not-found`).
2. Its `slip` is the stub's `slip`, and its `action`, `amount`, `with` and
   `details` are each the same as the stub's, or absent from both
   (`approval-mismatch`).
3. Its `id` is not the `id` of an approval on an earlier line
   (`approval-reused`), nor of any other record (`duplicate-id`). Single
   pages cannot show this.
4. The passkey signature checks, by the steps of section 4.4, against the
   `issuer` of the slip (`approval-invalid`).
5. Its `when` is not more than 300 seconds after the stub's `when`
   (`approval-dated-after-stub`). The stub names the approval, so the
   stub was signed after the approval was written.

## 18. The refusal

A service that refuses what an agent asked for may say so in a record of
its own. It leaves evidence of the attempt even if the agent's own record
is silent.

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.refusal.v0` |
| `id` | Unique number | Section 3.7 |
| `slip` | The slip the agent showed | The slip's fingerprint |
| `by` | Who refused | `{"keys": key set, "name": text}` |
| `action` | What the agent asked for | An action name. A name that begins `provared.` need not be on the shared list here: what was asked for is written down as it was asked |
| `amount` | Optional | `{"unit": text, "value": whole number}` |
| `reason` | Why | One of the names below |
| `when` | When | A time |

| Reason | Meaning |
|---|---|
| `not-in-slip` | The slip does not cover the action, or does not name this service. |
| `over-limit` | The action would pass a limit of the slip. |
| `outside-valid-time` | The slip was not in force at that time. |
| `slip-not-sound` | The slip did not pass its check. |
| `needs-approval` | The slip asks for the person's approval, and none was shown. |
| `against-terms` | The service's terms for agents do not accept the action. |
| `other` | Another reason. |

It is signed with the key set in `by`, with the refusal labels of section
3.2. A checker MUST confirm both signatures against `by.keys`, and MUST
say whether those keys are the keys the slip gives for one of its
services, or the keys of a party the slip does not name.

A refusal is one-sided: it is the service's statement. A checker MUST show
it as such, and MUST NOT count it as the agent going outside its slip.

## 19. A service's terms for agents

A service may state which actions it accepts from agents.

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.terms.v0` |
| `id` | Unique number | Section 3.7 |
| `by` | Whose terms | `{"keys": key set, "name": text}` |
| `accepts` | The actions it accepts | A list of 1 to 64 action names, none repeated |
| `never` | What it asks of agents | A list of 0 to 16 names from section 16, none repeated |
| `validFrom`, `validUntil` | When the terms are in force | Times; the second later than the first |

Terms MUST NOT accept a shared action of a kind that their own `never`
forbids. A rule of conduct in `never` is what the service asks of agents;
no check can show that an agent kept it.

It is signed with the key set in `by`, with the terms labels of section
3.2. A stub that relied on the terms names their fingerprint in `terms`.
A checker MUST show the fingerprint of the key set that signed a set of
terms or a refusal: the name in `by` is a label.

For such a stub a checker MUST confirm that the terms are earlier in the
book (`terms-not-found`), that they passed their own check
(`terms-unusable`), and that `by.keys` are exactly the keys the slip gives
for the service the stub names (`terms-mismatch`). It then reports
`outside-terms` as section 8 sets out.

How a service publishes its terms, for example at an address on its
website, is not part of this draft.

## 20. The check before acting

The software around an agent may ask, before each action, whether the
action would be outside the slip, and stop the action if so. The answer
MUST come from the same comparison as section 8, made over the book so
far. An action MUST be refused beforehand if, with its stub written, a
checker would report a finding for that stub, or because of it for a
stub dated after it. One case goes further. An action that would fall in
a period (a limit "within a period", section 4.1) which ends at a stub
dated after it, and which already holds more than the limit allows, MUST
be refused as well (`over-period-limit`): it would add to a period that
holds too much. A checker reports nothing new for it, because the
finding stands with the later stub. The answer MUST be that nothing is allowed
(`record-not-sound`) if the book so far has a problem, if any signature
in it could not be checked on that device, or if the check was not told
which issuer keys it trusts. An action dated before the last stub of
its own chain (the agent's, or the helper's under its pass; section 7)
is refused (`time-went-backwards`).

Where the slip asks for the person's approval, the action is allowed
only if the signed approval is handed to the check and passes the checks
of section 17. Where the slip asks for a countersignature, the check
says so: the action is inside the slip only if the other side then
countersigns it. Where the action names no service, or a service for
which the slip gives no keys, no countersignature could be given, and
the action is not allowed (`countersignature-missing`). An action whose
record, with its approval and a countersignature, could be longer than a
line of a book may be (section 9) is not allowed either (`too-large`).

This is a help to whoever runs the agent. It is not evidence: nothing in a
record shows that the check was made.

## 21. The Seal and the outside time-stamp

Whoever keeps a book (the recorder) seals it from time to time. A seal
fixes everything before it. An outside time-stamp on the seal states
when, in words the recorder cannot change afterwards.

### 21.1 The seal

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.seal.v0` |
| `id` | Unique number | Section 3.7 |
| `by` | The recorder | `{"keys": the recorder's three keys, "name": text}` |
| `size` | How many entries the book held | A whole number, 1 or more |
| `root` | The top fingerprint of those entries | A fingerprint (section 10) |
| `previous` | The seal before this one in the book. Absent for the first | That seal's fingerprint |
| `when` | When it was made, as the recorder states | A time |

It is signed with the three keys in `by`, with the seal labels of section
3.2. A seal is added to the book as its next entry, so the seal at entry
number n covers the n entries before it, and the next seal covers this
one too.

A checker that holds the whole book MUST confirm all of these, and
otherwise report a problem:

1. All three signatures check against `by.keys` (`signature-invalid`).
2. `size` is the number of entries before the seal, and `root` is their
   top fingerprint (`seal-mismatch`).
3. `previous` is the fingerprint of the seal before it in the book, and
   is absent if there is none (`seal-chain-broken`).
4. `when` is not earlier than the `when` of the seal before it
   (`time-went-backwards`). `when` is also not more than 300 seconds
   earlier than the latest time stated by an entry it covers that passed
   its own check (`time-went-backwards`): one of the two dates is then
   not as it says. There is one exception. Where the seal has a counted
   time-stamp and that entry states a time more than 300 seconds after
   the time the time-stamp counts as stating, the time-stamp settles
   which date is wrong for that entry: the entry is reported instead
   (section 21.3), and it does not count against the seal. Every other
   entry the seal covers is still compared with the seal's `when`. The
   same rule holds for a seal that comes with a Show, against the Show's
   pages (section 11). The times
   an entry states are its own `when` and the `when` of a
   countersignature or an approval on the same line.
   `when` is also not more than 300 seconds earlier than the latest time
   that a counted time-stamp from a service gave any seal before it
   (`time-went-backwards`). A seal covers the lines of the seals before
   it, time-stamps included, so it cannot have been made before a
   time-stamp that one of those lines holds. Among the pages of a Show,
   and for the seal that comes with a Show, the seals before it are
   those among the pages.
5. If the checker was given the fingerprints of the key sets of the
   recorders it expects, the fingerprint of `by.keys` is one of them
   (`sealer-not-expected`). If it was given none, it MUST say that the
   seal's keys were not compared with keys it trusts.

The **fingerprint of a key set** is the SHA-256 hash of the list of keys
written in the canonical form (section 3.4), in base64url.

### 21.2 The time-stamps

An entry that holds a seal MAY hold, in `stamps`, 1 to 4 time-stamps,
none repeated. There are two kinds. A time-stamp from a service, set out
here, is text. A block time-stamp, set out in section 21.4, is an object.

A time-stamp from a service
is a "TimeStampToken" as RFC 3161, section 2.4.2, sets out, in DER,
written in base64url, of at most 12,288 bytes. What it stamps (its
"message imprint") MUST be the seal's fingerprint: the fingerprint method
SHA-256, and the 32 bytes of the fingerprint. It MUST carry the
certificate of the service that signed it.

A checker reads the time-stamps of a seal only if none of the seal's own
signatures failed. For each time-stamp it MUST confirm all of these, and
otherwise report a problem:

1. It is laid out as RFC 3161 and RFC 5652 set out, in strict DER
   (`stamp-bad-data`). Every part is read, including parts the checker
   does not otherwise use: a whole number or an object identifier that is
   not in its shortest form, a part that does not fill what holds it, or a
   part the standards do not allow in that place, is refused. The signed
   data is of version 3, with exactly one signer. The public key in the
   certificate that signed is written exactly as its own standard sets
   out, with no unused bits: RSA as RFC 3279, section 2.3.1 (empty
   parameters, two positive whole numbers in strict DER and nothing
   after them), ECDSA as RFC 5480, section 2.2 (an uncompressed point),
   Ed25519 as RFC 8410, section 4 (no parameters, 32 bytes).
2. What it stamps is this seal's fingerprint (`stamp-wrong-data`).
3. Its signed attributes name a time-stamp statement, hold the
   fingerprint of the statement, and name the certificate that signed, by
   the "signing certificate" attribute that RFC 3161, section 2.4.2,
   requires (in the form of RFC 5035, or the older form of RFC 2634). The
   time-stamp carries that certificate, and the signature over the
   attributes fits its public key (`stamp-invalid`). A certificate with
   the same key and other contents is another certificate.
4. The fingerprint method used to check the signature is the one the
   signer names (RFC 5652, section 5.4): SHA-256, SHA-384 or SHA-512. A
   signing method that names another one is refused (`stamp-invalid`).
   The signing methods are RSA (PKCS #1 version 1.5; keys of 2,048 to
   8,192 bits, with an odd public number from 3 to 2^32 - 1: never 1,
   under which anyone can make a signature that checks), ECDSA on the
   curves P-256 and P-384, and Ed25519.
5. The time it states lies within the time that certificate is in force
   (`stamp-invalid`).
6. It does not say that its time is exact to no better than more than 300
   seconds, and it carries no extension marked as one that must be
   understood (`stamp-invalid`).
7. If it is counted (below): the seal's `when` is not more than 300
   seconds after the time it states (`dated-after-stamp`). A block
   time-stamp that section 21.3 sets aside is the one exception.

The time a time-stamp states is taken to the second, rounded down.

**Whom to trust is the checker's choice.** The person checking gives the
fingerprint (SHA-256, in base64url) of the certificate of each time-stamp
service they trust. A time-stamp counts only if the certificate it names
is one of those, and only if all three signatures of the seal were
checked on that device. A sound time-stamp from any other service MUST
be shown as not counted, with the fingerprint of its certificate, and
MUST NOT be treated as a time: it is compared with nothing. This format
names no service.

A checker follows no chain of certificates and asks no outside party. It
does not read what a certificate says its key may be used for: the person
checking decides that by naming the certificate.

### 21.3 What a time-stamp fixes

Every counted time-stamp of a seal is taken, of either kind, and the
earliest time that any of them states is the time by which every entry
before that seal existed. (A block time-stamp states its block's time and
7,200 seconds: section 21.4.) Two cases are set apart. In both, a block
states a time far behind the true time, and a service settles it.

1. Where a seal has a counted time-stamp from a service, a counted block
   time-stamp that states a time more than 300 seconds before the seal's
   own `when`, even with its 7,200 seconds, is set aside: it gives no
   time, and rule 7 of section 21.2 is not applied to it. A checker MUST
   then say that the two do not agree.
2. A counted block time-stamp that states a time, even with its 7,200
   seconds, more than 300 seconds before the latest time that a counted
   time-stamp from a service gave any seal before this one is set aside
   in the same way, whether or not a service's time-stamp stands beside
   it. This seal covers that seal's line, time-stamp included, so it
   cannot have existed by then. A checker MUST say that the block
   time-stamp was set aside. Among the pages of a Show, and for the seal
   that comes with a Show, the seals before it are those among the
   pages.

A time-stamp is counted only if all
three signatures of its seal were checked on that device; where they
were not, a checker MUST say that the time-stamp was not counted, and
MUST NOT report any date against it. More exactly, it shows
that the content of the seal existed then: the time-stamp is made over
the seal's fingerprint, which covers its content and not its signatures.

The time that counts for an entry is the earliest that the counted
time-stamps of any seal after it state: every seal after an entry covers
it. (In section 22, only the seals before the cancellation are taken.) A
checker
MUST report an entry that states a time (its own `when`, or the `when` of
a countersignature or an approval on the same line) more than 300 seconds
later than that (`dated-after-stamp`). The same holds for each page of a
Show that comes with a seal (section 11).

The earliest time that a counted time-stamp from a service gives a seal
MUST NOT be more than 300 seconds earlier than the latest such time that
a service gave any seal before it (`time-went-backwards`). So the times
cannot step backwards a little at a time. A block time-stamp is never
reported under this rule: it is made hours after its seal, and one that
states an earlier time is set aside (the second case above).

A checker that shows an entry's times MUST keep two apart: the time by
which a seal after the entry shows that it existed, and the time that a
seal's or a cancellation's own counted time-stamps give it. A
cancellation does not count from the time of a seal after it (section
22). A checker MUST NOT show a time of the second kind for a seal or a
cancellation that did not pass its check.

A seal shown as a single page of a Show cannot be compared with the
entries before it. A checker MUST confirm that its `size` is the page's
own place in the book (`seal-mismatch`), MUST say that it could not be
compared, and MUST NOT credit its time-stamp to any other page.

Its dates are still held against the other pages. Each page is shown to
be in the book at its place, so where the dates do not fit, the whole
book would fail its check one way or another. A checker MUST report:

- the seal, if a page that comes before it in the book states a time
  more than 300 seconds after the seal's counted time-stamp
  (`dated-after-stamp`). The finding is given for the seal and not for
  that page: either the page's date is not as it says, or the seal does
  not fit the entries before it, and single pages cannot show which;
- the seal, if its `when` is more than 300 seconds earlier than a time
  that a page before it states, where that page is not one of the first
  case (`time-went-backwards`);
- a seal, among the pages or come with the Show, whose `when` is earlier
  than that of a seal among the pages that comes before it in the book,
  or whose counted time-stamp from a service is more than 300 seconds
  earlier than such a seal's (`time-went-backwards`);
- a seal, among the pages or come with the Show, that does not fit the
  chain of seals as far as the pages show it (`seal-chain-broken`): it
  has no `previous` though a seal among the pages comes before it; or
  its `previous` names a seal among the pages that does not come before
  it, or that has another seal among the pages between the two.

A checker MUST say how far the last counted time-stamp reaches, and that
entries after it are not time-stamped.

What a seal and a time-stamp do not fix: the last seal of a book, with
everything after it, can be removed, and what is left still checks. Only
a copy of that seal, or of its top fingerprint and number of entries,
held by someone else shows it. And a time-stamp service signs with a
method of today's kind.

### 21.4 A block time-stamp

A second kind of time-stamp rests on no signature. It is a proof that
the seal's fingerprint was written into a block of a public blockchain.
The chain is used purely as a clock: no coin, no wallet, no account and
no payment is involved in making such a proof or in checking one.

In `stamps` a block time-stamp is the object `{"block": header, "proof":
proof}`, each in base64url:

- `proof` is a proof file of the open format OpenTimestamps, version 1,
  of at most 12,288 bytes;
- `block` is the 80-byte header of a block of the Bitcoin blockchain;
  one of any other length is refused (`stamp-bad-data`).

A proof file holds steps that lead from a fingerprint to a value, and
statements about values. A checker MUST confirm all of these, and
otherwise report a problem:

1. The file begins with these 31 bytes, in hex: `00 4f 70 65 6e 54 69 6d
   65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92
   94`; then the byte `01` (the version); then the byte `08` (SHA-256);
   then 32 bytes, the fingerprint that was stamped (`stamp-bad-data`).
2. Then comes everything that follows from that value. Each thing is a
   statement or a step, and each but the last is preceded by the byte
   `ff` (`stamp-bad-data`):
   - A **statement** is the byte `00`, 8 bytes that say its kind, a
     length, and that many bytes (at most 8,192). The kind `05 88 96 0d
     73 d7 19 01` says "this value is the Merkle root of the block with
     this number"; its bytes are the block's number and nothing more. A
     statement of any other kind is passed over.
   - A **step** makes a new value, and is followed by everything that
     follows from the new value. The byte `08`: the SHA-256 of the
     value. The byte `f0`, a length and that many bytes: the value with
     those bytes joined after it. The byte `f1`, likewise: joined before
     it. A step joins 1 to 4,096 bytes, and no value is longer than 4,096
     bytes. Any other step is refused. (The format also has steps for
     SHA-1, RIPEMD-160 and Keccak-256, and two it no longer uses. Proofs
     made today do not use them.)
   - No more than 255 steps follow one another, as the format's own reader allows.
3. A number (a length, a block's number) is written seven bits to a
   byte, lowest first, with the top bit of a byte saying that another
   follows; in its shortest form only, and in at most 5 bytes
   (`stamp-bad-data`).
4. Nothing follows the end (`stamp-bad-data`).
5. The fingerprint stamped is this seal's fingerprint
   (`stamp-wrong-data`).
6. A statement about a block stands at a value of 32 bytes that equals
   bytes 36 to 67 of the header in `block`, its Merkle root
   (`stamp-invalid`).

**Whom to trust is the checker's choice.** The fingerprint of a block is
SHA-256 taken twice over its 80-byte header, with the bytes then put in
reverse order, in hex: 64 characters, as it is written wherever blocks
are listed. The person checking gives the fingerprints of the blocks
they trust to be part of the chain, at most 100,000. A block time-stamp counts only if it
leads to one of those. One that leads to any other block MUST be shown,
with the block's fingerprint, and MUST NOT be counted. The block's
number in the proof is only what the proof says: nothing checks it, and
a checker that shows it MUST say so.

**Finding which blocks to trust.** A checker MAY take the blocks it
trusts from a chain of block headers that it checks itself, from the
chain's first block, by the rules every Bitcoin node applies to headers
(each names the block before it; its double SHA-256 meets the target its
`bits` state; that target follows the difficulty rule; its time is later
than the middle of the eleven before it, and not more than two hours
ahead of the checker's clock; its version is no lower than the upgrades
of 2013 and 2015 ask from their blocks on). Such a checker MUST also
require that the chain hold blocks known to be part of it, at their
places, and reach the last of them; MUST refuse, after the last of them,
a target more than four times easier than that block's; and MUST count a
block only with at least six blocks after it. This library's checker does so with `--headers`; the known blocks are
listed in `src/headers.js`. A chain file holds the 80-byte headers one
after another, from the chain's first block. Nothing in a record
changes.

**The time.** The time a block states is bytes 68 to 71 of its header: a
whole number of seconds since the start of 1970, lowest byte first. It
is set by whoever made the block, and is right only to within about two
hours. Which way that looseness is taken depends on what is asked, so
that it never works in favour of whoever is being checked:

- For a **seal**, a counted block time-stamp is taken to state that the
  seal existed by the block's stated time **and 7,200 seconds**. That is
  the time used in section 21.3, and for a stub in section 22.
- For a **cancellation** (section 22), which may carry block time-stamps
  in the same way, over the cancellation's fingerprint, a block
  time-stamp gives the block's stated time **less 7,200 seconds**: the
  earliest the proof could have been made. A later time would excuse
  stubs made after the person cancelled. There is one bound. The time
  given is never earlier than the cancellation's own `when`. By the
  person's own signed word the cancellation was not made before its
  `when`, so a stub shown to have existed by then was made before the
  person cancelled. So a cancellation cannot be moved back in time by
  having it put into a block before the date it gives. Where the block's
  stated time and 7,200 seconds is more than 300 seconds before the
  cancellation's `when`, the two do not agree. With no counted
  time-stamp from a service beside it, the cancellation is dated after
  its time-stamp and does not pass (`dated-after-stamp`). With one, the
  service settles it, and a checker MUST say that the two do not agree.

A checker MUST show the time the block states, say that it is right only
to within two hours, and for a cancellation show the time T it used.

A block that states a time more than two hours behind the true time,
which the chain's rules allow in rare cases, would make an honest seal
or entry read as dated after its time-stamp. A counted time-stamp from a
service beside it settles such a case: the service's time is then the
one used. A checker MUST then say that the block time-stamp states a
time more than two hours before the seal's own date: the other reading
is that the seal existed before the date it gives. A counted time-stamp
from a service on a seal earlier in the book settles it too (section
21.3, the second case): without that, such a block would show the
entries of a later seal to have existed earlier than they did.

What a block time-stamp does not fix: that the header is that of a real
block. The person who names a block vouches for that, having compared
its fingerprint with sources they trust. A proof is complete only one to
several hours after it is asked for, so it is an addition to a
time-stamp from a service, not a replacement.

## 22. Cancelling a slip

The person who signed a slip can end it early, with the same passkey.

Content: `{"id": unique number, "slip": the slip's fingerprint, "type":
"provared.cancellation.v0", "when": a time}`. It is signed as a slip is
(sections 4.2 and 4.3), with the cancellation label of section 3.2, and
checked against the `issuer` of the slip it names
(`cancellation-invalid`). The slip MUST be earlier in the book
(`slip-missing`).

The entry that holds a cancellation MAY hold `stamps`: time-stamps over
the cancellation's fingerprint, checked as section 21.2 sets out. The
person can have these made at once, without waiting for the recorder.
A time-stamp is counted only if the passkey signature of the
cancellation, and of its slip, was checked on that device; where it was
not, a checker MUST say that the time-stamp was not counted, and MUST
NOT report any date against it, as for a seal (section 21.3).

What a checker reports, as `after-cancellation` (section 8):

1. Every stub under the slip that comes after the cancellation in the
   book.
2. Where the cancellation has a counted time-stamp, at a time T: every
   stub under the slip that comes before the cancellation in the book,
   unless a counted time-stamp, on a seal that is before the cancellation
   in the book and covers the stub, states a time not more than 300
   seconds after T.

The second rule is strict on purpose. The time an agent writes into a
stub is its own word, so an agent could otherwise escape a cancellation
by writing an earlier time. A stub made honestly just before a
cancellation, and not yet sealed, is reported as "not shown to have
existed before the slip was cancelled", which is exactly what the record
can and cannot show. A recorder that seals often keeps this rare.

Every cancellation of a slip that passes its check counts. The first
rule is applied from the first of them in the book. The second rule is
applied with the earliest time T that a counted time-stamp gives any of
them, to the stubs that come before that cancellation in the book. So
the order in which whoever keeps the book places two cancellations
changes nothing.

**The time T.** Every counted time-stamp beside a cancellation is taken,
of either kind, and T is the earliest time that any of them gives. A
time-stamp from a service gives the time it states. A block time-stamp
gives the time that section 21.4 sets out. So a later time-stamp put
beside an earlier one changes nothing. (Section 21.3 sets out which
time counts for a seal.)

Single pages of a Show apply the first rule only, by the place each page
has in the book: single pages cannot show which seal covered a stub. A
checker MUST say so where a cancellation among the pages has a counted
time-stamp.

The time-stamps stand beside the cancellation, not inside what the
passkey signed. Whoever keeps the book can therefore put a later
time-stamp in the place of an earlier one, and no check can show that.
Where the time T is more than 300 seconds after the cancellation's own
`when`, a checker MUST point it out. (A later time-stamp beside a prompt
one leaves no such gap, and changes nothing.) The person SHOULD keep
their own copy of the cancellation, with its time-stamp.

A cancellation shows when the person signed it and had it time-stamped.
It does not show that the agent, or whoever keeps the book, was told. A
person can keep a cancellation back and hand it over later: every stub
made in between is then reported, though the check before acting allowed
each. Where a checker is handed a copy that the book does not hold, it
cannot show whether the book's keeper left it out or was never given
it, and MUST say so. An acknowledgement from the agent's side (section
26), handed over with the copy, shows that it was given it, and when.

**The person's own copy.** A checker MAY be handed, beside a book, up to
16 cancellations that the person kept, each as the entry it would be in
a book: `{"cancellation": cancellation record}`, with or without
`"stamps"`, and with or without `"acknowledgements"` (section 26). Each
is checked as a cancellation in the book is: against the
`issuer` of the slip it names, which MUST be in the book
(`slip-missing`, `cancellation-invalid`), and its time-stamps as section
21.2 sets out. A copy that does not pass is a problem with the check as
a whole: it is never set aside silently. The same cancellation MUST NOT
be handed over twice (`bad-field`). For a copy that passes:

1. where a counted time-stamp gives it a time T, every stub under the
   slip, wherever it stands in the book, is reported as
   `after-cancellation`, unless a counted time-stamp on a seal that
   covers the stub states a time not more than 300 seconds after T;
2. the check before acting (section 20) allows nothing under the slip;
3. a checker MUST say whether the book holds the same cancellation.

So a cancellation counts even where whoever keeps the book left it out,
and the person's own time-stamp counts even where the book holds the
cancellation with a later one. A copy with no counted time-stamp cannot
be placed in time, and no stub is reported because of it. Single pages
of a Show cannot use a copy, and a checker MUST say so.

## 23. Vouching for a name, and withdrawing

A name in a record is a label. A vouching record lets an organisation
stand behind one: it states that a key belongs to a name.

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.vouching.v0` |
| `id` | Unique number | Section 3.7 |
| `by` | The organisation that vouches | `{"keys": key set, "name": text}` |
| `for` | Whom it vouches for | One of the four forms below |
| `validFrom`, `validUntil` | When the statement holds | Times; the second later than the first |
| `when` | When it was made | A time |

| `for` | Form |
|---|---|
| A person | `{"key": the passkey's public key, "kind": "person", "name": text}` |
| An agent | `{"keys": key set, "kind": "agent", "name": text}` |
| A service | `{"keys": key set, "kind": "service", "name": text}` |
| A recorder | `{"keys": the three keys, "kind": "recorder", "name": text}` |

It is signed with the key set in `by`, with the vouching labels of
section 3.2.

**What it vouches for.** A vouching record stands behind a name in a
later record only if all of these hold: it is earlier in the book; it
passed its own check; it has not been withdrawn earlier in the book; its
`for.kind` fits the place of the name (`person` for the issuer of a
slip; `agent` for its agent, and for the helper agent a pass names in
`to`; `service` for one of its services; `recorder` for the recorder of
a seal); its key or keys are exactly the key or keys that record gives;
its `for.name` is exactly that name; and it is in force for the whole
time of that record. For a slip or a pass that means: its `validFrom` is
not later than the record's `validFrom`, and its `validUntil` is not
earlier than the record's `validUntil`. For a seal: the seal's `when`,
and the time of a counted time-stamp on the seal where there is one, are
not before its `validFrom` and are before its `validUntil`.

A covered name (section 24) that was not revealed is vouched for by
nobody. Where several vouching records stand behind one name, a checker
shows one that counts, if there is one.

**Whom to trust is the checker's choice.** The person checking gives the
fingerprint of the key set (section 21.1) of each organisation whose
vouching they trust. Only a vouching record signed by one of those
counts. A checker MUST show a name as vouched for only then, with the
fingerprint of the organisation's key set. A vouching record from any
other organisation MUST be shown as not counted.

**Withdrawing.** Content: `{"id": unique number, "type":
"provared.withdrawal.v0", "vouching": the vouching record's fingerprint,
"when": a time}`. It is signed with the key set of the organisation that
made the vouching record, with the withdrawal labels: only that
organisation can withdraw. The vouching record MUST be earlier in the
book (`vouching-missing`). From the withdrawal's place in the book
onwards, the vouching record stands behind nothing.

What a vouching record does not show: that the organisation checked well,
or that the organisation is who its own name says. The trust ends at keys
the person checking chose.

## 24. Covered fields

A slip can be shown with its names and its purpose hidden, while
everything about it still checks. The method is that of the standard
"Selective Disclosure for JSON Web Tokens" (RFC 9901): the same
disclosures, the same fingerprints, the same checking steps. A slip uses
less than the standard allows, as this section sets out, so that no two
readers can be shown slips that differ in anything a checker compares.

**What may be covered.** In a slip: `issuer.name`, `agent.name`, the
`name` of each service in `with`, and `purpose`. Nothing else, and
nothing in any other kind of record. An item of a list MUST NOT be
covered anywhere in a slip (the form `{"...": fingerprint}` of RFC 9901,
section 4.2.4.2; `cover-invalid`): a covered limit, condition, action,
service or key would give one reader a different slip from another.

**How a field is covered** (RFC 9901, section 4.2). A disclosure is the
JSON list `[salt, name, value]`, written in base64url, where the salt is
text holding at least 128 random bits. Its fingerprint is the SHA-256
hash of the characters of that base64url text, in base64url. The field
is taken out of its object, and the fingerprint is added to a list named
`_sd` in the same object. Every member of such a list MUST be a SHA-256 fingerprint in base64url,
43 characters (`cover-invalid`). In a slip, each such list holds exactly
one fingerprint: that of the one field that may be covered in that
object. A decoy fingerprint, which the
standard allows, is not accepted, and neither is a list that stands
beside the field it would stand in for (`bad-field`). So a field is
absent only where its fingerprint stands in its place.
A slip's content holds `"_sd_alg": "sha-256"` at the top where it covers
anything, and not otherwise (`bad-field`); no other fingerprint method
is accepted.

The person's passkey signs the content in this covered form. The
fingerprint of the slip, the chain and the tree are worked out from the
covered form, so they are the same for every reader.

**Where disclosures are kept.** Beside the record, not inside a line of
the book: a line is a leaf of the tree, and must be the same for every
reader. A page of a Show MAY hold `"disclosures"`, a list of 1 to 64
disclosures for the slip on that page; a page that is not a slip MUST
NOT hold it (`cover-invalid`). A checker MAY also be handed disclosures
by the fingerprint of the slip they belong to; where no such slip is
among the entries, they are not used and a checker MUST say so. Where a
page holds disclosures and others are handed over for the same slip, all
are used together, and one given both ways counts once.

**Checking** (RFC 9901, section 7.1, steps 3 to 5). A checker MUST:

1. work out the fingerprint of each disclosure handed over;
2. for each fingerprint in an `_sd` list that matches a disclosure, put
   the named field back in that object;
3. refuse (`cover-invalid`) if a fingerprint appears twice in
   the content; if a disclosure matches nothing; if a disclosure is
   handed over twice; if a disclosure is not a list of a salt, a name and
   a value; if its name is `_sd`, `...` or `_sd_alg`; if its name is
   already a field of that object; if an item of a list is covered; or if
   a disclosure, once its base64url is decoded, is not JSON in the
   canonical form of section 3.4;
4. refuse the record (`bad-field`) if an `_sd` list stands anywhere other
   than in the slip itself, its `issuer`, its `agent` or one of its
   services; if such a list does not hold exactly one fingerprint; if the
   field it stands in for is there as well; if a revealed field is not
   the one that may be covered there; or if `_sd_alg` is absent where a
   field is covered, or present where none is;
5. then check the slip as section 4 sets out, with every revealed field
   in place. A field that may be covered is absent exactly where its
   fingerprint stands in its place and no disclosure for it was handed
   over.

**What a slip is does not depend on what is handed over with it.** Where
a slip fails step 3, 4 or 5 with the disclosures handed over, a checker
MUST check it again with no disclosure. If it then passes, the fault
lies in the disclosures: they are not used, every field they would have
revealed stays covered, the slip and the stubs under it are checked as
they would be with no disclosure, and the checker MUST report the
problem as one with what was handed over, so that the check as a whole
is not a pass. Otherwise the signer of a slip could make it sound for a
reader with no disclosure and unsound for a reader with one. Disclosures
handed over in any other form than `{fingerprint of a slip:
[disclosures]}` are refused (`bad-field`).

A fingerprint in an `_sd` list with no disclosure is left alone: the
field is covered. A checker MUST show that fields are covered, and how
many, and MUST NOT show a covered field's place as empty.

The standard allows any JSON in a disclosure. A slip's disclosures are
narrower, as step 3 says: loose JSON (stray spaces, a repeated name, an
unusual escape) could be read in two ways by two checkers.

A checker MUST treat every member name as a plain name. A member named
`__proto__`, for example, is a member like any other: in a slip it is
refused as unknown (`bad-field`), and nothing is ever taken from it.

The standard's key binding (its section 4.3) is not used: a Provared
record is not presented by a holder who must prove possession of a key.

## 25. Passing a slip on to a helper agent

An agent may hand part of its permission to a helper agent, if the slip
allows it. The slip's `passes` says how many times in a row: 1 means the
slip's agent may pass on to a helper; 2 means that helper may pass on
once more; and so on, up to 10. A slip with no `passes` may not be passed on.

Content of a pass:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of record | `provared.pass.v0` |
| `id` | Unique number | Section 3.7 |
| `slip` | The slip | The slip's fingerprint |
| `from` | The pass its writer itself acts under. Absent when the writer is the slip's own agent | That pass's fingerprint |
| `to` | The helper agent | `{"keys": key set, "name": text}` |
| `actions` | What the helper may do | A list of 1 to 64 action names, none repeated |
| `limits` | Limits for the helper | A list of 0 to 64 limits, as in a slip (section 4.1) |
| `validFrom`, `validUntil` | When the pass holds | Times; the second later than the first |
| `when` | When it was written | A time |

A pass is signed with the key set of the agent that passes on: the
slip's `agent.keys`, or, where it names `from`, the `to.keys` of that
pass. A pass MUST come after its slip in the book, and after the pass it
names in `from` (`pass-missing`), and that pass MUST be under the same
slip (`pass-mismatch`). A pass MUST NOT be the eleventh in a row
(`pass-too-deep`): no slip can allow more than ten, and the rule lets
every stub be compared with every pass above its own at a small, fixed
cost. Ten is a first-draft number, taken from the upper number commonly
set for chains of delegated access between services.

A helper's stub names its pass in `pass`, and is signed with the
`to.keys` of that pass. The stubs under one pass form a chain of their
own (section 7).

What a checker reports about a pass:

| Code | Shown when |
|---|---|
| `pass-not-allowed` | The pass is one more in a row than the slip's `passes` allows. Every later pass that names it, and every stub under any of them, is reported too |
| `pass-wider` | An action in `actions` is not one its writer holds (the slip's `actions`, or the `actions` of the pass in `from`), or `validFrom` is earlier, or `validUntil` later, than its writer's own |
| `outside-valid-time` | `when` is outside the time its writer's own permission holds |
| `after-cancellation` | The person had cancelled the slip (section 22) |

What a checker reports about a helper's stub:

1. Everything of section 8, compared with the **slip**, exactly as for
   the slip's own agent. The slip's totals, counts and periods take in
   the stubs of the agent and of every helper together. The slip's
   conditions and stated rules hold for a helper too.
2. Also the findings of section 8 compared with the **pass**, taking its
   `actions`, its `limits` and its times as a slip's, with totals of its
   own.
3. And the same compared with **every pass above it**: the pass that its
   own pass names in `from`, and so on up. The totals of a pass take in
   the stubs written under it and under every pass handed on from it.

A finding with the same code as one that the slip, or a pass nearer the
stub, already gave for the stub is not given twice.

A pass's limits are not compared with the limits of the slip, or of the
pass above it. They need not be: the limits of the slip and of every
pass above always hold for a helper, so passing on cannot widen them.

## 26. Acknowledging a cancellation

A cancellation shows when the person signed it. It does not show that
the agent's side was told (section 22). An acknowledgement closes that
gap from the other side: the agent's own software states that it was
handed the cancellation, and when. The person keeps it with their copy
of the cancellation.

Content:

| Member | Meaning | Form |
|---|---|---|
| `type` | The kind of content | `provared.acknowledgement.v0` |
| `id` | A unique number | Section 3.7 |
| `slip` | The slip that was cancelled | A fingerprint |
| `cancellation` | The cancellation that was handed over | A fingerprint |
| `pass` | Optional. For a helper agent: the pass it acts under | A fingerprint |
| `when` | When the cancellation was handed over, as the agent's side states it | A time |

It is signed as a stub is (section 5.2), with the acknowledgement labels
of section 3.2: with the two keys of the agent the slip names or, where
it holds `pass`, with the `to.keys` of that pass
(`signature-invalid`). So it speaks for one agent: the slip's own, or
one helper.

**In a book.** The slip MUST be earlier in the book (`slip-missing`),
and so MUST the pass, under the same slip (`pass-missing`,
`pass-mismatch`). The cancellation it names MUST be earlier in the book,
MUST cancel the same slip, and MUST have passed its own check
(`cancellation-not-found`): that includes a cancellation which a later
seal's time-stamp shows to be dated later than it existed (section
21.3). Among the pages of a Show, the slip, the
pass and the cancellation MUST be among the pages. An acknowledgement in
a book changes nothing that section 22 reports: every stub after the
cancellation is reported already.

No rule ties its `when` to the cancellation's `when`. Each is one
side's own word, and the two clocks may differ: an acknowledgement may
be dated before the date the person's device gave.

**Handed over with the person's own copy.** The entry a checker is
handed for the person's own copy of a cancellation (section 22) MAY hold
`"acknowledgements"`: a list of 1 to 4 acknowledgement records, none
twice (`bad-field`). Each MUST name that cancellation and its slip
(`acknowledgement-mismatch`), and is checked against the keys of the
slip's agent, or of the helper of a pass that the book holds
(`pass-missing`, `signature-invalid`). One that does not pass is a
problem with the check as a whole, and is not used; it MUST be reported,
never set aside silently. The copy of the cancellation itself is still
used: an acknowledgement that does not pass takes nothing from what the
cancellation shows. One that this device could not check is not used,
and a checker MUST say so; that includes every acknowledgement beside a
copy, or under a slip, that this device could not confirm. For each
acknowledgement that passes:

1. a checker MUST show it: who acknowledged (the slip's agent, or which
   helper), and the time it states, as the agent's side's own word;
2. these are reported as `after-cancellation`, whether or not the copy
   has a counted time-stamp:
   - every stub in that agent's own chain (section 7) whose `when` is
     later than the acknowledgement's `when`;
   - every pass that agent wrote (section 25) whose `when` is later
     than the acknowledgement's `when`, every pass handed on from such
     a pass, and every stub under any of them.

   By the agent's own dates each was made after the agent's side was
   told. A checker MUST word this finding so that it can be told apart
   from the finding of section 22 ("not shown to have existed before
   the slip was cancelled");
3. the rule of section 22 is applied first, for every copy handed over,
   whatever order they were handed over in. A stub that it reports keeps
   that finding, which rests on an outside time-stamp; where rule 2
   applies to the stub as well, the finding says so in addition;
4. where the book does not hold the cancellation, a checker MUST say
   that the agent's side acknowledged it, and when. It was then left out
   of the book, or was still to be written into it when the copy of the
   book was made.

What an acknowledgement does not show: when the person cancelled; that
a helper agent was told, where only the slip's own agent acknowledged
(a helper that held its pass before then is not reported under rule 2);
or anything about a stub dated at or before its `when`. Whoever signs
an acknowledgement SHOULD NOT date it before the last stub of its own
chain, nor before a pass that it handed on: either may be dated a little
ahead of the signer's clock, and would otherwise read as made after the
agent's side was told. Where a copy holds several acknowledgements,
what each agent did itself after it was told is settled first, for every
acknowledgement, and then what was done under a pass handed on late: so
the wording of a finding does not depend on their order. Both dates in
rule 2 are the agent's own word: an agent that writes earlier dates into
its stubs escapes rule 2, and is caught only by the time-stamp rule of
section 22. Nothing obliges an agent's side to acknowledge: a
cancellation with no acknowledgement shows nothing about whether the
agent's side was told.

---

Copyright 2026 Pavel Izmaylov. This document is licensed under the
Creative Commons Attribution 4.0 International licence.
