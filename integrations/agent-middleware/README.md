# provared-agent-middleware

**Reads the signed receipts of another project, Agent Middleware (AMW),
and judges them against a Provared permission.** It checks each AMW
record by the gateway's published key, maps what a verified receipt
states onto the fields the Provared checker compares (the action, the
amount, the time, the permit it names), judges a set of receipts against
the slip's actions and limits, and states plainly what such a judgement
cannot show. An AMW receipt is never presented as a Provared receipt.

Status: version 0.1.0, a draft, not yet published. Evidence, not a verdict.

## What AMW is, and what this reads

Agent Middleware (https://github.com/agentmiddleware/agent-middleware)
is a gateway that stands in front of an agent's tools: it issues a
*permit* (what the agent may do) and writes a *receipt* for each call,
both signed with the gateway's own Ed25519 key. This package was written
from AMW's published test data alone (its `spec/test-vectors/` folder at
commit 326341c, under the Apache License 2.0), read as data, and from
the published standards. No AMW program was read or run.

It reads AMW's envelope form: `{receipt_id or permit_id, kid, alg,
canonicalization, signing_input, signature}`, where `signing_input` is
the exact signed text and the key list is `{"keys": [{kid, alg, status,
public_key_b64 or jwk}]}`.

## Use

```js
import { judgeReceipts } from 'provared-agent-middleware';

const result = await judgeReceipts({
  slip,                              // the Provared permission the person signed
  issuerKeys: ['<thumbprint>'],      // the passkey you trust, as for the checker
  keys,                              // AMW's published key list
  receipts,                          // the AMW receipt envelopes
  permits,                           // the AMW permits they name, if you hold them (optional)
  service: 'amw',                    // the id in the slip's "with" that is the AMW gateway
  tools: { 'golden-path-echo': 'echo' },   // AMW tool name to action name (optional)
  credits: { unit: 'credits', decimals: 2 },  // how AMW's credits are read as an amount
});
```

Or on the command line, from a copy of the repository, in its top folder:

```
node integrations/agent-middleware/bin.mjs verify --keys keys.json --receipt receipt.json
node --import ./integrations/agent-middleware/test/local-library.mjs integrations/agent-middleware/bin.mjs judge --slip slip.json --keys keys.json --receipts receipts.json --service amw --issuer-key <thumbprint> --credits credits:2
```

`verify` needs Node.js alone. `judge` needs the library `provared` at a
version after 0.6.0 (`peerDependencies`: `>0.6.0 <0.8.0`), which is not
yet on npm; until it is, the `--import` above points the name `provared`
at the copy of the repository you are in, as the tests do. The package
pins no other version of the library.

The command ends with code 0 only where every receipt verified, every
one was compared (none refused by the gateway, none of another outcome,
none handed over twice) and found within the slip (and within the AMW
permits where they were handed over), no condition of the slip that
applies to a receipt was left unjudged, and the judgement rests on a
passkey you named; 1 where it is sound as far as it goes but not that; 2
where nothing could be judged. What a record or a key list says is shown
with control characters and characters that cannot be seen replaced by a
mark, as the Provared checker shows it; with `--json`, they are written
as escapes.

### The slip

The slip is checked exactly as the Provared checker checks it. It must
name the AMW gateway among its services (`with`); the `service` option
says which. Where the slip sets any limit or condition on an amount, you
must say how AMW's credits (a decimal written as text, such as `"2.5"`)
are read as a whole-number amount: the slip's unit and the number of
decimal places. Nothing is rounded: `"2.5"` with two decimal places is
`250`; `"2.555"` cannot be read, and where a limit needs the amount that
is the finding `amount-missing`.

### What is judged

Only a receipt that verifies and whose outcome is `success` is compared,
in order of its `created_at` time. Times are compared to the nanosecond,
with every digit of the fraction the gateway wrote (up to nine), so two
receipts 3,599.9996 seconds apart fall in the same hour. A receipt handed
over twice (the same `receipt_id` in the signed content) is counted once:
the first copy is compared, and each later one is listed with
`kind: "duplicate"` and `duplicateOf` (the place of the first), not
compared, with a note that says whether it is the same record or another
record the gateway signed with that identifier. The slip's rules are
applied with the checker's own arithmetic and its own finding codes:

- `action-not-allowed`: the tool (or the action it is mapped to) is not
  in the slip's actions;
- `prohibited`: the action is a shared action of a kind the slip's
  `never` list forbids;
- `outside-valid-time`: the receipt is dated outside the slip's time;
- `over-limit`, `over-each-limit`, `over-count-limit`,
  `over-period-limit`: the slip's limits, with totals and counts over the
  receipts handed over, and periods counted back from each receipt;
- `amount-missing`: the slip needs an amount and the receipt's credits
  give none in that unit;
- `approval-missing`: the slip asks for the person's approval and the
  receipt names no `approval_id`.

The words of every finding say "AMW receipt", never "stub".

Two conditions of a slip cannot be judged from an AMW receipt: a
countersignature by the service, and the person's approval where the
receipt names an `approval_id` (an identifier, not a signed approval).
Where either applies to a compared receipt, the receipt lists it in its
own `notJudged`, and it is never said to be within the slip:
`summary.withinSlip` is `false` where any compared receipt has a finding,
otherwise `null` (not known) where any compared receipt has a condition
not judged (`summary.notJudged` counts them), and `true` only where
neither holds. The command never ends with 0 while one is not judged.

A receipt whose outcome is `denied` is the gateway's statement that it
refused the call: it is listed, not compared, and never counted against
the agent, as a Provared denial would be. A receipt that does not verify
is listed with its place in what was handed over, its status and its
reason only: what it says is not shown, and neither is its identifier
(`id` is `null`), since the envelope's identifier is not signed.

Where you hand over the AMW permits, each verified receipt is also held
against the permit it names, as the gateway's own statement: codes of
this reader's own, `amw-permit-not-handed-over`, `amw-permit-not-active`,
`amw-permit-tool-not-allowed`, `amw-permit-not-in-force` and
`amw-permit-subject-differs`. These change nothing about the slip.

### What cannot be judged

Every answer carries this list (`cannotShow`):

- **No chain.** An AMW receipt names no earlier receipt and no place in a
  sequence, so a receipt left out, a set cut short at either end, or a
  receipt never written does not show. Totals and counts are over the
  receipts handed over, which may not be all of them.
- **No countersignature.** An AMW receipt is signed by the gateway alone.
  A slip condition that asks for the service's countersignature is not
  judged (`notJudged`), and a receipt it applies to is never said to be
  within the slip.
- **No signature of the person on the AMW permit.** It is signed by the
  gateway's key. What the person allowed rests on the Provared slip.
- **Approvals by identifier only.** No signed approval can be checked. A
  receipt that names none is a finding; one that names an identifier is
  not judged, and is never said to be within the slip.
- **Which agent.** AMW names the agent by a wallet identifier; the slip
  by its keys. Nothing ties the two.
- **With whom.** No party beyond the gateway is named.
- **The gateway's word.** The outcome, tool, amount and time are what the
  gateway wrote; the signature shows who wrote them, not that they are
  true.
- **No cancellation.** A cancellation of the slip cannot be handed to
  this reader, so a receipt dated after the person cancelled the slip is
  not shown as such.
- **Only successes are counted.** A receipt whose outcome is not
  `success` is left out of every total, count and period, even where the
  gateway charged credits for it.
- **Retired keys.** A key marked `retired` still checks a receipt of any
  date; when it was retired is not known here.

### Carrying an AMW receipt in a Provared receipt

`receiptDocument(bundle)` gives `{name: 'agent-middleware.receipt',
sha256}`, the fingerprint of the AMW envelope, as handed over, in the one
form of RFC 8785, for a Provared receipt's `details`. Whoever keeps the
AMW receipt can then show it is the one the Provared receipt named.
Comparing a book's receipts with AMW receipts by these fingerprints is
not built. The fingerprint covers the whole envelope, signature included,
and is kept so (not changed to the signed content alone): for an Ed25519
receipt the signature has one form, since S must be below the group order
and the base64 must be strict. A P-256 signature does not: anyone
holding a valid one can make a second valid signature over the same text
by replacing S with the group order less S, so one P-256 receipt can have
two envelope fingerprints.
P-256 receipts never verify here (they read `unsupported`), but
`receiptDocument` does not check, so do not rely on its fingerprint being
unique for one.

## The answer

`judgeReceipts` gives an object with: `judged` (whether anything was
judged); `problems` (why not); `slip` (the checker's answer for the
slip); `permits` and `receipts` (one item each, in the order handed over,
with `place`, `id` (`null` unless the record verified), `status`,
`reason`, `compared`, `kind` (`action`, `denied`, `other` or
`duplicate`), `tool`, `action`, `when`, `amount`, `permit`, `approval`,
`duplicateOf`, `findings`, `permitFindings`, `notJudged`, `notes`);
`notJudged` (the conditions the slip sets that this reader cannot judge,
whether or not they apply to a receipt); `summary` (`handed`,
`byStatus`, `compared`, `denied`, `duplicates`, `notCompared`,
`notJudged`, `withinSlip`, `withinPermits`, `trusted`); and `cannotShow`.

## The signature check (`verify.mjs`)

`verifyRecord(bundle, keys, kind)` answers with one of AMW's own six
words, in this order of precedence: `malformed` (not an envelope; the
signed text not well-formed Unicode text, not a JSON object, or naming
one member twice in one object; the content's `kid` present and not
text; the signature not strict base64 or of the wrong length),
`unknown_key` (the key named is absent, or its status is not `active` or
`retired`, or it cannot be read), `unsupported` (a key method this reader
cannot check at all), `invalid` (the signature does not fit),
`unsupported` (the signature fits, but the key's own method is not
Ed25519, or the signed content names a method other than Ed25519 or a
form other than `awi-canonical-json/1`), `mismatch` (the envelope's id,
`kid`, `alg` or `canonicalization` differs from the signed content),
`verified`. The key is found by the `kid` in the signed content, or the
envelope's where the content has none. A raw key of 32 bytes in
`public_key_b64` is used first, else the JSON Web Key. An Ed25519
signature whose S is not below the group order is refused (RFC 8032,
section 5.1.7). A key whose `alg` is `ECDSA-P256-SHA256` (a P-256 key in
`public_key_b64`, DER) is used to check the signature over SHA-256 in
DER form, so that a changed record reads `invalid`; where the signature
fits, the answer is `unsupported` whatever method the content or the
envelope names, as AMW's data expects, and the record's content is not
given back.

These rules reproduce every expected answer in AMW's 96 published cases
(`test/vectors/`). Where AMW's own verifier does something that data does
not show, this reader may differ; nothing here is AMW's code.

## Limits of this reader

- Zero runtime dependencies beyond `provared` and Node.js's own
  cryptography. Nothing is sent anywhere.
- The eight Ed25519 public keys of small order are not refused here; the
  Provared library refuses them in its own records.
- A tool name that is not in the form of a Provared action name cannot
  be allowed by any slip, and is reported as `action-not-allowed` without
  being quoted.
- An Ed25519 signature whose S is not below the group order is refused
  by this reader and also by Node.js itself, so no test can show that
  this reader's own check is needed while Node.js refuses them.

## Licence

The code is under the Apache License 2.0 (`LICENSE`); this document under
Creative Commons Attribution 4.0 (`LICENSE-CC-BY-4.0.txt`). The test data
under `test/vectors/` is AMW's, under its Apache License 2.0; see the
notice there.
