// What is refused, and what is reported: one test for every code in the
// table of docs/threat-model.md, section 8. A last test reads that table and
// fails if a code there has no test here, or the other way round.
//
// Every case goes through the public interface: checkBook or checkShow.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { checkBook, checkShow, checkSlip, entryLine, generateKeySet, makeShow, prepareSlip, writeBook, writeStub } from '../src/index.js';
import { makeWorld, withContent } from './helpers/world.mjs';

const b64 = (text) => Buffer.from(text).toString('base64url');

/** Every code in a result: on the book, on its entries, and what the entries show. */
function allCodes(result) {
  const codes = result.problems.map((p) => p.code);
  for (const e of result.entries) {
    for (const p of e.problems) codes.push(p.code);
    for (const p of e.breaches) codes.push(p.code);
  }
  return codes;
}

/** A world with three stubs in its book. */
async function three(o) {
  const w = await makeWorld(o);
  await w.add();
  await w.add();
  await w.add();
  return w;
}

// Each case builds a record a checker must refuse, and returns the result.
const REFUSED = {
  'not-json': async () => {
    const w = await three();
    return checkBook(w.book() + 'this line is not JSON\n');
  },
  'bad-envelope': async () => {
    const w = await makeWorld();
    return checkBook(writeBook([{ slip: { ...w.slip, extra: 'x' } }]));
  },
  'bad-base64url': async () => {
    const w = await three();
    const stub = structuredClone(w.entries[1].stub);
    stub.signatures[0].signature += '=';
    w.entries[1] = { ...w.entries[1], stub };
    return checkBook(w.book());
  },
  'too-large': async () => {
    const w = await makeWorld();
    return checkBook(writeBook([{ slip: { ...w.slip, payload: 'A'.repeat(70000) } }]));
  },
  'unknown-type': async () => {
    const w = await three();
    const stub = structuredClone(w.entries[1].stub);
    stub.signatures[0].protected = b64('{"typ":"vnd.provared.stub.v1+json","alg":"Ed25519"}');
    w.entries[1] = { ...w.entries[1], stub };
    return checkBook(w.book());
  },
  // The quantum-safe signature taken off: what is left is not a valid stub.
  'bad-signatures-layout': async () => {
    const w = await three();
    const stub = structuredClone(w.entries[1].stub);
    stub.signatures.pop();
    w.entries[1] = { ...w.entries[1], stub };
    return checkBook(w.book());
  },
  // A repeated member name: two checkers could read it in two ways.
  'payload-not-canonical': async () => {
    const w = await three();
    w.entries[1] = {
      ...w.entries[1],
      stub: withContent(w.entries[1].stub, (c) => JSON.stringify(c).replace('{', '{"action":"supplies.cancel",')),
    };
    return checkBook(w.book());
  },
  // A stub presented as a countersignature.
  'payload-type-mismatch': async () => {
    const w = await three();
    w.entries[1] = { stub: w.entries[1].stub, countersignature: w.entries[1].stub };
    return checkBook(w.book());
  },
  'bad-field': async () => {
    const w = await makeWorld();
    return checkBook(writeBook([{ slip: withContent(w.slip, (c) => void (c.extra = 'x')) }]));
  },
  // A slip that names only an Ed25519 key for the agent: no hybrid, no slip.
  'bad-key': async () => {
    const w = await makeWorld();
    return checkBook(writeBook([{ slip: withContent(w.slip, (c) => void c.agent.keys.pop()) }]));
  },
  'signature-invalid': async () => {
    const w = await three();
    w.entries[2] = { ...w.entries[2], stub: withContent(w.entries[2].stub, (c) => void (c.amount.value = 1)) };
    return checkBook(w.book());
  },
  'passkey-wrong-type': async () => {
    const w = await makeWorld({ assertion: { type: 'webauthn.create' } });
    return checkBook(w.book());
  },
  // The slip widened after the person signed it.
  'passkey-challenge-mismatch': async () => {
    const w = await makeWorld();
    return checkBook(writeBook([{ slip: withContent(w.slip, (c) => void (c.limits[0].max = 1000000)) }]));
  },
  'passkey-origin-mismatch': async () => {
    const w = await makeWorld({ assertion: { origin: 'https://elsewhere.example' } });
    return checkBook(w.book());
  },
  'passkey-rpid-mismatch': async () => {
    const w = await makeWorld({ assertion: { rpId: 'elsewhere.example' } });
    return checkBook(w.book());
  },
  'passkey-user-not-present': async () => {
    const w = await makeWorld({ assertion: { flags: 0x04 } });
    return checkBook(w.book());
  },
  'passkey-user-not-verified': async () => {
    const w = await makeWorld({ assertion: { flags: 0x01 } });
    return checkBook(w.book());
  },
  'passkey-bad-data': async () => {
    const w = await makeWorld({ assertion: { extra: new Uint8Array([1, 2, 3]) } });
    return checkBook(w.book());
  },
  'issuer-not-expected': async () => {
    const w = await three();
    return checkBook(w.book(), { issuerKeys: ['A'.repeat(43)] });
  },
  'slip-missing': async () => {
    const w = await three();
    return checkBook(writeBook(w.entries.slice(1)));
  },
  'slip-unusable': async () => {
    const w = await three({ assertion: { flags: 0x01 } });
    return checkBook(w.book());
  },
  // A stub removed from the middle.
  'chain-broken': async () => {
    const w = await three();
    w.entries.splice(2, 1);
    return checkBook(w.book());
  },
  'time-went-backwards': async () => {
    const w = await makeWorld();
    await w.add({ when: Date.parse('2026-10-06T10:00:00Z') });
    await w.add({ when: Date.parse('2026-10-06T09:00:00Z') });
    return checkBook(w.book());
  },
  'duplicate-id': async () => {
    const w = await makeWorld();
    await w.add({ id: 'AAAAAAAAAAAAAAAAAAAAAA' });
    await w.add({ id: 'AAAAAAAAAAAAAAAAAAAAAA' });
    return checkBook(w.book());
  },
  'duplicate-slip': async () => {
    const w = await three();
    w.entries.push({ slip: w.slip });
    return checkBook(w.book());
  },
  'countersignature-invalid': async () => {
    const w = await makeWorld();
    const stranger = await makeWorld();
    await w.add({ countersigner: stranger.service.privateKeys });
    return checkBook(w.book());
  },
  'countersignature-wrong-stub': async () => {
    const w = await three();
    w.entries[2] = { stub: w.entries[2].stub, countersignature: w.entries[1].countersignature };
    return checkBook(w.book());
  },
  'countersignature-not-possible': async () => {
    const w = await makeWorld({ fields: { with: [{ id: 'supplier', name: 'A service with no keys' }] } });
    await w.add();
    return checkBook(w.book());
  },
  // The same entry with its members in another order.
  'line-not-canonical': async () => {
    const w = await three();
    const e = w.entries[1];
    const line = JSON.stringify({ stub: e.stub, countersignature: e.countersignature });
    return checkBook(entryLine(w.entries[0]) + '\n' + line + '\n');
  },
  'unknown-entry': async () => {
    const w = await three();
    return checkBook(w.book() + '{"note":"hello"}\n');
  },
  'proof-invalid': async () => {
    const w = await three();
    const show = await makeShow(w.book(), [0, 2]);
    show.pages[1].entry = entryLine(w.entries[3]);
    return checkShow(show);
  },
  'root-mismatch': async () => {
    const w = await three();
    return checkShow(await makeShow(w.book(), [0, 2]), { expectedRoot: 'A'.repeat(43) });
  },
  // Something the checker itself did not expect: here, a Show whose "pages"
  // cannot even be looked at. It is never a pass.
  'check-failed': async () => {
    const w = await three();
    const show = await makeShow(w.book(), [0]);
    return checkShow(
      Object.defineProperty({ ...show }, 'pages', {
        enumerable: true,
        get() {
          throw new Error('not a list');
        },
      }),
    );
  },
};

Object.assign(REFUSED, {
  'approval-mismatch': async () => {
    const w = await makeWorld();
    // The person approved 10. The agent wrote 90 and put that approval with it.
    await w.add({ value: 90, approve: { amount: { unit: 'GBP', value: 10 } } });
    return checkBook(w.book());
  },
  'approval-reused': async () => {
    const w = await makeWorld();
    const first = await w.add({ approve: true });
    const approvalName = JSON.parse(Buffer.from(first.entry.stub.payload, 'base64url').toString()).approval;
    // One approval is one action: it cannot go with a second, identical one.
    const second = await w.add({ approval: approvalName });
    second.entry.approval = first.entry.approval;
    return checkBook(w.book());
  },
  'approval-invalid': async () => {
    const w = await makeWorld();
    // The device did not confirm the person: "user verified" is not set.
    await w.add({ approve: { assertion: { flags: 0x01 } } });
    return checkBook(w.book());
  },
  'approval-not-found': async () => {
    const w = await makeWorld();
    const a = await w.approve({ slip: w.slipFingerprint, action: 'supplies.order', amount: { unit: 'GBP', value: 10 }, with: 'supplier' });
    await w.add({ approval: a.fingerprint });
    return checkBook(w.book());
  },
  'approval-dated-after-stub': async () => {
    const w = await makeWorld();
    // The approval is dated a day after the stub that names it.
    await w.add({ approve: { when: Date.parse('2026-10-06T09:00:00Z') } });
    return checkBook(w.book());
  },
  'terms-not-found': async () => {
    const w = await makeWorld();
    await w.add({ terms: 'A'.repeat(43) });
    return checkBook(w.book());
  },
  'terms-unusable': async () => {
    const w = await makeWorld();
    const other = await generateKeySet();
    // Signed with keys other than the ones the terms themselves give.
    const terms = await w.publishTerms({ privateKeys: other.privateKeys });
    await w.add({ terms: terms.fingerprint });
    return checkBook(w.book());
  },
  'terms-mismatch': async () => {
    const w = await makeWorld();
    // Sound terms, but from someone other than the service the stub names.
    const terms = await w.publishTerms({ signer: await generateKeySet() });
    await w.add({ terms: terms.fingerprint });
    return checkBook(w.book());
  },
});

// One sealed book serves the cases about seals and time-stamps: a slip,
// two stubs, a seal with a time-stamp, a third stub, a second seal with a
// time-stamp. Signing a seal is slow, so it is made once.
let sealedOnce;
function sealedBook() {
  sealedOnce ??= (async () => {
    const w = await makeWorld();
    await w.add();
    await w.add();
    await w.seal();
    await w.add();
    await w.seal();
    return { w, lines: w.book().split('\n').filter(Boolean), trust: { stampServices: [w.stampService.fingerprint] } };
  })();
  return sealedOnce;
}
const withStamps = (line, stamps) => entryLine({ ...JSON.parse(line), stamps });

Object.assign(REFUSED, {
  'seal-mismatch': async () => {
    const { lines, trust } = await sealedBook();
    // The last stub before the first seal is removed, with nothing after it.
    return checkBook([lines[0], lines[1], lines[3]].join('\n') + '\n', trust);
  },
  'seal-chain-broken': async () => {
    const { lines, trust } = await sealedBook();
    // The first seal is taken out.
    return checkBook(lines.filter((_, i) => i !== 3).join('\n') + '\n', trust);
  },
  'sealer-not-expected': async () => {
    const { lines, trust } = await sealedBook();
    return checkBook(lines.join('\n') + '\n', { ...trust, sealKeys: ['A'.repeat(43)] });
  },
  'dated-after-stamp': async () => {
    const w = await makeWorld();
    await w.add();
    // A seal dated two days after the time its own time-stamp states.
    await w.seal({ when: Date.parse('2026-10-07T09:00:00Z'), stampTime: Date.parse('2026-10-05T12:00:00Z') });
    return checkBook(w.book(), { stampServices: [w.stampService.fingerprint] });
  },
  'stamp-bad-data': async () => {
    const { lines, trust } = await sealedBook();
    return checkBook([...lines.slice(0, 3), withStamps(lines[3], ['AAAA'])].join('\n') + '\n', trust);
  },
  'stamp-wrong-data': async () => {
    const { lines, trust } = await sealedBook();
    // The second seal's time-stamp, put on the first seal.
    return checkBook([...lines.slice(0, 3), withStamps(lines[3], JSON.parse(lines[5]).stamps)].join('\n') + '\n', trust);
  },
  'stamp-invalid': async () => {
    const { lines, trust } = await sealedBook();
    const token = Buffer.from(JSON.parse(lines[3]).stamps[0], 'base64url');
    token[token.length - 1] ^= 1;
    return checkBook([...lines.slice(0, 3), withStamps(lines[3], [token.toString('base64url')])].join('\n') + '\n', trust);
  },
});

Object.assign(REFUSED, {
  'pass-missing': async () => {
    const w = await makeWorld({ fields: { passes: 1 } });
    await w.add({ pass: 'A'.repeat(43) });
    return checkBook(w.book());
  },
  'pass-too-deep': async () => {
    // An eleventh pass in a row: no slip can allow it.
    const w = await makeWorld({ fields: { passes: 10 } });
    let last = await w.pass();
    for (let i = 0; i < 10; i++) last = await w.pass({ from: last.fingerprint, signer: last.helper.privateKeys });
    return checkBook(w.book());
  },
  'pass-mismatch': async () => {
    const w = await makeWorld({ fields: { passes: 1 } });
    const other = await makeWorld({ fields: { passes: 1 } });
    // A pass given under one slip, used for a stub under another.
    const pass = await other.pass();
    w.entries.push(other.entries[0], other.entries[1]);
    await w.add({ pass: pass.fingerprint, signer: pass.helper.privateKeys });
    return checkBook(w.book());
  },
  'cover-invalid': async () => {
    const w = await makeWorld({ cover: ['purpose'] });
    await w.add();
    // A disclosure that belongs to nothing in the slip.
    const forged = b64(JSON.stringify(['salt', 'purpose', 'Buy whatever you like.']));
    return checkBook(w.book(), { disclosures: { [w.slipFingerprint]: [forged] } });
  },
  'cancellation-invalid': async () => {
    const w = await makeWorld();
    await w.add();
    // Somebody else's passkey tries to cancel the slip.
    await w.cancel({ passkey: (await makeWorld()).passkey });
    return checkBook(w.book());
  },
  'cancellation-not-found': async () => {
    const w = await makeWorld();
    const cancel = await w.cancel();
    w.entries.pop();
    await w.acknowledge(cancel.fingerprint);
    return checkBook(w.book());
  },
  'acknowledgement-mismatch': async () => {
    const w = await makeWorld();
    const cancel = await w.cancel();
    const other = await w.cancel();
    w.entries.length = 1;
    const given = await w.acknowledge(other.fingerprint);
    w.entries.pop();
    return checkBook(w.book(), { cancellations: [{ ...cancel.entry, acknowledgements: [given.record] }] });
  },
  'vouching-missing': async () => {
    const w = await makeWorld();
    await w.vouch({ kind: 'agent', keys: w.agent.keys, name: 'Office supplies agent' });
    w.entries.pop();
    await w.withdraw('A'.repeat(43));
    return checkBook(w.book());
  },
});

// Each case builds a sound record that shows the agent outside its slip.
const REPORTED = {
  'action-not-allowed': async () => {
    const w = await makeWorld();
    await w.add({ action: 'supplies.sell', amount: undefined });
    return checkBook(w.book());
  },
  'party-not-allowed': async () => {
    const w = await makeWorld();
    await w.add({ with: 'someone-else', countersigned: false });
    return checkBook(w.book());
  },
  'outside-valid-time': async () => {
    const w = await makeWorld();
    await w.add({ when: Date.parse('2026-10-12T08:00:00Z') });
    return checkBook(w.book());
  },
  'amount-missing': async () => {
    const w = await makeWorld();
    await w.add({ amount: { unit: 'items', value: 1 } });
    return checkBook(w.book());
  },
  'over-limit': async () => {
    const w = await makeWorld();
    await w.add({ value: 150 });
    await w.add({ value: 51 });
    return checkBook(w.book());
  },
  'over-each-limit': async () => {
    const w = await makeWorld({ fields: { limits: [{ action: 'supplies.order', each: 50, unit: 'GBP' }] } });
    await w.add({ value: 50 });
    await w.add({ value: 51 });
    return checkBook(w.book());
  },
  'over-count-limit': async () => {
    const w = await makeWorld({ fields: { limits: [{ action: 'supplies.order', count: 2 }] } });
    await w.add();
    await w.add();
    await w.add();
    return checkBook(w.book());
  },
  'over-period-limit': async () => {
    // No more than 100 in any two hours. The stubs are an hour apart.
    const w = await makeWorld({ fields: { limits: [{ action: 'supplies.order', max: 100, per: 7200, unit: 'GBP' }] } });
    await w.add({ value: 60 });
    await w.add({ value: 60 });
    return checkBook(w.book());
  },
  'countersignature-missing': async () => {
    const w = await makeWorld({ fields: { requires: [{ need: 'countersignature' }] } });
    await w.add();
    await w.add({ countersigned: false });
    return checkBook(w.book());
  },
  'approval-missing': async () => {
    const w = await makeWorld({ fields: { requires: [{ above: 50, action: 'supplies.order', need: 'approval', unit: 'GBP' }] } });
    await w.add({ value: 50 });
    await w.add({ value: 60 });
    return checkBook(w.book());
  },
  prohibited: async () => {
    const w = await makeWorld({ fields: { never: ['destroys'] } });
    await w.add({ action: 'provared.data.delete', amount: undefined });
    return checkBook(w.book());
  },
  'pass-not-allowed': async () => {
    // The slip says nothing about passing on, so it may not be passed on.
    const w = await makeWorld();
    await w.pass();
    return checkBook(w.book());
  },
  'pass-wider': async () => {
    const w = await makeWorld({ fields: { passes: 1 } });
    await w.pass({ actions: ['supplies.order', 'supplies.sell'] });
    return checkBook(w.book());
  },
  'after-cancellation': async () => {
    const w = await makeWorld();
    await w.add();
    await w.cancel();
    await w.add();
    return checkBook(w.book());
  },
  'outside-terms': async () => {
    const w = await makeWorld();
    const terms = await w.publishTerms({ accepts: ['supplies.return'] });
    await w.add({ terms: terms.fingerprint });
    return checkBook(w.book());
  },
};

// An action the slip forbids by kind is, in a slip that checks, also an
// action the slip does not list: both are reported.
const ALSO = { prohibited: ['action-not-allowed'] };

// Codes of the check before acting, which answers in a shape of its own.
// Their tests are in test/limits.test.mjs.
const GUARD = ['record-not-sound'];
// Refused by the check of a chain of block headers, and tested in test/headers.test.mjs.
const HEADERS = ['headers-invalid'];

for (const [code, build] of Object.entries(REFUSED)) {
  test(`refused: ${code}`, async () => {
    const result = await build();
    assert.ok(allCodes(result).includes(code), `expected ${code}, got ${allCodes(result).join(', ') || 'nothing'}`);
    assert.equal(result.summary.intact, false);
    assert.equal(result.summary.problemFound, true);
    assert.equal(result.summary.withinSlips, false);
  });
}

for (const [code, build] of Object.entries(REPORTED)) {
  test(`reported: ${code}`, async () => {
    const result = await build();
    assert.deepEqual(allCodes(result), [...(ALSO[code] ?? []), code]);
    // The record is sound. It is what the record shows that is the finding.
    assert.equal(result.summary.intact, true);
    assert.equal(result.summary.withinSlips, false);
  });
}

test('the table in the threat model and these tests name the same codes', () => {
  const text = readFileSync(new URL('../docs/threat-model.md', import.meta.url), 'utf8');
  const section = text.slice(text.indexOf('## 8.'), text.indexOf('## 9.'));
  const inTable = [...section.matchAll(/^\| `([a-z0-9-]+)` \|/gm)].map((m) => m[1]);
  const here = [...Object.keys(REFUSED), ...Object.keys(REPORTED), ...GUARD, ...HEADERS];
  assert.deepEqual([...inTable].sort(), [...here].sort());
  assert.equal(new Set(inTable).size, inTable.length);
});

// --- further attacks, by the same rule: through the public interface ---

test('a slip changed after signing is refused whichever member is changed', async () => {
  const changes = [
    (c) => void c.actions.push('supplies.sell'),
    (c) => void (c.validUntil = '2027-10-12T08:00:00Z'),
    (c) => void (c.agent.name = 'Another agent'),
    (c) => void (c.purpose = 'Anything at all.'),
    (c) => void c.limits.pop(),
  ];
  for (const change of changes) {
    const w = await makeWorld();
    const result = await checkBook(writeBook([{ slip: withContent(w.slip, change) }]));
    assert.deepEqual(allCodes(result), ['passkey-challenge-mismatch']);
  }
});

test('a slip cannot name another agent\'s keys and keep its signature', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  const result = await checkBook(writeBook([{ slip: withContent(w.slip, (c) => void (c.agent.keys = other.agent.keys)) }]));
  assert.deepEqual(allCodes(result), ['passkey-challenge-mismatch']);
});

test('a passkey signature from one slip does not fit another slip', async () => {
  const w = await makeWorld();
  const again = await makeWorld();
  const mixed = { payload: again.slip.payload, signatures: w.slip.signatures };
  const result = await checkBook(writeBook([{ slip: mixed }]));
  assert.equal(result.summary.intact, false);
});

test('a stub signed by another agent is refused', async () => {
  const w = await makeWorld();
  const other = await makeWorld();
  await w.add({ signer: other.agent.privateKeys });
  assert.deepEqual(allCodes(await checkBook(w.book())), ['signature-invalid']);
});

test('a stub with one good and one wrong signature is refused, whichever is wrong', async () => {
  const other = await makeWorld();
  for (const wrong of [0, 1]) {
    const w = await makeWorld();
    const keys = [...w.agent.privateKeys];
    keys[wrong] = other.agent.privateKeys[wrong];
    await w.add({ signer: keys });
    const result = await checkBook(w.book());
    assert.deepEqual(allCodes(result), ['signature-invalid']);
    assert.equal(result.entries[1].signatures[wrong].state, 'invalid');
    assert.equal(result.entries[1].signatures[1 - wrong].state, 'valid');
  }
});

test('the two signatures of a stub cannot be swapped', async () => {
  const w = await three();
  const stub = structuredClone(w.entries[1].stub);
  stub.signatures.reverse();
  w.entries[1] = { ...w.entries[1], stub };
  assert.ok(allCodes(await checkBook(w.book())).includes('bad-signatures-layout'));
});

test('a countersignature cannot stand in for the agent\'s signature', async () => {
  // The service signs the stub's own content, but under its own label.
  const w = await three();
  const e = w.entries[1];
  const forged = { payload: e.stub.payload, signatures: e.countersignature.signatures };
  w.entries[1] = { stub: forged };
  assert.ok(allCodes(await checkBook(w.book())).includes('payload-type-mismatch'));
});

test('stubs put in another order break the chain', async () => {
  const w = await three();
  [w.entries[1], w.entries[2]] = [w.entries[2], w.entries[1]];
  assert.ok(allCodes(await checkBook(w.book())).includes('chain-broken'));
});

test('a stub repeated in the book breaks the chain and repeats its number', async () => {
  const w = await three();
  w.entries.splice(2, 0, w.entries[1]);
  const codes = allCodes(await checkBook(w.book()));
  assert.ok(codes.includes('chain-broken'));
  assert.ok(codes.includes('duplicate-id'));
});

test('a stub from one slip does not count under another', async () => {
  const a = await makeWorld();
  const b = await makeWorld();
  await a.add();
  // The stub names slip a. Put it in a book that holds only slip b.
  const result = await checkBook(writeBook([b.entries[0], a.entries[1]]));
  assert.deepEqual(allCodes(result), ['slip-missing']);
});

test('one break in the chain is reported once, not at every later stub', async () => {
  const w = await makeWorld();
  for (let i = 0; i < 5; i++) await w.add();
  w.entries.splice(2, 1);
  const result = await checkBook(w.book());
  assert.deepEqual(allCodes(result), ['chain-broken']);
});

test('the latest stubs under a slip can be removed unnoticed: a stated limit of this draft', async () => {
  const w = await three();
  const cut = await checkBook(writeBook(w.entries.slice(0, 3)));
  assert.equal(cut.summary.intact, true);
  assert.match(cut.summary.limits.join(' '), /the latest stubs under a slip or a pass, or a slip or a pass with all its stubs, could have been removed/);

  // The same is true in the middle of a book that holds two slips: the
  // last stub of the first chain, or the first slip with its whole chain.
  const a = await three();
  const b = await three();
  const all = [...a.entries, ...b.entries];
  assert.equal((await checkBook(writeBook(all))).summary.intact, true);
  assert.equal((await checkBook(writeBook([...a.entries.slice(0, 3), ...b.entries]))).summary.intact, true);
  assert.equal((await checkBook(writeBook(b.entries))).summary.intact, true);
});

test('content that is not what it should be never makes the checker throw', async () => {
  const label = (text) => Buffer.from(text).toString('base64url');
  const stubLabels = ['{"typ":"vnd.provared.stub.v0+json","alg":"Ed25519"}', '{"typ":"vnd.provared.stub.v0+json","alg":"ML-DSA-87"}'];
  const slipLabel = '{"typ":"vnd.provared.slip.v0+json","alg":"prova.red/webauthn/v0"}';
  // Made with no key: the right labels, empty signatures, and a "type" that is not text.
  for (const type of ['{"toString":0}', '{"valueOf":0,"toString":0}', '[]', '[[]]', '7', '{"__proto__":0}', '""']) {
    const payload = label(`{"type":${type}}`);
    const stub = { payload, signatures: stubLabels.map((p) => ({ protected: label(p), signature: '' })) };
    const slip = { payload, signatures: [{ protected: label(slipLabel), header: { authenticatorData: '', clientDataJSON: '' }, signature: '' }] };
    for (const book of [writeBook([{ stub }]), writeBook([{ slip }]), writeBook([{ stub, countersignature: stub }])]) {
      const r = await checkBook(book);
      assert.equal(r.summary.problemFound, true, type);
      assert.equal(r.summary.intact, false);
    }
    assert.equal((await checkSlip(slip)).problems.length, 1);
  }
});

test('an object that throws when it is looked at is reported, not thrown', async () => {
  const hostile = { get payload() { throw new Error('no'); }, signatures: [] };
  const r = await checkSlip(hostile);
  assert.deepEqual(r.problems.map((p) => p.code), ['check-failed']);
  for (const options of [null, 42, 'x']) {
    assert.equal((await checkBook('x\n', options)).summary.problemFound, true);
  }
});

test('the writers refuse to make a record the checker would refuse for its size', async () => {
  const w = await makeWorld();
  // Section 4.1 allows 64 services, but only as many as fit in one record.
  const services = Array.from({ length: 17 }, (_, i) => ({ id: `service-${i}`, name: 'A service', keys: w.service.keys }));
  await assert.rejects(prepareSlip({ ...w.fields, with: services }), (e) => e.code === 'too-large');
  await prepareSlip({ ...w.fields, with: services.slice(0, 11) });
  const details = Array.from({ length: 32 }, (_, i) => ({ name: 'x'.repeat(200), sha256: 'A'.repeat(43) }));
  await writeStub({ slip: w.slipFingerprint, after: null, action: 'supplies.order', details }, w.agent.privateKeys);
});

test('lengths are counted in characters, however a character is stored', async () => {
  const face = '\u{1F600}';
  const ok = await makeWorld({ fields: { purpose: face.repeat(1000) } });
  assert.equal((await checkBook(ok.book())).summary.intact, true);
  await assert.rejects(makeWorld({ fields: { purpose: face.repeat(1001) } }), (e) => e.code === 'bad-field');
  await assert.rejects(makeWorld({ fields: { purpose: '' } }), (e) => e.code === 'bad-field');
});

test('hostile text in a record is carried as text and changes no result', async () => {
  const script = '<img src=x onerror=alert(1)>"\'‮';
  const w = await makeWorld({ fields: { purpose: script } });
  await w.add({ details: [{ name: script, sha256: 'A'.repeat(43) }] });
  const result = await checkBook(w.book());
  assert.equal(result.summary.intact, true);
  assert.equal(result.entries[0].content.purpose, script);
});

test('records that are not objects at all are refused, not crashed on', async () => {
  for (const line of ['null', '42', '"text"', '[]', '{}', '{"slip":null}', '{"slip":[]}', '{"stub":"x"}', '{"slip":{"payload":1,"signatures":[]}}', '{"slip":{"payload":"","signatures":[null]}}', '{"__proto__":{}}']) {
    const result = await checkBook(line + '\n');
    assert.equal(result.summary.intact, false, line);
    assert.equal(result.entries.length, 1);
  }
});

test('a book whose lines end with a carriage return and a line feed is refused', async () => {
  const w = await three();
  const result = await checkBook(w.book().replace(/\n/g, '\r\n'));
  assert.equal(result.summary.intact, false);
});
