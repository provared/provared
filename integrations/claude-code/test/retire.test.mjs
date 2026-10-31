// Retiring a passkey: the recorder takes no new permission from it, with
// or without --new-passkey, while everything it signed stands and limits
// are still counted across the books it signed; "admit-passkey" takes it
// back; a list written before "retired" existed is read as it was; a
// permission superseded before a book was kept cannot be brought back at
// start-up through the completion of a new book; and two changes to the
// list at the same moment lose neither.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

const { checkBook, thumbprint } = await import('provared');
const { developmentPasskey } = await import('provared/dev');
const { readRetired, readTrusted, retirePasskey, startService, writeTrusted } = await import('../recorder.mjs');
const { freePort, refusedStart, runCommand, runHook, signSlip, status, tempFolder, world } = await import('./world.mjs');

const read = (folder, name) => readFileSync(join(folder, name), 'utf8');
const listFile = (folder) => JSON.parse(read(folder, 'trusted-passkeys.json'));

function saveSlip(slip) {
  const file = join(tempFolder('provared-slip-'), 'slip.json');
  writeFileSync(file, JSON.stringify(slip));
  return file;
}

const LIMITS = [{ action: 'provared.code.run', count: 2 }];

test('a retired passkey signs no new permission, even with --new-passkey; what it signed stands, limits are counted across its books, and admitted again it signs', async () => {
  const { folder, passkey: old, agent } = await world(LIMITS);
  const A = await thumbprint(old.key);
  let service = await startService({ folder, port: 0 });
  try {
    // One call under the first permission, then a new book: the receipt is in book-1.jsonl.
    const ask = (port, id) => runHook(port, 'PreToolUse', 'Bash', { command: `npm run ${id}` }, { more: { tool_use_id: id } });
    assert.equal((await ask(service.port, 'one')).out, '', 'one allowed');
    assert.equal((await runHook(service.port, 'PostToolUse', 'Bash', { command: 'npm run one' }, { more: { tool_use_id: 'one' } })).code, 0);
    const made = await runCommand(['new-book'], { folder, port: service.port });
    assert.equal(made.code, 0, made.err);
    assert.ok(existsSync(join(folder, 'book-1.jsonl')));
    assert.deepEqual(readRetired(folder), []);

    // Retired while the service runs: the file says so, and so does status.
    const retired = await runCommand(['retire-passkey', A], { folder, port: service.port });
    assert.equal(retired.code, 0, retired.err);
    assert.match(retired.out, /is retired: the recorder takes no new permission from it, with or without --new-passkey/);
    assert.match(retired.out, /It signed the permission in force/);
    assert.deepEqual(listFile(folder).retired, [A]);
    assert.deepEqual(listFile(folder).passkeys, [A], 'the passkey stays on the list of those in the record');
    assert.deepEqual((await status(service.port)).retired, [A]);
    const again = await runCommand(['retire-passkey', A], { folder, port: service.port });
    assert.equal(again.code, 0);
    assert.match(again.out, /is retired already/);

    // A new permission from the retired passkey is refused, with or without --new-passkey.
    const fromOld = await signSlip({ agentKeys: agent.keys, passkey: old, limits: LIMITS, purpose: 'Signed again with the retired passkey.' });
    for (const args of [['renew', saveSlip(fromOld)], ['renew', saveSlip(fromOld), '--new-passkey']]) {
      const r = await runCommand(args, { folder, port: service.port });
      assert.notEqual(r.code, 0, args.join(' '));
      assert.match(r.out + r.err, /was retired with .*retire-passkey.*, so it is not used, with or without --new-passkey/);
      assert.match(r.out + r.err, new RegExp(`admit-passkey ${A}`));
    }
    assert.equal(read(folder, 'book.jsonl').split('\n').filter((l) => l.startsWith('{"slip":')).length, 1, 'the book holds the first permission only');

    // The recorder still starts, with the permission in force from the retired passkey,
    // and counts the limit across the kept book and the new one: two calls in all.
    await service.close();
    service = await startService({ folder, port: 0 });
    assert.deepEqual((await status(service.port)).retired, [A]);
    assert.deepEqual((await status(service.port)).trusted, [A]);
    assert.equal((await ask(service.port, 'two')).out, '', 'two allowed: the second of two');
    const third = await ask(service.port, 'three');
    assert.notEqual(third.out, '', 'three refused: one is in the kept book, two not yet recorded');
    assert.match(third.out, /over-count-limit/);

    // A passkey the recorder has never seen is taken with --new-passkey, as before.
    const fresh = await developmentPasskey();
    const B = await thumbprint(fresh.key);
    const fromFresh = await signSlip({ agentKeys: agent.keys, passkey: fresh, limits: LIMITS, purpose: 'Signed with a new passkey.' });
    const renewed = await runCommand(['renew', saveSlip(fromFresh), '--new-passkey'], { folder, port: service.port });
    assert.equal(renewed.code, 0, renewed.err);
    assert.deepEqual(listFile(folder).passkeys, [A, B]);
    assert.deepEqual(listFile(folder).retired, [A], 'the renewal kept the retired list');
    assert.deepEqual((await status(service.port)).trusted, [A, B]);

    // Still retired: a further permission from the old passkey is refused; admitted, it is taken without --new-passkey.
    const later = await signSlip({ agentKeys: agent.keys, passkey: old, limits: LIMITS, purpose: 'The retired passkey, once more.' });
    assert.notEqual((await runCommand(['renew', saveSlip(later), '--new-passkey'], { folder, port: service.port })).code, 0);
    const admitted = await runCommand(['admit-passkey', A], { folder, port: service.port });
    assert.equal(admitted.code, 0, admitted.err);
    assert.match(admitted.out, /is admitted again/);
    assert.deepEqual(listFile(folder).retired, []);
    assert.deepEqual(readRetired(folder), []);
    const taken = await runCommand(['renew', saveSlip(later)], { folder, port: service.port });
    assert.equal(taken.code, 0, taken.err);
    assert.doesNotMatch(taken.out, /new passkey/);
    const notRetired = await runCommand(['admit-passkey', A], { folder, port: service.port });
    assert.equal(notRetired.code, 0);
    assert.match(notRetired.out, /is not retired/);

    // The record checks with both passkeys named, whatever was retired on the way.
    for (const name of ['book-1.jsonl', 'book.jsonl']) {
      const result = await checkBook(read(folder, name), { issuerKeys: [A, B] });
      assert.equal(result.summary.intact, true, `${name}: ${JSON.stringify(result.entries.flatMap((e) => e.problems))}`);
    }
  } finally {
    await service.close();
  }
});

test('only a passkey on the list can be retired or admitted; the thumbprint must be one; a folder with no list has nothing to retire', async () => {
  const { folder, passkey } = await world([]);
  const A = await thumbprint(passkey.key);
  const port = await freePort();
  // No list yet: the first "use" (or the first start) writes it.
  const none = await runCommand(['retire-passkey', A], { folder, port });
  assert.notEqual(none.code, 0);
  assert.match(none.out + none.err, /has no list of passkeys yet/);
  const service = await startService({ folder, port: 0 });
  await service.close();
  assert.deepEqual(readTrusted(folder), [A]);
  const other = await thumbprint((await developmentPasskey()).key);
  const notOn = await runCommand(['retire-passkey', other], { folder, port });
  assert.notEqual(notOn.code, 0);
  assert.match(notOn.out + notOn.err, /is not on the list of passkeys whose permissions this recorder has taken/);
  assert.deepEqual(readRetired(folder), []);
  const malformed = await runCommand(['retire-passkey', 'not-a-thumbprint'], { folder, port });
  assert.notEqual(malformed.code, 0);
  assert.match(malformed.out + malformed.err, /named by its thumbprint/);
  assert.equal((await runCommand(['retire-passkey'], { folder, port })).code, 2, 'the usage, with no thumbprint');
  assert.throws(() => retirePasskey(folder, other, false), /nothing to admit/);
  // Retired, the passkey of the permission in force: the recorder starts all the same.
  assert.deepEqual(retirePasskey(folder, A, true), { passkeys: [A], retired: [A], changed: true });
  const started = await startService({ folder, port: 0 });
  assert.deepEqual((await status(started.port)).retired, [A]);
  await started.close();
});

test('a list written before "retired" existed is read as retiring none, and a malformed "retired" stops the recorder', async () => {
  const { folder, passkey, agent } = await world([]);
  const A = await thumbprint(passkey.key);
  // The form every earlier version wrote: "passkeys" alone.
  writeFileSync(join(folder, 'trusted-passkeys.json'), JSON.stringify({ passkeys: [A] }));
  assert.deepEqual(readRetired(folder), []);
  const service = await startService({ folder, port: 0 });
  try {
    assert.deepEqual((await status(service.port)).trusted, [A]);
    assert.deepEqual((await status(service.port)).retired, []);
    // The first change writes the file in the new form, both lists.
    const r = await runCommand(['retire-passkey', A], { folder, port: service.port });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(listFile(folder), { about: listFile(folder).about, passkeys: [A], retired: [A] });
    assert.match(listFile(folder).about, /retire-passkey/);
    // A new permission put in place by hand from the retired passkey is refused at the next start, like one handed to renew.
    const fromOld = await signSlip({ agentKeys: agent.keys, passkey, purpose: 'Put in place by hand.' });
    await service.close();
    writeFileSync(join(folder, 'slip.json'), JSON.stringify(fromOld));
    await refusedStart(startService, { folder, port: 0 }, /was retired with .*retire-passkey/);
  } finally {
    await service.close();
  }
  // "retired" must list thumbprints from "passkeys".
  const other = await thumbprint((await developmentPasskey()).key);
  for (const bad of [{ passkeys: [A], retired: [other] }, { passkeys: [A], retired: 'all' }, { passkeys: [A], retired: ['x'] }]) {
    writeFileSync(join(folder, 'trusted-passkeys.json'), JSON.stringify(bad));
    assert.throws(() => readRetired(folder), /holds "retired", which must be a list of thumbprints from its "passkeys"/);
    await refusedStart(startService, { folder, port: 0 }, /holds "retired"/);
  }
});

test('a permission superseded before a book was kept, from a retired passkey, is not brought back at start-up through the completion of a new book; the permission last in force is', async () => {
  // The reviewer's scenario, where the first permission is not the kept book's last.
  const { folder, passkey: old, agent, slip: s1 } = await world(LIMITS);
  const A = await thumbprint(old.key);
  let service = await startService({ folder, port: 0 });
  const fresh = await developmentPasskey();
  const s2 = await signSlip({ agentKeys: agent.keys, passkey: fresh, limits: LIMITS, purpose: 'The second permission, from a new passkey.' });
  let s2Fingerprint;
  try {
    const s1Fingerprint = (await status(service.port)).slip;
    // Renewed with a new passkey, then the old one retired, then a new book: the kept book holds S1, then S2.
    const renewed = await runCommand(['renew', saveSlip(s2), '--new-passkey'], { folder, port: service.port });
    assert.equal(renewed.code, 0, renewed.err);
    s2Fingerprint = (await status(service.port)).slip;
    assert.notEqual(s2Fingerprint, s1Fingerprint);
    assert.equal((await runCommand(['retire-passkey', A], { folder, port: service.port })).code, 0);
    const made = await runCommand(['new-book'], { folder, port: service.port });
    assert.equal(made.code, 0, made.err);
    const kept = read(folder, 'book-1.jsonl').split('\n').filter((l) => l.startsWith('{"slip":'));
    assert.equal(kept.length, 2, 'the kept book holds both permissions');
  } finally {
    await service.close();
  }
  // Any program on the computer: the book in force emptied, and the superseded S1 put back in place.
  const inForce = read(folder, 'slip.json');
  writeFileSync(join(folder, 'book.jsonl'), '');
  writeFileSync(join(folder, 'slip.json'), JSON.stringify(s1));
  await refusedStart(startService, { folder, port: 0 }, /was retired with .*retire-passkey/);
  // The permission that was in force when the book was kept (S2, the kept book's last) still completes the new book.
  writeFileSync(join(folder, 'slip.json'), inForce);
  service = await startService({ folder, port: 0 });
  try {
    assert.equal((await status(service.port)).slip, s2Fingerprint);
    const first = read(folder, 'book.jsonl').split('\n')[0];
    assert.ok(first.startsWith('{"slip":'), 'the new book begins with the permission in force');
    assert.equal(first, read(folder, 'book-1.jsonl').split('\n').filter((l) => l.startsWith('{"slip":')).at(-1));
  } finally {
    await service.close();
  }
});

test('two changes to the list of passkeys at the same moment: a passkey added while another is retired stays, and a retirement made while a passkey is added stays', async () => {
  const { folder, passkey } = await world([]);
  const A = await thumbprint(passkey.key);
  const service = await startService({ folder, port: 0 });
  await service.close();
  assert.deepEqual(readTrusted(folder), [A]);
  const B = await thumbprint((await developmentPasskey()).key);
  const C = await thumbprint((await developmentPasskey()).key);
  // "retire-passkey A" has read the list ([A]); before it writes, a renewal with --new-passkey adds B.
  const retired = retirePasskey(folder, A, true, { beforeRead: () => writeTrusted(folder, [A, B]) });
  assert.deepEqual(retired, { passkeys: [A, B], retired: [A], changed: true });
  assert.deepEqual(listFile(folder).passkeys, [A, B], 'B was not dropped');
  assert.deepEqual(listFile(folder).retired, [A]);
  // A renewal has read the list ([A, B]) and is about to add C; meanwhile B is retired.
  const added = writeTrusted(folder, [A, B, C], null, { beforeRead: () => retirePasskey(folder, B, true) });
  assert.deepEqual(added, { passkeys: [A, B, C], retired: [A, B] });
  assert.deepEqual(listFile(folder), { about: listFile(folder).about, passkeys: [A, B, C], retired: [A, B] }, 'the retirement was not undone');
  // Admitted while another passkey is added: both changes stay.
  const admitted = retirePasskey(folder, A, false, { beforeRead: () => writeTrusted(folder, [C]) });
  assert.deepEqual(admitted, { passkeys: [A, B, C], retired: [B], changed: true });
  // A list given with fewer passkeys never shortens the file.
  assert.deepEqual(writeTrusted(folder, [A]).passkeys, [A, B, C]);
  // Each write used a temporary file of its own, and none is left behind.
  assert.deepEqual(readdirSync(folder).filter((n) => n.endsWith('.tmp')), []);
});
