// A book sealed by a central sealer (format description, section 21.7):
// the recorder's keys are held by the program in sealer/, the executor
// sends it the leaf fingerprint of each line as the line is written, and
// the sealer signs seals only over what it was sent.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';

const { leafFingerprint } = await import('provared');
const { openWorld, pause, signSlip, tempFolder, until, world } = await import('./world.mjs');
const { httpWorld, openHttpWorld, call } = await import('./http-world.mjs');
const { RECORDER, centralWorld, closeAll, largeAnswer, refusal, sealerFolder, standIn } = await import('./sealer-world.mjs');
const { lockFiles } = await import('../lock.mjs');
const { connectSealer } = await import('../sealer-client.mjs');

// What a failed test left open is closed, so that the file still ends where no time limit ends it.
afterEach(closeAll);
const { checkConfig, readSettings, statusFromFiles } = await import('../executor.mjs');
const { centralSealer } = await import('../sealing.mjs');
const { startSealer } = await import('../../sealer/sealer.mjs');

test('a test\'s world whose executor was never opened closes without an error of its own, so that a start that fails is what the test reports (review 3.2, F5)', async () => {
  // Over stdio there is nothing to close yet.
  const w = await world({ open: false });
  await w.close();
  // Over HTTP the made-up upstream is closed, and no longer listens.
  const h = await httpWorld({ agents: ['alpha'], open: false });
  assert.equal((await fetch(h.settings.upstream.url, { method: 'POST', body: '{}' })).status > 0, true, 'the upstream listens until it is closed');
  await h.close();
  await assert.rejects(fetch(h.settings.upstream.url, { method: 'POST', body: '{}' }));
  // With a central sealer, the same.
  const c = await centralWorld({ open: false });
  try {
    await c.close();
  } finally {
    await c.sealer.stop();
  }
});

/** The status of the link to the sealer, once it says what is wrong. */
const problemShown = (w) =>
  until(async () => {
    const now = (await w.executor.report()).agent.sealer;
    return now.problem ? now : null;
  });

test('central sealer: each line\'s leaf fingerprint is sent as the line is written, and the seal the sealer signs is added to the book', async () => {
  const w = await centralWorld();
  try {
    // At the start the sealer was sent the permission's line, the book's first.
    assert.equal((await w.held()).size, 1);
    await w.client.call('echo', {});
    await w.client.call('echo', {});
    await w.level();
    assert.equal(w.lines().length, 3);
    const shown = (await w.executor.report()).agent.sealer;
    assert.deepEqual(shown, { address: w.settings.recorder.sealer.address, recorder: 'guard-one', unsent: 0, since: null, answeredAt: shown.answeredAt, problem: null });
    assert.ok(Date.now() - Date.parse(shown.answeredAt) < 60000);
    const sealed = await w.executor.seal();
    assert.equal(sealed.entry, 3, 'the permission, two receipts, then the seal');
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[3].kind, 'seal');
    assert.equal(c.entries[3].fingerprint, sealed.fingerprint);
    assert.equal(c.entries[3].content.size, 3);
    assert.deepEqual(c.entries[3].signatures.map((s) => s.state), ['valid', 'valid', 'valid']);
    assert.equal(c.entries[3].content.by.name, 'The test central sealer (invented)', 'the seal gives the sealer\'s own name');
    // The seal's own line is a line of the book like any other: the sealer is sent it too.
    await w.level();
    const held = await w.held();
    assert.equal(held.size, 4);
    assert.equal(held.latest, sealed.fingerprint);
    // A second seal names the first.
    await w.client.call('echo', {});
    const second = await w.executor.seal();
    assert.equal(second.entry, 5);
    const again = await w.checked();
    assert.equal(again.summary.problemFound, false);
    assert.equal(again.entries[5].content.previous, sealed.fingerprint);
    // A reader who names another recorder is told.
    const other = await w.checked({ sealKeys: ['A'.repeat(43)] });
    assert.equal(other.summary.problemFound, true);
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: a restart of the executor goes on from the line the sealer holds, and sends no line twice', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.close();
    assert.equal((await w.held()).size, 2, 'the last line was sent before the executor ended');
    await openWorld(w);
    await w.client.call('echo', {});
    await w.level();
    assert.equal((await w.held()).size, 3);
    await w.executor.seal();
    assert.equal((await w.checked()).summary.problemFound, false);
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: while the sealer is stopped the lines wait in order, the status says how many and since when, no seal is asked for, and they are sent when it answers again', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.level();
    await w.sealer.stop();
    const before = Date.now();
    assert.equal(refusal(await w.client.call('echo', {})), null, 'a call is taken while no more lines are unsent than the settings allow');
    assert.equal(refusal(await w.client.call('echo', {})), null);
    const s = await problemShown(w);
    assert.equal(s.unsent, 2);
    assert.ok(Date.parse(s.since) >= before - 1000 && Date.parse(s.since) <= Date.now(), 'since: when the oldest unsent line was written');
    assert.match(s.problem, /gave no answer that can be used/);
    assert.ok(w.logs.some((e) => e.event === 'sealer-behind'));
    await assert.rejects(w.executor.seal(), /No seal was asked for: the central sealer does not hold every line of the book \(2 not sent\)/);
    assert.equal(w.executor.stopped(), null, 'the agent is not stopped');
    assert.equal((await w.checked()).entries.filter((e) => e.kind === 'seal').length, 0);
    // The sealer starts again. It kept no line that no seal covers, so it stands at the book's first line: every line since is sent again, in order.
    await w.sealer.start();
    assert.equal((await w.held()).size, 1);
    assert.equal(refusal(await w.client.call('echo', {})), null, 'calls go on');
    await w.level();
    const after = (await w.executor.report()).agent.sealer;
    assert.equal(after.unsent, 0);
    assert.equal(after.since, null);
    assert.equal(after.problem, null);
    assert.ok(w.logs.some((e) => e.event === 'sealer-caught-up'));
    const sealed = await w.executor.seal();
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[sealed.entry].content.size, 5, 'the seal covers the permission and the four receipts');
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: a seal asked for just after the sealer started again covers every line, because the sealer is asked what it holds first', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.client.call('echo', {});
    await w.level();
    await w.sealer.stop();
    await w.sealer.start();
    assert.equal((await w.held()).size, 1, 'the sealer stands at the first line again');
    const sealed = await w.executor.seal();
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[sealed.entry].content.size, 3);
    assert.equal(w.executor.stopped(), null);
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: past the limit of unsent lines a call is refused with a denial and not sent, until the sealer has caught up', async () => {
  const w = await centralWorld({ sealer: { maxUnsent: 1 } });
  try {
    await w.sealer.stop();
    assert.equal(refusal(await w.client.call('echo', {})), null);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    const sent = w.fakeSeen().length;
    const refused = refusal(await w.client.call('echo', {}));
    assert.equal(refused.code, 'sealer-behind');
    assert.match(refused.text, /The central sealer has not taken 2 line\(s\) of the book.*more than the settings allow to be unsent/);
    assert.equal(w.fakeSeen().length, sent, 'the call did not reach the tool server');
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'stub', 'denial']);
    assert.equal(c.entries[3].fingerprint, refused.denial);
    assert.equal(c.entries[3].content.source, 'rule');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'sealer-behind'));
    await w.sealer.start();
    await w.level();
    assert.equal(refusal(await w.client.call('echo', {})), null, 'taken again once the sealer holds the lines');
  } finally {
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: with a sealer that takes a question and never answers, no call and no seal waits longer than a question may take', async () => {
  // A limit of 1.5 seconds on a question: past what the disk may hold this process's thread for (sealer-world.mjs). A seal
  // may wait for two questions; the 4.5 seconds allowed below are short of the 5 seconds one question may take unless set.
  const w = await centralWorld({ open: false, sealer: { maxUnsent: 0, timeout: 1500 } });
  let hang = false;
  const fake = await standIn({ token: w.sealer.token, real: w.settings.recorder.sealer.address, answer: (path, body, forward) => (hang ? new Promise(() => {}) : forward()) });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    assert.equal(refusal(await w.client.call('echo', {})), null);
    await w.level();
    hang = true;
    assert.equal(refusal(await w.client.call('echo', {})), null, 'nothing was unsent when this call came');
    let from = Date.now();
    assert.equal(refusal(await w.client.call('echo', {})).code, 'sealer-behind');
    assert.ok(Date.now() - from < 4500, `the call waited ${Date.now() - from} ms`);
    from = Date.now();
    await assert.rejects(w.executor.seal(), /No seal was asked for/);
    assert.ok(Date.now() - from < 4500, `the seal waited ${Date.now() - from} ms`);
    assert.match((await w.executor.report()).agent.sealer.problem, /TimeoutError/);
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: an answer that does not prove it comes from the sealer is not used, and the executor does not start', async () => {
  const w = await centralWorld({ open: false });
  const impostor = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ name: 'An impostor', keys: [], sealer: w.sealer.keySet, held: null }));
    });
  });
  await new Promise((done) => impostor.listen(0, '127.0.0.1', done));
  try {
    w.settings.recorder.sealer.address = `http://127.0.0.1:${impostor.address().port}`;
    await assert.rejects(openWorld(w), /The executor does not start: what the central sealer holds could not be compared with the book file.*did not prove that it comes from the sealer/s);
    assert.equal(existsSync(join(w.folder, 'book.jsonl')), false, 'nothing was written');
    // And with no sealer there at all.
    impostor.closeAllConnections();
    await new Promise((done) => impostor.close(done));
    await assert.rejects(openWorld(w), /The executor does not start.*ECONNREFUSED/s);
    assert.equal(existsSync(join(w.folder, 'book.jsonl')), false);
    // The files are free again: with the real sealer the executor starts.
    w.settings.recorder.sealer.address = `http://127.0.0.1:${w.sealer.port}`;
    await openWorld(w);
    await w.close();
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: a sealer that signs with another key set than the settings name stops the start', async () => {
  const w = await centralWorld({ open: false });
  const fake = await standIn({ token: w.sealer.token, real: w.settings.recorder.sealer.address, answer: async (path, body, forward) => (path === '/about' ? { ...(await forward()), sealer: 'A'.repeat(43) } : forward()) });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer at .* signs with the key set A{43}, and the settings name/);
  } finally {
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: an answer with another number of lines than was sent is not taken as the sealer holding them', async () => {
  const w = await centralWorld({ open: false });
  let wrong = false;
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    // The lines are not handed on, and the answer gives one line more than was sent.
    answer: (path, body, forward) => (wrong && path === '/extend' ? { size: body.at + body.leaves.length + 1 } : forward()),
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    wrong = true;
    await w.client.call('echo', {});
    const s = await problemShown(w);
    assert.equal(s.unsent, 1);
    assert.match(s.problem, /answered with another number of lines than it was sent/);
    await assert.rejects(w.executor.seal(), /No seal was asked for/);
    wrong = false;
    await until(async () => (await w.executor.report()).agent.sealer.unsent === 0);
    assert.equal((await w.held()).size, 2);
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a place the sealer does not hold ("at") makes the executor ask what it holds and send from there; a sealer that never agrees is given up on, and the lines stay unsent', async () => {
  const w = await centralWorld({ open: false });
  let wrong = false;
  let asked = 0;
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: (path, body, forward) => {
      if (!wrong || path !== '/extend') return forward();
      asked += 1;
      return { refused: { code: 'out-of-step', message: 'This sealer holds 1 lines of this book: send the lines from place 1.' }, size: 1 };
    },
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    wrong = true;
    await w.client.call('echo', {});
    const s = await problemShown(w);
    assert.equal(s.unsent, 1);
    assert.match(s.problem, /three times in a row/);
    assert.equal(asked, 4, 'one try, and three more, each after asking what the sealer holds');
    assert.ok(fake.seen.filter((q) => q.path === '/held').length >= 3);
    assert.equal(w.executor.stopped(), null);
    wrong = false;
    await until(async () => (await w.executor.report()).agent.sealer.unsent === 0);
    assert.equal((await w.held()).size, 2);
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a sealer that refuses to sign leaves the book without a seal and the agent at work', async () => {
  const w = await centralWorld({ open: false });
  let refuse = true;
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: (path, body, forward) => (refuse && path === '/seal' ? { refused: { code: 'check-failed', message: 'The sealer could not sign a seal, so it gave none.' } } : forward()),
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    await w.client.call('echo', {});
    await assert.rejects(w.executor.seal(), /The central sealer signed no seal: The sealer could not sign a seal, so it gave none\. \(check-failed\)/);
    assert.equal(w.executor.stopped(), null);
    assert.equal(w.lines().length, 2, 'no seal was added');
    assert.equal(refusal(await w.client.call('echo', {})), null);
    refuse = false;
    const sealed = await w.executor.seal();
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[sealed.entry].content.size, 3);
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a seal the sealer signed whose answer never came is added before any other line; meanwhile no call is taken and no line is written', async () => {
  const w = await centralWorld({ open: false });
  let lose = true;
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: async (path, body, forward) => {
      if (!lose || path !== '/seal') return forward();
      await forward();
      return null;
    },
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    await w.client.call('echo', {});
    await assert.rejects(w.executor.seal(), /The book was not sealed: a seal was asked for, and whether the central sealer signed one is not known/);
    lose = false;
    assert.match(w.executor.stopped(), /No line is written until the sealer has said|signed a seal that the book does not hold yet/);
    const lines = w.lines().length;
    const answer = await w.client.call('echo', {});
    assert.match(answer.error.message, /The executor takes no call/);
    const unlisted = refusal(await w.client.call('no_such_tool', {}));
    assert.equal(unlisted.code, 'unlisted');
    assert.equal(unlisted.denial, null, 'no denial is written before the seal');
    assert.equal(w.lines().length, lines, 'no line was written');
    // The executor asks the sealer again, is handed the seal, and adds it in the agent's turn.
    await until(() => w.executor.stopped() === null, { timeout: 15000 });
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'seal']);
    assert.equal(c.entries[2].fingerprint, (await w.held()).latest);
    assert.equal(refusal(await w.client.call('echo', {})), null, 'calls are taken again');
    await w.level();
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

/**
 * For the tests of one seal that comes two ways (review 3.2, F1): a world
 * whose sealer signs a seal and loses the answer, and whose answer to the
 * executor's own question for that seal ("latest") is held back until the
 * test lets it go. "first(entry)" may change the entry that first answer
 * hands over. Gives the world with "w.asked()", which is true once that
 * question is out, and "w.letGo()".
 */
async function lostSealWorld({ first = (entry) => entry } = {}) {
  const w = await centralWorld({ open: false });
  let lose = true;
  let asked = 0;
  let letGo;
  const held = new Promise((done) => (letGo = done));
  w.fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: async (path, body, forward) => {
      if (path === '/latest') {
        asked += 1;
        if (asked > 1) return forward();
        const real = await forward();
        await held;
        return { latest: { ...real.latest, entry: first(real.latest.entry) } };
      }
      if (!lose || path !== '/seal') return forward();
      await forward();
      lose = false;
      return null; // the sealer signed, and its answer never comes
    },
  });
  w.settings.recorder.sealer.address = w.fake.address;
  w.asked = () => asked >= 1;
  w.letGo = () => letGo();
  await openWorld(w);
  await w.client.call('echo', {});
  await w.level();
  await assert.rejects(w.executor.seal(), /whether the central sealer signed one is not known/);
  return w;
}

test('central sealer: one seal that comes two ways after a lost answer is added once, and the agent stays at work (review 3.2, F1)', async () => {
  const w = await lostSealWorld();
  try {
    // Two seconds after the lost answer the executor asks the sealer itself, and is about to be handed the seal.
    await until(w.asked, { timeout: 30000 });
    // A seal is asked for at that moment: it takes the agent's turn, and is handed the same seal.
    const second = w.executor.seal();
    w.letGo();
    const sealed = await second;
    assert.equal(sealed.entry, 2, 'the permission, one receipt, then the seal');
    // The seal the executor's own question found comes next in the agent's turn. It is in the book already: nothing is
    // added and nothing is wrong. A further seal, which takes the turn after it, covers the first seal's own line.
    const third = await w.executor.seal();
    assert.equal(third.entry, 3);
    assert.equal(w.executor.stopped(), null, 'the agent is not stopped');
    assert.equal(w.logs.some((e) => e.event === 'sealer-disagrees'), false);
    assert.deepEqual(w.logs.filter((e) => e.event === 'sealed').map((e) => e.entry), [2, 3], 'each seal is added once');
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'seal', 'seal']);
    assert.equal(c.entries[2].fingerprint, sealed.fingerprint);
    assert.equal(refusal(await w.client.call('echo', {})), null, 'calls are taken');
    await w.level();
  } finally {
    await w.close();
    await w.fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a seal that differs from the book\'s last line in anything is not passed over as the same seal: the book refuses it and the agent stops (review 3.2, F1)', async () => {
  // The same fingerprint named, another entry: the first answer hands the seal over with a member beside it.
  const changed = await lostSealWorld({ first: (entry) => ({ ...entry, beside: 'not the seal the book holds' }) });
  try {
    await until(changed.asked, { timeout: 30000 });
    const second = changed.executor.seal();
    changed.letGo();
    assert.equal((await second).entry, 2, 'the seal itself is added');
    // The changed one comes next in the agent's turn, with the fingerprint of the seal the book now holds at its end.
    await assert.rejects(changed.executor.seal(), /The agent is stopped: the central sealer signed a seal that the book does not take/);
    assert.ok(changed.logs.some((e) => e.event === 'sealer-disagrees'));
    assert.deepEqual((await changed.checked()).entries.map((e) => e.kind), ['slip', 'stub', 'seal'], 'nothing more was added');
  } finally {
    await changed.close();
    await changed.fake.close();
    await changed.sealer.stop();
  }
});

// The book's own last line handed back as "the latest seal": a receipt, with its own fingerprint named; and the book's
// last seal, with another fingerprint named. Neither is a seal the book lacks, and neither is said to be added.
for (const which of ['a receipt', 'another fingerprint']) {
  test(`central sealer: the book's last line handed back as the sealer's latest seal is not taken as a seal already added: ${which === 'a receipt' ? 'a receipt, named by its own fingerprint' : 'the last seal, named by another fingerprint'} (review 3.2, F1)`, async () => {
    const w = await centralWorld({ open: false });
    let lie = null;
    const fake = await standIn({
      token: w.sealer.token,
      real: w.settings.recorder.sealer.address,
      answer: async (path, body, forward) => {
        if (!lie) return forward();
        if (path === '/held') return { held: { ...(await forward()).held, size: lie.lines, sealed: lie.lines, latest: lie.named } };
        if (path === '/latest') return { latest: { fingerprint: lie.named, entry: lie.entry } };
        return forward();
      },
    });
    try {
      w.settings.recorder.sealer.address = fake.address;
      await openWorld(w);
      await w.client.call('echo', {});
      if (which === 'another fingerprint') await w.executor.seal();
      await w.level();
      const before = w.bookText();
      const last = (await w.checked()).entries.at(-1);
      assert.equal(last.kind, which === 'a receipt' ? 'stub' : 'seal');
      lie = { lines: w.lines().length, entry: JSON.parse(w.lines().at(-1)), named: which === 'a receipt' ? last.fingerprint : 'A'.repeat(43) };
      await assert.rejects(w.executor.seal(), /The agent is stopped: the central sealer signed a seal that the book does not take/, which);
      assert.match(w.executor.stopped(), /the book and what the sealer holds of it do not agree/, which);
      assert.equal(w.bookText(), before, `${which}: the book is as it was`);
      assert.equal(w.logs.filter((e) => e.event === 'sealed').length, which === 'a receipt' ? 0 : 1, `${which}: no seal is said to be added`);
    } finally {
      await w.close();
      await fake.close();
      await w.sealer.stop();
    }
  });
}

test('central sealer: a seal that waits for the agent\'s turn is handed over once, however often the sealer is asked meanwhile (review 3.2, F1)', async () => {
  const w = await centralWorld();
  let link = null;
  let free = () => {};
  try {
    await w.client.call('echo', {});
    await w.level();
    await w.close();
    // The book's own link to the sealer, opened as the executor opens it, with a turn that does not come.
    const fake = await standIn({ token: w.sealer.token, real: w.settings.recorder.sealer.address, answer: (path, body, forward) => forward() });
    const sealer = centralSealer({ address: fake.address, name: RECORDER, token: { file: join(w.folder, 'keys', 'sealer-token') }, keySet: w.sealer.keySet, timeout: 2000, maxUnsent: 100 });
    const handed = [];
    const turn = new Promise((done) => (free = done));
    link = sealer.open({
      first: w.lines()[0],
      takeBack: (entry, named) => {
        handed.push(named);
        return turn;
      },
    });
    await link.start(w.bookText());
    // The sealer signs a seal the book does not take, as after an answer that was lost.
    await w.ask().seal(await w.first(), { previous: null, when: Date.now() });
    const signed = (await w.held()).latest;
    const got = await link.seal(undefined, Date.now());
    assert.equal(got.named, signed, 'a seal asked for is handed the one the sealer signed, with the fingerprint the sealer named');
    // The link now asks the sealer by itself, at once and then every two seconds, and finds the same seal each time.
    const asked = () => fake.seen.filter((q) => q.path === '/latest').length;
    await until(() => asked() >= 4, { timeout: 60000 });
    assert.deepEqual(handed, [signed], 'handed to the agent\'s turn once');
    // Once the turn has come and gone without the seal in the book, it is handed over again.
    free();
    await until(() => handed.length >= 2, { timeout: 60000 });
    assert.equal(handed[1], signed);
  } finally {
    free();
    await link?.end();
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer: a seal the sealer signed that the book never took is added at the next start, before any other line', async () => {
  const w = await centralWorld({ open: false });
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: async (path, body, forward) => {
      if (path !== '/seal') return forward();
      await forward();
      return null;
    },
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    await w.client.call('echo', {});
    await assert.rejects(w.executor.seal(), /whether the central sealer signed one is not known/);
    await w.close();
    assert.equal(w.lines().length, 2, 'the executor ended before the seal was added');
    // A sealer that says it holds a seal and then hands over none: nothing is added, and the executor does not start.
    const empty = await standIn({ token: w.sealer.token, real: `http://127.0.0.1:${w.sealer.port}`, answer: (path, body, forward) => (path === '/latest' ? { latest: null } : forward()) });
    w.settings.recorder.sealer.address = empty.address;
    await assert.rejects(openWorld(w), /The executor does not start: .*The sealer's answer with its latest seal is not in the form its protocol gives/);
    await empty.close();
    assert.equal(w.lines().length, 2);
    // A sealer that names one seal as its latest and hands over a seal under another fingerprint: the same (review 3.2, F4).
    // The seal handed over is the true one, so only the fingerprint beside it tells.
    const misnamed = await standIn({
      token: w.sealer.token,
      real: `http://127.0.0.1:${w.sealer.port}`,
      answer: async (path, body, forward) => {
        if (path !== '/latest') return forward();
        const real = await forward();
        return { latest: { ...real.latest, fingerprint: 'A'.repeat(43) } };
      },
    });
    w.settings.recorder.sealer.address = misnamed.address;
    await assert.rejects(openWorld(w), /The executor does not start: .*The sealer's answer with its latest seal is not in the form its protocol gives/);
    await misnamed.close();
    assert.equal(w.lines().length, 2, 'the seal was not added');
    w.settings.recorder.sealer.address = `http://127.0.0.1:${w.sealer.port}`;
    await openWorld(w);
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'seal']);
    assert.ok(w.logs.some((e) => e.event === 'sealed' && e.by === 'central-sealer'));
    assert.equal(refusal(await w.client.call('echo', {})), null);
  } finally {
    await w.close();
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a book cut short behind the executor\'s back is not started on', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.client.call('echo', {});
    await w.close();
    assert.equal((await w.held()).size, 3);
    const lines = w.lines();
    writeFileSync(join(w.folder, 'book.jsonl'), `${lines.slice(0, 2).join('\n')}\n`);
    assert.equal((await w.checked()).summary.problemFound, false, 'what is left still passes the book\'s own check');
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer holds 3 lines of this book, and the executor has sent it 2 at most: the book file was cut short/);
    assert.equal(w.lines().length, 2, 'nothing was written');
    // From the files, the status says so too.
    const status = await statusFromFiles(w.settings, w.folder);
    assert.equal(status.agent.sealer.holds, 3);
    assert.match(status.agent.sealer.problem, /holds 3 lines of this book, and the book file holds 2/);
    // A new book file under the same permission is a second history of the same first line: not started on either.
    rmSync(join(w.folder, 'book.jsonl'));
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer holds 3 lines of this book, and the executor has sent it 0 at most/);
    assert.equal(existsSync(join(w.folder, 'book.jsonl')), false, 'nothing was written');
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: a book put back to before its seal and written on is not started on; a seal cut off its end is put back from the sealer', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    await w.close();
    const unsealed = w.bookText();
    const copy = readFileSync(join(w.folder, 'copy.jsonl'), 'utf8');
    await openWorld(w);
    const sealed = await w.executor.seal();
    await w.close();
    const whole = w.bookText();
    // The sealer starts again, and stands at its seal.
    await w.sealer.stop();
    await w.sealer.start();
    assert.equal((await w.held()).size, 2);
    // The book as it was before the seal, with another receipt where the seal stood: written by an executor that names no recorder.
    writeFileSync(join(w.folder, 'book.jsonl'), unsealed);
    writeFileSync(join(w.folder, 'copy.jsonl'), copy);
    const central = w.settings.recorder;
    delete w.settings.recorder;
    await openWorld(w);
    await w.client.call('echo', {});
    await w.close();
    w.settings.recorder = central;
    assert.equal((await w.checked()).summary.problemFound, false);
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer's latest seal covers 2 entries and is not in the book, which holds another entry at its place/);
    // The book with only its seal cut off: the sealer hands the seal back, and the book takes it.
    writeFileSync(join(w.folder, 'book.jsonl'), unsealed);
    writeFileSync(join(w.folder, 'copy.jsonl'), copy);
    await openWorld(w);
    assert.equal(w.bookText(), whole, 'the same seal, at its place');
    assert.equal((await w.checked()).entries[2].fingerprint, sealed.fingerprint);
    await w.close();
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: a line changed behind the executor\'s back is found when the seal is added: the book refuses the seal, the agent stops, and the executor does not start again', async () => {
  const w = await centralWorld();
  try {
    await w.close();
    const start = w.bookText();
    const copy = existsSync(join(w.folder, 'copy.jsonl')) ? readFileSync(join(w.folder, 'copy.jsonl'), 'utf8') : '';
    await openWorld(w);
    await w.client.call('echo', {});
    await w.close();
    assert.equal((await w.held()).size, 2);
    // Another receipt in the place of the one the sealer was sent: the book put back, and one call made by an executor that names no recorder.
    writeFileSync(join(w.folder, 'book.jsonl'), start);
    writeFileSync(join(w.folder, 'copy.jsonl'), copy);
    const central = w.settings.recorder;
    delete w.settings.recorder;
    await openWorld(w);
    await w.client.call('echo', {});
    await w.close();
    w.settings.recorder = central;
    assert.equal((await w.checked()).summary.problemFound, false);
    // As many lines as the sealer holds, so the start finds nothing: the sealer sees fingerprints, and gives none back.
    await openWorld(w);
    const lines = w.lines().length;
    await assert.rejects(w.executor.seal(), /The agent is stopped: the central sealer signed a seal that the book does not take/);
    assert.match(w.executor.stopped(), /the book and what the sealer holds of it do not agree/);
    assert.ok(w.logs.some((e) => e.event === 'sealer-disagrees'));
    assert.equal(w.lines().length, lines, 'the seal was not added');
    assert.match((await w.client.call('echo', {})).error.message, /The executor takes no call/);
    await w.close();
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer signed a seal that the book does not take/);
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: a sealer whose record is behind the book\'s seals (lost, or put back to an older one) stops the start', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    const first = await w.executor.seal();
    await w.level();
    const older = readFileSync(join(w.sealer.folder, 'state.json'), 'utf8');
    await w.client.call('echo', {});
    await w.executor.seal();
    await w.close();
    const book = w.bookText();
    // Put back to the state it had at the first seal.
    await w.sealer.stop();
    writeFileSync(join(w.sealer.folder, 'state.json'), older);
    await w.sealer.start();
    assert.equal((await w.held()).latest, first.fingerprint);
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer's latest seal of this book is an earlier one than the book's: its record was lost or put back to an older one/);
    // Lost altogether, and begun again.
    await w.sealer.stop();
    rmSync(join(w.sealer.folder, 'state.json'));
    await w.sealer.start({ fresh: true });
    assert.equal(await w.held(), null);
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer holds nothing of this book, and the book holds a seal of it/);
    // Begun again, and sent the book's first line by another program: it holds the book, and no seal of it.
    const line = w.lines()[0];
    assert.deepEqual(await w.ask().extend(await w.first(), 0, [await leafFingerprint(line)], { line }), { size: 1 });
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer holds no seal of this book, and the book holds one/);
    assert.equal(w.bookText(), book, 'nothing was written');
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: a book that a later book follows at the sealer is not started on', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    const sealed = await w.executor.seal();
    await w.close();
    // Another program with the recorder's token starts the next book with the same permission, and has it sealed.
    const line = w.lines()[0];
    const first = await w.first();
    const next = { first, number: 2 };
    assert.deepEqual(await w.ask().extend(next, 0, [await leafFingerprint(line)], { follows: first, line }), { size: 1 });
    assert.ok((await w.ask().seal(next, { previous: sealed.fingerprint })).entry);
    assert.equal((await w.held()).closed, true);
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer holds a later book that follows this one/);
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: an answer larger than an answer may be is read up to the limit and no further, with its length declared or not (review 3.2, F3)', async () => {
  const MIB = 1024 * 1024;
  const file = join(tempFolder(), 'sealer-token');
  writeFileSync(file, `${randomBytes(32).toString('base64url')}\n`);
  for (const declared of [false, true]) {
    // Whatever listens at the sealer's address, while the sealer is stopped, say: 96 MiB, where an answer may be 8.
    const big = await largeAnswer(96 * MIB, { declared });
    try {
      const sealer = centralSealer({ address: big.address, name: RECORDER, token: { file }, keySet: 'A'.repeat(43), timeout: 30000, maxUnsent: 100 });
      // One question, as the status read from the files asks it.
      const got = await sealer.look('{"a line of a book":1}\n');
      assert.equal(got.reached, false);
      assert.match(got.problem, /The sealer's answer is larger than an answer may be\./, `declared: ${declared}`);
      assert.ok(big.sent() <= 40 * MIB, `declared: ${declared}: the listener handed over ${big.sent()} of its ${96 * MIB} bytes before the connection was given up`);
    } finally {
      await big.close();
    }
  }
});

test('central sealer: an answer that is not in the form the protocol gives is not used', async () => {
  const w = await centralWorld({ open: false });
  let wrong = '/held';
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: (path, body, forward) => {
      if (path !== wrong) return forward();
      if (path === '/about') return { name: 'A sealer', keys: [] };
      if (path === '/held') return { held: { size: 2 } };
      return { size: 'many' };
    },
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await assert.rejects(openWorld(w), /The executor does not start: what the central sealer holds could not be compared with the book file, as a start needs\. The sealer's answer about what it holds of this book is not in the form its protocol gives/);
    wrong = '/extend';
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer has not taken every line of the book\. The central sealer answered with another number of lines than it was sent/);
    wrong = '/about';
    await assert.rejects(openWorld(w), /The executor does not start: .*The sealer's answer about itself is not in the form its protocol gives/);
  } finally {
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a sealer that was not told this agent refuses the book\'s first line, and the executor does not start', async () => {
  const w = await centralWorld({ open: false });
  // A second sealer, whose recorder of the same name is named for another agent's key set.
  const other = await sealerFolder([w.executorKeys]);
  const running = await startSealer({ folder: other.folder, port: other.port });
  try {
    writeFileSync(join(w.folder, 'keys', 'sealer-token'), `${other.token}\n`);
    w.settings.recorder.sealer = { ...w.settings.recorder.sealer, address: running.address, keySet: running.fingerprint };
    await assert.rejects(openWorld(w), /The executor does not start: the central sealer has not taken every line of the book\. The central sealer did not take the lines: .*\(agent-not-allowed\)/);
    const asked = (await import('../sealer-client.mjs')).connectSealer({ address: running.address, recorder: RECORDER, token: other.token });
    assert.equal(await asked.held(await w.first()), null, 'the sealer started no book');
  } finally {
    await running.close();
    await w.sealer.stop();
  }
});

test('central sealer: a seal the book never took, with a permission new to the book: the executor does not start until the seal is in the book', async () => {
  const w = await centralWorld({ open: false });
  const fake = await standIn({
    token: w.sealer.token,
    real: w.settings.recorder.sealer.address,
    answer: async (path, body, forward) => {
      if (path !== '/seal') return forward();
      await forward();
      return null;
    },
  });
  try {
    w.settings.recorder.sealer.address = fake.address;
    await openWorld(w);
    await w.client.call('echo', {});
    await assert.rejects(w.executor.seal(), /whether the central sealer signed one is not known/);
    await w.close();
    w.settings.recorder.sealer.address = `http://127.0.0.1:${w.sealer.port}`;
    const book = w.bookText();
    const slip = readFileSync(join(w.folder, 'slip.json'), 'utf8');
    writeFileSync(join(w.folder, 'slip.json'), JSON.stringify(await signSlip({ passkey: w.passkey, agentKeys: w.agentKeys, executorKeys: w.executorKeys, until: Date.now() + 7200000 })));
    const renewed = readFileSync(join(w.folder, 'slip.json'), 'utf8');
    await assert.rejects(openWorld(w), /The executor does not start: .*the permission in force is new to the book: its line would come before the seal/);
    assert.equal(w.bookText(), book, 'nothing was written');
    // Once with the permission the book last held: the seal is added.
    writeFileSync(join(w.folder, 'slip.json'), slip);
    await openWorld(w);
    await w.close();
    // Then with the new one.
    writeFileSync(join(w.folder, 'slip.json'), renewed);
    await openWorld(w);
    await w.level();
    await w.close();
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.deepEqual(c.entries.map((e) => e.kind), ['slip', 'stub', 'seal', 'slip']);
  } finally {
    await fake.close();
    await w.sealer.stop();
  }
});

test('central sealer: a book with no seal, begun before the settings named a sealer, is sent whole at the first start; one sealed with a key file here is not started on', async () => {
  const w = await centralWorld({ open: false });
  try {
    const central = w.settings.recorder;
    delete w.settings.recorder;
    await openWorld(w);
    await w.client.call('echo', {});
    await w.client.call('echo', {});
    await w.close();
    w.settings.recorder = central;
    assert.equal(await w.held(), null);
    await openWorld(w);
    assert.equal((await w.held()).size, 3, 'every line was sent before the start ended');
    const sealed = await w.executor.seal();
    await w.close();
    const c = await w.checked();
    assert.equal(c.summary.problemFound, false);
    assert.equal(c.entries[sealed.entry].content.size, 3);
  } finally {
    await w.sealer.stop();
  }
  // A book sealed with a key file here: its seal is not the sealer's, so the book does not pass the check the executor makes with the sealer's key set.
  const v = await centralWorld({ open: false });
  try {
    const central = v.settings.recorder;
    const { makeKeyFile } = await import('../files.mjs');
    await makeKeyFile(join(v.folder, 'keys', 'recorder.jwk'), 'recorder');
    v.settings.recorder = { keys: 'keys/recorder.jwk' };
    await openWorld(v);
    await v.client.call('echo', {});
    await v.executor.seal();
    await v.close();
    v.settings.recorder = central;
    await assert.rejects(openWorld(v), /does not pass its check/);
    assert.equal(await v.held(), null, 'the sealer was sent nothing');
  } finally {
    await v.sealer.stop();
  }
});

test('central sealer: the status read from the files asks the sealer how many lines it holds, and says where it cannot be asked', async () => {
  const w = await centralWorld();
  try {
    await w.client.call('echo', {});
    const sealed = await w.executor.seal();
    await w.close();
    let status = await statusFromFiles(w.settings, w.folder);
    assert.deepEqual(status.recorder, { fingerprint: w.sealer.keySet, sealEvery: null, sealer: { address: w.settings.recorder.sealer.address, recorder: 'guard-one', maxUnsent: 100 } });
    assert.deepEqual(status.agent.sealer, { address: w.settings.recorder.sealer.address, recorder: 'guard-one', reached: true, holds: 3, unsent: 0, latestSeal: sealed.fingerprint });
    assert.equal(status.agent.sound, true);
    await w.sealer.stop();
    status = await statusFromFiles(w.settings, w.folder);
    assert.equal(status.agent.sealer.reached, false);
    assert.match(status.agent.sealer.problem, /ECONNREFUSED/);
    assert.equal(status.agent.sound, true, 'the book is still checked');
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: the status read from the files shows nothing held by a sealer that signs with another key set than the settings name (review 3.2, F4)', async () => {
  const w = await centralWorld();
  try {
    // A book with no seal yet, so that the book's own check has nothing to say about the key set.
    await w.client.call('echo', {});
    await w.level();
    await w.close();
    const other = 'A'.repeat(43);
    const status = await statusFromFiles({ ...w.settings, recorder: { sealer: { ...w.settings.recorder.sealer, keySet: other } } }, w.folder);
    assert.equal(status.agent.sound, true);
    assert.equal(status.agent.sealer.reached, false);
    assert.equal(status.agent.sealer.holds, undefined, 'what it holds is not shown');
    assert.match(status.agent.sealer.problem, new RegExp(`signs with the key set ${w.sealer.keySet}, and the settings name ${other}`));
    // The same book and the sealer's own key set: it is asked, and answers.
    assert.equal((await statusFromFiles(w.settings, w.folder)).agent.sealer.holds, 2);
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: the settings name a sealer or a key file, never both; the token is read from a file or the environment and is never in the settings', async () => {
  const w = await centralWorld({ open: false });
  try {
    const central = w.settings.recorder.sealer;
    const problems = (recorder) => readSettings({ ...w.settings, recorder }, w.folder).problems.join('\n');
    assert.equal(problems({ sealer: central }), '');
    assert.match(problems({ sealer: central, keys: 'keys/recorder.jwk' }), /recorder\.keys: must not be named together with recorder\.sealer/);
    assert.match(problems({ sealer: central, name: 'A name' }), /recorder\.name: must not be named together with recorder\.sealer/);
    assert.match(problems({ sealer: { ...central, token: w.sealer.token } }), /recorder\.sealer\.token: must say where the recorder's token is read from/);
    assert.match(problems({ sealer: { ...central, token: { value: w.sealer.token } } }), /recorder\.sealer\.token/);
    assert.match(problems({ sealer: { ...central, token: { file: 'a', env: 'B' } } }), /recorder\.sealer\.token/);
    assert.equal(problems({ sealer: { ...central, token: w.sealer.token } }).includes(w.sealer.token), false, 'a token written in the settings is not repeated');
    assert.match(problems({ sealer: { ...central, address: 'http://192.0.2.1:8797' } }), /recorder\.sealer\.address: must be http:\/\/127\.0\.0\.1:<port>/);
    assert.match(problems({ sealer: { ...central, name: 'Guard One' } }), /recorder\.sealer\.name/);
    assert.match(problems({ sealer: { ...central, keySet: 'short' } }), /recorder\.sealer\.keySet/);
    assert.match(problems({ sealer: { ...central, timeout: 50 } }), /recorder\.sealer\.timeout/);
    assert.match(problems({ sealer: { ...central, maxUnsent: -1 } }), /recorder\.sealer\.maxUnsent/);
    assert.match(problems({ sealer: 'http://127.0.0.1:8797' }), /recorder\.sealer: must be an object/);
    // "keys" reads the settings before recorder.sealer is complete (X157): the sealer gives the token only once it is told
    // the agent's key set, which "keys" makes. Every other reading names what is missing (review 3.2, F4).
    const early = { sealer: { address: central.address } };
    assert.match(problems(early), /recorder\.sealer\.name: .*\n.*recorder\.sealer\.keySet: .*\n.*recorder\.sealer\.token: /);
    assert.deepEqual(readSettings({ ...w.settings, recorder: early }, w.folder, { keysOnly: true }).problems, []);
    assert.equal(readFileSync(w.configPath, 'utf8').includes(w.sealer.token), false, 'the token is not in the settings file');
    // "check" reads the token and asks the sealer nothing.
    await w.sealer.stop();
    let checkedConfig = await checkConfig(w.settings, w.folder);
    assert.deepEqual(checkedConfig.problems, []);
    assert.equal(checkedConfig.warnings.some((x) => /cannot seal/.test(x)), false);
    // A token file that holds something else, or is missing, is a problem.
    writeFileSync(join(w.folder, 'keys', 'sealer-token'), 'not-a-token\n');
    checkedConfig = await checkConfig(w.settings, w.folder);
    assert.match(checkedConfig.problems.join('\n'), /recorder\.sealer\.token: is not a token of the sealer's/);
    assert.equal(checkedConfig.problems.join('\n').includes('not-a-token'), false, 'what the file holds is not repeated');
    rmSync(join(w.folder, 'keys', 'sealer-token'));
    assert.match((await checkConfig(w.settings, w.folder)).problems.join('\n'), /recorder\.sealer\.token: the file .* could not be read \(ENOENT\)/);
    // From the environment.
    await w.sealer.start();
    w.settings.recorder.sealer.token = { env: 'PROVARED_TEST_SEALER_TOKEN' };
    await assert.rejects(openWorld(w), /recorder\.sealer\.token: the variable PROVARED_TEST_SEALER_TOKEN is not set/);
    process.env.PROVARED_TEST_SEALER_TOKEN = w.sealer.token;
    try {
      await openWorld(w);
      await w.client.call('echo', {});
      await w.level();
      await w.close();
    } finally {
      delete process.env.PROVARED_TEST_SEALER_TOKEN;
    }
  } finally {
    await w.sealer.stop();
  }
});

test('central sealer: at the end of a book\'s link, what is unsent is sent in one last try, and nothing is sent after it (review 3.2, F4)', async () => {
  const w = await centralWorld();
  let link = null;
  try {
    await w.client.call('echo', {});
    await w.level();
    await w.close();
    // The book's own link to the sealer, opened as the executor opens it, through a stand-in that can be made to give no answer.
    let away = false;
    const fake = await standIn({ token: w.sealer.token, real: w.settings.recorder.sealer.address, answer: (path, body, forward) => (away ? null : forward()) });
    const sealer = centralSealer({ address: fake.address, name: RECORDER, token: { file: join(w.folder, 'keys', 'sealer-token') }, keySet: w.sealer.keySet, timeout: 20000, maxUnsent: 100 });
    link = sealer.open({ first: w.lines()[0] });
    const text = w.bookText();
    await link.start(text);
    assert.equal((await w.held()).size, 2);
    // A line is written while the sealer gives no answer: it waits, and is to be sent again two seconds on.
    away = true;
    const more = `${text}{"a line":"written while the sealer gave no answer"}\n`;
    link.wrote(more);
    await until(() => link.status().problem !== null, { timeout: 30000 });
    assert.equal(link.status().unsent, 1);
    // The sealer answers again, and the link is ended at once, before that next try: the end sends the line itself.
    away = false;
    await link.end();
    assert.equal((await w.held()).size, 3, 'the line was sent at the end');
    assert.equal(link.status().unsent, 0);
    // After the end nothing is sent, whatever is written.
    const asked = fake.seen.length;
    link.wrote(`${more}{"a line":"written after the end"}\n`);
    await pause(500);
    assert.equal(fake.seen.length, asked, 'no question after the end');
    assert.equal((await w.held()).size, 3);
  } finally {
    await link?.end();
    await w.sealer.stop();
  }
});

/**
 * For the two tests below: a stand-in for the sealer that gives no answer
 * while "away" is true and, while "holding" is true, keeps each question
 * until "letGo()" and then passes it on. "kept" is how many it keeps.
 */
async function holdingStandIn(token, real) {
  const state = { away: false, holding: false, kept: 0, letGo: () => {} };
  const gate = new Promise((done) => {
    state.letGo = () => {
      state.holding = false;
      done();
    };
  });
  state.fake = await standIn({
    token,
    real,
    answer: async (path, body, forward) => {
      if (state.away) return null;
      if (state.holding) {
        state.kept += 1;
        await gate;
      }
      return forward();
    },
  });
  return state;
}

/**
 * The end of an executor with a line the sealer lacks: the last try to
 * send it is kept by the stand-in, and until it is answered the lock on the
 * book is not let go; once it is, the lock is free and the sealer holds
 * the line. "close" ends the executor; "held" asks the real sealer how many
 * lines it holds; "lines" is how many the book file holds.
 */
async function endsBeforeTheLockIsFree(s, { book, close, held, lines }) {
  // The sealer answers again, slowly: whatever it is asked now, it keeps.
  s.away = false;
  s.holding = true;
  const closing = close();
  await until(() => s.kept >= 1, { timeout: 30000 });
  // Time for a lock that was let go too early to be seen free.
  await pause(500);
  await assert.rejects(lockFiles(book), (e) => e.code === 'LOCKED', 'the lock is held while the last question to the sealer is out');
  s.letGo();
  await closing;
  const lock = await lockFiles(book, { wait: 10000 });
  await lock.release();
  assert.equal(await held(), lines(), 'the sealer holds every line');
}

test('central sealer, over stdio: at the end the link to the sealer is ended, with its last try, before the lock on the book is let go (review 3.2, F4)', async () => {
  const w = await centralWorld({ open: false, sealer: { timeout: 20000 } });
  const s = await holdingStandIn(w.sealer.token, w.settings.recorder.sealer.address);
  try {
    w.settings.recorder.sealer.address = s.fake.address;
    await openWorld(w);
    s.away = true;
    assert.equal(refusal(await w.client.call('echo', {})), null);
    assert.equal((await problemShown(w)).unsent, 1);
    await endsBeforeTheLockIsFree(s, { book: join(w.folder, 'book.jsonl'), close: () => w.close(), held: async () => (await w.held()).size, lines: () => w.lines().length });
  } finally {
    s.away = false;
    s.letGo();
    await w.close();
    await w.sealer.stop();
  }
});

test('central sealer, over HTTP: at the end each agent\'s link to the sealer is ended, with its last try, before the lock on its book is let go (review 3.2, F4)', async () => {
  const w = await httpWorld({ agents: ['alpha'], open: false });
  const made = await sealerFolder([w.agents.alpha.agentKeys]);
  const running = await startSealer({ folder: made.folder, port: made.port });
  const s = await holdingStandIn(made.token, running.address);
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await w.close();
  };
  try {
    writeFileSync(join(w.folder, 'secrets', 'sealer-token'), `${made.token}\n`);
    w.settings.recorder = { sealer: { address: s.fake.address, name: RECORDER, token: { file: 'secrets/sealer-token' }, keySet: running.fingerprint, timeout: 20000 } };
    await openHttpWorld(w);
    const lines = () => readFileSync(w.agents.alpha.book, 'utf8').split('\n').filter(Boolean);
    const sealer = connectSealer({ address: running.address, recorder: RECORDER, token: made.token });
    const held = async () => (await sealer.held(Buffer.from(await leafFingerprint(lines()[0])).toString('base64url'))).size;
    s.away = true;
    assert.ok((await call(w, 'alpha', 'echo', {})).json.result);
    await until(async () => (await w.executor.report()).agents.alpha.sealer.problem !== null, { timeout: 30000 });
    assert.equal(await held(), 1);
    await endsBeforeTheLockIsFree(s, { book: w.agents.alpha.book, close, held, lines: () => lines().length });
  } finally {
    s.away = false;
    s.letGo();
    if (w.executor) await close();
    await running.close();
  }
});
