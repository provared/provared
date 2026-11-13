// A book sealed by a central sealer (format description, section 21.7):
// the recorder's keys are held by the program in sealer/, the executor
// sends it the leaf fingerprint of each line as the line is written, and
// the sealer signs seals only over what it was sent.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { test } from 'node:test';

const { leafFingerprint } = await import('provared');
const { openWorld, signSlip, until } = await import('./world.mjs');
const { RECORDER, centralWorld, refusal, sealerFolder, standIn } = await import('./sealer-world.mjs');
const { checkConfig, readSettings, statusFromFiles } = await import('../executor.mjs');
const { startSealer } = await import('../../sealer/sealer.mjs');

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
  const w = await centralWorld({ sealer: { timeout: 500 } });
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
  const w = await centralWorld({ sealer: { maxUnsent: 1, timeout: 500 } });
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
  const w = await centralWorld({ open: false, sealer: { maxUnsent: 0, timeout: 400 } });
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
    assert.ok(Date.now() - from < 3000, `the call waited ${Date.now() - from} ms`);
    from = Date.now();
    await assert.rejects(w.executor.seal(), /No seal was asked for/);
    assert.ok(Date.now() - from < 3000, `the seal waited ${Date.now() - from} ms`);
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
  const w = await centralWorld({ open: false, sealer: { timeout: 500 } });
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
  const w = await centralWorld({ open: false, sealer: { timeout: 500 } });
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
  const w = await centralWorld({ open: false, sealer: { timeout: 500 } });
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

test('central sealer: a seal the sealer signed that the book never took is added at the next start, before any other line', async () => {
  const w = await centralWorld({ open: false, sealer: { timeout: 500 } });
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
  const w = await centralWorld({ open: false, sealer: { timeout: 500 } });
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
  const w = await centralWorld({ sealer: { timeout: 500 } });
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
