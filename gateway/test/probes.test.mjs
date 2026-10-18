// Probes through the real gateway: addresses written in other ways reach the
// upstream as the rule that named them would have it, or not at all; many
// calls at once never pass a limit; and, in random runs, after every call the
// gateway's own view of each book equals a whole check of its file.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { world, json, call, ADMIN_SECRET } = await import('./world.mjs');

const stubs = async (w) => (await w.gateway.writers().get('patching').check()).entries.filter((e) => e.kind === 'stub');
const JSONTYPE = { 'content-type': 'application/json' };

test('addresses that differ only in how they are written reach the upstream as the rule matched them, or not at all', async () => {
  const w = await world({
    rules: [
      { upstream: 'tickets', method: 'DELETE', path: '/api/now/table/change_request/:id', action: 'provared.data.delete' },
      { upstream: 'tickets', method: 'DELETE', path: '/api/now/table/:table/:id', action: 'ticket.update' },
    ],
    slip: { actions: ['provared.data.delete', 'ticket.update'] },
  });
  try {
    const cases = [
      // [address, what the upstream must receive (null: nothing), the action it must be named]
      ['/tickets/api/now/table/change_request/1', '/api/now/table/change_request/1', 'provared.data.delete'],
      ['/tickets/api/now/table/change%5Frequest/1', '/api/now/table/change_request/1', 'provared.data.delete'],
      ['/tickets/api/now/table/CHANGE_REQUEST/1', '/api/now/table/CHANGE_REQUEST/1', 'provared.data.delete'],
      ['/tickets/api/now/table/change_request/1/', '/api/now/table/change_request/1/', 'provared.data.delete'],
      ['/tickets/api/now/table/incident/1', '/api/now/table/incident/1', 'ticket.update'],
      ['/tickets/api/now/table/change_request%2F1/x', null, null],
      ['/tickets/api/now/table/x/..%2Fchange_request/1', null, null],
      ['/tickets/api/now/table/incident/../change_request/1', null, null],
      ['/tickets/api/now/table/incident/%2E%2E/change_request/1', null, null],
      ['/tickets/api/now//table/change_request/1', null, null],
      ['/tickets/api/now/table/change_request/1%252F', null, null],
      ['/tickets/api/now/table/change_request\\1', null, null],
    ];
    for (const [address, received, action] of cases) {
      const before = w.tickets.calls.length;
      const r = await w.call('DELETE', address);
      if (received === null) {
        assert.ok(r.status === 400, `${address}: ${r.status} ${r.text}`);
        assert.equal(w.tickets.calls.length, before, `${address}: not forwarded`);
        continue;
      }
      assert.equal(r.status, 200, `${address}: ${r.text}`);
      assert.equal(w.tickets.calls.length, before + 1, address);
      assert.equal(w.tickets.calls.at(-1).url, received, address);
      assert.equal((await stubs(w)).at(-1).content.action, action, address);
    }
  } finally {
    await w.close();
  }
});

test('many calls at once from one agent never pass a limit, by count or by amount', async () => {
  const slow = (c, res) => setTimeout(() => json(res, 200, { ok: true }), 15);
  const w = await world({
    patchAnswer: slow,
    config: { waitingCalls: 32 },
    slip: { limits: [{ action: 'host.reboot', count: 3 }, { action: 'patch.apply', max: 10, unit: 'hosts' }] },
  });
  try {
    const reboots = await Promise.all(Array.from({ length: 20 }, (_, i) => w.call('POST', `/patch/v1/hosts/h${i}/reboot`, { headers: JSONTYPE, body: {} })));
    assert.equal(reboots.filter((r) => r.status === 200).length, 3);
    assert.equal(reboots.filter((r) => r.status === 403).length, 17);
    const waves = await Promise.all(Array.from({ length: 12 }, () => w.call('POST', '/patch/v1/waves', { headers: JSONTYPE, body: { hosts: ['a', 'b', 'c'] } })));
    assert.equal(waves.filter((r) => r.status === 200).length, 3, '3 waves of 3 hosts: 9 of the 10');
    assert.equal(w.patch.calls.length, 6);
    const all = await stubs(w);
    assert.equal(all.filter((s) => s.content.action === 'host.reboot').length, 3);
    assert.equal(all.filter((s) => s.content.action === 'patch.apply').reduce((n, s) => n + s.content.amount.value, 0), 9);
    const text = readFileSync(w.bookPath, 'utf8');
    const result = await checkBook(text, w.gateway.checkOptions('patching'));
    assert.equal(result.summary.withinSlips, true);
    assert.equal(result.summary.counts.denials, 26);
  } finally {
    await w.close();
  }
});

// A small random number source with a seed, so that a run can be repeated.
function random(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

for (const seed of [1, 2, 3]) {
  test(`random calls (seed ${seed}): after every call the gateway's view of the book equals a whole check of its file`, async () => {
    const pick = random(seed);
    let mode = 'ok';
    const answer = (c, res) => {
      if (mode === 'ok') return json(res, 200, { n: Math.floor(pick() * 1000) });
      if (mode === '500') return json(res, 500, { error: 'no' });
      if (mode === 'half') {
        res.writeHead(200, { 'content-length': 50 });
        res.write('{');
        return setTimeout(() => res.socket.destroy(), 5);
      }
      // "none": never answers.
    };
    const w = await world({
      tickets: { timeout: 150 },
      patch: { timeout: 150 },
      ticketsAnswer: answer,
      patchAnswer: answer,
      slip: {
        actions: ['provared.data.read', 'ticket.update', 'patch.apply', 'host.reboot'],
        limits: [{ action: 'host.reboot', count: 4 }, { action: 'patch.apply', max: 12, unit: 'hosts' }, { action: 'ticket.update', count: 3, per: 3600 }],
        never: ['destroys'],
      },
    });
    let sealsLeft = 1;
    try {
      const writer = w.gateway.writers().get('patching');
      for (let step = 0; step < 40; step++) {
        mode = ['ok', 'ok', 'ok', '500', 'half', 'none'][Math.floor(pick() * 6)];
        const kind = Math.floor(pick() * 8);
        const sentBefore = w.tickets.calls.length + w.patch.calls.length;
        const stubsBefore = (await writer.check()).summary.counts.stubs;
        let r;
        if (kind === 0) r = await w.call('GET', `/tickets/api/now/table/t${step}`);
        else if (kind === 1) r = await w.call('PATCH', `/tickets/api/now/table/change_request/${step}`, { headers: JSONTYPE, body: { s: step } });
        else if (kind === 2) r = await w.call('POST', `/patch/v1/hosts/h${step}/reboot`, { headers: JSONTYPE, body: {} });
        else if (kind === 3) r = await w.call('POST', '/patch/v1/waves', { headers: JSONTYPE, body: { hosts: Array(Math.floor(pick() * 5)).fill('h') } });
        else if (kind === 4) r = await w.call('DELETE', `/tickets/api/now/table/incident/${step}`);
        else if (kind === 5) r = await w.call('PUT', `/tickets/unlisted/${step}`);
        else if (kind === 6) r = await w.call('POST', '/patch/v1/waves', { headers: JSONTYPE, body: { hosts: 'not a list' } });
        else if (sealsLeft-- > 0) r = await call(w.port, 'POST', '/provared/seal', { secret: ADMIN_SECRET, headers: JSONTYPE, body: { agent: 'patching' } });
        else r = await w.call('GET', `/tickets/api/now/table/x%2Fy`);
        const text = readFileSync(w.bookPath, 'utf8');
        assert.equal(text, writer.book(), `step ${step}: the file holds the writer's book`);
        const whole = await checkBook(text, w.gateway.checkOptions('patching'));
        assert.deepEqual(await writer.check(), whole, `step ${step}`);
        assert.equal(whole.summary.problemFound, false, `step ${step}`);
        assert.equal(whole.summary.withinSlips, true, `step ${step}: the gateway let nothing outside the slip through`);
        const sent = w.tickets.calls.length + w.patch.calls.length - sentBefore;
        assert.equal(whole.summary.counts.stubs - stubsBefore, sent, `step ${step}: one stub for each call sent (${r.status})`);
      }
    } finally {
      await w.close();
    }
  });
}
