// The signing page's two checks that rest on the clock of the device a
// person signs on (a review of the hand-over, 3 November 2026: "the
// five-minute rule rests on the clock of the device the person signs on,
// and the signing page sets no limit of its own on a start").
//
// - Its own limit on a start: a permission another page asks for, new or
//   a renewal, is not signed where it starts more than 300 seconds after
//   this device's clock at the press of Sign (startRefusal), the same
//   allowance by which the agent's software refuses a renewal handed over
//   ("starts-later").
// - A warning that the clock may be behind: where a request carries an
//   earlier permission that, by this device's clock, will not start for
//   more than 300 seconds yet (clockWarning).
//
// Both are plain functions of page/sign-page.js, tested here without a
// browser; the last test reads the page's own text to see that the two
// signing buttons use them before a passkey is asked.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { CLOCK_ALLOWANCE_MS } from '../src/seal.js';
import { clockWarning, startRefusal } from '../page/sign-page.js';

const NOW = Date.parse('2026-11-03T12:00:00Z');
const refusal = (kind, start) => `This ${kind} starts at ${start}, more than 5 minutes after this device's clock, so it is not signed: the agent's software does not take a permission from the application that starts later than that. If the clock of this device is right, ask again from the page that opened this window; if it is not, set it first.`;

test('a permission another page asks for, new or a renewal, is not signed where it starts more than 300 seconds after this device\'s clock; one that starts 300 seconds after it, or earlier, is', () => {
  assert.equal(CLOCK_ALLOWANCE_MS, 300 * 1000);
  for (const kind of ['renewal', 'permission']) {
    assert.equal(startRefusal(kind, '2026-11-03T12:05:00Z', NOW), null, '300 seconds after: the last start signed');
    assert.equal(startRefusal(kind, '2026-11-03T12:00:00Z', NOW), null, 'now');
    assert.equal(startRefusal(kind, '2026-11-03T11:50:00Z', NOW), null, 'ten minutes ago');
    assert.equal(startRefusal(kind, '2026-11-03T12:05:01Z', NOW), refusal(kind, '2026-11-03T12:05:01Z'));
    assert.equal(startRefusal(kind, '2027-01-01T00:00:00Z', NOW), refusal(kind, '2027-01-01T00:00:00Z'));
    // The clock moves, and the same start is signed once it is near enough.
    assert.equal(startRefusal(kind, '2026-11-03T12:05:01Z', NOW + 1000), null);
  }
});

test('the limit is the one the agent\'s software keeps for a renewal handed over', () => {
  const recorder = readFileSync(new URL('../integrations/claude-code/recorder.mjs', import.meta.url), 'utf8');
  assert.ok(recorder.includes('export const HAND_OVER_ALLOWANCE_MS = 300 * 1000;'));
  assert.equal(CLOCK_ALLOWANCE_MS, 300 * 1000);
});

test('the limit stands only where another page asks: a permission signed from a starting link may start whenever the person writes, and a cancellation has no start', () => {
  assert.equal(startRefusal(null, '2027-01-01T00:00:00Z', NOW), null);
  assert.equal(startRefusal(undefined, '2027-01-01T00:00:00Z', NOW), null);
  assert.equal(startRefusal('cancellation', '2027-01-01T00:00:00Z', NOW), null);
});

test('a start that is not a time is left to the format\'s own check', () => {
  for (const start of ['tomorrow', '2026-11-03T12:10:00+00:00', '2026-02-30T00:00:00Z', 1793707800000, null, undefined, ['2027-01-01T00:00:00Z']]) {
    assert.equal(startRefusal('renewal', start, NOW), null, JSON.stringify(start));
  }
});

test('the page warns that this device\'s clock may be behind where, by it, the earlier permission will not start for more than 300 seconds yet', () => {
  assert.equal(clockWarning('2026-11-03T12:05:00Z', NOW), null, 'starts 300 seconds after the clock: within the allowance');
  assert.equal(clockWarning('2026-11-01T09:00:00Z', NOW), null, 'started two days ago');
  const words = clockWarning('2026-11-03T12:05:01Z', NOW);
  assert.equal(
    words,
    'The clock of this device may be wrong: by it, the earlier permission (which starts at 2026-11-03T12:05:01Z) will not start for more than 5 minutes yet. What you sign here is dated and judged by this clock. Check the date and time of this device; go on only if they are right.',
  );
  // A clock a year behind.
  assert.equal(clockWarning('2026-11-01T09:00:00Z', Date.parse('2025-11-03T12:00:00Z')), words.replace('2026-11-03T12:05:01Z', '2026-11-01T09:00:00Z'));
  // A start that is not a time gives no warning (the earlier permission has passed its check by then).
  for (const start of ['soon', null, undefined, 5]) assert.equal(clockWarning(start, NOW), null, JSON.stringify(start));
});

test('the warning\'s words do not change from one press to the next, so that a second press confirms what the first showed', () => {
  const start = '2026-11-03T13:00:00Z';
  assert.equal(clockWarning(start, NOW), clockWarning(start, NOW + 20000));
});

test('the page uses both at each press: the limit before any warning or passkey for a permission, the warning before a permission and before a cancellation', () => {
  const source = readFileSync(new URL('../page/sign-page.js', import.meta.url), 'utf8');
  const between = (from, to) => {
    const start = source.indexOf(from);
    assert.ok(start >= 0, from);
    const end = source.indexOf(to, start);
    assert.ok(end > start, to);
    return source.slice(start, end);
  };
  // The press of "Sign": the limit, by this device's clock then, before the warnings and the passkey.
  const press = between("$('sign').addEventListener('click'", 'function handBack(');
  const limit = press.indexOf('const late = startRefusal(request ? request.kind : null, what.validFrom, Date.now());');
  assert.ok(limit >= 0, 'the limit, on what is signed');
  assert.ok(press.indexOf('if (late) throw new Error(late);') > limit);
  assert.ok(press.indexOf('warningsBefore(what)') > limit, 'before the warnings');
  assert.ok(press.indexOf('findPasskey(') > limit, 'before a passkey is found or made');
  assert.ok(press.indexOf('prepareSlip(') > limit, 'before anything is prepared to sign');
  // The warnings before a permission and before a cancellation.
  const call = 'const clock = earlier ? clockWarning(earlier.content.validFrom, Date.now()) : null;';
  assert.ok(between('async function warningsBefore(f) {', 'function cancelWarningsBefore() {').includes(call + "\n    if (clock) add('clock-behind', clock);"));
  assert.ok(between('function cancelWarningsBefore() {', 'function showWarnings(').includes(call + "\n    if (clock) list.push({ code: 'clock-behind', text: clock });"));
});
