// Money between a whole number of a currency's smallest unit and Shopify's
// decimal string: exact both ways, and refused where it cannot be exact.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { places, shown, toDecimal, toMinor } from '../money.mjs';

test('the decimal places of a currency are those of ISO 4217; a currency not in the table has none to give', () => {
  assert.deepEqual(['GBP', 'USD', 'EUR', 'JPY', 'KRW', 'ISK', 'KWD', 'BHD', 'CLF', 'HUF'].map(places), [2, 2, 2, 0, 0, 0, 3, 3, 4, 2]);
  for (const unknown of ['XXX', 'gbp', 'GBPX', '', undefined, null, 826]) assert.equal(places(unknown), null, String(unknown));
});

test('a whole number of smallest units becomes Shopify\'s decimal string', () => {
  assert.deepEqual([0, 1, 5, 50, 99, 100, 1250, 50000, 123456789].map((n) => toDecimal(n, 'GBP')), ['0.00', '0.01', '0.05', '0.50', '0.99', '1.00', '12.50', '500.00', '1234567.89']);
  assert.deepEqual([0, 1, 1250].map((n) => toDecimal(n, 'JPY')), ['0', '1', '1250']);
  assert.deepEqual([1, 1250, 12500].map((n) => toDecimal(n, 'KWD')), ['0.001', '1.250', '12.500']);
  assert.equal(toDecimal(12345, 'CLF'), '1.2345');
  assert.equal(toDecimal(Number.MAX_SAFE_INTEGER, 'GBP'), '90071992547409.91');
  for (const bad of [12.5, -1, '1250', NaN, Infinity, 2 ** 53, null, undefined]) assert.equal(toDecimal(bad, 'GBP'), null, String(bad));
  assert.equal(toDecimal(1250, 'XXX'), null);
});

test('Shopify\'s decimal string becomes a whole number of smallest units, and nothing is rounded', () => {
  assert.deepEqual(['0', '0.0', '12', '12.5', '12.50', '12.500', '0.01', '1234567.89'].map((s) => toMinor(s, 'GBP')), [0, 0, 1200, 1250, 1250, 1250, 1, 123456789]);
  assert.deepEqual(['1250', '1250.0', '1250.00'].map((s) => toMinor(s, 'JPY')), [1250, 1250, 1250]);
  assert.deepEqual(['1.25', '1.250', '0.001'].map((s) => toMinor(s, 'KWD')), [1250, 1250, 1]);
  for (const bad of ['12.505', '0.001', '1250.5']) assert.equal(toMinor(bad, bad === '1250.5' ? 'JPY' : 'GBP'), null, bad);
  for (const bad of ['', '.5', '12.', '-1.00', '+1.00', '1e3', ' 12.50', '12,50', '1 250', 'abc', 12.5, null, undefined]) assert.equal(toMinor(bad, 'GBP'), null, String(bad));
  assert.equal(toMinor('12.50', 'XXX'), null);
});

test('every amount goes to a decimal and back to itself', () => {
  for (const currency of ['GBP', 'JPY', 'KWD', 'CLF']) {
    for (const n of [0, 1, 9, 10, 99, 100, 101, 999, 1000, 12345, 999999999, Number.MAX_SAFE_INTEGER]) {
      assert.equal(toMinor(toDecimal(n, currency), currency), n, `${n} ${currency}`);
    }
  }
});

test('money as a tool shows it: the decimal, the whole number and the currency; no whole number for a currency not known', () => {
  assert.deepEqual(shown({ amount: '12.5', currencyCode: 'GBP' }), { amount: '12.5', amount_minor: 1250, currency: 'GBP' });
  assert.deepEqual(shown({ amount: '12.50', currencyCode: 'XXX' }), { amount: '12.50', amount_minor: null, currency: 'XXX' });
  assert.equal(shown(null), null);
  assert.equal(shown({ amount: 12.5, currencyCode: 'GBP' }), null);
});
