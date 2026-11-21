// The floor under a price. A permission's limits are ceilings, so nothing
// in the guard stops a price being cut. The server's own settings do: a
// lowest price, and the largest cut below the present price that one call
// may make. The agent cannot change them, and unless they are set a price
// may be raised and not lowered.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, runToEnd, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const BLUE = 'gid://shopify/ProductVariant/11'; // 10.00 GBP in the made-up store
const price = (price_minor, currency = 'GBP') => ({ variant_id: BLUE, price_minor, currency });

async function world(env, options) {
  const fake = await fakeShopify(options);
  return { fake, server: startServer(fake, { env }) };
}

test('with nothing set: a price may be raised or left as it is, and not lowered by anything', async () => {
  const { fake, server } = await world({});
  const lower = await server.call('set_variant_price', price(999));
  assert.equal(lower.isError, true);
  assert.equal(lower.text, 'The price of Mug - Blue is 10.00 GBP, and 9.99 GBP was asked for. This server\'s settings allow no price below 0.01 GBP and no cut in a price, so the lowest it would set now is 10.00 GBP. Nothing was changed.');
  for (const low of [1, 0, 500]) assert.equal((await server.call('set_variant_price', price(low))).isError, true, String(low));
  assert.equal(fake.of('SetVariantPrice').length, 0, 'no change was sent');
  assert.equal((await server.call('set_variant_price', price(1000))).isError, false, 'the same price');
  assert.equal((await server.call('set_variant_price', price(1001))).isError, false, 'a higher price');
  assert.equal(fake.store.products[0].variants[0].price, '10.01');
  await server.close();
  assert.match(server.stderr(), /provared-shopify: a price: none below 1 of the currency's smallest unit, and no cut\./, 'the floor is said at the start');
});

test('the largest cut is a percentage of the price Shopify has just given, in one call', async () => {
  const { fake, server } = await world({ SHOPIFY_MAX_PRICE_CUT_PERCENT: '20' });
  const tooFar = await server.call('set_variant_price', price(799));
  assert.equal(tooFar.text, 'The price of Mug - Blue is 10.00 GBP, and 7.99 GBP was asked for. This server\'s settings allow no price below 0.01 GBP and no cut of more than 20% of the present price in one call, so the lowest it would set now is 8.00 GBP. Nothing was changed.');
  assert.equal(fake.of('SetVariantPrice').length, 0);
  const cut = await server.call('set_variant_price', price(800));
  assert.equal(cut.isError, false, cut.text);
  assert.equal(fake.store.products[0].variants[0].price, '8.00');
  // The next call is held against the new price: 20% below 8.00 is 6.40.
  assert.match((await server.call('set_variant_price', price(639))).text, /is 8\.00 GBP, and 6\.39 GBP was asked for\..+the lowest it would set now is 6\.40 GBP/);
  assert.equal((await server.call('set_variant_price', price(640))).isError, false);
  // A cut that does not come to a whole penny is rounded against the agent: 20% below 6.41 is 5.128, so 5.13.
  fake.store.products[0].variants[0].price = '6.41';
  assert.match((await server.call('set_variant_price', price(512))).text, /the lowest it would set now is 5\.13 GBP/);
  assert.equal((await server.call('set_variant_price', price(513))).isError, false);
  await server.close();
  assert.match(server.stderr(), /provared-shopify: a price: none below 1 of the currency's smallest unit, and no cut of more than 20% in one call\./);
});

test('the lowest price holds whatever cut is allowed, and against a price given by another reading', async () => {
  const { fake, server } = await world({ SHOPIFY_MAX_PRICE_CUT_PERCENT: '100', SHOPIFY_MIN_PRICE_MINOR: '900' });
  const below = await server.call('set_variant_price', price(899));
  assert.equal(below.text, 'The price of Mug - Blue is 10.00 GBP, and 8.99 GBP was asked for. This server\'s settings allow no price below 9.00 GBP and no cut of more than 100% of the present price in one call, so the lowest it would set now is 9.00 GBP. Nothing was changed.');
  assert.equal((await server.call('set_variant_price', price(900))).isError, false);
  // A price already below the lowest may be raised only to the lowest or above.
  fake.store.products[0].variants[0].price = '5.00';
  assert.equal((await server.call('set_variant_price', price(600))).isError, true);
  assert.equal((await server.call('set_variant_price', price(900))).isError, false);
  assert.equal(fake.of('SetVariantPrice').length, 2);
});

test('with every cut allowed and no lowest price, a price of nothing may be set', async () => {
  const { fake, server } = await world({ SHOPIFY_MAX_PRICE_CUT_PERCENT: '100', SHOPIFY_MIN_PRICE_MINOR: '0' });
  assert.equal((await server.call('set_variant_price', price(0))).isError, false);
  assert.equal(fake.store.products[0].variants[0].price, '0.00');
});

test('a present price the server cannot read stops the change', async () => {
  const { fake, server } = await world({ SHOPIFY_MAX_PRICE_CUT_PERCENT: '100' });
  fake.faults.push({ on: 'ReadVariant', kind: 'tamper', with: (d) => {
    d.productVariant.price = 'ten pounds';
  } }, { on: 'ReadVariant', kind: 'tamper', with: (d) => {
    d.productVariant.price = null;
  } });
  for (let i = 0; i < 2; i++) assert.equal((await server.call('set_variant_price', price(2000))).text, 'Shopify gave the present price of Mug - Blue in a form this server cannot read, so it cannot tell how large a cut this would be. Nothing was changed.');
  assert.equal(fake.of('SetVariantPrice').length, 0);
});

test('the floor is in the smallest unit of the shop\'s currency, whatever that is', async () => {
  const { fake, server } = await world({ SHOPIFY_MAX_PRICE_CUT_PERCENT: '10', SHOPIFY_MIN_PRICE_MINOR: '950' }, { currency: 'JPY' });
  // The made-up variant costs 1,000 yen: 10% below is 900, and the lowest price is 950.
  assert.match((await server.call('set_variant_price', price(949, 'JPY'))).text, /is 1000 JPY, and 949 JPY was asked for\. This server's settings allow no price below 950 JPY and no cut of more than 10% .+ the lowest it would set now is 950 JPY/);
  assert.equal((await server.call('set_variant_price', price(950, 'JPY'))).isError, false);
  assert.equal(fake.store.products[0].variants[0].price, '950');
});

test('no call can change the floor: the tool takes no argument for it', async () => {
  const { fake, server } = await world({});
  for (const extra of [{ min_price_minor: 0 }, { max_price_cut_percent: 100 }, { SHOPIFY_MAX_PRICE_CUT_PERCENT: '100' }, { force: true }]) {
    const refused = await server.call('set_variant_price', { ...price(500), ...extra });
    assert.equal(refused.isError, true);
    assert.match(refused.text, /is not an argument of this tool/);
  }
  assert.equal(fake.sent.length, 0);
});

test('a floor that cannot be read stops the start', async () => {
  const good = { SHOPIFY_SHOP: 'made-up-store', SHOPIFY_TEST_ORIGIN: 'http://127.0.0.1:9', SHOPIFY_CLIENT_ID: 'made-up-client-id', SHOPIFY_CLIENT_SECRET: 'shpss_made_up_secret' };
  const cases = [
    [{ SHOPIFY_MAX_PRICE_CUT_PERCENT: '101' }, /SHOPIFY_MAX_PRICE_CUT_PERCENT must be a whole number from 0 to 100, in digits alone\./],
    [{ SHOPIFY_MAX_PRICE_CUT_PERCENT: '20%' }, /SHOPIFY_MAX_PRICE_CUT_PERCENT must be/],
    [{ SHOPIFY_MAX_PRICE_CUT_PERCENT: '12.5' }, /SHOPIFY_MAX_PRICE_CUT_PERCENT must be/],
    [{ SHOPIFY_MAX_PRICE_CUT_PERCENT: '-5' }, /SHOPIFY_MAX_PRICE_CUT_PERCENT must be/],
    [{ SHOPIFY_MIN_PRICE_MINOR: '9.99' }, /SHOPIFY_MIN_PRICE_MINOR must be a whole number from 0 to 9007199254740991, in digits alone\./],
    [{ SHOPIFY_MIN_PRICE_MINOR: '1e3' }, /SHOPIFY_MIN_PRICE_MINOR must be/],
    [{ SHOPIFY_MIN_PRICE_MINOR: '9007199254740993' }, /SHOPIFY_MIN_PRICE_MINOR must be/],
  ];
  for (const [env, said] of cases) {
    const run = await runToEnd([], { ...good, ...env });
    assert.equal(run.code, 1, String(said));
    assert.match(run.stderr, said);
  }
  assert.equal((await runToEnd([], { ...good, SHOPIFY_MAX_PRICE_CUT_PERCENT: '0', SHOPIFY_MIN_PRICE_MINOR: '0' })).code, 0);
});
