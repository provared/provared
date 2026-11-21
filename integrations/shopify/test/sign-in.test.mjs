// Signing in with the app's client ID and secret, and keeping the access
// token fresh: renewed before it expires, and asked for again where
// Shopify stops accepting it mid-session. Against the made-up Shopify.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { API_PATH, CLIENT_ID, CLIENT_SECRET, TOKEN_PATH, closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const MUG = { product_id: 'gid://shopify/Product/1' };
const BLUE = 'gid://shopify/ProductVariant/11';

async function world(options, serverOptions) {
  const fake = await fakeShopify(options);
  const server = startServer(fake, serverOptions);
  return { fake, server, end: async () => {
    await server.close();
    await fake.close();
  } };
}

test('the sign-in is the client credentials grant as Shopify documents it, sent once for many calls', async () => {
  const { fake, server, end } = await world();
  for (let i = 0; i < 3; i++) assert.equal((await server.call('read_product', MUG)).data.title, 'Mug');
  const signIns = fake.of('sign-in');
  assert.equal(signIns.length, 1, 'one sign-in for three calls');
  const [signIn] = signIns;
  assert.equal(signIn.path, TOKEN_PATH);
  assert.equal(signIn.method, 'POST');
  assert.equal(signIn.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.deepEqual(Object.fromEntries(new URLSearchParams(signIn.body)), { grant_type: 'client_credentials', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }, 'no scope and nothing else is sent');
  const reads = fake.of('ReadProduct');
  assert.equal(reads.length, 3);
  for (const r of reads) {
    assert.equal(r.path, API_PATH, 'the one pinned version of the Admin API');
    assert.equal(r.headers['x-shopify-access-token'], fake.issued[0]);
    assert.equal(r.headers['user-agent'], 'provared-shopify/0.1.0');
  }
  assert.ok(fake.sent.every((r) => r.path === TOKEN_PATH || r.path === API_PATH), 'no other address is asked anything');
  await end();
});

test('the client ID and secret may be given as values, as the guard gives them after reading its files', async () => {
  const { fake, server, end } = await world({}, { env: { SHOPIFY_CLIENT_ID_FILE: undefined, SHOPIFY_CLIENT_SECRET_FILE: undefined, SHOPIFY_CLIENT_ID: CLIENT_ID, SHOPIFY_CLIENT_SECRET: CLIENT_SECRET } });
  assert.equal((await server.call('read_product', MUG)).data.title, 'Mug');
  assert.equal(fake.of('sign-in').length, 1);
  await end();
});

test('a token with a minute or less left is renewed before the next request', async () => {
  const { fake, server, end } = await world({ expiresIn: 60 });
  assert.equal((await server.call('read_product', MUG)).isError, false);
  assert.equal((await server.call('read_product', MUG)).isError, false);
  assert.equal(fake.of('sign-in').length, 2, 'each call found the token too near its end and signed in again');
  const used = fake.of('ReadProduct').map((r) => r.headers['x-shopify-access-token']);
  assert.deepEqual(used, [fake.issued[0], fake.issued[1]], 'the second call used the new token');
  await end();
});

test('a token that stops working mid-session: a query is sent again with a new token', async () => {
  const { fake, server, end } = await world();
  assert.equal((await server.call('read_product', MUG)).data.title, 'Mug');
  fake.expireTokens();
  const again = await server.call('read_product', MUG);
  assert.equal(again.isError, false);
  assert.equal(again.data.title, 'Mug');
  assert.equal(fake.of('sign-in').length, 2);
  assert.deepEqual(fake.of('ReadProduct').map((r) => r.headers['x-shopify-access-token']), [fake.issued[0], fake.issued[0], fake.issued[1]], 'refused once with the old token, then answered with the new');
  await end();
});

test('a token that stops working mid-session: a change goes through, sent once, because the reading before it renewed the token', async () => {
  const { fake, server, end } = await world();
  assert.equal((await server.call('read_product', MUG)).isError, false);
  fake.expireTokens();
  const changed = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.equal(changed.isError, false, changed.text);
  assert.equal(fake.of('SetVariantPrice').length, 1);
  assert.equal(fake.of('SetVariantPrice')[0].headers['x-shopify-access-token'], fake.issued[1]);
  assert.equal(fake.store.products[0].variants[0].price, '12.50');
  await end();
});

test('a change that Shopify answers 401 is not sent a second time; the next call signs in again', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'SetVariantPrice', kind: 'status', status: 401 });
  const refused = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.equal(refused.isError, true);
  assert.match(refused.text, /did not accept the access token \(HTTP 401\), so the change was not made/);
  assert.equal(fake.of('SetVariantPrice').length, 1, 'the change was sent once');
  assert.equal(fake.store.products[0].variants[0].price, '10.00');
  assert.equal(fake.of('sign-in').length, 1);
  const next = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.equal(next.isError, false, next.text);
  assert.equal(fake.of('sign-in').length, 2, 'the token was dropped, so the next call signed in again');
  assert.equal(fake.of('SetVariantPrice').length, 2);
  assert.equal(fake.store.products[0].variants[0].price, '12.50');
  await end();
});

test('a query that is answered 401 twice is given up, with no third try', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'ReadProduct', kind: 'status', status: 401 }, { on: 'ReadProduct', kind: 'status', status: 401 });
  const refused = await server.call('read_product', MUG);
  assert.equal(refused.isError, true);
  assert.match(refused.text, /did not accept the access token, nor a new one/);
  assert.equal(fake.of('ReadProduct').length, 2);
  assert.equal(fake.of('sign-in').length, 2);
  await end();
});

test('a sign-in that Shopify refuses is a tool error in plain words, and the store is asked nothing', async () => {
  const { fake, server, end } = await world({}, { env: { SHOPIFY_CLIENT_SECRET_FILE: undefined, SHOPIFY_CLIENT_SECRET: 'shpss_a_wrong_secret_77aa' } });
  const refused = await server.call('list_orders', {});
  assert.equal(refused.isError, true);
  assert.match(refused.text, /^Shopify refused the sign-in \(HTTP 400: invalid_client: /);
  assert.match(refused.text, /Nothing was asked of the store\.$/);
  assert.ok(!server.output().includes('shpss_a_wrong_secret_77aa'), 'the secret Shopify repeated is taken out of the answer');
  assert.match(refused.text, /its secret \[removed\] is not right/);
  assert.equal(fake.sent.filter((r) => r.path === API_PATH).length, 0);
  // The next call tries the sign-in again; nothing is remembered as failed.
  await server.call('list_orders', {});
  assert.equal(fake.of('sign-in').length, 2);
  await end();
});

test('a sign-in answered without a token, or with Shopify\'s own failure, is a tool error', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'sign-in', kind: 'status', status: 200, body: { scope: 'write_orders' } }, { on: 'sign-in', kind: 'status', status: 503, body: {} });
  const noToken = await server.call('list_products', {});
  assert.equal(noToken.isError, true);
  assert.match(noToken.text, /something other than an access token/);
  const failed = await server.call('list_products', {});
  assert.equal(failed.isError, true);
  assert.match(failed.text, /Shopify refused the sign-in \(HTTP 503/);
  assert.equal((await server.call('list_products', {})).isError, false, 'the third sign-in is answered, and the call goes through');
  await end();
});
