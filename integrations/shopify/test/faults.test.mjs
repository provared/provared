// What the server does when Shopify throttles, fails or goes quiet: a tool
// error in plain words, and nothing sent a second time. And that the
// client secret and the access tokens are in nothing the server writes.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { CLIENT_SECRET, THROTTLED, closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const BLUE = 'gid://shopify/ProductVariant/11';
const ORDER_1001 = 'gid://shopify/Order/1001';
const REFUND = { order_id: ORDER_1001, amount_minor: 750, currency: 'GBP' };

async function world(options) {
  const fake = await fakeShopify(options);
  const server = startServer(fake);
  return { fake, server, end: async () => {
    await server.close();
    await fake.close();
  } };
}

test('Shopify\'s throttling answer on a query: a tool error, and the query is not sent again', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'ListOrders', kind: 'errors', errors: THROTTLED });
  const throttled = await server.call('list_orders', {});
  assert.equal(throttled.isError, true);
  assert.equal(throttled.text, 'Shopify is limiting this app\'s requests just now (THROTTLED). Wait a second or more and send the call again; this server does not try again by itself.');
  assert.equal(fake.of('ListOrders').length, 1);
  assert.equal((await server.call('list_orders', {})).isError, false, 'the call sent again by the agent is answered');
  await end();
});

test('Shopify\'s throttling answer on a refund: the refund was not made, and is not sent again', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'RefundOrder', kind: 'errors', errors: THROTTLED });
  const throttled = await server.call('refund_order', REFUND);
  assert.equal(throttled.isError, true);
  assert.equal(throttled.text, `Shopify is limiting this app's requests just now (THROTTLED). The change was not made. Wait a second or more and send the call again; this server does not try again by itself. This refund was sent with "idempotency_key": "${fake.of('RefundOrder')[0].variables.idempotencyKey}".`);
  assert.equal(fake.of('RefundOrder').length, 1, 'sent once');
  assert.equal(fake.store.orders[0].refunds.length, 0);
  await end();
});

test('Shopify\'s throttling answer on a price change and on a discount code: sent once', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'SetVariantPrice', kind: 'errors', errors: THROTTLED }, { on: 'CreateDiscountCode', kind: 'status', status: 429 });
  const price = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.match(price.text, /\(THROTTLED\)\. The change was not made\./);
  const code = await server.call('create_percentage_discount_code', { code: 'TEN', percent: 10 });
  assert.match(code.text, /\(HTTP 429\)\. The change was not made\./);
  assert.deepEqual([fake.of('SetVariantPrice').length, fake.of('CreateDiscountCode').length], [1, 1]);
  assert.equal(fake.store.products[0].variants[0].price, '10.00');
  assert.equal(fake.store.discounts.length, 2);
  await end();
});

test('a refund whose answer is lost after Shopify made it: the outcome is said to be unknown, and the refund is not sent again', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'RefundOrder', kind: 'after', status: 'drop' });
  const lost = await server.call('refund_order', REFUND);
  assert.equal(lost.isError, true);
  const key = fake.of('RefundOrder')[0].variables.idempotencyKey;
  assert.equal(lost.text.replace(/^Could not reach Shopify \(.+?\)\. /, ''), `Whether the change was made is not known. Read the order before trying again; to send this same refund again, give "idempotency_key": "${key}" with every other argument as it was, and Shopify will not make it twice.`);
  assert.equal(fake.of('RefundOrder').length, 1, 'sent once: a second sending would have refunded twice');
  assert.equal(fake.store.orders[0].refunds.length, 1, 'the made-up store did make the refund');
  const read = await server.call('read_order', { order_id: ORDER_1001 });
  assert.equal(read.data.refunded.amount_minor, 750, 'reading the order, as the answer says to, shows it');
  // The agent sends the same call again with the key it was told: Shopify answers with the first refund and makes no second.
  const again = await server.call('refund_order', { ...REFUND, idempotency_key: key });
  assert.equal(again.isError, false, again.text);
  assert.equal(again.data.done, '7.50 GBP was refunded on order #1001.');
  assert.equal(again.data.idempotency_key, key);
  assert.deepEqual(fake.of('RefundOrder').map((r) => r.variables.idempotencyKey), [key, key]);
  assert.equal(fake.store.orders[0].refunds.length, 1, 'still one refund');
  // Sent again without the key, it is a refund of its own.
  const second = await server.call('refund_order', REFUND);
  assert.notEqual(second.data.idempotency_key, key);
  assert.equal(fake.store.orders[0].refunds.length, 2);
  await end();
});

test('Shopify\'s own failure on a change (HTTP 500, or an error in its answer): the outcome is said to be unknown, sent once', async () => {
  const { fake, server, end } = await world();
  fake.faults.push({ on: 'RefundOrder', kind: 'after', status: 502 }, { on: 'SetVariantPrice', kind: 'errors', errors: [{ message: 'Internal error. Looks like something went wrong on our end.', extensions: { code: 'INTERNAL_SERVER_ERROR' } }] });
  const refund = await server.call('refund_order', REFUND);
  assert.match(refund.text, /^Shopify had an error \(HTTP 502\)\. Whether the change was made is not known\. Read the order before trying again; to send this same refund again, give "idempotency_key": "[0-9a-f-]{36}" /);
  const price = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.equal(price.text, 'Shopify answered with an error: Internal error. Looks like something went wrong on our end.. Whether the change was made is not known. Read the product before trying again.');
  assert.deepEqual([refund.isError, price.isError], [true, true]);
  assert.deepEqual([fake.of('RefundOrder').length, fake.of('SetVariantPrice').length], [1, 1]);
  await end();
});

test('a query that fails says so and nothing of a change; a missing access scope is named as such', async () => {
  const { fake, server, end } = await world();
  fake.faults.push(
    { on: 'ListProducts', kind: 'status', status: 500 },
    { on: 'ListProducts', kind: 'drop' },
    { on: 'ListProducts', kind: 'errors', errors: [{ message: 'Access denied for products field. Required access: `read_products` access scope.', extensions: { code: 'ACCESS_DENIED' } }] },
    { on: 'ListProducts', kind: 'status', status: 402 },
    { on: 'ListProducts', kind: 'status', status: 423 },
    { on: 'ListProducts', kind: 'status', status: 404 },
    { on: 'ListProducts', kind: 'status', status: 200, body: { data: null } },
  );
  const said = [];
  for (let i = 0; i < 7; i++) {
    const failed = await server.call('list_products', {});
    assert.equal(failed.isError, true);
    said.push(failed.text);
  }
  assert.equal(said[0], 'Shopify had an error (HTTP 500).');
  assert.match(said[1], /^Could not reach Shopify \(.+\)\.$/);
  assert.equal(said[2], 'Shopify refused: the app does not have the access this tool needs (Access denied for products field. Required access: `read_products` access scope.). The access scopes this server needs are listed in its README.');
  assert.match(said[3], /^The shop is frozen \(HTTP 402\)/);
  assert.equal(said[4], 'The shop is locked (HTTP 423).');
  assert.match(said[5], /^Shopify found no such store, or no such version of the Admin API \(HTTP 404\)/);
  assert.equal(said[6], 'Shopify\'s answer held no data.');
  assert.equal(fake.of('ListProducts').length, 7, 'each call was sent once');
  await end();
});

test('a redirect is not followed: neither the client secret nor the access token is sent to another address', async () => {
  const { fake, server, end } = await world();
  const elsewhere = await fakeShopify();
  fake.faults.push({ on: 'sign-in', kind: 'redirect', to: `${elsewhere.origin}/admin/oauth/access_token` });
  const signIn = await server.call('list_products', {});
  assert.equal(signIn.isError, true);
  assert.match(signIn.text, /^Could not sign in to Shopify \(.+\)\. Nothing was asked of the store\.$/);
  fake.faults.push({ on: 'ListProducts', kind: 'redirect', to: `${elsewhere.origin}/admin/api/2026-10/graphql.json` });
  const query = await server.call('list_products', {});
  assert.equal(query.isError, true);
  assert.match(query.text, /^Could not reach Shopify \(.+\)\.$/);
  fake.faults.push({ on: 'RefundOrder', kind: 'redirect', to: `${elsewhere.origin}/admin/api/2026-10/graphql.json` });
  const refund = await server.call('refund_order', REFUND);
  assert.match(refund.text, /^Could not reach Shopify \(.+?\)\. Whether the change was made is not known\. Read the order before trying again; /);
  assert.equal(elsewhere.sent.length, 0, 'the other address was sent nothing');
  await end();
  await elsewhere.close();
});

test('the client secret and the access tokens are in nothing the server writes, whatever Shopify says', async () => {
  const fake = await fakeShopify();
  const server = startServer(fake);
  await server.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  await server.request('tools/list');
  // Every tool, and every kind of failure, in one run.
  await server.call('list_products', {});
  await server.call('read_product', { product_id: 'gid://shopify/Product/1' });
  await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  await server.call('list_discount_codes', {});
  await server.call('create_percentage_discount_code', { code: 'TEN', percent: 10 });
  await server.call('create_amount_discount_code', { code: 'FIVE', amount_minor: 500, currency: 'GBP' });
  await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' });
  await server.call('list_orders', {});
  await server.call('read_order', { order_id: ORDER_1001 });
  await server.call('refund_order', REFUND);
  await server.call('refund_order', { order_id: 'gid://shopify/Order/1004', amount_minor: 1, currency: 'GBP' });
  fake.expireTokens();
  await server.call('list_orders', {});
  // A made-up Shopify that repeats the secret and the token in its errors, and in a product's title.
  const leak = `client secret ${CLIENT_SECRET} and tokens ${fake.issued.join(' ')}`;
  fake.faults.push(
    { on: 'ListOrders', kind: 'errors', errors: [{ message: `Bad request: ${leak}`, extensions: { code: 'BAD' } }] },
    { on: 'RefundOrder', kind: 'errors', errors: [{ message: leak, extensions: { code: 'ACCESS_DENIED' } }] },
  );
  const leaked = await server.call('list_orders', {});
  assert.match(leaked.text, /client secret \[removed\] and tokens \[removed\] \[removed\]/);
  await server.call('refund_order', REFUND);
  fake.store.products[0].title = `Mug ${leak}`;
  const product = await server.call('read_product', { product_id: 'gid://shopify/Product/1' });
  assert.equal(product.data.title, 'Mug client secret [removed] and tokens [removed] [removed]');
  await server.request('tools/call', { name: `no_such_tool_${CLIENT_SECRET}`, arguments: {} });
  await server.request(`method/${CLIENT_SECRET}`);
  await server.call('refund_order', { order_id: ORDER_1001, amount_minor: 1, currency: 'GBP', note: 7, [CLIENT_SECRET]: 1 });
  // A sign-in that fails with the secret in what Shopify says.
  fake.expireTokens();
  fake.faults.push({ on: 'sign-in', kind: 'status', status: 400, body: { error: 'invalid_request', error_description: leak } });
  const signIn = await server.call('list_orders', {});
  assert.match(signIn.text, /Shopify refused the sign-in \(HTTP 400: invalid_request: client secret \[removed\]/);
  await server.close();
  const all = server.output();
  assert.ok(all.length > 5000, 'there is output to look through');
  assert.ok(!all.includes(CLIENT_SECRET), 'the client secret is in no output');
  for (const token of fake.issued) assert.ok(!all.includes(token), 'no access token is in any output');
  assert.equal(fake.issued.length, 2);
  await fake.close();
});
