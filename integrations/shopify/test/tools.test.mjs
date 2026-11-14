// Each tool, against the made-up Shopify: what it sends, what it answers,
// and what it refuses before anything is sent.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const BLUE = 'gid://shopify/ProductVariant/11';
const ORDER_1001 = 'gid://shopify/Order/1001';
const ORDER_1002 = 'gid://shopify/Order/1002';
const gbp = (amount, amount_minor) => ({ amount, amount_minor, currency: 'GBP' });

async function world(options) {
  const fake = await fakeShopify(options);
  const server = startServer(fake);
  return { fake, server, end: async () => {
    await server.close();
    await fake.close();
  } };
}

/** The requests that change something at the made-up store. */
function changes(fake) {
  return fake.sent.filter((r) => ['SetVariantPrice', 'CreateDiscountCode', 'DeactivateDiscountCode', 'RefundOrder'].includes(r.operation));
}

test('list_products: a page at a time, each product with its lowest and highest price', async () => {
  const { fake, server, end } = await world();
  const first = await server.call('list_products', { first: 2 });
  assert.equal(first.isError, false, first.text);
  assert.deepEqual(first.data.products.map((p) => p.title), ['Mug', 'Teapot']);
  assert.deepEqual(first.data.products[0], { product_id: 'gid://shopify/Product/1', title: 'Mug', handle: 'mug', status: 'ACTIVE', vendor: 'Made-up Pottery', type: 'Kitchen', lowest_price: gbp('10.00', 1000), highest_price: gbp('11.00', 1100) });
  assert.equal(first.data.next, '2');
  const second = await server.call('list_products', { first: 2, after: first.data.next, query: 'status:draft' });
  assert.deepEqual(second.data.products.map((p) => p.title), ['Tray']);
  assert.equal(second.data.next, null);
  assert.deepEqual(fake.of('ListProducts').map((r) => r.variables), [{ first: 2, after: null, query: null }, { first: 2, after: '2', query: 'status:draft' }]);
  assert.deepEqual((await server.call('list_products', {})).data.products.length, 3);
  assert.equal(fake.of('ListProducts')[2].variables.first, 20, '20 where "first" is left out');
  await end();
});

test('read_product: the product and each variant with its price in the shop\'s currency', async () => {
  const { server, end } = await world();
  const read = await server.call('read_product', { product_id: 'gid://shopify/Product/1' });
  assert.equal(read.isError, false, read.text);
  assert.deepEqual(read.data.variants, [
    { variant_id: BLUE, title: 'Blue', sku: 'MUG-B', price: gbp('10.00', 1000), compare_at_price: null },
    { variant_id: 'gid://shopify/ProductVariant/12', title: 'Red', sku: 'MUG-R', price: gbp('11.00', 1100), compare_at_price: gbp('13.00', 1300) },
  ]);
  const none = await server.call('read_product', { product_id: 'gid://shopify/Product/999' });
  assert.equal(none.isError, true);
  assert.match(none.text, /The store has no product gid:\/\/shopify\/Product\/999\./);
  await end();
});

test('set_variant_price: the whole number of pence is sent as Shopify\'s decimal, once, for the variant\'s own product', async () => {
  const { fake, server, end } = await world();
  const changed = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'GBP' });
  assert.equal(changed.isError, false, changed.text);
  assert.equal(changed.data.done, 'The price of Mug - Blue is now 12.50 GBP.');
  assert.deepEqual(changed.data.price, gbp('12.50', 1250));
  assert.deepEqual(changed.data.price_before, gbp('10.00', 1000));
  assert.equal(changed.data.warning, undefined);
  assert.deepEqual(fake.of('SetVariantPrice').map((r) => r.variables), [{ productId: 'gid://shopify/Product/1', variants: [{ id: BLUE, price: '12.50' }] }]);
  assert.equal(fake.store.products[0].variants[0].price, '12.50');
  assert.equal(fake.store.products[0].variants[1].price, '11.00', 'the other variant is as it was');
  await end();
});

test('set_variant_price: a currency that is not the shop\'s, a variant that is not there, and a price that is not a whole number change nothing', async () => {
  const { fake, server, end } = await world();
  const cases = [
    [{ variant_id: BLUE, price_minor: 1250, currency: 'USD' }, /The shop's currency is GBP, not USD\. Nothing was changed\./],
    [{ variant_id: 'gid://shopify/ProductVariant/999', price_minor: 1250, currency: 'GBP' }, /The store has no variant/],
    [{ variant_id: BLUE, price_minor: 12.5, currency: 'GBP' }, /"price_minor" must be a whole number/],
    [{ variant_id: BLUE, price_minor: '1250', currency: 'GBP' }, /"price_minor" must be a whole number/],
    [{ variant_id: BLUE, price_minor: -1, currency: 'GBP' }, /"price_minor" must be from 0 to/],
    [{ variant_id: BLUE, price_minor: 1250 }, /"currency" is missing/],
    [{ variant_id: BLUE, price_minor: 1250, currency: 'gbp' }, /"currency" is not in the form/],
    [{ variant_id: '11', price_minor: 1250, currency: 'GBP' }, /"variant_id" is not in the form/],
    [{ variant_id: BLUE, price_minor: 1250, currency: 'GBP', compare_at_price_minor: 1 }, /"compare_at_price_minor" is not an argument of this tool/],
    [[BLUE, 1250, 'GBP'], /The arguments must be an object/],
  ];
  for (const [args, said] of cases) {
    const refused = await server.call('set_variant_price', args);
    assert.equal(refused.isError, true, String(said));
    assert.match(refused.text, said);
  }
  assert.equal(changes(fake).length, 0, 'no change was sent');
  assert.equal(fake.store.products[0].variants[0].price, '10.00');
  await end();
});

test('a shop whose currency has no decimal places: 1250 is 1,250 yen, sent as "1250"', async () => {
  const { fake, server, end } = await world({ currency: 'JPY' });
  const changed = await server.call('set_variant_price', { variant_id: BLUE, price_minor: 1250, currency: 'JPY' });
  assert.equal(changed.isError, false, changed.text);
  assert.equal(fake.of('SetVariantPrice')[0].variables.variants[0].price, '1250');
  assert.deepEqual(changed.data.price, { amount: '1250', amount_minor: 1250, currency: 'JPY' });
  await end();
});

test('list_discount_codes: a percentage code with its percent; another kind with its name and state', async () => {
  const { server, end } = await world();
  const list = await server.call('list_discount_codes', {});
  assert.equal(list.isError, false, list.text);
  assert.deepEqual(list.data.discount_codes, [
    { discount_id: 'gid://shopify/DiscountCodeNode/1', kind: 'DiscountCodeBasic', title: 'Welcome', status: 'ACTIVE', starts_at: '2026-01-01T00:00:00Z', ends_at: null, codes: ['WELCOME10'], percent: 10, usage_limit: null, times_used: 3, once_per_customer: true },
    { discount_id: 'gid://shopify/DiscountCodeNode/2', kind: 'DiscountCodeFreeShipping', title: 'Free delivery', status: 'EXPIRED', starts_at: '2026-01-01T00:00:00Z', ends_at: '2026-02-01T00:00:00Z' },
  ]);
  assert.equal(list.data.next, null);
  await end();
});

test('create_percentage_discount_code: 30 is sent as 0.3, for every buyer and every item, once', async () => {
  const { fake, server, end } = await world();
  const made = await server.call('create_percentage_discount_code', { code: 'WINTER30', percent: 30, starts_at: '2026-12-01T00:00:00Z', ends_at: '2026-12-31T23:59:59Z', usage_limit: 100, once_per_customer: true });
  assert.equal(made.isError, false, made.text);
  assert.equal(made.data.done, 'The code WINTER30 now gives 30% off.');
  assert.equal(made.data.percent, 30);
  assert.equal(made.data.warning, undefined);
  assert.deepEqual(fake.of('CreateDiscountCode').map((r) => r.variables), [{ basicCodeDiscount: {
    title: 'WINTER30', code: 'WINTER30', startsAt: '2026-12-01T00:00:00Z', endsAt: '2026-12-31T23:59:59Z', context: { all: 'ALL' },
    customerGets: { value: { percentage: 0.3 }, items: { all: true } }, usageLimit: 100, appliesOncePerCustomer: true,
  } }]);
  // Left out: the title is the code, the start is now, there is no end and no limit.
  const plain = await server.call('create_percentage_discount_code', { code: 'SEVEN', percent: 7 });
  assert.equal(plain.isError, false, plain.text);
  const sent = fake.of('CreateDiscountCode')[1].variables.basicCodeDiscount;
  assert.deepEqual(Object.keys(sent).sort(), ['appliesOncePerCustomer', 'code', 'context', 'customerGets', 'startsAt', 'title']);
  assert.equal(sent.customerGets.value.percentage, 0.07);
  assert.ok(Math.abs(Date.parse(sent.startsAt) - Date.now()) < 60000);
  assert.equal(sent.appliesOncePerCustomer, false);
  await end();
});

test('create_percentage_discount_code: a percentage that is not a whole number from 1 to 100 is refused before anything is sent; a code Shopify refuses is told in its words', async () => {
  const { fake, server, end } = await world();
  for (const percent of [0, 101, 30.5, '30', 0.3]) {
    const refused = await server.call('create_percentage_discount_code', { code: 'X', percent });
    assert.equal(refused.isError, true, String(percent));
    assert.match(refused.text, /"percent" must be/);
  }
  assert.equal(fake.sent.length, 0, 'nothing was sent, not even a sign-in');
  const taken = await server.call('create_percentage_discount_code', { code: 'welcome10', percent: 10 });
  assert.equal(taken.isError, true);
  assert.equal(taken.text, 'Shopify refused the discount code: basicCodeDiscount.code: Code must be unique. Please try a different code.. Nothing was changed.');
  assert.equal(fake.store.discounts.length, 2);
  await end();
});

test('create_amount_discount_code: 500 pence is sent as "5.00", in the shop\'s currency alone', async () => {
  const { fake, server, end } = await world();
  const made = await server.call('create_amount_discount_code', { code: 'FIVEOFF', amount_minor: 500, currency: 'GBP', title: 'Five pounds off' });
  assert.equal(made.isError, false, made.text);
  assert.equal(made.data.done, 'The code FIVEOFF now gives 5.00 GBP off an order.');
  assert.deepEqual(made.data.amount_off, gbp('5.00', 500));
  assert.equal(made.data.warning, undefined);
  const sent = fake.of('CreateDiscountCode')[0].variables.basicCodeDiscount;
  assert.deepEqual(sent.customerGets, { value: { discountAmount: { amount: '5.00', appliesOnEachItem: false } }, items: { all: true } });
  assert.equal(sent.title, 'Five pounds off');
  const wrong = await server.call('create_amount_discount_code', { code: 'TENOFF', amount_minor: 1000, currency: 'EUR' });
  assert.equal(wrong.isError, true);
  assert.match(wrong.text, /The shop's currency is GBP, not EUR\. Nothing was changed\./);
  const none = await server.call('create_amount_discount_code', { code: 'NOTHING', amount_minor: 0, currency: 'GBP' });
  assert.match(none.text, /"amount_minor" must be from 1 to/);
  assert.equal(fake.of('CreateDiscountCode').length, 1);
  await end();
});

test('deactivate_discount_code: the code can no longer be used; one that is not there is told in Shopify\'s words', async () => {
  const { fake, server, end } = await world();
  const ended = await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' });
  assert.equal(ended.isError, false, ended.text);
  assert.equal(ended.data.done, 'The discount code WELCOME10 can no longer be used.');
  assert.equal(ended.data.status, 'EXPIRED');
  assert.deepEqual(fake.of('DeactivateDiscountCode').map((r) => r.variables), [{ id: 'gid://shopify/DiscountCodeNode/1' }]);
  const none = await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/999' });
  assert.equal(none.isError, true);
  assert.match(none.text, /Shopify refused the change to the discount code: id: Discount does not exist\. Nothing was changed\./);
  await end();
});

test('list_orders and read_order: totals, payments and refunds, and nothing about the customer is asked for', async () => {
  const { fake, server, end } = await world();
  const list = await server.call('list_orders', { first: 3 });
  assert.equal(list.isError, false, list.text);
  assert.deepEqual(list.data.orders.map((o) => o.name), ['#1004', '#1003', '#1002'], 'newest first');
  assert.deepEqual(list.data.orders[2], { order_id: ORDER_1002, name: '#1002', created_at: '2026-11-10T09:00:02Z', cancelled_at: null, test: false, payment: 'PAID', fulfilment: 'UNFULFILLED', currency: 'GBP', total: gbp('35.00', 3500), refunded: gbp('0.00', 0) });
  assert.equal(list.data.next, '3');
  const read = await server.call('read_order', { order_id: ORDER_1001 });
  assert.equal(read.isError, false, read.text);
  assert.deepEqual(read.data, {
    order_id: ORDER_1001, name: '#1001', test: false, currency: 'GBP', shop_currency: 'GBP',
    total: gbp('25.00', 2500), received: gbp('25.00', 2500), refunded: gbp('0.00', 0), paid_and_not_refunded: gbp('25.00', 2500), can_be_refunded: true,
    created_at: '2026-11-10T09:00:01Z', cancelled_at: null, payment: 'PAID', fulfilment: 'UNFULFILLED',
    items: [
      { item_id: 'gid://shopify/LineItem/9001', title: 'Mug', sku: 'MUG-B', quantity: 2, unit_price: gbp('10.00', 1000) },
      { item_id: 'gid://shopify/LineItem/9002', title: 'Delivery box', sku: null, quantity: 1, unit_price: gbp('5.00', 500) },
    ],
    more_items: false,
    transactions: [{ transaction_id: 'gid://shopify/OrderTransaction/501', kind: 'SALE', status: 'SUCCESS', gateway: 'made-up-gateway', created_at: '2026-11-10T09:00:05Z', amount: gbp('25.00', 2500), parent: null }],
    refunds: [],
  });
  const none = await server.call('read_order', { order_id: 'gid://shopify/Order/999' });
  assert.match(none.text, /The store has no order gid:\/\/shopify\/Order\/999\./);
  for (const r of fake.sent) assert.doesNotMatch(r.body, /email|phone|[aA]ddress|firstName|lastName|customer\s*\{/, `${r.operation} asks nothing about a customer`);
  await end();
});

test('refund_order: part of an order, as one refund transaction against the payment, sent once with an idempotency key', async () => {
  const { fake, server, end } = await world();
  const refund = await server.call('refund_order', { order_id: ORDER_1001, amount_minor: 750, currency: 'GBP', note: 'One mug arrived chipped' });
  assert.equal(refund.isError, false, refund.text);
  assert.deepEqual(refund.data, { done: '7.50 GBP was refunded on order #1001.', refund_id: 'gid://shopify/Refund/701', order_id: ORDER_1001, refunded: gbp('7.50', 750), customer_told: false });
  const sent = fake.of('RefundOrder');
  assert.equal(sent.length, 1);
  assert.match(JSON.parse(sent[0].body).query, /refundCreate\(input: \$input\) @idempotent\(key: \$idempotencyKey\)/);
  assert.match(sent[0].variables.idempotencyKey, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.deepEqual(sent[0].variables.input, {
    orderId: ORDER_1001, currency: 'GBP', notify: false, note: 'One mug arrived chipped',
    transactions: [{ orderId: ORDER_1001, parentId: 'gid://shopify/OrderTransaction/501', kind: 'REFUND', gateway: 'made-up-gateway', amount: '7.50' }],
  });
  const after = await server.call('read_order', { order_id: ORDER_1001 });
  assert.deepEqual(after.data.refunded, gbp('7.50', 750));
  assert.deepEqual(after.data.paid_and_not_refunded, gbp('17.50', 1750));
  assert.deepEqual(after.data.refunds, [{ refund_id: 'gid://shopify/Refund/701', created_at: '2026-11-14T12:00:00Z', note: 'One mug arrived chipped', total: gbp('7.50', 750) }]);
  await end();
});

test('refund_order: all of an order is its "paid_and_not_refunded", stated as any other amount; a second refund has a key of its own', async () => {
  const { fake, server, end } = await world();
  await server.call('refund_order', { order_id: ORDER_1001, amount_minor: 750, currency: 'GBP' });
  const left = (await server.call('read_order', { order_id: ORDER_1001 })).data.paid_and_not_refunded.amount_minor;
  assert.equal(left, 1750);
  const rest = await server.call('refund_order', { order_id: ORDER_1001, amount_minor: left, currency: 'GBP', notify: true });
  assert.equal(rest.isError, false, rest.text);
  assert.equal(rest.data.customer_told, true);
  assert.equal(fake.of('RefundOrder')[1].variables.input.notify, true);
  assert.equal(fake.of('RefundOrder')[1].variables.input.transactions[0].amount, '17.50');
  assert.notEqual(fake.of('RefundOrder')[0].variables.idempotencyKey, fake.of('RefundOrder')[1].variables.idempotencyKey);
  const now = (await server.call('read_order', { order_id: ORDER_1001 })).data;
  assert.deepEqual([now.refunded.amount_minor, now.paid_and_not_refunded.amount_minor, now.can_be_refunded], [2500, 0, false]);
  const more = await server.call('refund_order', { order_id: ORDER_1001, amount_minor: 1, currency: 'GBP' });
  assert.equal(more.isError, true);
  assert.match(more.text, /cannot be refunded/);
  assert.equal(fake.of('RefundOrder').length, 2, 'no third refund was sent');
  await end();
});

test('refund_order: a refund Shopify refuses is a tool error in its words, sent once, and no money moves', async () => {
  const { fake, server, end } = await world();
  const refused = await server.call('refund_order', { order_id: 'gid://shopify/Order/1004', amount_minor: 1000, currency: 'GBP' });
  assert.equal(refused.isError, true);
  assert.equal(refused.text, 'Shopify refused the refund: transactions: The payment gateway declined the refund. Nothing was changed.');
  assert.equal(fake.of('RefundOrder').length, 1, 'the refund was sent once and not again');
  assert.equal(fake.store.orders[3].refunds.length, 0);
  await end();
});

test('refund_order: what the server refuses itself, before any refund is sent', async () => {
  const { fake, server, end } = await world();
  const cases = [
    [{ order_id: ORDER_1001, amount_minor: 2501, currency: 'GBP' }, /Order #1001 has 25\.00 GBP paid and not refunded, less than the 25\.01 GBP asked for\. Nothing was refunded\./],
    [{ order_id: ORDER_1001, amount_minor: 750, currency: 'USD' }, /Order #1001 was paid in GBP, not USD\. Nothing was refunded\./],
    [{ order_id: 'gid://shopify/Order/1003', amount_minor: 750, currency: 'EUR' }, /Order #1003 was paid in EUR and the shop's currency is GBP\. This server refunds only an order paid in the shop's own currency/],
    [{ order_id: 'gid://shopify/Order/999', amount_minor: 750, currency: 'GBP' }, /The store has no order/],
    [{ order_id: ORDER_1002, amount_minor: 750, currency: 'GBP' }, /Order #1002 has 2 payments\. Say which to refund with "transaction_id": gid:\/\/shopify\/OrderTransaction\/502 \(20\.00 GBP\), gid:\/\/shopify\/OrderTransaction\/503 \(15\.00 GBP\)\. Nothing was refunded\./],
    [{ order_id: ORDER_1002, amount_minor: 750, currency: 'GBP', transaction_id: 'gid://shopify/OrderTransaction/504' }, /gid:\/\/shopify\/OrderTransaction\/504 is not a successful payment of order #1002/],
    [{ order_id: ORDER_1001, amount_minor: 7.5, currency: 'GBP' }, /"amount_minor" must be a whole number/],
    [{ order_id: ORDER_1001, amount_minor: '750', currency: 'GBP' }, /"amount_minor" must be a whole number/],
    [{ order_id: ORDER_1001, amount_minor: 0, currency: 'GBP' }, /"amount_minor" must be from 1 to/],
    [{ order_id: ORDER_1001, currency: 'GBP' }, /"amount_minor" is missing/],
    [{ order_id: ORDER_1001, amount_minor: 750 }, /"currency" is missing/],
    [{ order_id: ORDER_1001, amount_minor: 750, currency: 'GBP', allowOverRefunding: true }, /"allowOverRefunding" is not an argument of this tool/],
    [{ order_id: ORDER_1001, amount_minor: 750, currency: 'GBP', Amount_minor: 1 }, /"Amount_minor" is not an argument of this tool/],
    [{ order_id: ORDER_1001, amount_minor: 750, currency: 'GBP', notify: 'yes' }, /"notify" must be true or false/],
  ];
  for (const [args, said] of cases) {
    const refused = await server.call('refund_order', args);
    assert.equal(refused.isError, true, String(said));
    assert.match(refused.text, said);
  }
  assert.equal(fake.of('RefundOrder').length, 0, 'no refund was sent');
  await end();
});

test('refund_order: an order with two payments is refunded from the one named', async () => {
  const { fake, server, end } = await world();
  const refund = await server.call('refund_order', { order_id: ORDER_1002, amount_minor: 1500, currency: 'GBP', transaction_id: 'gid://shopify/OrderTransaction/503' });
  assert.equal(refund.isError, false, refund.text);
  assert.equal(fake.of('RefundOrder')[0].variables.input.transactions[0].parentId, 'gid://shopify/OrderTransaction/503');
  await end();
});
