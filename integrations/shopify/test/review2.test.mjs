// The findings of the second review, each as the case that failed: a
// refund sent again with its key, what a refund's answer takes from
// Shopify, a new discount code held against what was asked, the key named
// in every answer to a refund that was sent, the thing read held against
// the id asked for, and a setting whose name is not one of the server's.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, runToEnd, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const BLUE = 'gid://shopify/ProductVariant/11';
const ORDER_1001 = 'gid://shopify/Order/1001';
const REFUND = { order_id: ORDER_1001, amount_minor: 750, currency: 'GBP' };
const SENT_NONE = 'This call sent no refund. A key was given, so it may be a second sending of a refund, and whether the first was made is not known to this server.';
const set = (amount, currencyCode = 'GBP') => ({ presentmentMoney: { amount, currencyCode } });

async function world(options, serverOptions) {
  const fake = await fakeShopify(options);
  return { fake, server: startServer(fake, serverOptions) };
}

/** A refund that the made-up store makes and whose answer is lost: the key the answer names. */
async function lostRefund(fake, server, amount_minor) {
  fake.faults.push({ on: 'RefundOrder', kind: 'after', status: 'drop' });
  const lost = await server.call('refund_order', { ...REFUND, amount_minor });
  assert.match(lost.text, /Whether the change was made is not known\./);
  return /"idempotency_key": "([0-9a-f-]{36})"/.exec(lost.text)[1];
}

// --- a refund sent again with its key ---

test('a whole order refunded, the answer lost, and the call sent again with its key: the answer does not say that nothing was refunded, and lists the refund', async () => {
  const { fake, server } = await world();
  const key = await lostRefund(fake, server, 2500);
  const again = await server.call('refund_order', { ...REFUND, amount_minor: 2500, idempotency_key: key });
  assert.equal(again.isError, true);
  assert.equal(again.text, `Shopify says order #1001 cannot be refunded: it has no payment that can be given back. ${SENT_NONE} The refunds of order #1001 so far: gid://shopify/Refund/701 of 25.00 GBP, made at 2026-11-14T12:00:00Z.`);
  assert.doesNotMatch(again.text, /Nothing was refunded/);
  assert.equal(fake.of('RefundOrder').length, 1, 'no second refund was sent');
});

test('most of an order refunded, the answer lost, and the call sent again with its key: the same', async () => {
  const { fake, server } = await world();
  const key = await lostRefund(fake, server, 2000);
  const again = await server.call('refund_order', { ...REFUND, amount_minor: 2000, idempotency_key: key });
  assert.equal(again.text, `Order #1001 has 5.00 GBP paid and not refunded, less than the 20.00 GBP asked for. ${SENT_NONE} The refunds of order #1001 so far: gid://shopify/Refund/701 of 20.00 GBP, made at 2026-11-14T12:00:00Z.`);
  assert.doesNotMatch(again.text, /Nothing was refunded/);
  assert.equal(fake.of('RefundOrder').length, 1);
});

test('with a key given, no refusal of the server says that nothing was refunded; without one, it does', async () => {
  const { fake, server } = await world();
  const key = '3f5b6ebf-143c-4da5-8d0f-fb8553bfd85d';
  const none = `${SENT_NONE} Order #1001 has no refund so far.`;
  const keyed = async (args) => (await server.call('refund_order', { ...REFUND, idempotency_key: key, ...args })).text;
  assert.equal(await keyed({ amount_minor: 2501 }), `Order #1001 has 25.00 GBP paid and not refunded, less than the 25.01 GBP asked for. ${none}`);
  assert.equal(await keyed({ currency: 'USD' }), `Order #1001 was paid in GBP, not USD. ${none}`);
  assert.equal(await keyed({ transaction_id: 'gid://shopify/OrderTransaction/999' }), `gid://shopify/OrderTransaction/999 is not a successful payment of order #1001. ${none}`);
  // Before the order is read there are no refunds to list.
  const read = `${SENT_NONE} Read the order: its refunds show what was given back.`;
  fake.faults.push({ on: 'OrderForRefund', kind: 'status', status: 500 });
  assert.equal(await keyed({}), `Shopify had an error (HTTP 500). ${read}`);
  assert.equal(await keyed({ order_id: 'gid://shopify/Order/999' }), `The store has no order gid://shopify/Order/999. ${read}`);
  // Where Shopify does not list the refunds, that is said.
  fake.faults.push({ on: 'OrderForRefund', kind: 'tamper', with: (d) => {
    delete d.order.refunds;
  } });
  assert.equal(await keyed({ amount_minor: 2501 }), `Order #1001 has 25.00 GBP paid and not refunded, less than the 25.01 GBP asked for. ${SENT_NONE} Shopify did not list the order's refunds; read the order to see what was given back.`);
  // Without a key the call is no second sending, and the plain ending stands.
  assert.equal((await server.call('refund_order', { ...REFUND, amount_minor: 2501 })).text, 'Order #1001 has 25.00 GBP paid and not refunded, less than the 25.01 GBP asked for. Nothing was refunded.');
  assert.equal(fake.of('RefundOrder').length, 0);
  // The refunds are asked for with the order.
  assert.match(JSON.parse(fake.of('OrderForRefund')[0].body).query, /refunds\(first: 50\) \{ id createdAt note totalRefundedSet/);
});

test('a refund\'s answer says when Shopify made it', async () => {
  const { server } = await world();
  assert.equal((await server.call('refund_order', REFUND)).data.made_at, '2026-11-14T12:00:00Z');
});

// --- what a refund's answer takes from Shopify ---

test('a refund not yet confirmed whose amount is not the one asked for, or cannot be read, is a tool error', async () => {
  const { fake, server } = await world();
  fake.store.orders[0].paymentState = 'PENDING';
  const payment = (change) => ({ on: 'RefundOrder', kind: 'tamper', with: (d) => change(d.refundCreate.refund.transactions.nodes[0]) });
  fake.faults.push(
    payment((t) => {
      t.amountSet = set('25.00');
    }),
    payment((t) => {
      t.amountSet = set('0.00');
    }),
    payment((t) => {
      t.amountSet = set('1.00', 'EUR');
    }),
    payment((t) => {
      delete t.amountSet;
    }),
  );
  const said = [];
  for (let i = 0; i < 4; i++) {
    const refund = await server.call('refund_order', { ...REFUND, amount_minor: 100 });
    assert.equal(refund.isError, true, refund.text);
    assert.doesNotMatch(refund.text, /recorded a refund of/);
    said.push(refund.text.replace(/ This refund was sent with .+$/, ''));
  }
  assert.equal(said[0], 'Shopify made a refund on order #1001 (gid://shopify/Refund/701) and reports 25.00 GBP to be sent back, where 1.00 GBP was asked for. Read the order to see what was given back.');
  assert.equal(said[1], 'Shopify made a refund on order #1001 (gid://shopify/Refund/702) and reports 0.00 GBP to be sent back, where 1.00 GBP was asked for. Read the order to see what was given back.');
  for (const [i, text] of said.slice(2).entries()) assert.equal(text, `Shopify recorded a refund on order #1001 (gid://shopify/Refund/70${i + 3}) and gives the amount of its payment in a form this server cannot read, or in another currency than GBP, where 1.00 GBP was asked for. Read the order to see what was given back.`);
});

test('a refund whose transaction is not a refund is not said to be done', async () => {
  const { fake, server } = await world();
  for (const kind of ['SALE', 'VOID']) {
    fake.faults.push({ on: 'RefundOrder', kind: 'tamper', with: (d) => {
      d.refundCreate.refund.transactions.nodes[0].kind = kind;
    } });
    const refund = await server.call('refund_order', { ...REFUND, amount_minor: 100 });
    assert.equal(refund.isError, true);
    assert.match(refund.text, new RegExp(`^Shopify recorded a refund on order #1001 \\(gid://shopify/Refund/70\\d\\) and names with it a transaction that is not a refund \\(${kind}\\), so whether any money was given back is not known\\.`));
    assert.doesNotMatch(refund.text, /was refunded/);
  }
});

// --- the key in every answer to a refund that was sent ---

test('every answer to a refund that was sent names the key it was sent with, a failure too', async () => {
  const { fake, server } = await world();
  fake.store.orders[0].paymentState = 'FAILURE';
  fake.faults.push(
    { on: 'RefundOrder', kind: 'status', status: 401 },
    { on: 'RefundOrder', kind: 'status', status: 403, body: {} },
    { on: 'RefundOrder', kind: 'answer', body: { data: { refundCreate: { refund: null, userErrors: [] } } } },
  );
  const calls = [
    REFUND, // answered 401
    REFUND, // answered 403
    REFUND, // no refund and no reason
    REFUND, // the payment failed
    { ...REFUND, order_id: 'gid://shopify/Order/1004' }, // refused by Shopify in its userErrors
  ];
  for (const [i, args] of calls.entries()) {
    const answer = await server.call('refund_order', args);
    const key = fake.of('RefundOrder')[i].variables.idempotencyKey;
    assert.equal(answer.isError, true, answer.text);
    assert.ok(answer.text.includes(`"idempotency_key": "${key}"`), answer.text);
    assert.equal(answer.text.split(key).length, 2, 'named once');
  }
  assert.equal(fake.of('RefundOrder').length, 5);
});

// --- a new discount code held against what was asked ---

test('a new discount code is said to be made only where its limit on uses, its end, its code and its state are as asked', async () => {
  const { fake, server } = await world();
  const asked = { code: 'TEN', percent: 10, usage_limit: 10, once_per_customer: true, starts_at: '2026-12-01T00:00:00Z', ends_at: '2026-12-31T23:59:59Z' };
  const code = (change) => ({ on: 'CreateDiscountCode', kind: 'tamper', with: (d) => change(d.discountCodeBasicCreate.codeDiscountNode.codeDiscount, d.discountCodeBasicCreate.codeDiscountNode) });
  fake.faults.push(
    code((c) => {
      c.usageLimit = null;
      c.appliesOncePerCustomer = false;
      c.endsAt = null;
    }),
    code((c) => {
      c.codes.nodes = [{ code: 'OTHER' }];
      c.status = 'EXPIRED';
      c.startsAt = '2026-11-01T00:00:00Z';
    }),
    code((c) => {
      c.usageLimit = 5;
    }),
  );
  const said = [];
  for (const name of ['TEN', 'TEN2', 'FIVE']) {
    const answer = name === 'FIVE'
      ? await server.call('create_amount_discount_code', { code: 'FIVE', amount_minor: 500, currency: 'GBP' })
      : await server.call('create_percentage_discount_code', { ...asked, code: name });
    assert.equal(answer.isError, true, answer.text);
    assert.doesNotMatch(answer.text, /now gives|will give/);
    said.push(answer.text);
  }
  assert.equal(said[0], 'Shopify made the code TEN (gid://shopify/DiscountCodeNode/3) and reports it otherwise than was asked: the limit on uses as none where 10 was asked for; once for each customer as false where true was asked for; its end as none where 2026-12-31T23:59:59Z was asked for. List the discount codes to see what it is.');
  assert.equal(said[1], 'Shopify made the code TEN2 (gid://shopify/DiscountCodeNode/4) and reports it otherwise than was asked: the code OTHER; its start as 2026-11-01T00:00:00Z where 2026-12-01T00:00:00Z was asked for; the state EXPIRED. List the discount codes to see what it is.');
  assert.equal(said[2], 'Shopify made the code FIVE (gid://shopify/DiscountCodeNode/5) and reports it otherwise than was asked: the limit on uses as 5 where none was asked for. List the discount codes to see what it is.');
});

test('a code that starts later is said to give its discount from then; a time Shopify writes in another zone is the same time; a code is the same in either case of letters', async () => {
  const { fake, server } = await world();
  fake.faults.push({ on: 'CreateDiscountCode', kind: 'tamper', with: (d) => {
    const c = d.discountCodeBasicCreate.codeDiscountNode.codeDiscount;
    c.status = 'SCHEDULED';
    c.startsAt = '2026-12-01T01:00:00+01:00';
    c.endsAt = '2026-12-31T18:59:59-05:00';
    c.codes.nodes = [{ code: 'WINTER' }];
  } });
  const later = await server.call('create_percentage_discount_code', { code: 'Winter', percent: 15, starts_at: '2026-12-01T00:00:00Z', ends_at: '2026-12-31T23:59:59Z' });
  assert.equal(later.isError, false, later.text);
  assert.equal(later.data.done, 'The code Winter will give 15% off from 2026-12-01T01:00:00+01:00.');
});

// --- the thing read is the thing asked for ---

test('a reading answered with another variant, order, product or discount code than the one asked for changes nothing', async () => {
  const { fake, server } = await world();
  fake.faults.push(
    { on: 'ReadVariant', kind: 'tamper', with: (d) => {
      d.productVariant.id = 'gid://shopify/ProductVariant/99';
    } },
    { on: 'ReadVariant', kind: 'tamper', with: (d) => {
      delete d.productVariant.id;
    } },
    { on: 'OrderForRefund', kind: 'tamper', with: (d) => {
      d.order.id = 'gid://shopify/Order/1002';
    } },
    { on: 'ReadProduct', kind: 'tamper', with: (d) => {
      d.product.id = 'gid://shopify/Product/2';
    } },
    { on: 'ReadOrder', kind: 'tamper', with: (d) => {
      d.order.id = 'gid://shopify/Order/1002';
    } },
    { on: 'DeactivateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeDeactivate.codeDiscountNode.id = 'gid://shopify/DiscountCodeNode/2';
    } },
  );
  const price = { variant_id: BLUE, price_minor: 1250, currency: 'GBP' };
  assert.equal((await server.call('set_variant_price', price)).text, 'Shopify answered the reading of gid://shopify/ProductVariant/11 with another variant (gid://shopify/ProductVariant/99). Nothing was changed.');
  assert.equal((await server.call('set_variant_price', price)).text, 'Shopify answered the reading of gid://shopify/ProductVariant/11 with another variant (one with no id). Nothing was changed.');
  assert.equal((await server.call('refund_order', REFUND)).text, 'Shopify answered the reading of gid://shopify/Order/1001 with another order (gid://shopify/Order/1002). Nothing was refunded.');
  assert.equal((await server.call('read_product', { product_id: 'gid://shopify/Product/1' })).text, 'Shopify answered the reading of gid://shopify/Product/1 with another product.');
  assert.equal((await server.call('read_order', { order_id: ORDER_1001 })).text, 'Shopify answered the reading of gid://shopify/Order/1001 with another order.');
  assert.equal(fake.of('SetVariantPrice').length + fake.of('RefundOrder').length, 0, 'no change was sent');
  const stopped = await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' });
  assert.equal(stopped.isError, true);
  assert.equal(stopped.text, 'Shopify answered with another discount code (gid://shopify/DiscountCodeNode/2) than the one asked for. List the discount codes to see which can still be used.');
});

test('an id is written one way: a number with noughts before it is refused', async () => {
  const { fake, server } = await world();
  const cases = [
    ['refund_order', { ...REFUND, order_id: 'gid://shopify/Order/01001' }, /"order_id" is not in the form/],
    ['refund_order', { ...REFUND, order_id: 'gid://shopify/Order/0' }, /"order_id" is not in the form/],
    ['refund_order', { ...REFUND, transaction_id: 'gid://shopify/OrderTransaction/0501' }, /"transaction_id" is not in the form/],
    ['set_variant_price', { variant_id: 'gid://shopify/ProductVariant/011', price_minor: 1250, currency: 'GBP' }, /"variant_id" is not in the form/],
    ['read_product', { product_id: 'gid://shopify/Product/01' }, /"product_id" is not in the form/],
    ['deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/001' }, /"discount_id" is not in the form/],
  ];
  for (const [tool, args, said] of cases) {
    const refused = await server.call(tool, args);
    assert.equal(refused.isError, true, JSON.stringify(args));
    assert.match(refused.text, said);
  }
  assert.equal(fake.sent.length, 0);
});

// --- a setting the server does not know ---

test('a variable that begins SHOPIFY_ and is not one of the server\'s settings stops the start, and its value is not said', async () => {
  const good = { SHOPIFY_SHOP: 'made-up-store', SHOPIFY_TEST_ORIGIN: 'http://127.0.0.1:9', SHOPIFY_CLIENT_ID: 'made-up-client-id', SHOPIFY_CLIENT_SECRET: 'shpss_made_up_secret', SHOPIFY_MAX_PRICE_CUT_PERCENT: '50' };
  for (const [name, value] of [['SHOPIFY_MIN_PRICE', '500'], ['SHOPIFY_MAX_PRICE_CUT', '100'], ['SHOPIFY_MIN_PRICE_MINOR_', '500'], ['shopify_min_price', '500'], ['SHOPIFY_ACCESS_TOKEN', 'shpat_a_value_not_to_be_said']]) {
    const run = await runToEnd([], { ...good, [name]: value });
    assert.equal(run.code, 1, name);
    assert.ok(run.stderr.startsWith(`provared-shopify: ${name}: not a setting of this server, so it will not start. Its settings are SHOPIFY_SHOP, SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_ID_FILE, SHOPIFY_CLIENT_SECRET, SHOPIFY_CLIENT_SECRET_FILE, SHOPIFY_MIN_PRICE_MINOR, SHOPIFY_MAX_PRICE_CUT_PERCENT.`), run.stderr);
    assert.ok(!run.stderr.includes(value), 'the value is not said');
    assert.equal(run.stdout, '');
  }
  assert.equal((await runToEnd([], good)).code, 0, 'with its own settings alone it starts');
  assert.match((await runToEnd(['--help'], {})).stdout, /Any other variable whose name begins SHOPIFY_ stops the start/);
});
