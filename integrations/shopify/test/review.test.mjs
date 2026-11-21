// The findings of the independent review of 14 November 2026, each as the
// case that failed: what a refund's answer says, where a line ends, when
// "not made" may be said, how orders are found, which version of the Admin
// API answered, and the smaller points. Against the made-up Shopify.

import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { THROTTLED, closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, startServer } from './world.mjs';

// A test that fails half-way leaves no server running and nothing listening.
afterEach(async () => {
  await closeServers();
  await closeFakes();
});

const BLUE = 'gid://shopify/ProductVariant/11';
const ORDER_1001 = 'gid://shopify/Order/1001';
const REFUND = { order_id: ORDER_1001, amount_minor: 750, currency: 'GBP' };
const PRICE = { variant_id: BLUE, price_minor: 1250, currency: 'GBP' };
const gbp = (amount, amount_minor) => ({ amount, amount_minor, currency: 'GBP' });
const set = (amount) => ({ presentmentMoney: { amount, currencyCode: 'GBP' } });

async function world(options, serverOptions) {
  const fake = await fakeShopify(options);
  return { fake, server: startServer(fake, serverOptions) };
}

/** The requests that change something at the made-up store. */
function changes(fake) {
  return fake.sent.filter((r) => ['SetVariantPrice', 'CreateDiscountCode', 'DeactivateDiscountCode', 'RefundOrder'].includes(r.operation));
}

// --- a refund's answer says what Shopify reports of the money ---

test('a refund whose payment Shopify has not yet confirmed is not said to be done', async () => {
  const { fake, server } = await world();
  for (const state of ['PENDING', 'AWAITING_RESPONSE', 'UNKNOWN']) {
    fake.store.orders[0].paymentState = state;
    const refund = await server.call('refund_order', { ...REFUND, amount_minor: 100 });
    assert.equal(refund.isError, false, refund.text);
    assert.equal(refund.data.done, undefined, 'it does not say done');
    assert.equal(refund.data.refunded, undefined, 'nor that any money was refunded');
    assert.equal(refund.data.not_confirmed, `Shopify recorded a refund of 1.00 GBP on order #1001, and has not yet reported the money as sent (${state}). Read the order later to see whether it was.`);
    assert.equal(refund.data.transactions[0].status, state);
    assert.doesNotMatch(refund.text, /was refunded/);
  }
  // The state of the refund's own transactions is asked for with the refund.
  assert.match(JSON.parse(fake.of('RefundOrder')[0].body).query, /refund \{ id createdAt totalRefundedSet \{ presentmentMoney \{ amount currencyCode \} \} transactions\(first: 10\) \{ nodes \{ id kind status amountSet \{ presentmentMoney \{ amount currencyCode \} \} \} \} \}/);
});

test('a refund whose payment Shopify reports as failed is a tool error', async () => {
  const { fake, server } = await world();
  for (const state of ['FAILURE', 'ERROR']) {
    fake.store.orders[0].paymentState = state;
    const refund = await server.call('refund_order', { ...REFUND, amount_minor: 100 });
    assert.equal(refund.isError, true);
    assert.match(refund.text, new RegExp(`^Shopify recorded a refund on order #1001 \\(gid://shopify/Refund/70\\d\\), and reports that the sending of the money failed \\(${state}\\)\\. Read the order to see what was given back\\. This refund was sent with "idempotency_key": "[0-9a-f-]{36}"\\.$`));
    assert.doesNotMatch(refund.text, /was refunded/);
  }
});

test('a refund for which Shopify reports another amount, or names no payment, is a tool error that gives Shopify\'s figure', async () => {
  const { fake, server } = await world();
  fake.faults.push(
    { on: 'RefundOrder', kind: 'tamper', with: (d) => {
      d.refundCreate.refund.totalRefundedSet = set('0.00');
      d.refundCreate.refund.transactions.nodes[0].amountSet = set('0.00');
    } },
    { on: 'RefundOrder', kind: 'tamper', with: (d) => {
      d.refundCreate.refund.totalRefundedSet = set('25.00');
    } },
    { on: 'RefundOrder', kind: 'tamper', with: (d) => {
      d.refundCreate.refund.transactions.nodes = [];
    } },
    { on: 'RefundOrder', kind: 'tamper', with: (d) => {
      delete d.refundCreate.refund.transactions;
    } },
  );
  const said = [];
  for (let i = 0; i < 4; i++) {
    const refund = await server.call('refund_order', { ...REFUND, amount_minor: 100 });
    assert.equal(refund.isError, true);
    assert.doesNotMatch(refund.text, /was refunded/);
    said.push(refund.text);
  }
  const keys = fake.of('RefundOrder').map((r) => r.variables.idempotencyKey);
  assert.equal(said[0], `Shopify made a refund on order #1001 (gid://shopify/Refund/701) and reports 0.00 GBP sent back, where 1.00 GBP was asked for. Read the order to see what was given back. This refund was sent with "idempotency_key": "${keys[0]}".`);
  assert.equal(said[1], `Shopify made a refund on order #1001 (gid://shopify/Refund/702) and reports 25.00 GBP sent back, where 1.00 GBP was asked for. Read the order to see what was given back. This refund was sent with "idempotency_key": "${keys[1]}".`);
  for (const [i, text] of said.slice(2).entries()) assert.equal(text.replace(/Refund\/70\d/, 'Refund/70N'), `Shopify recorded a refund on order #1001 (gid://shopify/Refund/70N) and named no payment of it, so whether any money was given back is not known. Read the order to see what was given back. This refund was sent with "idempotency_key": "${keys[i + 2]}".`);
});

// --- one message is one line ---

test('a message with carriage returns in it is one message, and what stands between them is not a call', async () => {
  const { fake, server } = await world();
  const hidden = JSON.stringify({ jsonrpc: '2.0', id: 9002, method: 'tools/call', params: { name: 'refund_order', arguments: { order_id: ORDER_1001, amount_minor: 2500, currency: 'GBP' } } });
  const line = `{"jsonrpc":"2.0","id":9001,"method":"tools/call","params":{"name":"list_products","arguments":{},"_meta":{"x":[\r${hidden}\r]}}}\n`;
  JSON.parse(line); // it is one valid JSON message
  const answer = await server.raw(9001, line);
  assert.equal(answer.result.isError, undefined);
  assert.equal(JSON.parse(answer.result.content[0].text).products.length, 3);
  assert.deepEqual((await server.request('ping')).result, {});
  assert.deepEqual(server.unasked, [], 'no piece of it was read as a line of its own');
  assert.deepEqual(fake.sent.map((r) => r.operation), ['sign-in', 'ListProducts'], 'no refund was sent');
  assert.equal(fake.store.orders[0].refunds.length, 0);
});

test('U+2028 and U+2029 inside a text argument do not end the line: the call is answered', async () => {
  const { fake, server } = await world();
  for (const [mark, code] of [['\u2028', 'LS'], ['\u2029', 'PS']]) {
    const call = JSON.stringify({ jsonrpc: '2.0', id: 9100 + code.length + code.charCodeAt(0), method: 'tools/call', params: { name: 'create_percentage_discount_code', arguments: { code, percent: 10, title: `Ten${mark}off` } } });
    assert.ok(call.includes(mark), 'the mark is written raw in the message');
    const answer = await server.raw(JSON.parse(call).id, `${call}\n`);
    assert.equal(answer.result?.isError, undefined, JSON.stringify(answer));
    assert.equal(fake.of('CreateDiscountCode').at(-1).variables.basicCodeDiscount.title, `Ten${mark}off`);
  }
  assert.deepEqual(server.unasked, []);
});

test('a line may end with a carriage return and a line feed, and the last line needs no line feed', async () => {
  const { server } = await world();
  assert.deepEqual((await server.raw(9201, '{"jsonrpc":"2.0","id":9201,"method":"ping"}\r\n')).result, {});
  const last = server.raw(9202, '{"jsonrpc":"2.0","id":9202,"method":"ping"}');
  assert.equal(await server.close(), 0);
  assert.deepEqual((await last).result, {});
  assert.deepEqual(server.unasked, []);
});

// --- "not made" is said only where it is known ---

test('an error beside a result does not say the change was not made', async () => {
  const { fake, server } = await world();
  const beside = (code) => ({ data: { refundCreate: { refund: { id: 'gid://shopify/Refund/999' }, userErrors: [] } }, errors: [{ message: 'Access denied for staffMember field.', extensions: { code } }] });
  fake.faults.push({ on: 'RefundOrder', kind: 'answer', body: beside('ACCESS_DENIED') }, { on: 'RefundOrder', kind: 'answer', body: beside('THROTTLED') });
  const denied = await server.call('refund_order', REFUND);
  const throttled = await server.call('refund_order', REFUND);
  assert.match(denied.text, /^Shopify refused part of the request for want of access \(Access denied for staffMember field\.\), yet its answer also holds a result\. Whether the change was made is not known\. Read the order before trying again; /);
  assert.match(throttled.text, /^Shopify says it is limiting this app's requests \(THROTTLED\), yet its answer also holds a result\. Whether the change was made is not known\. /);
  for (const answer of [denied, throttled]) {
    assert.equal(answer.isError, true);
    assert.doesNotMatch(answer.text, /not made|Nothing was/);
  }
  // With no result at all (no data, or the change's own field null), it is a refusal, as before.
  fake.faults.push({ on: 'RefundOrder', kind: 'answer', body: { data: { refundCreate: null }, errors: THROTTLED } }, { on: 'RefundOrder', kind: 'answer', body: { errors: [{ message: 'Access denied', extensions: { code: 'ACCESS_DENIED' } }] } });
  assert.match((await server.call('refund_order', REFUND)).text, /\(THROTTLED\)\. The change was not made\./);
  assert.match((await server.call('refund_order', REFUND)).text, /\(Access denied\)\. The change was not made\./);
});

test('an HTTP answer that is neither Shopify\'s answer nor one of its refusals does not say the change was not made', async () => {
  const { fake, server } = await world();
  for (const status of [202, 204, 408, 409, 418]) {
    fake.faults.push({ on: 'SetVariantPrice', kind: 'status', status, body: {} });
    const answer = await server.call('set_variant_price', PRICE);
    assert.equal(answer.isError, true);
    assert.equal(answer.text, `Shopify answered HTTP ${status}, which is neither its answer to a request nor one of its refusals. Whether the change was made is not known. Read the product before trying again.`);
  }
  for (const status of [400, 403]) {
    fake.faults.push({ on: 'SetVariantPrice', kind: 'status', status, body: {} });
    assert.equal((await server.call('set_variant_price', PRICE)).text, `Shopify refused the request (HTTP ${status}). The change was not made.`);
  }
  assert.equal(fake.of('SetVariantPrice').length, 7, 'each was sent once');
});

test('Shopify\'s userErrors beside a result do not say that nothing was changed', async () => {
  const { fake, server } = await world();
  const fault = [{ field: ['input', 'note'], message: 'Note was cut short' }];
  fake.faults.push(
    { on: 'RefundOrder', kind: 'tamper', with: (d) => {
      d.refundCreate.userErrors = fault;
    } },
    { on: 'SetVariantPrice', kind: 'tamper', with: (d) => {
      d.productVariantsBulkUpdate.userErrors = fault;
    } },
    { on: 'CreateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeBasicCreate.userErrors = fault;
    } },
    { on: 'DeactivateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeDeactivate.userErrors = fault;
    } },
  );
  const answers = [
    await server.call('refund_order', REFUND),
    await server.call('set_variant_price', PRICE),
    await server.call('create_percentage_discount_code', { code: 'TEN', percent: 10 }),
    await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' }),
  ];
  for (const answer of answers) {
    assert.equal(answer.isError, true);
    assert.match(answer.text, /^Shopify reported a fault with the .+ \(input\.note: Note was cut short\), yet its answer also holds a result\. Whether the change was made is not known\. (Read the order before trying again; |Read the product before trying again\.|List the discount codes before trying again\.)/);
    assert.doesNotMatch(answer.text, /Nothing was|not made/);
  }
});

// --- orders are not found by anything about a customer ---

test('list_orders takes fixed filters, and writes Shopify\'s search text itself', async () => {
  const { fake, server } = await world();
  const all = await server.call('list_orders', { status: 'open', financial_status: 'partially_refunded', fulfillment_status: 'unfulfilled', created_from: '2026-11-01T00:00:00Z', created_to: '2026-11-14T23:59:59+01:00', name: '#1001', test: false, first: 5 });
  assert.equal(all.isError, false, all.text);
  assert.deepEqual(fake.of('ListOrders')[0].variables, { first: 5, after: null, query: "status:open financial_status:partially_refunded fulfillment_status:unfulfilled created_at:>='2026-11-01T00:00:00Z' created_at:<='2026-11-14T23:59:59+01:00' name:1001 test:false" });
  await server.call('list_orders', {});
  assert.equal(fake.of('ListOrders')[1].variables.query, null, 'no filter, no search text');
});

test('list_orders takes no search text of the agent\'s, and no filter value that could carry one', async () => {
  const { fake, server } = await world();
  const cases = [
    [{ query: 'email:someone@example.com' }, /"query" is not an argument of this tool/],
    [{ query: 'Bob Norman' }, /"query" is not an argument of this tool/],
    [{ email: 'someone@example.com' }, /"email" is not an argument of this tool/],
    [{ customer_id: '1' }, /"customer_id" is not an argument of this tool/],
    [{ credit_card_last4: '4242' }, /"credit_card_last4" is not an argument of this tool/],
    [{ status: 'open email:someone@example.com' }, /"status" must be one of: open, closed, cancelled, not_closed\./],
    [{ financial_status: 'paid OR email:a*' }, /"financial_status" must be one of/],
    [{ fulfillment_status: 'any' }, /"fulfillment_status" must be one of/],
    [{ name: '1001 email:a*' }, /"name" is not in the form/],
    [{ name: 'Bob Norman' }, /"name" is not in the form/],
    [{ name: "1001' OR email:'a" }, /"name" is not in the form/],
    [{ created_from: "2026-11-01T00:00:00Z' email:'a" }, /"created_from" (is not in the form|must be from)/],
    [{ created_to: 'now' }, /"created_to" is not in the form/],
    [{ test: 'true email:a' }, /"test" must be true or false/],
  ];
  for (const [args, said] of cases) {
    const refused = await server.call('list_orders', args);
    assert.equal(refused.isError, true, JSON.stringify(args));
    assert.match(refused.text, said);
  }
  assert.equal(fake.sent.length, 0, 'nothing was asked of Shopify');
  const schema = (await server.request('tools/list')).result.tools.find((t) => t.name === 'list_orders').inputSchema;
  assert.deepEqual(Object.keys(schema.properties), ['first', 'after', 'status', 'financial_status', 'fulfillment_status', 'created_from', 'created_to', 'name', 'test']);
});

// --- the version of the Admin API that answered ---

const CHANGE_CALLS = {
  set_variant_price: PRICE,
  create_percentage_discount_code: { code: 'TEN', percent: 10 },
  create_amount_discount_code: { code: 'FIVE', amount_minor: 500, currency: 'GBP' },
  deactivate_discount_code: { discount_id: 'gid://shopify/DiscountCodeNode/1' },
  refund_order: REFUND,
};

test('where Shopify answers with another version of the Admin API, or names none, no tool sends a change and no answer is used', async () => {
  const { fake, server } = await world();
  const tools = (await server.request('tools/list')).result.tools;
  assert.deepEqual(tools.filter((t) => !t.annotations.readOnlyHint).map((t) => t.name), Object.keys(CHANGE_CALLS), 'every tool that makes a change is tried here');
  for (const [version, named] of [['2027-07', 'version 2027-07'], [null, 'no version named']]) {
    fake.version = version;
    for (const [tool, args] of Object.entries(CHANGE_CALLS)) {
      const answer = await server.call(tool, args);
      assert.equal(answer.isError, true, tool);
      assert.equal(answer.text, `Shopify answered with ${named} of its Admin API, not 2026-10, the version this server was written for and tested with. Its answer was not used. ${tool === 'refund_order' ? 'Nothing was refunded.' : 'Nothing was changed.'}`);
    }
    const read = await server.call('list_orders', {});
    assert.equal(read.isError, true);
    assert.equal(read.text, `Shopify answered with ${named} of its Admin API, not 2026-10, the version this server was written for and tested with. Its answer was not used.`);
  }
  assert.equal(changes(fake).length, 0, 'no change was sent');
  assert.match(server.stderr(), /provared-shopify: Shopify answered with version 2027-07 of its Admin API, not 2026-10, the version this server was written for\. Its answer was not used, and no change is sent while that is so\./);
  // Once Shopify answers with the server's version again, the tools work.
  fake.version = '2026-10';
  assert.equal((await server.call('refund_order', REFUND)).data.done, '7.50 GBP was refunded on order #1001.');
});

test('a change that another version answers is said to be of unknown outcome', async () => {
  const { fake, server } = await world();
  fake.faults.push({ on: 'RefundOrder', kind: 'version', version: '2027-01' });
  const refund = await server.call('refund_order', REFUND);
  assert.equal(refund.isError, true);
  assert.match(refund.text, /^Shopify answered with version 2027-01 of its Admin API, not 2026-10, the version this server was written for and tested with\. Its answer was not used\. Whether the change was made is not known\. Read the order before trying again; /);
});

// --- the smaller points ---

test('a secret that Shopify repeats late in a long text is taken out whole, not cut in two', async () => {
  const secret = 'shpss_made_up_secret_that_is_long_0123456789abcdef';
  const { fake, server } = await world({ clientSecret: secret }, { env: { SHOPIFY_CLIENT_SECRET_FILE: undefined, SHOPIFY_CLIENT_SECRET: secret } });
  const padding = 'x'.repeat(270);
  fake.faults.push({ on: 'sign-in', kind: 'status', status: 400, body: { error: 'invalid_request', error_description: `${padding} ${secret}` } });
  const signIn = await server.call('list_products', {});
  assert.match(signIn.text, /x{270} \[removed\]/);
  await server.call('list_products', {});
  fake.faults.push({ on: 'ListProducts', kind: 'errors', errors: [{ message: `${'y'.repeat(280)} ${fake.issued[0]} ${secret}`, extensions: { code: 'BAD' } }] });
  const error = await server.call('list_products', {});
  assert.match(error.text, /y{280} \[removed\]/);
  for (let cut = 6; cut < secret.length; cut++) assert.ok(!server.output().includes(secret.slice(0, cut)), `not the first ${cut} characters of the secret`);
  assert.ok(!server.output().includes(fake.issued[0].slice(0, 12)), 'nor the start of the token');
});

test('a secret with a quote or a backslash in it is taken out of an answer written as JSON', async () => {
  const secret = 'sh"pss\\made"up\\secret';
  const { fake, server } = await world({ clientSecret: secret }, { env: { SHOPIFY_CLIENT_SECRET_FILE: undefined, SHOPIFY_CLIENT_SECRET: secret } });
  fake.store.products[0].title = `Mug ${secret}`;
  fake.store.products[0].variants[0].sku = secret;
  const read = await server.call('read_product', { product_id: 'gid://shopify/Product/1' });
  assert.equal(read.isError, false, read.text);
  assert.equal(read.data.title, 'Mug [removed]');
  assert.equal(read.data.variants[0].sku, '[removed]');
  const all = server.output();
  assert.ok(!all.includes(secret) && !all.includes(JSON.stringify(secret).slice(1, -1)) && !all.includes(JSON.stringify(JSON.stringify(secret)).slice(3, -3)), 'the secret is in no output, as itself or as JSON writes it');
});

test('a reading that fails before a change says what became of the change', async () => {
  const { fake, server } = await world();
  fake.faults.push(
    { on: 'OrderForRefund', kind: 'status', status: 500 },
    { on: 'ReadVariant', kind: 'status', status: 500 },
    { on: 'ShopCurrency', kind: 'drop' },
    { on: 'ShopCurrency', kind: 'errors', errors: THROTTLED },
    { on: 'ShopCurrency', kind: 'status', status: 401 }, { on: 'ShopCurrency', kind: 'status', status: 401 },
  );
  assert.equal((await server.call('refund_order', REFUND)).text, 'Shopify had an error (HTTP 500). Nothing was refunded.');
  assert.equal((await server.call('set_variant_price', PRICE)).text, 'Shopify had an error (HTTP 500). Nothing was changed.');
  assert.match((await server.call('create_amount_discount_code', { code: 'FIVE', amount_minor: 500, currency: 'GBP' })).text, /^Could not reach Shopify \(.+\)\. Nothing was changed\.$/);
  assert.match((await server.call('create_percentage_discount_code', { code: 'TEN', percent: 10 })).text, /\(THROTTLED\)\. Nothing was changed\. Wait a second/);
  assert.match((await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' })).text, /nor a new one \(HTTP 401\)\. Check that the app is still installed on this store\. Nothing was changed\.$/);
  assert.equal(changes(fake).length, 0);
});

test('after a change, "done" is said only where Shopify reports what was asked for', async () => {
  const { fake, server } = await world();
  fake.faults.push(
    { on: 'SetVariantPrice', kind: 'tamper', with: (d) => {
      d.productVariantsBulkUpdate.productVariants[0].price = '99.00';
    } },
    { on: 'SetVariantPrice', kind: 'tamper', with: (d) => {
      d.productVariantsBulkUpdate.productVariants = [];
    } },
    { on: 'DeactivateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeDeactivate.codeDiscountNode.codeDiscount.status = 'ACTIVE';
    } },
    { on: 'CreateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeBasicCreate.codeDiscountNode.codeDiscount.customerGets.value.percentage = 0.9;
    } },
    { on: 'CreateDiscountCode', kind: 'tamper', with: (d) => {
      d.discountCodeBasicCreate.codeDiscountNode.codeDiscount.customerGets.value.amount.amount = '50.00';
    } },
  );
  const said = [
    await server.call('set_variant_price', PRICE),
    await server.call('set_variant_price', { ...PRICE, price_minor: 1300 }),
    await server.call('deactivate_discount_code', { discount_id: 'gid://shopify/DiscountCodeNode/1' }),
    await server.call('create_percentage_discount_code', { code: 'TEN', percent: 10 }),
    await server.call('create_amount_discount_code', { code: 'FIVE', amount_minor: 500, currency: 'GBP' }),
  ];
  for (const answer of said) {
    assert.equal(answer.isError, true, answer.text);
    assert.doesNotMatch(answer.text, /is now|now gives|can no longer be used/);
  }
  assert.equal(said[0].text, 'Shopify took the change and reports the price of Mug - Blue as 99.00 GBP, where 12.50 GBP was asked for. Read the product to see what it is.');
  assert.equal(said[1].text, 'Shopify took the change and reports the price of Mug - Blue as nothing, where 13.00 GBP was asked for. Read the product to see what it is.');
  assert.equal(said[2].text, 'Shopify answered, and reports the discount code WELCOME10 as ACTIVE. List the discount codes to see whether it can still be used.');
  assert.equal(said[3].text, 'Shopify made the code TEN (gid://shopify/DiscountCodeNode/3) and reports 90% off, where 10% was asked for. List the discount codes to see what it is.');
  assert.equal(said[4].text, 'Shopify made the code FIVE (gid://shopify/DiscountCodeNode/4) and reports 50.00 GBP off, where 5.00 GBP was asked for. List the discount codes to see what it is.');
});

test('a refund is not sent where the server cannot read how much is paid and not refunded, or whether the order can be refunded', async () => {
  const { fake, server } = await world();
  const order = (change) => ({ on: 'OrderForRefund', kind: 'tamper', with: (d) => change(d.order) });
  fake.faults.push(
    order((o) => {
      o.netPaymentSet = set('-5.00');
    }),
    order((o) => {
      delete o.netPaymentSet;
    }),
    order((o) => {
      o.netPaymentSet = { presentmentMoney: { amount: '25.00', currencyCode: 'EUR' } };
    }),
    order((o) => {
      delete o.refundable;
    }),
    order((o) => {
      o.refundable = null;
    }),
  );
  const said = [];
  for (let i = 0; i < 5; i++) {
    const refused = await server.call('refund_order', REFUND);
    assert.equal(refused.isError, true);
    said.push(refused.text);
  }
  for (const text of said.slice(0, 3)) assert.equal(text, 'Shopify did not say, in a form this server can read, how much of order #1001 is paid and not refunded. Nothing was refunded.');
  for (const text of said.slice(3)) assert.equal(text, 'Shopify did not say whether order #1001 can be refunded. Nothing was refunded.');
  assert.equal(fake.of('RefundOrder').length, 0);
});

test('every answer to a refund names its idempotency key, and a key that is not a UUID is refused', async () => {
  const { fake, server } = await world();
  fake.store.orders[0].paymentState = 'PENDING';
  const waiting = await server.call('refund_order', REFUND);
  assert.equal(waiting.data.idempotency_key, fake.of('RefundOrder')[0].variables.idempotencyKey);
  const given = await server.call('refund_order', { ...REFUND, idempotency_key: '3f5b6ebf-143c-4da5-8d0f-fb8553bfd85d' });
  assert.equal(fake.of('RefundOrder')[1].variables.idempotencyKey, '3f5b6ebf-143c-4da5-8d0f-fb8553bfd85d');
  assert.equal(given.data.idempotency_key, '3f5b6ebf-143c-4da5-8d0f-fb8553bfd85d');
  for (const bad of ['abc', '3F5B6EBF-143C-4DA5-8D0F-FB8553BFD85D', '3f5b6ebf143c4da58d0ffb8553bfd85d0000', 7]) {
    const refused = await server.call('refund_order', { ...REFUND, idempotency_key: bad });
    assert.equal(refused.isError, true, String(bad));
    assert.match(refused.text, /"idempotency_key" (is not in the form|must be)/);
  }
  assert.equal(fake.of('RefundOrder').length, 2);
});
