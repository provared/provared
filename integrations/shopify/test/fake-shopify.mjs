// A made-up Shopify, for the tests alone: the token address and the Admin
// GraphQL API of one made-up store, on the local address. It answers the
// requests provared-shopify makes, in the forms Shopify's documentation
// gives, and keeps every request it was sent so that a test can say what
// was sent and how many times. It is not Shopify, and nothing here shows
// how a real store behaves.

import { createServer } from 'node:http';

export const CLIENT_ID = 'made-up-client-id-0123456789abcdef';
export const CLIENT_SECRET = 'shpss_made_up_secret_5f2e9c1a7b3d';
export const API_PATH = '/admin/api/2026-10/graphql.json';
export const TOKEN_PATH = '/admin/oauth/access_token';

const money = (amount, currencyCode) => ({ amount, currencyCode });
const set = (amount, currencyCode) => ({ presentmentMoney: money(amount, currencyCode) });

/** A decimal string as hundredths (the made-up store's currencies all have two places, but JPY, which has none). */
function minor(amount, currency) {
  const [units, fraction = ''] = String(amount).split('.');
  return currency === 'JPY' ? Number(units) : Number(units) * 100 + Number(fraction.padEnd(2, '0').slice(0, 2));
}

/** Whether a value is a decimal string as Shopify takes money: digits, or digits, a full stop and digits. */
function isDecimal(value) {
  const parts = String(value).split('.');
  return typeof value === 'string' && parts.length <= 2 && parts.every((p) => /^\d+$/.test(p));
}

function decimal(value, currency) {
  if (currency === 'JPY') return String(value);
  const digits = String(value).padStart(3, '0');
  return `${digits.slice(0, -2)}.${digits.slice(-2)}`;
}

function madeUpStore(currency) {
  return {
    currency,
    products: [
      {
        id: 'gid://shopify/Product/1', title: 'Mug', handle: 'mug', status: 'ACTIVE', vendor: 'Made-up Pottery', productType: 'Kitchen',
        variants: [
          { id: 'gid://shopify/ProductVariant/11', title: 'Blue', displayName: 'Mug - Blue', sku: 'MUG-B', price: decimal(1000, currency), compareAtPrice: null },
          { id: 'gid://shopify/ProductVariant/12', title: 'Red', displayName: 'Mug - Red', sku: 'MUG-R', price: decimal(1100, currency), compareAtPrice: decimal(1300, currency) },
        ],
      },
      {
        id: 'gid://shopify/Product/2', title: 'Teapot', handle: 'teapot', status: 'ACTIVE', vendor: 'Made-up Pottery', productType: 'Kitchen',
        variants: [{ id: 'gid://shopify/ProductVariant/21', title: 'Default Title', displayName: 'Teapot', sku: null, price: decimal(3500, currency), compareAtPrice: null }],
      },
      {
        id: 'gid://shopify/Product/3', title: 'Tray', handle: 'tray', status: 'DRAFT', vendor: 'Made-up Joinery', productType: 'Kitchen',
        variants: [{ id: 'gid://shopify/ProductVariant/31', title: 'Default Title', displayName: 'Tray', sku: 'TRAY', price: decimal(1999, currency), compareAtPrice: null }],
      },
    ],
    discounts: [
      { id: 'gid://shopify/DiscountCodeNode/1', kind: 'DiscountCodeBasic', title: 'Welcome', code: 'WELCOME10', status: 'ACTIVE', startsAt: '2026-01-01T00:00:00Z', endsAt: null, usageLimit: null, asyncUsageCount: 3, appliesOncePerCustomer: true, value: { percentage: 0.1 } },
      { id: 'gid://shopify/DiscountCodeNode/2', kind: 'DiscountCodeFreeShipping', title: 'Free delivery', code: 'FREEDEL', status: 'EXPIRED', startsAt: '2026-01-01T00:00:00Z', endsAt: '2026-02-01T00:00:00Z' },
    ],
    orders: [
      order('1001', currency, currency, [payment('501', 'SALE', 2500, currency)], [item('9001', 'Mug', 'MUG-B', 2, 1000, currency), item('9002', 'Delivery box', null, 1, 500, currency)]),
      order('1002', currency, currency, [payment('502', 'SALE', 2000, currency), payment('503', 'CAPTURE', 1500, currency), { ...payment('504', 'SALE', 900, currency), status: 'FAILURE' }], [item('9003', 'Teapot', null, 1, 3500, currency)]),
      order('1003', currency, 'EUR', [payment('505', 'SALE', 4000, 'EUR')], [item('9004', 'Teapot', null, 1, 4000, 'EUR')]),
      { ...order('1004', currency, currency, [payment('506', 'SALE', 3000, currency)], [item('9005', 'Tray', 'TRAY', 1, 3000, currency)]), gatewayRefuses: true },
    ],
  };
}

function payment(n, kind, value, currency) {
  return { id: `gid://shopify/OrderTransaction/${n}`, kind, status: 'SUCCESS', gateway: 'made-up-gateway', createdAt: '2026-11-10T09:00:05Z', value, currency, parent: null };
}

function item(n, title, sku, quantity, value, currency) {
  return { id: `gid://shopify/LineItem/${n}`, title, sku, quantity, value, currency };
}

function order(n, shopCurrency, currency, transactions, lineItems) {
  return { id: `gid://shopify/Order/${n}`, name: `#${n}`, createdAt: `2026-11-10T09:00:0${n.slice(-1)}Z`, cancelledAt: null, test: false, shopCurrency, currency, transactions, lineItems, refunds: [], displayFinancialStatus: 'PAID', displayFulfillmentStatus: 'UNFULFILLED' };
}

function page(list, variables) {
  const from = variables.after ? Number(variables.after) : 0;
  const nodes = list.slice(from, from + variables.first);
  const end = from + nodes.length;
  return { nodes, pageInfo: { hasNextPage: end < list.length, endCursor: nodes.length ? String(end) : null } };
}

function discountNode(d) {
  const common = { __typename: d.kind, title: d.title, status: d.status, startsAt: d.startsAt, endsAt: d.endsAt };
  if (d.kind !== 'DiscountCodeBasic') return { id: d.id, codeDiscount: common };
  const value = d.value.percentage !== undefined
    ? { __typename: 'DiscountPercentage', percentage: d.value.percentage }
    : { __typename: 'DiscountAmount', amount: money(d.value.amount, d.value.currency), appliesOnEachItem: false };
  return { id: d.id, codeDiscount: { ...common, usageLimit: d.usageLimit, asyncUsageCount: d.asyncUsageCount, appliesOncePerCustomer: d.appliesOncePerCustomer, codes: { nodes: [{ code: d.code }] }, customerGets: { value } } };
}

function orderTotals(o) {
  const paid = o.transactions.filter((t) => (t.kind === 'SALE' || t.kind === 'CAPTURE') && t.status === 'SUCCESS').reduce((sum, t) => sum + t.value, 0);
  const refunded = o.refunds.reduce((sum, r) => sum + r.value, 0);
  return { paid, refunded };
}

function orderNode(o) {
  const { paid, refunded } = orderTotals(o);
  const total = o.lineItems.reduce((sum, l) => sum + l.value * l.quantity, 0);
  return {
    id: o.id, name: o.name, createdAt: o.createdAt, cancelledAt: o.cancelledAt, test: o.test,
    displayFinancialStatus: refunded === 0 ? 'PAID' : refunded < paid ? 'PARTIALLY_REFUNDED' : 'REFUNDED',
    displayFulfillmentStatus: o.displayFulfillmentStatus,
    refundable: paid - refunded > 0,
    currencyCode: o.shopCurrency, presentmentCurrencyCode: o.currency,
    currentTotalPriceSet: set(decimal(total, o.currency), o.currency),
    totalReceivedSet: set(decimal(paid, o.currency), o.currency),
    totalRefundedSet: set(decimal(refunded, o.currency), o.currency),
    netPaymentSet: set(decimal(paid - refunded, o.currency), o.currency),
    transactions: o.transactions.map((t) => ({ id: t.id, kind: t.kind, status: t.status, gateway: t.gateway, createdAt: t.createdAt, amountSet: set(decimal(t.value, t.currency), t.currency), parentTransaction: t.parent ? { id: t.parent } : null })),
    lineItems: { nodes: o.lineItems.map((l) => ({ id: l.id, title: l.title, sku: l.sku, quantity: l.quantity, originalUnitPriceSet: set(decimal(l.value, l.currency), l.currency) })), pageInfo: { hasNextPage: false } },
    refunds: o.refunds.map((r) => ({ id: r.id, createdAt: r.createdAt, note: r.note, totalRefundedSet: set(decimal(r.value, o.currency), o.currency) })),
  };
}

/**
 * Start the made-up Shopify. `expiresIn` is how long its tokens say they
 * last, in seconds; `currency` is the shop's. Gives its address, what it
 * was sent, its store, and ways to make it fail on purpose.
 */
export async function fakeShopify({ expiresIn = 86399, currency = 'GBP' } = {}) {
  const store = madeUpStore(currency);
  const sent = []; // every request: {path, method, headers, body, operation, variables}
  const issued = []; // every access token given
  const valid = new Set();
  const faults = []; // {on: an operation's name or "sign-in", kind, ...}: each is used once
  const keys = new Set(); // the idempotency keys of the refunds made

  const operations = {
    ShopCurrency: () => ({ shop: { currencyCode: store.currency } }),
    ListProducts: (v) => ({
      products: page(store.products.map((p) => {
        const prices = p.variants.map((x) => minor(x.price, store.currency));
        return { id: p.id, title: p.title, handle: p.handle, status: p.status, vendor: p.vendor, productType: p.productType, priceRangeV2: { minVariantPrice: money(decimal(Math.min(...prices), store.currency), store.currency), maxVariantPrice: money(decimal(Math.max(...prices), store.currency), store.currency) } };
      }), v),
    }),
    ReadProduct: (v) => {
      const p = store.products.find((x) => x.id === v.id);
      return { product: p ? { id: p.id, title: p.title, handle: p.handle, status: p.status, vendor: p.vendor, productType: p.productType, variants: { nodes: p.variants.map((x) => ({ id: x.id, title: x.title, sku: x.sku, price: x.price, compareAtPrice: x.compareAtPrice })), pageInfo: { hasNextPage: false } } } : null, shop: { currencyCode: store.currency } };
    },
    ReadVariant: (v) => {
      for (const p of store.products) {
        const x = p.variants.find((y) => y.id === v.id);
        if (x) return { productVariant: { id: x.id, displayName: x.displayName, price: x.price, product: { id: p.id } }, shop: { currencyCode: store.currency } };
      }
      return { productVariant: null, shop: { currencyCode: store.currency } };
    },
    SetVariantPrice: (v) => {
      const p = store.products.find((x) => x.id === v.productId);
      const changed = [];
      const userErrors = [];
      for (const input of v.variants) {
        const x = p?.variants.find((y) => y.id === input.id);
        if (!x) userErrors.push({ field: ['variants', '0', 'id'], message: 'Product variant does not exist' });
        else if (!isDecimal(input.price)) userErrors.push({ field: ['variants', '0', 'price'], message: 'Price is not a number' });
        else {
          x.price = String(input.price);
          changed.push({ id: x.id, price: x.price });
        }
      }
      return { productVariantsBulkUpdate: { productVariants: userErrors.length ? null : changed, userErrors } };
    },
    ListDiscountCodes: (v) => ({ codeDiscountNodes: page(store.discounts.map(discountNode), v) }),
    CreateDiscountCode: (v) => {
      const input = v.basicCodeDiscount;
      const userErrors = [];
      if (store.discounts.some((d) => d.code.toLowerCase() === String(input.code).toLowerCase())) userErrors.push({ field: ['basicCodeDiscount', 'code'], message: 'Code must be unique. Please try a different code.' });
      if (input.context?.all !== 'ALL' || input.customerGets?.items?.all !== true || typeof input.startsAt !== 'string' || typeof input.title !== 'string') userErrors.push({ field: ['basicCodeDiscount'], message: 'The made-up store takes only a code for every buyer and every item, with a title and a start.' });
      const given = input.customerGets?.value ?? {};
      let value = null;
      if (typeof given.percentage === 'number' && given.percentage > 0 && given.percentage <= 1) value = { percentage: given.percentage };
      else if (given.discountAmount && isDecimal(given.discountAmount.amount)) value = { amount: String(given.discountAmount.amount), currency: store.currency };
      else userErrors.push({ field: ['basicCodeDiscount', 'customerGets', 'value'], message: 'Value is not valid' });
      if (userErrors.length) return { discountCodeBasicCreate: { codeDiscountNode: null, userErrors } };
      const d = { id: `gid://shopify/DiscountCodeNode/${store.discounts.length + 1}`, kind: 'DiscountCodeBasic', title: input.title, code: input.code, status: 'ACTIVE', startsAt: input.startsAt, endsAt: input.endsAt ?? null, usageLimit: input.usageLimit ?? null, asyncUsageCount: 0, appliesOncePerCustomer: input.appliesOncePerCustomer ?? false, value };
      store.discounts.push(d);
      return { discountCodeBasicCreate: { codeDiscountNode: discountNode(d), userErrors: [] } };
    },
    DeactivateDiscountCode: (v) => {
      const d = store.discounts.find((x) => x.id === v.id);
      if (!d) return { discountCodeDeactivate: { codeDiscountNode: null, userErrors: [{ field: ['id'], message: 'Discount does not exist' }] } };
      d.status = 'EXPIRED';
      d.endsAt = '2026-11-14T12:00:00Z';
      return { discountCodeDeactivate: { codeDiscountNode: discountNode(d), userErrors: [] } };
    },
    ListOrders: (v) => ({ orders: page(store.orders.toReversed().map(orderNode), v) }),
    ReadOrder: (v) => ({ order: store.orders.some((o) => o.id === v.id) ? orderNode(store.orders.find((o) => o.id === v.id)) : null }),
    OrderForRefund: (v) => operations.ReadOrder(v),
    RefundOrder: (v, query) => {
      const refused = (field, message) => ({ refundCreate: { refund: null, userErrors: [{ field, message }] } });
      // As of version 2026-04 Shopify asks for an idempotency key with refundCreate.
      if (!query.includes('@idempotent(key: $idempotencyKey)') || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(String(v.idempotencyKey))) return refused(null, 'An idempotency key is required');
      const input = v.input;
      const o = store.orders.find((x) => x.id === input.orderId);
      if (!o) return refused(['orderId'], 'Order does not exist');
      if (keys.has(v.idempotencyKey)) return refused(null, 'This request was already made');
      const t = input.transactions?.[0];
      const parent = o.transactions.find((x) => x.id === t?.parentId);
      if (input.transactions?.length !== 1 || !parent || t.orderId !== o.id || t.kind !== 'REFUND' || t.gateway !== parent.gateway || !isDecimal(t.amount)) return refused(['transactions'], 'Transactions are not valid');
      if (input.currency !== o.currency) return refused(['currency'], 'Currency must be the presentment currency');
      if (o.gatewayRefuses) return refused(['transactions'], 'The payment gateway declined the refund');
      const value = minor(t.amount, o.currency);
      const { paid, refunded } = orderTotals(o);
      if (value > paid - refunded) return refused(['transactions'], 'Refund amount is greater than the amount that can be refunded');
      keys.add(v.idempotencyKey);
      const r = { id: `gid://shopify/Refund/${700 + o.refunds.length + 1}`, createdAt: '2026-11-14T12:00:00Z', note: input.note ?? null, notify: input.notify ?? null, value };
      o.refunds.push(r);
      return { refundCreate: { refund: { id: r.id, createdAt: r.createdAt, totalRefundedSet: set(decimal(value, o.currency), o.currency) }, userErrors: [] } };
    },
  };

  function takeFault(on) {
    const at = faults.findIndex((f) => f.on === on);
    return at === -1 ? null : faults.splice(at, 1)[0];
  }

  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const record = { path: req.url, method: req.method, headers: req.headers, body, operation: null, variables: null };
      sent.push(record);
      const json = (status, value) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(value));
      };
      if (req.url === TOKEN_PATH && req.method === 'POST') {
        record.operation = 'sign-in';
        const fault = takeFault('sign-in');
        if (fault?.kind === 'status') return json(fault.status, fault.body ?? {});
        if (fault?.kind === 'redirect') return void res.writeHead(307, { Location: fault.to }).end();
        const form = new URLSearchParams(body);
        if (req.headers['content-type'] !== 'application/x-www-form-urlencoded' || form.get('grant_type') !== 'client_credentials' || form.get('client_id') !== CLIENT_ID || form.get('client_secret') !== CLIENT_SECRET) {
          // A made-up refusal that repeats what it was sent, to show that the server takes the secret out of what it says.
          return json(400, { error: 'invalid_client', error_description: `The client ${form.get('client_id')} or its secret ${form.get('client_secret')} is not right.` });
        }
        const token = `shpat_made_up_token_${issued.length + 1}_c4d1`;
        issued.push(token);
        valid.add(token);
        return json(200, { access_token: token, scope: 'write_products,write_discounts,write_orders', expires_in: expiresIn });
      }
      if (req.url !== API_PATH || req.method !== 'POST') return json(404, { errors: 'Not Found' });
      let message;
      try {
        message = JSON.parse(body);
      } catch {
        return json(400, { errors: 'Bad Request' });
      }
      const named = /^(?:query|mutation) (\w+)/.exec(message.query ?? '');
      record.operation = named ? named[1] : null;
      record.variables = message.variables ?? null;
      if (!valid.has(req.headers['x-shopify-access-token'])) return json(401, { errors: '[API] Invalid API key or access token (unrecognized login or wrong password)' });
      const fault = takeFault(record.operation);
      if (fault?.kind === 'status') return json(fault.status, fault.body ?? { errors: 'made-up failure' });
      if (fault?.kind === 'errors') return json(200, { errors: fault.errors });
      if (fault?.kind === 'drop') return void req.socket.destroy();
      if (fault?.kind === 'redirect') return void res.writeHead(307, { Location: fault.to }).end();
      const run = operations[record.operation];
      if (!run) return json(200, { errors: [{ message: `The made-up store does not know the operation ${record.operation}.` }] });
      const data = run(message.variables ?? {}, message.query);
      if (fault?.kind === 'after') return fault.status === 'drop' ? void req.socket.destroy() : json(fault.status, { errors: 'made-up failure after the change' });
      json(200, { data, extensions: { cost: { requestedQueryCost: 10, actualQueryCost: 10, throttleStatus: { maximumAvailable: 2000, currentlyAvailable: 1990, restoreRate: 100 } } } });
    });
  });
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const fake = {
    origin: `http://127.0.0.1:${server.address().port}`,
    store,
    sent,
    issued,
    faults,
    /** Every request for one operation ("sign-in", "RefundOrder" and so on). */
    of: (operation) => sent.filter((r) => r.operation === operation),
    /** The tokens given so far stop working, as when they expire. */
    expireTokens: () => valid.clear(),
    close: () => new Promise((resolve) => {
      open.delete(fake);
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
  open.add(fake);
  return fake;
}

// Every made-up Shopify started and not yet closed, so that a test that
// fails half-way leaves none listening.
const open = new Set();

/** Close every made-up Shopify still open. */
export async function closeFakes() {
  for (const fake of [...open]) await fake.close();
}

export const THROTTLED = [{ message: 'Throttled', extensions: { code: 'THROTTLED' } }];
