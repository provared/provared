// The tools. Each has a plain schema, and each argument that carries money
// or a percentage is one whole number at one fixed place in the arguments
// (DESIGN.md, S4 and S5), so that the guard's rule for the tool can read it
// as the call's amount and a permission can limit it.
//
// A change (a price, a discount code, a refund) is one request to Shopify,
// sent once. Before it, a tool reads what it needs to be sure the amount
// means what it says: the shop's currency, or the order's.

import { randomUUID } from 'node:crypto';
import { ToolError } from './admin.mjs';
import { places, shown, toDecimal, toMinor } from './money.mjs';

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// --- schemas ---

// The pattern a text argument must match, kept beside its schema so that
// what the schema says and what is tested are one thing.
const TESTS = new WeakMap();

function text(description, { pattern, minLength = 1, maxLength = 500 } = {}) {
  const schema = { type: 'string', description, minLength, maxLength, ...(pattern ? { pattern: pattern.source } : {}) };
  if (pattern) TESTS.set(schema, pattern);
  return schema;
}

function whole(description, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  return { type: 'integer', description, minimum, maximum };
}

function flag(description) {
  return { type: 'boolean', description };
}

function id(kind, description) {
  return text(`${description} As Shopify writes it: gid://shopify/${kind}/ and the number.`, { pattern: ID_PATTERNS[kind], maxLength: 100 });
}

const ID_PATTERNS = {
  Product: /^gid:\/\/shopify\/Product\/[0-9]+$/,
  ProductVariant: /^gid:\/\/shopify\/ProductVariant\/[0-9]+$/,
  DiscountCodeNode: /^gid:\/\/shopify\/DiscountCodeNode\/[0-9]+$/,
  Order: /^gid:\/\/shopify\/Order\/[0-9]+$/,
  OrderTransaction: /^gid:\/\/shopify\/OrderTransaction\/[0-9]+$/,
};

const CURRENCY = /^[A-Z]{3}$/;
const DATE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$/;

const MINOR = 'A whole number of the currency\'s smallest unit, never a decimal: 1250 is 12.50 GBP, and 1250 is 1,250 JPY.';

function currency(description) {
  return text(`${description} Three capital letters (ISO 4217), such as GBP.`, { pattern: CURRENCY, minLength: 3, maxLength: 3 });
}

function schema(properties, required = []) {
  return { type: 'object', properties, required, additionalProperties: false };
}

const PAGE = {
  first: whole('How many to give, from 1 to 50. 20 where it is left out.', 1, 50),
  after: text('Where to go on from: the "next" of the answer before.'),
  query: text('A filter in Shopify\'s search syntax, such as status:active or created_at:>2026-11-01.'),
};

const DISCOUNT_OPTIONS = {
  title: text('The name the merchant sees in the Shopify admin. The code itself where it is left out.', { maxLength: 255 }),
  starts_at: text('When the code starts to work, as a date and time to the second with its zone (2026-12-01T00:00:00Z, or 2026-12-01T00:00:00+01:00). Now where it is left out.', { pattern: DATE_TIME, maxLength: 25 }),
  ends_at: text('When the code stops working, as a date and time to the second with its zone. No end where it is left out.', { pattern: DATE_TIME, maxLength: 25 }),
  usage_limit: whole('The most times the code may be used in all. No limit where it is left out.', 1, 2147483647),
  once_per_customer: flag('Whether a customer may use the code only once. False where it is left out.'),
};

/** What is wrong with a call's arguments, held against the tool's schema; null where nothing is. */
function wrong(args, toolSchema) {
  if (!isObject(args)) return 'The arguments must be an object.';
  for (const name of Object.keys(args)) {
    if (!Object.hasOwn(toolSchema.properties, name)) return `"${name}" is not an argument of this tool. Its arguments are: ${Object.keys(toolSchema.properties).join(', ')}.`;
  }
  for (const name of toolSchema.required) {
    if (!Object.hasOwn(args, name)) return `"${name}" is missing.`;
  }
  for (const [name, value] of Object.entries(args)) {
    const s = toolSchema.properties[name];
    if (s.type === 'string') {
      if (typeof value !== 'string') return `"${name}" must be text.`;
      if (value.length < s.minLength || value.length > s.maxLength) return `"${name}" must be from ${s.minLength} to ${s.maxLength} characters long.`;
      if (TESTS.has(s) && !TESTS.get(s).test(value)) return `"${name}" is not in the form this tool takes. ${s.description}`;
    } else if (s.type === 'integer') {
      if (!Number.isSafeInteger(value)) return `"${name}" must be a whole number. ${s.description}`;
      if (value < s.minimum || value > s.maximum) return `"${name}" must be from ${s.minimum} to ${s.maximum}.`;
    } else if (typeof value !== 'boolean') {
      return `"${name}" must be true or false.`;
    }
  }
  return null;
}

// --- what Shopify is asked ---

const MONEY = 'amount currencyCode';

const LIST_PRODUCTS = `query ListProducts($first: Int!, $after: String, $query: String) {
  products(first: $first, after: $after, query: $query) {
    nodes { id title handle status vendor productType priceRangeV2 { minVariantPrice { ${MONEY} } maxVariantPrice { ${MONEY} } } }
    pageInfo { hasNextPage endCursor }
  }
}`;

const READ_PRODUCT = `query ReadProduct($id: ID!) {
  product(id: $id) {
    id title handle status vendor productType
    variants(first: 100) { nodes { id title sku price compareAtPrice } pageInfo { hasNextPage } }
  }
  shop { currencyCode }
}`;

const READ_VARIANT = `query ReadVariant($id: ID!) {
  productVariant(id: $id) { id displayName price product { id } }
  shop { currencyCode }
}`;

const SET_VARIANT_PRICE = `mutation SetVariantPrice($productId: ID!, $variants: [ProductVariantsBulkInput!]!) {
  productVariantsBulkUpdate(productId: $productId, variants: $variants) {
    productVariants { id price }
    userErrors { field message }
  }
}`;

const DISCOUNT = `__typename
  ... on DiscountCodeBasic {
    title status startsAt endsAt usageLimit asyncUsageCount appliesOncePerCustomer
    codes(first: 5) { nodes { code } }
    customerGets { value { __typename ... on DiscountPercentage { percentage } ... on DiscountAmount { amount { ${MONEY} } appliesOnEachItem } } }
  }
  ... on DiscountCodeBxgy { title status startsAt endsAt }
  ... on DiscountCodeFreeShipping { title status startsAt endsAt }
  ... on DiscountCodeApp { title status startsAt endsAt }`;

const LIST_DISCOUNT_CODES = `query ListDiscountCodes($first: Int!, $after: String, $query: String) {
  codeDiscountNodes(first: $first, after: $after, query: $query) {
    nodes { id codeDiscount { ${DISCOUNT} } }
    pageInfo { hasNextPage endCursor }
  }
}`;

const SHOP_CURRENCY = 'query ShopCurrency { shop { currencyCode } }';

const CREATE_DISCOUNT_CODE = `mutation CreateDiscountCode($basicCodeDiscount: DiscountCodeBasicInput!) {
  discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
    codeDiscountNode { id codeDiscount { ${DISCOUNT} } }
    userErrors { field message }
  }
}`;

const DEACTIVATE_DISCOUNT_CODE = `mutation DeactivateDiscountCode($id: ID!) {
  discountCodeDeactivate(id: $id) {
    codeDiscountNode { id codeDiscount { ${DISCOUNT} } }
    userErrors { field message }
  }
}`;

const SET = (name) => `${name} { presentmentMoney { ${MONEY} } }`;

const LIST_ORDERS = `query ListOrders($first: Int!, $after: String, $query: String) {
  orders(first: $first, after: $after, query: $query, reverse: true) {
    nodes {
      id name createdAt cancelledAt test displayFinancialStatus displayFulfillmentStatus presentmentCurrencyCode
      ${SET('currentTotalPriceSet')} ${SET('totalRefundedSet')}
    }
    pageInfo { hasNextPage endCursor }
  }
}`;

const ORDER_MONEY = `id name test refundable currencyCode presentmentCurrencyCode
    ${SET('currentTotalPriceSet')} ${SET('totalReceivedSet')} ${SET('totalRefundedSet')} ${SET('netPaymentSet')}
    transactions(first: 50) { id kind status gateway createdAt ${SET('amountSet')} parentTransaction { id } }`;

const READ_ORDER = `query ReadOrder($id: ID!) {
  order(id: $id) {
    ${ORDER_MONEY}
    createdAt cancelledAt displayFinancialStatus displayFulfillmentStatus
    lineItems(first: 50) { nodes { id title sku quantity ${SET('originalUnitPriceSet')} } pageInfo { hasNextPage } }
    refunds(first: 50) { id createdAt note ${SET('totalRefundedSet')} }
  }
}`;

const ORDER_FOR_REFUND = `query OrderForRefund($id: ID!) {
  order(id: $id) {
    ${ORDER_MONEY}
  }
}`;

const REFUND_ORDER = `mutation RefundOrder($input: RefundInput!, $idempotencyKey: String!) {
  refundCreate(input: $input) @idempotent(key: $idempotencyKey) {
    refund { id createdAt ${SET('totalRefundedSet')} }
    userErrors { field message }
  }
}`;

// --- what the agent is told ---

function page(args) {
  return { first: args.first ?? 20, after: args.after ?? null, query: args.query ?? null };
}

function next(pageInfo) {
  return pageInfo?.hasNextPage ? pageInfo.endCursor : null;
}

/** Shopify's reasons for refusing a change (its userErrors), as one sentence; throws where there are any. */
function refusedBy(payload, what) {
  if (!isObject(payload)) throw new ToolError(`Shopify gave no answer for ${what}. Whether the change was made is not known.`);
  const errors = Array.isArray(payload.userErrors) ? payload.userErrors : [];
  if (errors.length === 0) return;
  const said = errors.map((e) => `${Array.isArray(e?.field) && e.field.length ? `${e.field.join('.')}: ` : ''}${typeof e?.message === 'string' ? e.message : 'no reason given'}`).join('; ');
  throw new ToolError(`Shopify refused ${what}: ${said}. Nothing was changed.`);
}

function presentment(set) {
  return shown(set?.presentmentMoney);
}

function discountShown(node) {
  const d = node?.codeDiscount ?? {};
  const value = d.customerGets?.value;
  const out = {
    discount_id: node?.id ?? null,
    kind: d.__typename ?? null,
    title: d.title ?? null,
    status: d.status ?? null,
    starts_at: d.startsAt ?? null,
    ends_at: d.endsAt ?? null,
  };
  if (d.__typename !== 'DiscountCodeBasic') return out;
  out.codes = (d.codes?.nodes ?? []).map((c) => c.code);
  if (value?.__typename === 'DiscountPercentage' && Number.isFinite(value.percentage)) out.percent = Math.round(value.percentage * 10000) / 100;
  if (value?.__typename === 'DiscountAmount') out.amount_off = shown(value.amount);
  out.usage_limit = d.usageLimit ?? null;
  out.times_used = d.asyncUsageCount ?? null;
  out.once_per_customer = d.appliesOncePerCustomer ?? null;
  return out;
}

function transactionShown(t) {
  return { transaction_id: t.id, kind: t.kind, status: t.status, gateway: t.gateway ?? null, created_at: t.createdAt ?? null, amount: presentment(t.amountSet), parent: t.parentTransaction?.id ?? null };
}

/** The successful payments of an order: what a refund can be taken from. */
function payments(order) {
  return (order.transactions ?? []).filter((t) => (t.kind === 'SALE' || t.kind === 'CAPTURE') && t.status === 'SUCCESS');
}

function orderMoneyShown(order) {
  return {
    order_id: order.id,
    name: order.name,
    test: order.test ?? null,
    currency: order.presentmentCurrencyCode,
    shop_currency: order.currencyCode,
    total: presentment(order.currentTotalPriceSet),
    received: presentment(order.totalReceivedSet),
    refunded: presentment(order.totalRefundedSet),
    paid_and_not_refunded: presentment(order.netPaymentSet),
    can_be_refunded: order.refundable ?? null,
  };
}

async function shopCurrency(admin, given) {
  const data = await admin.graphql(SHOP_CURRENCY, {});
  const is = data.shop?.currencyCode;
  if (typeof is !== 'string') throw new ToolError('Shopify did not say which currency the shop uses. Nothing was changed.');
  if (is !== given) throw new ToolError(`The shop's currency is ${is}, not ${given}. Nothing was changed.`);
  if (places(is) === null) throw new ToolError(`This server does not know how many decimal places ${is} has, so it will not send an amount in it. Nothing was changed.`);
  return is;
}

function discountInput(args, value) {
  return {
    title: args.title ?? args.code,
    code: args.code,
    startsAt: args.starts_at ?? new Date().toISOString(),
    ...(args.ends_at !== undefined ? { endsAt: args.ends_at } : {}),
    context: { all: 'ALL' },
    customerGets: { value, items: { all: true } },
    ...(args.usage_limit !== undefined ? { usageLimit: args.usage_limit } : {}),
    appliesOncePerCustomer: args.once_per_customer ?? false,
  };
}

async function createDiscount(admin, input) {
  const data = await admin.graphql(CREATE_DISCOUNT_CODE, { basicCodeDiscount: input }, { change: 'List the discount codes before trying again.' });
  refusedBy(data.discountCodeBasicCreate, 'the discount code');
  const node = data.discountCodeBasicCreate.codeDiscountNode;
  if (!isObject(node)) throw new ToolError('Shopify gave no discount code and no reason. List the discount codes before trying again.');
  return discountShown(node);
}

// --- the tools ---

const READS = { readOnlyHint: true };
const ADDS = { readOnlyHint: false, destructiveHint: false, idempotentHint: false };
const CHANGES = { readOnlyHint: false, destructiveHint: true, idempotentHint: false };

export const TOOLS = [
  {
    name: 'list_products',
    description: 'Lists the store\'s products, with the lowest and highest price of each. Gives "next" where there are more.',
    inputSchema: schema(PAGE),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(LIST_PRODUCTS, page(args));
      return {
        products: (data.products?.nodes ?? []).map((p) => ({
          product_id: p.id,
          title: p.title,
          handle: p.handle,
          status: p.status,
          vendor: p.vendor,
          type: p.productType,
          lowest_price: shown(p.priceRangeV2?.minVariantPrice),
          highest_price: shown(p.priceRangeV2?.maxVariantPrice),
        })),
        next: next(data.products?.pageInfo),
      };
    },
  },
  {
    name: 'read_product',
    description: 'Reads one product and its variants (up to 100), each with its price.',
    inputSchema: schema({ product_id: id('Product', 'The product.') }, ['product_id']),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(READ_PRODUCT, { id: args.product_id });
      const p = data.product;
      if (!isObject(p)) throw new ToolError(`The store has no product ${args.product_id}.`);
      const unit = data.shop?.currencyCode;
      const price = (amount) => (typeof amount === 'string' && typeof unit === 'string' ? shown({ amount, currencyCode: unit }) : null);
      return {
        product_id: p.id,
        title: p.title,
        handle: p.handle,
        status: p.status,
        vendor: p.vendor,
        type: p.productType,
        variants: (p.variants?.nodes ?? []).map((v) => ({ variant_id: v.id, title: v.title, sku: v.sku ?? null, price: price(v.price), compare_at_price: price(v.compareAtPrice) })),
        more_variants: p.variants?.pageInfo?.hasNextPage ?? false,
      };
    },
  },
  {
    name: 'set_variant_price',
    description: 'Changes the price of one variant of a product. The price is in the shop\'s own currency, which must be named.',
    inputSchema: schema({
      variant_id: id('ProductVariant', 'The variant.'),
      price_minor: whole(`The new price. ${MINOR}`, 0),
      currency: currency('The currency of the price: the shop\'s own.'),
    }, ['variant_id', 'price_minor', 'currency']),
    annotations: CHANGES,
    async run(args, admin) {
      const data = await admin.graphql(READ_VARIANT, { id: args.variant_id });
      const v = data.productVariant;
      if (!isObject(v) || typeof v.product?.id !== 'string') throw new ToolError(`The store has no variant ${args.variant_id}. Nothing was changed.`);
      const unit = data.shop?.currencyCode;
      if (typeof unit !== 'string') throw new ToolError('Shopify did not say which currency the shop uses. Nothing was changed.');
      if (unit !== args.currency) throw new ToolError(`The shop's currency is ${unit}, not ${args.currency}. Nothing was changed.`);
      const price = toDecimal(args.price_minor, unit);
      if (price === null) throw new ToolError(`This server does not know how many decimal places ${unit} has, so it will not send a price in it. Nothing was changed.`);
      const changed = await admin.graphql(SET_VARIANT_PRICE, { productId: v.product.id, variants: [{ id: v.id, price }] }, { change: 'Read the product before trying again.' });
      refusedBy(changed.productVariantsBulkUpdate, 'the price');
      const now = (changed.productVariantsBulkUpdate.productVariants ?? []).find((x) => x?.id === v.id);
      const out = {
        done: `The price of ${v.displayName ?? v.id} is now ${price} ${unit}.`,
        variant_id: v.id,
        product_id: v.product.id,
        price: shown({ amount: price, currencyCode: unit }),
        price_before: typeof v.price === 'string' ? shown({ amount: v.price, currencyCode: unit }) : null,
      };
      if (!now || toMinor(now.price, unit) !== args.price_minor) out.warning = `Shopify took the change but reports the price as ${now?.price ?? 'nothing'}. Read the product to see what it is.`;
      return out;
    },
  },
  {
    name: 'list_discount_codes',
    description: 'Lists the store\'s discount codes: the code, whether it is active, and the percentage or amount off. Gives "next" where there are more.',
    inputSchema: schema(PAGE),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(LIST_DISCOUNT_CODES, page(args));
      return { discount_codes: (data.codeDiscountNodes?.nodes ?? []).map(discountShown), next: next(data.codeDiscountNodes?.pageInfo) };
    },
  },
  {
    name: 'create_percentage_discount_code',
    description: 'Makes a discount code that takes a percentage off every product, for every customer.',
    inputSchema: schema({
      code: text('The code a customer types at the checkout.', { maxLength: 255 }),
      percent: whole('The percentage off, a whole number from 1 to 100: 30 is 30% off.', 1, 100),
      ...DISCOUNT_OPTIONS,
    }, ['code', 'percent']),
    annotations: ADDS,
    async run(args, admin) {
      const made = await createDiscount(admin, discountInput(args, { percentage: args.percent / 100 }));
      const out = { done: `The code ${args.code} now gives ${args.percent}% off.`, ...made };
      if (made.percent !== args.percent) out.warning = `Shopify made the code but reports ${made.percent ?? 'no percentage'} where ${args.percent} was asked for. List the discount codes to see what it is.`;
      return out;
    },
  },
  {
    name: 'create_amount_discount_code',
    description: 'Makes a discount code that takes a fixed amount of money off an order, for every customer. The amount is in the shop\'s own currency, which must be named.',
    inputSchema: schema({
      code: text('The code a customer types at the checkout.', { maxLength: 255 }),
      amount_minor: whole(`The amount off the order. ${MINOR}`, 1),
      currency: currency('The currency of the amount: the shop\'s own.'),
      ...DISCOUNT_OPTIONS,
    }, ['code', 'amount_minor', 'currency']),
    annotations: ADDS,
    async run(args, admin) {
      const unit = await shopCurrency(admin, args.currency);
      const amount = toDecimal(args.amount_minor, unit);
      const made = await createDiscount(admin, discountInput(args, { discountAmount: { amount, appliesOnEachItem: false } }));
      const out = { done: `The code ${args.code} now gives ${amount} ${unit} off an order.`, ...made };
      if (made.amount_off?.amount_minor !== args.amount_minor || made.amount_off?.currency !== unit) out.warning = `Shopify made the code but reports ${made.amount_off ? `${made.amount_off.amount} ${made.amount_off.currency}` : 'no amount'} where ${amount} ${unit} was asked for. List the discount codes to see what it is.`;
      return out;
    },
  },
  {
    name: 'deactivate_discount_code',
    description: 'Stops a discount code from being used from now on. The code is kept, and can be turned on again in the Shopify admin.',
    inputSchema: schema({ discount_id: id('DiscountCodeNode', 'The discount code, by the discount_id that list_discount_codes gives.') }, ['discount_id']),
    annotations: CHANGES,
    async run(args, admin) {
      const data = await admin.graphql(DEACTIVATE_DISCOUNT_CODE, { id: args.discount_id }, { change: 'List the discount codes before trying again.' });
      refusedBy(data.discountCodeDeactivate, 'the change to the discount code');
      const node = data.discountCodeDeactivate.codeDiscountNode;
      if (!isObject(node)) throw new ToolError('Shopify gave no discount code and no reason. List the discount codes to see whether it still works.');
      const made = discountShown(node);
      return { done: `The discount code ${made.codes?.[0] ?? made.title ?? args.discount_id} can no longer be used.`, ...made };
    },
  },
  {
    name: 'list_orders',
    description: 'Lists the store\'s orders, newest first: the order\'s name, its state, its total and what has been refunded. No customer\'s name, address, email or telephone number is given. Gives "next" where there are more.',
    inputSchema: schema(PAGE),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(LIST_ORDERS, page(args));
      return {
        orders: (data.orders?.nodes ?? []).map((o) => ({
          order_id: o.id,
          name: o.name,
          created_at: o.createdAt,
          cancelled_at: o.cancelledAt ?? null,
          test: o.test ?? null,
          payment: o.displayFinancialStatus ?? null,
          fulfilment: o.displayFulfillmentStatus ?? null,
          currency: o.presentmentCurrencyCode,
          total: presentment(o.currentTotalPriceSet),
          refunded: presentment(o.totalRefundedSet),
        })),
        next: next(data.orders?.pageInfo),
      };
    },
  },
  {
    name: 'read_order',
    description: 'Reads one order: its items, its payments, its refunds, and how much has been paid and not refunded. No customer\'s name, address, email or telephone number is given.',
    inputSchema: schema({ order_id: id('Order', 'The order.') }, ['order_id']),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(READ_ORDER, { id: args.order_id });
      const o = data.order;
      if (!isObject(o)) throw new ToolError(`The store has no order ${args.order_id}.`);
      return {
        ...orderMoneyShown(o),
        created_at: o.createdAt,
        cancelled_at: o.cancelledAt ?? null,
        payment: o.displayFinancialStatus ?? null,
        fulfilment: o.displayFulfillmentStatus ?? null,
        items: (o.lineItems?.nodes ?? []).map((l) => ({ item_id: l.id, title: l.title, sku: l.sku ?? null, quantity: l.quantity, unit_price: presentment(l.originalUnitPriceSet) })),
        more_items: o.lineItems?.pageInfo?.hasNextPage ?? false,
        transactions: (o.transactions ?? []).map(transactionShown),
        refunds: (o.refunds ?? []).map((r) => ({ refund_id: r.id, created_at: r.createdAt, note: r.note ?? null, total: presentment(r.totalRefundedSet) })),
      };
    },
  },
  {
    name: 'refund_order',
    description: 'Gives money back on an order: part of what was paid, or all of it. The amount is always stated; to refund the whole order, read it first and give its "paid_and_not_refunded". The money goes back the way it was paid. Nothing is put back into stock, and the customer is told only where "notify" is true.',
    inputSchema: schema({
      order_id: id('Order', 'The order.'),
      amount_minor: whole(`The money to give back. ${MINOR}`, 1),
      currency: currency('The currency of the amount: the one the order was paid in.'),
      transaction_id: id('OrderTransaction', 'Which payment to refund, where the order has more than one: a transaction_id that read_order gives.'),
      note: text('A note kept with the refund, for the merchant.'),
      notify: flag('Whether Shopify tells the customer of the refund. False where it is left out.'),
    }, ['order_id', 'amount_minor', 'currency']),
    annotations: CHANGES,
    async run(args, admin) {
      const data = await admin.graphql(ORDER_FOR_REFUND, { id: args.order_id });
      const o = data.order;
      if (!isObject(o)) throw new ToolError(`The store has no order ${args.order_id}. Nothing was refunded.`);
      const unit = o.presentmentCurrencyCode;
      if (typeof unit !== 'string' || typeof o.currencyCode !== 'string') throw new ToolError('Shopify did not say which currency the order was paid in. Nothing was refunded.');
      if (unit !== o.currencyCode) throw new ToolError(`Order ${o.name} was paid in ${unit} and the shop's currency is ${o.currencyCode}. This server refunds only an order paid in the shop's own currency; refund this one in the Shopify admin. Nothing was refunded.`);
      if (unit !== args.currency) throw new ToolError(`Order ${o.name} was paid in ${unit}, not ${args.currency}. Nothing was refunded.`);
      const amount = toDecimal(args.amount_minor, unit);
      if (amount === null) throw new ToolError(`This server does not know how many decimal places ${unit} has, so it will not send an amount in it. Nothing was refunded.`);
      if (o.refundable === false) throw new ToolError(`Shopify says order ${o.name} cannot be refunded: it has no payment that can be given back. Nothing was refunded.`);
      const left = presentment(o.netPaymentSet);
      if (left && left.amount_minor !== null && args.amount_minor > left.amount_minor) throw new ToolError(`Order ${o.name} has ${left.amount} ${unit} paid and not refunded, less than the ${amount} ${unit} asked for. Nothing was refunded.`);
      const paid = payments(o);
      let from;
      if (args.transaction_id !== undefined) {
        from = paid.find((t) => t.id === args.transaction_id);
        if (!from) throw new ToolError(`${args.transaction_id} is not a successful payment of order ${o.name}. Nothing was refunded.`);
      } else {
        if (paid.length === 0) throw new ToolError(`Order ${o.name} has no successful payment to refund. Nothing was refunded.`);
        if (paid.length > 1) throw new ToolError(`Order ${o.name} has ${paid.length} payments. Say which to refund with "transaction_id": ${paid.map((t) => `${t.id} (${presentment(t.amountSet)?.amount ?? '?'} ${unit})`).join(', ')}. Nothing was refunded.`);
        from = paid[0];
      }
      if (typeof from.gateway !== 'string' || from.gateway === '') throw new ToolError(`Shopify did not say how the payment ${from.id} was taken, so it cannot be refunded here. Nothing was refunded.`);
      const input = {
        orderId: o.id,
        currency: unit,
        notify: args.notify ?? false,
        ...(args.note !== undefined ? { note: args.note } : {}),
        transactions: [{ orderId: o.id, parentId: from.id, kind: 'REFUND', gateway: from.gateway, amount }],
      };
      // One key for this one request, as Shopify asks of refundCreate; the request is not sent again.
      const sent = await admin.graphql(REFUND_ORDER, { input, idempotencyKey: randomUUID() }, { change: 'Read the order before trying again.' });
      refusedBy(sent.refundCreate, 'the refund');
      const refund = sent.refundCreate.refund;
      if (!isObject(refund)) throw new ToolError('Shopify gave no refund and no reason. Read the order to see whether money was given back.');
      const total = presentment(refund.totalRefundedSet);
      const out = { done: `${amount} ${unit} was refunded on order ${o.name}.`, refund_id: refund.id, order_id: o.id, refunded: shown({ amount, currencyCode: unit }), customer_told: input.notify };
      if (!total || total.amount_minor !== args.amount_minor || total.currency !== unit) out.warning = `Shopify made the refund but reports its total as ${total ? `${total.amount} ${total.currency}` : 'nothing'}. Read the order to see what was given back.`;
      return out;
    },
  },
];

/** The tool of a name, or null. */
export function toolNamed(name) {
  return TOOLS.find((t) => t.name === name) ?? null;
}

/** Run one tool: its answer as plain data, or a ToolError in plain words. */
export async function runTool(tool, args, admin) {
  const problem = wrong(args, tool.inputSchema);
  if (problem) throw new ToolError(`${problem} Nothing was asked of the store.`);
  return tool.run(args, admin);
}
