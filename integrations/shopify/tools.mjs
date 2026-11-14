// The tools. Each has a plain schema, and each argument that carries money
// or a percentage is one whole number at one fixed place in the arguments
// (DESIGN.md, S9 and S12), so that the guard's rule for the tool can read it
// as the call's amount and a permission can limit it.
//
// A change (a price, a discount code, a refund) is one request to Shopify,
// sent once, straight after a reading: of the shop's currency, the variant
// or the order, so that the amount means what it says, and so that Shopify
// has just answered with this server's version of the Admin API.
//
// After a change a tool says "done" only where Shopify reports what was
// asked for. Where it reports something else, the tool says what it reports.

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

function oneOf(description, values) {
  return { type: 'string', description: `${description} One of: ${values.join(', ')}.`, enum: values };
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
  Product: /^gid:\/\/shopify\/Product\/[1-9][0-9]*$/,
  ProductVariant: /^gid:\/\/shopify\/ProductVariant\/[1-9][0-9]*$/,
  DiscountCodeNode: /^gid:\/\/shopify\/DiscountCodeNode\/[1-9][0-9]*$/,
  Order: /^gid:\/\/shopify\/Order\/[1-9][0-9]*$/,
  OrderTransaction: /^gid:\/\/shopify\/OrderTransaction\/[1-9][0-9]*$/,
};

const CURRENCY = /^[A-Z]{3}$/;
const DATE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ORDER_NAME = /^#?[A-Za-z0-9-]{1,30}$/;

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
};

const SEARCH = {
  ...PAGE,
  query: text('A filter in Shopify\'s search syntax, such as status:active.'),
};

// Orders are found by these filters alone. Each value is one of a fixed
// list, a date or an order's name, so that no order can be looked for by a
// customer's email, name or card (DESIGN.md, S36).
const ORDER_FILTERS = {
  ...PAGE,
  status: oneOf('Only orders in this state.', ['open', 'closed', 'cancelled', 'not_closed']),
  financial_status: oneOf('Only orders whose payment is in this state.', ['paid', 'pending', 'authorized', 'partially_paid', 'partially_refunded', 'refunded', 'voided', 'expired']),
  fulfillment_status: oneOf('Only orders whose delivery is in this state.', ['unshipped', 'shipped', 'fulfilled', 'partial', 'scheduled', 'on_hold', 'unfulfilled', 'request_declined']),
  created_from: text('Only orders made at or after this date and time, to the second, with its zone (2026-11-01T00:00:00Z).', { pattern: DATE_TIME, maxLength: 25 }),
  created_to: text('Only orders made at or before this date and time, to the second, with its zone.', { pattern: DATE_TIME, maxLength: 25 }),
  name: text('Only the order of this name, such as #1001.', { pattern: ORDER_NAME, maxLength: 31 }),
  test: flag('True for test orders only, false for real orders only.'),
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
      if (s.enum) {
        if (!s.enum.includes(value)) return `"${name}" must be one of: ${s.enum.join(', ')}.`;
      } else {
        if (value.length < s.minLength || value.length > s.maxLength) return `"${name}" must be from ${s.minLength} to ${s.maxLength} characters long.`;
        if (TESTS.has(s) && !TESTS.get(s).test(value)) return `"${name}" is not in the form this tool takes. ${s.description}`;
      }
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
    transactions(first: 50) { id kind status gateway createdAt ${SET('amountSet')} parentTransaction { id } }
    refunds(first: 50) { id createdAt note ${SET('totalRefundedSet')} }`;

const READ_ORDER = `query ReadOrder($id: ID!) {
  order(id: $id) {
    ${ORDER_MONEY}
    createdAt cancelledAt displayFinancialStatus displayFulfillmentStatus
    lineItems(first: 50) { nodes { id title sku quantity ${SET('originalUnitPriceSet')} } pageInfo { hasNextPage } }
  }
}`;

const ORDER_FOR_REFUND = `query OrderForRefund($id: ID!) {
  order(id: $id) {
    ${ORDER_MONEY}
  }
}`;

// The refund's own payments are asked for with it: Shopify's page for a
// refund says that a refund's being there does not show that the money
// went back, and that the state of each of its transactions does.
const REFUND_ORDER = `mutation RefundOrder($input: RefundInput!, $idempotencyKey: String!) {
  refundCreate(input: $input) @idempotent(key: $idempotencyKey) {
    refund { id createdAt ${SET('totalRefundedSet')} transactions(first: 10) { nodes { id kind status ${SET('amountSet')} } } }
    userErrors { field message }
  }
}`;

// --- what the agent is told ---

function page(args) {
  return { first: args.first ?? 20, after: args.after ?? null, query: args.query ?? null };
}

/** The filters of list_orders as Shopify's search text: each a filter's name, a colon and a value that was held against its list or its form. */
function orderQuery(args) {
  const terms = [];
  for (const filter of ['status', 'financial_status', 'fulfillment_status']) if (args[filter] !== undefined) terms.push(`${filter}:${args[filter]}`);
  if (args.created_from !== undefined) terms.push(`created_at:>='${args.created_from}'`);
  if (args.created_to !== undefined) terms.push(`created_at:<='${args.created_to}'`);
  if (args.name !== undefined) terms.push(`name:${args.name.replace('#', '')}`);
  if (args.test !== undefined) terms.push(`test:${args.test}`);
  return terms.length ? terms.join(' ') : null;
}

function next(pageInfo) {
  return pageInfo?.hasNextPage ? pageInfo.endCursor : null;
}

/**
 * Shopify's reasons for refusing a change (its userErrors); throws where
 * there are any. "Nothing was changed" is said only where the answer holds
 * no result beside them; with a result, the outcome is not known.
 */
function refusedBy(payload, what, result, toRead) {
  if (!isObject(payload)) throw new ToolError(`Shopify gave no answer for ${what}. Whether the change was made is not known. ${toRead}`);
  const errors = Array.isArray(payload.userErrors) ? payload.userErrors : [];
  if (errors.length === 0) return;
  const said = errors.map((e) => `${Array.isArray(e?.field) && e.field.length ? `${e.field.join('.')}: ` : ''}${typeof e?.message === 'string' ? e.message : 'no reason given'}`).join('; ');
  const made = payload[result];
  if (made === null || made === undefined || (Array.isArray(made) && made.length === 0)) throw new ToolError(`Shopify refused ${what}: ${said}. Nothing was changed.`);
  throw new ToolError(`Shopify reported a fault with ${what} (${said}), yet its answer also holds a result. Whether the change was made is not known. ${toRead}`);
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

/** The refunds an order has, in a sentence, for a refund sent again with its key: they show whether the first sending was made. */
function refundsSoFar(order) {
  if (!Array.isArray(order.refunds)) return 'Shopify did not list the order\'s refunds; read the order to see what was given back.';
  if (order.refunds.length === 0) return `Order ${order.name} has no refund so far.`;
  return `The refunds of order ${order.name} so far: ${order.refunds.map((r) => {
    const total = presentment(r?.totalRefundedSet);
    return `${r?.id} of ${total ? `${total.amount} ${total.currency}` : 'an amount not given'}, made at ${r?.createdAt}`;
  }).join('; ')}.`;
}

/** The shop's currency, read before a change; throws where it is not the one given. */
async function shopCurrency(admin, given) {
  const data = await admin.graphql(SHOP_CURRENCY, {}, { ending: 'Nothing was changed.' });
  const is = data.shop?.currencyCode;
  if (typeof is !== 'string') throw new ToolError('Shopify did not say which currency the shop uses. Nothing was changed.');
  if (given !== undefined && is !== given) throw new ToolError(`The shop's currency is ${is}, not ${given}. Nothing was changed.`);
  if (given !== undefined && places(is) === null) throw new ToolError(`This server does not know how many decimal places ${is} has, so it will not send an amount in it. Nothing was changed.`);
  return is;
}

/**
 * The lowest price the server's own settings allow a variant now, in
 * smallest units: not below the minimum price, and not more than the
 * largest cut below the present price. Worked in whole numbers.
 */
function lowestPrice(present, limits) {
  const afterCut = (BigInt(present) * BigInt(100 - limits.maxPriceCutPercent) + 99n) / 100n;
  const least = BigInt(limits.minPriceMinor);
  return Number(afterCut > least ? afterCut : least);
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

const LIST_CODES = 'List the discount codes before trying again.';

async function createDiscount(admin, input) {
  const data = await admin.graphql(CREATE_DISCOUNT_CODE, { basicCodeDiscount: input }, { change: LIST_CODES });
  refusedBy(data.discountCodeBasicCreate, 'the discount code', 'codeDiscountNode', LIST_CODES);
  const node = data.discountCodeBasicCreate.codeDiscountNode;
  if (!isObject(node)) throw new ToolError(`Shopify gave no discount code and no reason. Whether the code was made is not known. ${LIST_CODES}`);
  return discountShown(node);
}

/**
 * Where a discount code as Shopify reports it is not the one asked for:
 * each difference in a few words. An empty list where there is none. The
 * percentage or the amount is held by the tool itself.
 */
function discountDifferences(made, args) {
  const out = [];
  const same = (a, b) => Date.parse(a) === Date.parse(b);
  if (made.discount_id === null) out.push('no id');
  if (!(made.codes ?? []).some((c) => typeof c === 'string' && c.toLowerCase() === args.code.toLowerCase())) out.push(`the code ${(made.codes ?? []).join(', ') || 'missing'}`);
  if ((made.usage_limit ?? null) !== (args.usage_limit ?? null)) out.push(`the limit on uses as ${made.usage_limit ?? 'none'} where ${args.usage_limit ?? 'none'} was asked for`);
  if (made.once_per_customer !== (args.once_per_customer ?? false)) out.push(`once for each customer as ${made.once_per_customer} where ${args.once_per_customer ?? false} was asked for`);
  if (args.ends_at === undefined ? made.ends_at !== null : !same(made.ends_at, args.ends_at)) out.push(`its end as ${made.ends_at ?? 'none'} where ${args.ends_at ?? 'none'} was asked for`);
  if (args.starts_at !== undefined && !same(made.starts_at, args.starts_at)) out.push(`its start as ${made.starts_at ?? 'none'} where ${args.starts_at} was asked for`);
  if (made.status !== 'ACTIVE' && made.status !== 'SCHEDULED') out.push(`the state ${made.status ?? 'missing'}`);
  return out;
}

/** The answer for a discount code that Shopify reports as asked for: "now gives" only for one that is active, "will give" for one that starts later. */
function discountDone(made, args, off) {
  const differences = discountDifferences(made, args);
  if (differences.length > 0) throw new ToolError(`Shopify made the code ${args.code} (${made.discount_id}) and reports it otherwise than was asked: ${differences.join('; ')}. List the discount codes to see what it is.`);
  return { done: made.status === 'ACTIVE' ? `The code ${args.code} now gives ${off}.` : `The code ${args.code} will give ${off} from ${made.starts_at}.`, ...made };
}

/**
 * What became of a refund, from the state of its own transactions as
 * Shopify reports them. "done" is said only where every one of them is a
 * refund that succeeded and they come to the amount asked for; every
 * figure told is Shopify's.
 */
function refundOutcome(refund, order, asked, unit, more) {
  const amount = toDecimal(asked, unit);
  const nodes = Array.isArray(refund.transactions?.nodes) ? refund.transactions.nodes : [];
  const transactions = nodes.map((t) => ({ transaction_id: t?.id ?? null, kind: t?.kind ?? null, status: t?.status ?? null, amount: presentment(t?.amountSet) }));
  const states = transactions.map((t) => String(t.status)).join(', ');
  const toRead = 'Read the order to see what was given back.';
  const recorded = `Shopify recorded a refund on order ${order.name} (${refund.id})`;
  if (transactions.length === 0) throw new ToolError(`${recorded} and named no payment of it, so whether any money was given back is not known. ${toRead}`);
  if (transactions.some((t) => t.kind !== 'REFUND')) throw new ToolError(`${recorded} and names with it a transaction that is not a refund (${transactions.map((t) => String(t.kind)).join(', ')}), so whether any money was given back is not known. ${toRead}`);
  if (transactions.some((t) => t.status === 'FAILURE' || t.status === 'ERROR')) throw new ToolError(`${recorded}, and reports that the sending of the money failed (${states}). ${toRead}`);
  if (transactions.some((t) => t.amount?.currency !== unit || t.amount.amount_minor === null)) throw new ToolError(`${recorded} and gives the amount of its payment in a form this server cannot read, or in another currency than ${unit}, where ${amount} ${unit} was asked for. ${toRead}`);
  const sent = transactions.reduce((sum, t) => sum + t.amount.amount_minor, 0);
  const waiting = transactions.some((t) => t.status !== 'SUCCESS');
  if (sent !== asked) throw new ToolError(`Shopify made a refund on order ${order.name} (${refund.id}) and reports ${toDecimal(sent, unit)} ${unit} ${waiting ? 'to be sent back' : 'sent back'}, where ${amount} ${unit} was asked for. ${toRead}`);
  const base = { refund_id: refund.id, made_at: refund.createdAt ?? null, order_id: order.id, transactions, ...more };
  if (waiting) {
    return { not_confirmed: `Shopify recorded a refund of ${toDecimal(sent, unit)} ${unit} on order ${order.name}, and has not yet reported the money as sent (${states}). Read the order later to see whether it was.`, ...base };
  }
  // Every transaction succeeded: the refund's own total is held against the amount too.
  const total = presentment(refund.totalRefundedSet);
  if (total?.amount_minor !== asked || total.currency !== unit) throw new ToolError(`Shopify made a refund on order ${order.name} (${refund.id}) and reports ${total ? `${total.amount} ${total.currency}` : 'a total this server cannot read'} sent back, where ${amount} ${unit} was asked for. ${toRead}`);
  return { done: `${toDecimal(sent, unit)} ${unit} was refunded on order ${order.name}.`, refunded: shown({ amount: toDecimal(sent, unit), currencyCode: unit }), ...base };
}

// --- the tools ---

const READS = { readOnlyHint: true };
const ADDS = { readOnlyHint: false, destructiveHint: false, idempotentHint: false };
const CHANGES = { readOnlyHint: false, destructiveHint: true, idempotentHint: false };

export const TOOLS = [
  {
    name: 'list_products',
    description: 'Lists the store\'s products, with the lowest and highest price of each. Gives "next" where there are more.',
    inputSchema: schema(SEARCH),
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
      if (p.id !== args.product_id) throw new ToolError(`Shopify answered the reading of ${args.product_id} with another product.`);
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
    description: 'Changes the price of one variant of a product. The price is in the shop\'s own currency, which must be named. The server\'s own settings, which no call can change, set the lowest price it will set and how far below the present price one call may go; unless they say otherwise, a price may be raised and not lowered.',
    inputSchema: schema({
      variant_id: id('ProductVariant', 'The variant.'),
      price_minor: whole(`The new price. ${MINOR}`, 0),
      currency: currency('The currency of the price: the shop\'s own.'),
    }, ['variant_id', 'price_minor', 'currency']),
    annotations: CHANGES,
    async run(args, admin, limits) {
      const data = await admin.graphql(READ_VARIANT, { id: args.variant_id }, { ending: 'Nothing was changed.' });
      const v = data.productVariant;
      if (!isObject(v) || typeof v.product?.id !== 'string') throw new ToolError(`The store has no variant ${args.variant_id}. Nothing was changed.`);
      // The variant written is the one asked for, not whichever the reading gave.
      if (v.id !== args.variant_id) throw new ToolError(`Shopify answered the reading of ${args.variant_id} with another variant (${typeof v.id === 'string' ? v.id : 'one with no id'}). Nothing was changed.`);
      const unit = data.shop?.currencyCode;
      if (typeof unit !== 'string') throw new ToolError('Shopify did not say which currency the shop uses. Nothing was changed.');
      if (unit !== args.currency) throw new ToolError(`The shop's currency is ${unit}, not ${args.currency}. Nothing was changed.`);
      const price = toDecimal(args.price_minor, unit);
      if (price === null) throw new ToolError(`This server does not know how many decimal places ${unit} has, so it will not send a price in it. Nothing was changed.`);
      const name = v.displayName ?? v.id;
      // The floor: held against the price Shopify has just given, by the server's own settings.
      const present = toMinor(v.price, unit);
      if (present === null) throw new ToolError(`Shopify gave the present price of ${name} in a form this server cannot read, so it cannot tell how large a cut this would be. Nothing was changed.`);
      const lowest = lowestPrice(present, limits);
      if (args.price_minor < lowest) {
        const cut = limits.maxPriceCutPercent === 0 ? 'no cut in a price' : `no cut of more than ${limits.maxPriceCutPercent}% of the present price in one call`;
        throw new ToolError(`The price of ${name} is ${toDecimal(present, unit)} ${unit}, and ${price} ${unit} was asked for. This server's settings allow no price below ${toDecimal(limits.minPriceMinor, unit)} ${unit} and ${cut}, so the lowest it would set now is ${toDecimal(lowest, unit)} ${unit}. Nothing was changed.`);
      }
      const toRead = 'Read the product before trying again.';
      const changed = await admin.graphql(SET_VARIANT_PRICE, { productId: v.product.id, variants: [{ id: v.id, price }] }, { change: toRead });
      refusedBy(changed.productVariantsBulkUpdate, 'the price', 'productVariants', toRead);
      const now = (changed.productVariantsBulkUpdate.productVariants ?? []).find((x) => x?.id === v.id);
      if (!now || toMinor(now.price, unit) !== args.price_minor) throw new ToolError(`Shopify took the change and reports the price of ${name} as ${typeof now?.price === 'string' ? `${now.price} ${unit}` : 'nothing'}, where ${price} ${unit} was asked for. Read the product to see what it is.`);
      return {
        done: `The price of ${name} is now ${price} ${unit}.`,
        variant_id: v.id,
        product_id: v.product.id,
        price: shown({ amount: price, currencyCode: unit }),
        price_before: shown({ amount: v.price, currencyCode: unit }),
      };
    },
  },
  {
    name: 'list_discount_codes',
    description: 'Lists the store\'s discount codes: the code, whether it is active, and the percentage or amount off. Gives "next" where there are more.',
    inputSchema: schema(SEARCH),
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
      await shopCurrency(admin); // a reading first: no change is sent until Shopify has just answered with this server's version
      const made = await createDiscount(admin, discountInput(args, { percentage: args.percent / 100 }));
      if (made.percent !== args.percent) throw new ToolError(`Shopify made the code ${args.code} (${made.discount_id}) and reports ${made.percent === undefined ? 'no percentage' : `${made.percent}%`} off, where ${args.percent}% was asked for. List the discount codes to see what it is.`);
      return discountDone(made, args, `${args.percent}% off`);
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
      if (made.amount_off?.amount_minor !== args.amount_minor || made.amount_off?.currency !== unit) throw new ToolError(`Shopify made the code ${args.code} (${made.discount_id}) and reports ${made.amount_off ? `${made.amount_off.amount} ${made.amount_off.currency}` : 'no amount'} off, where ${amount} ${unit} was asked for. List the discount codes to see what it is.`);
      return discountDone(made, args, `${amount} ${unit} off an order`);
    },
  },
  {
    name: 'deactivate_discount_code',
    description: 'Stops a discount code from being used from now on. The code is kept, and can be turned on again in the Shopify admin.',
    inputSchema: schema({ discount_id: id('DiscountCodeNode', 'The discount code, by the discount_id that list_discount_codes gives.') }, ['discount_id']),
    annotations: CHANGES,
    async run(args, admin) {
      await shopCurrency(admin); // a reading first, as for making a code
      const data = await admin.graphql(DEACTIVATE_DISCOUNT_CODE, { id: args.discount_id }, { change: LIST_CODES });
      refusedBy(data.discountCodeDeactivate, 'the change to the discount code', 'codeDiscountNode', LIST_CODES);
      const node = data.discountCodeDeactivate.codeDiscountNode;
      if (!isObject(node)) throw new ToolError('Shopify gave no discount code and no reason. List the discount codes to see whether it still works.');
      const made = discountShown(node);
      const name = made.codes?.[0] ?? made.title ?? args.discount_id;
      if (made.discount_id !== args.discount_id) throw new ToolError(`Shopify answered with another discount code (${made.discount_id ?? 'one with no id'}) than the one asked for. List the discount codes to see which can still be used.`);
      if (typeof made.status !== 'string' || made.status === 'ACTIVE') throw new ToolError(`Shopify answered, and reports the discount code ${name} as ${made.status ?? 'in no state it names'}. List the discount codes to see whether it can still be used.`);
      return { done: `The discount code ${name} can no longer be used.`, ...made };
    },
  },
  {
    name: 'list_orders',
    description: 'Lists the store\'s orders, newest first: the order\'s name, its state, its total and what has been refunded. Orders are found by their state, their date or their name, and by nothing about the customer. No customer\'s name, address, email or telephone number is given. Gives "next" where there are more.',
    inputSchema: schema(ORDER_FILTERS),
    annotations: READS,
    async run(args, admin) {
      const data = await admin.graphql(LIST_ORDERS, { first: args.first ?? 20, after: args.after ?? null, query: orderQuery(args) });
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
      if (o.id !== args.order_id) throw new ToolError(`Shopify answered the reading of ${args.order_id} with another order.`);
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
    description: 'Gives money back on an order: part of what was paid, or all of it. The amount is always stated; to refund the whole order, read it first and give its "paid_and_not_refunded". The money goes back the way it was paid. Nothing is put back into stock, and the customer is told only where "notify" is true. The answer says "done" only where Shopify reports the money as sent. Where an answer says the outcome is not known, send the same call again with the "idempotency_key" it names, and Shopify will not make the refund twice.',
    inputSchema: schema({
      order_id: id('Order', 'The order.'),
      amount_minor: whole(`The money to give back. ${MINOR}`, 1),
      currency: currency('The currency of the amount: the one the order was paid in.'),
      transaction_id: id('OrderTransaction', 'Which payment to refund, where the order has more than one: a transaction_id that read_order gives.'),
      note: text('A note kept with the refund, for the merchant.'),
      notify: flag('Whether Shopify tells the customer of the refund. False where it is left out.'),
      idempotency_key: text('Only when sending again a refund whose outcome was not known: the key that answer named, with every other argument as it was. Shopify then treats the two as one refund, for 24 hours. Left out, the server makes a new key.', { pattern: UUID, minLength: 36, maxLength: 36 }),
    }, ['order_id', 'amount_minor', 'currency']),
    annotations: CHANGES,
    async run(args, admin) {
      // With a key given, this call may be the second sending of a refund whose outcome was not known, and the order may by now show that
      // refund. So where the server refuses such a call, it says that this call sent no refund and what the order's refunds are, and never
      // "Nothing was refunded": that would read as the first refund not having been made.
      const again = args.idempotency_key !== undefined;
      const sentNone = 'This call sent no refund. A key was given, so it may be a second sending of a refund, and whether the first was made is not known to this server.';
      let nothing = again ? `${sentNone} Read the order: its refunds show what was given back.` : 'Nothing was refunded.';
      const data = await admin.graphql(ORDER_FOR_REFUND, { id: args.order_id }, { ending: nothing });
      const o = data.order;
      if (!isObject(o)) throw new ToolError(`The store has no order ${args.order_id}. ${nothing}`);
      if (o.id !== args.order_id) throw new ToolError(`Shopify answered the reading of ${args.order_id} with another order (${typeof o.id === 'string' ? o.id : 'one with no id'}). ${nothing}`);
      if (again) nothing = `${sentNone} ${refundsSoFar(o)}`;
      const unit = o.presentmentCurrencyCode;
      if (typeof unit !== 'string' || typeof o.currencyCode !== 'string') throw new ToolError(`Shopify did not say which currency the order was paid in. ${nothing}`);
      if (unit !== o.currencyCode) throw new ToolError(`Order ${o.name} was paid in ${unit} and the shop's currency is ${o.currencyCode}. This server refunds only an order paid in the shop's own currency; refund this one in the Shopify admin. ${nothing}`);
      if (unit !== args.currency) throw new ToolError(`Order ${o.name} was paid in ${unit}, not ${args.currency}. ${nothing}`);
      const amount = toDecimal(args.amount_minor, unit);
      if (amount === null) throw new ToolError(`This server does not know how many decimal places ${unit} has, so it will not send an amount in it. ${nothing}`);
      if (o.refundable === false) throw new ToolError(`Shopify says order ${o.name} cannot be refunded: it has no payment that can be given back. ${nothing}`);
      if (o.refundable !== true) throw new ToolError(`Shopify did not say whether order ${o.name} can be refunded. ${nothing}`);
      const left = presentment(o.netPaymentSet);
      if (!left || left.amount_minor === null || left.currency !== unit) throw new ToolError(`Shopify did not say, in a form this server can read, how much of order ${o.name} is paid and not refunded. ${nothing}`);
      if (args.amount_minor > left.amount_minor) throw new ToolError(`Order ${o.name} has ${left.amount} ${unit} paid and not refunded, less than the ${amount} ${unit} asked for. ${nothing}`);
      const paid = payments(o);
      let from;
      if (args.transaction_id !== undefined) {
        from = paid.find((t) => t.id === args.transaction_id);
        if (!from) throw new ToolError(`${args.transaction_id} is not a successful payment of order ${o.name}. ${nothing}`);
      } else {
        if (paid.length === 0) throw new ToolError(`Order ${o.name} has no successful payment to refund. ${nothing}`);
        if (paid.length > 1) throw new ToolError(`Order ${o.name} has ${paid.length} payments. Say which to refund with "transaction_id": ${paid.map((t) => `${t.id} (${presentment(t.amountSet)?.amount ?? '?'} ${unit})`).join(', ')}. ${nothing}`);
        from = paid[0];
      }
      if (typeof from.gateway !== 'string' || from.gateway === '') throw new ToolError(`Shopify did not say how the payment ${from.id} was taken, so it cannot be refunded here. ${nothing}`);
      const input = {
        orderId: o.id,
        currency: unit,
        notify: args.notify ?? false,
        ...(args.note !== undefined ? { note: args.note } : {}),
        transactions: [{ orderId: o.id, parentId: from.id, kind: 'REFUND', gateway: from.gateway, amount }],
      };
      // Shopify asks for a key with refundCreate, and treats two requests with one key as one refund for 24 hours. The server sends the request once; the key is named in every answer so that the agent, should it send the call again, can give it.
      const key = args.idempotency_key ?? randomUUID();
      const toRead = `Read the order before trying again; to send this same refund again, give "idempotency_key": "${key}" with every other argument as it was, and Shopify will not make it twice.`;
      try {
        const sent = await admin.graphql(REFUND_ORDER, { input, idempotencyKey: key }, { change: toRead });
        refusedBy(sent.refundCreate, 'the refund', 'refund', toRead);
        const refund = sent.refundCreate.refund;
        if (!isObject(refund)) throw new ToolError(`Shopify gave no refund and no reason. Whether money was given back is not known. ${toRead}`);
        return refundOutcome(refund, o, args.amount_minor, unit, { customer_told: input.notify, idempotency_key: key });
      } catch (e) {
        // Every answer to a refund that was sent names the key it was sent with, a failure too.
        if (e instanceof ToolError && !e.message.includes(key)) throw new ToolError(`${e.message} This refund was sent with "idempotency_key": "${key}".`);
        throw e;
      }
    },
  },
];

/** The tool of a name, or null. */
export function toolNamed(name) {
  return TOOLS.find((t) => t.name === name) ?? null;
}

/** Run one tool: its answer as plain data, or a ToolError in plain words. `limits` are the server's own settings for a price. */
export async function runTool(tool, args, admin, limits) {
  const problem = wrong(args, tool.inputSchema);
  if (problem) throw new ToolError(`${problem} Nothing was asked of the store.`);
  return tool.run(args, admin, limits);
}
