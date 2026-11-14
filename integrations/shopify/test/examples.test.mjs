// The example settings and rules for the guard, held against the server
// itself: every tool has one action of its own, and each amount is read
// from a place where the tool's schema puts a whole number that must be
// given. The forms tested here are the guard's (its README, "The
// settings") and the format's (an action name, a unit); the guard's own
// code is not loaded.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';
import { closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, startServer } from './world.mjs';

const read = (name) => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const settings = JSON.parse(read('executor-http.example.json'));
const rules = JSON.parse(read('content-rules.example.json'));

let tools;
before(async () => {
  const server = startServer(await fakeShopify());
  tools = (await server.request('tools/list')).result.tools;
  await server.close();
});
after(async () => {
  await closeServers();
  await closeFakes();
});

test('the example settings name every tool of the server and no other, each with an action of its own', () => {
  assert.deepEqual(Object.keys(settings.tools), tools.map((t) => t.name));
  const actions = Object.values(settings.tools).map((r) => r.action);
  assert.equal(new Set(actions).size, actions.length, 'no two tools share an action');
  for (const [tool, rule] of Object.entries(settings.tools)) {
    assert.equal(rule.action, `shopify.${tool}`);
    assert.match(rule.action, /^[a-z0-9][a-z0-9._-]{0,63}$/, 'an action name as the format takes it');
  }
  assert.equal(settings.unlisted, 'refuse');
});

test('each tool that carries money or a percentage has its amount read from a required whole number of its schema', () => {
  const withAmount = Object.entries(settings.tools).filter(([, rule]) => rule.amount);
  assert.deepEqual(withAmount.map(([tool, rule]) => [tool, rule.amount]), [
    ['set_variant_price', { unit: 'GBP-pence', pointer: '/price_minor' }],
    ['create_percentage_discount_code', { unit: 'percent', pointer: '/percent' }],
    ['create_amount_discount_code', { unit: 'GBP-pence', pointer: '/amount_minor' }],
    ['refund_order', { unit: 'GBP-pence', pointer: '/amount_minor' }],
  ]);
  for (const [tool, rule] of withAmount) {
    const schema = tools.find((t) => t.name === tool).inputSchema;
    const argument = rule.amount.pointer.slice(1);
    assert.match(rule.amount.unit, /^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/, 'a unit as the format takes it');
    assert.equal(schema.properties[argument]?.type, 'integer', `${tool}: ${argument} is a whole number`);
    assert.ok(schema.properties[argument].minimum >= 0, `${tool}: ${argument} is not below 0`);
    assert.ok(schema.required.includes(argument), `${tool}: ${argument} must be given`);
  }
  // Every whole number of money or percentage in any schema is the amount of its tool's rule.
  for (const t of tools) {
    const money = Object.keys(t.inputSchema.properties).filter((name) => /_minor$|^percent$/.test(name));
    assert.deepEqual(money.map((name) => `/${name}`), settings.tools[t.name].amount ? [settings.tools[t.name].amount.pointer] : [], t.name);
  }
});

test('the example settings start the server with its three settings read from files, and hold no credential', () => {
  assert.deepEqual(Object.keys(settings.server.env), ['SHOPIFY_SHOP', 'SHOPIFY_CLIENT_ID', 'SHOPIFY_CLIENT_SECRET', 'SHOPIFY_MIN_PRICE_MINOR', 'SHOPIFY_MAX_PRICE_CUT_PERCENT']);
  assert.ok(settings.shutdownWait >= 90000, 'time for the three requests a refund can take, 30 seconds each');
  for (const [name, from] of Object.entries(settings.server.env)) assert.deepEqual(Object.keys(from), ['file'], `${name} is read from a file`);
  assert.equal(settings.upstream, undefined, 'a local program, not an upstream');
  assert.deepEqual(settings.oauth.clients, ['https://claude.ai/oauth/mcp-oauth-client-metadata']);
  assert.equal(settings.agents['claude-1'].oauth, true);
  assert.equal(settings.contentRules, 'content-rules.json');
});

test('the example rules on content fix the currency of each tool whose amount is money, and name only tools of the server', () => {
  assert.equal(rules.version, 1);
  const moneyTools = Object.entries(settings.tools).filter(([, rule]) => rule.amount?.unit === 'GBP-pence').map(([tool]) => tool).sort();
  assert.deepEqual(rules.rules.map((r) => r.tool).sort(), moneyTools);
  for (const rule of rules.rules) {
    assert.deepEqual(rule.test, { pointer: '/currency', equals: 'GBP' }, rule.name);
    const schema = tools.find((t) => t.name === rule.tool).inputSchema;
    assert.ok(schema.required.includes('currency'), `${rule.tool} must be given its currency`);
  }
});

test('DESIGN.md and the README name every tool, every action and every access scope', () => {
  const design = read('DESIGN.md');
  const readme = read('README.md');
  for (const t of tools) {
    assert.ok(design.includes(`\`${t.name}\``), `DESIGN.md names ${t.name}`);
    assert.ok(design.includes(`\`shopify.${t.name}\``), `DESIGN.md names the action shopify.${t.name}`);
    assert.ok(readme.includes(`\`${t.name}\``), `the README names ${t.name}`);
  }
  for (const scope of ['write_products', 'write_discounts', 'write_orders']) {
    assert.ok(readme.includes(`\`${scope}\``), `the README names ${scope}`);
    assert.ok(design.includes(`\`${scope}\``), `DESIGN.md names ${scope}`);
  }
  assert.ok(read('CHANGELOG.md').includes('0.1.0'));
});

test('the documents name the settings of the floor under a price and the filters of list_orders, and state the server\'s size truly', () => {
  const design = read('DESIGN.md');
  const readme = read('README.md');
  for (const name of ['SHOPIFY_MIN_PRICE_MINOR', 'SHOPIFY_MAX_PRICE_CUT_PERCENT']) {
    assert.ok(readme.includes(`\`${name}\``), `the README names ${name}`);
    assert.ok(design.includes(`\`${name}\``), `DESIGN.md names ${name}`);
  }
  const filters = Object.keys(tools.find((t) => t.name === 'list_orders').inputSchema.properties).filter((name) => !['first', 'after'].includes(name));
  for (const filter of filters) {
    assert.ok(readme.includes(`\`${filter}\``), `the README names the filter ${filter}`);
    assert.ok(design.includes(`\`${filter}\``), `DESIGN.md names the filter ${filter}`);
  }
  const lines = ['server.mjs', 'admin.mjs', 'tools.mjs', 'money.mjs'].reduce((sum, file) => sum + read(file).split('\n').length - 1, 0);
  assert.ok(lines < 1300, `${lines} lines`);
  assert.ok(readme.includes('Four files,\n  under 1,300 lines') && design.includes('four files, under 1,300\nlines'), 'both documents give that figure');
});
