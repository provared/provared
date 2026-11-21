// The server as an MCP server over standard input and output: how it
// starts, what it says of itself, and what it does with a message that is
// not a tool call. Shopify is not reached; a made-up one stands in.

import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, afterEach, before, test } from 'node:test';
import { CLIENT_ID, CLIENT_SECRET, closeFakes, fakeShopify } from './fake-shopify.mjs';
import { closeServers, runToEnd, startServer } from './world.mjs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

let fake;
before(async () => {
  fake = await fakeShopify();
});
// A test that fails half-way leaves no server running and nothing listening.
afterEach(closeServers);
after(closeFakes);

test('initialize: the protocol version asked for is answered where it is one the server speaks, and 2025-11-25 otherwise', async () => {
  const server = startServer(fake);
  const a = await server.request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  assert.equal(a.result.protocolVersion, '2025-11-25');
  assert.deepEqual(a.result.capabilities, { tools: {} });
  assert.deepEqual(a.result.serverInfo, { name: 'provared-shopify', version: pkg.version });
  assert.match(a.result.instructions, /whole number/);
  const earlier = await server.request('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  assert.equal(earlier.result.protocolVersion, '2025-06-18');
  const unknown = await server.request('initialize', { protocolVersion: '1999-01-01', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  assert.equal(unknown.result.protocolVersion, '2025-11-25');
  assert.equal(await server.close(), 0);
  assert.equal(fake.sent.length, 0, 'nothing is asked of Shopify before a tool is called');
});

test('tools/list: ten tools, each with a closed schema, and money and percentages as whole numbers', async () => {
  const server = startServer(fake);
  const { result } = await server.request('tools/list');
  assert.deepEqual(result.tools.map((t) => t.name), [
    'list_products', 'read_product', 'set_variant_price',
    'list_discount_codes', 'create_percentage_discount_code', 'create_amount_discount_code', 'deactivate_discount_code',
    'list_orders', 'read_order', 'refund_order',
  ]);
  for (const t of result.tools) {
    assert.equal(t.inputSchema.type, 'object', t.name);
    assert.equal(t.inputSchema.additionalProperties, false, t.name);
    assert.ok(t.description.length > 20, t.name);
    assert.equal(typeof t.annotations.readOnlyHint, 'boolean', t.name);
    assert.deepEqual(Object.keys(t).sort(), ['annotations', 'description', 'inputSchema', 'name'], t.name);
  }
  const schema = (name) => result.tools.find((t) => t.name === name).inputSchema;
  for (const [tool, argument] of [['set_variant_price', 'price_minor'], ['create_amount_discount_code', 'amount_minor'], ['refund_order', 'amount_minor'], ['create_percentage_discount_code', 'percent']]) {
    assert.equal(schema(tool).properties[argument].type, 'integer', `${tool}.${argument}`);
    assert.ok(schema(tool).required.includes(argument), `${tool}.${argument} is required`);
  }
  for (const tool of ['set_variant_price', 'create_amount_discount_code', 'refund_order']) {
    assert.ok(schema(tool).required.includes('currency'), `${tool} names its currency`);
  }
  assert.deepEqual([schema('create_percentage_discount_code').properties.percent.minimum, schema('create_percentage_discount_code').properties.percent.maximum], [1, 100]);
  assert.deepEqual(result.tools.filter((t) => t.annotations.readOnlyHint).map((t) => t.name), ['list_products', 'read_product', 'list_discount_codes', 'list_orders', 'read_order']);
  await server.close();
});

test('ping is answered; an unknown method, an unknown tool, a line that is not JSON and a list are refused; a notification is not answered', async () => {
  const server = startServer(fake);
  assert.deepEqual((await server.request('ping')).result, {});
  assert.equal((await server.request('resources/list')).error.code, -32601);
  const unknown = await server.request('tools/call', { name: 'cancel_order', arguments: {} });
  assert.equal(unknown.error.code, -32602);
  assert.match(unknown.error.message, /Unknown tool: cancel_order/);
  server.write('{"jsonrpc":"2.0","method":"notifications/initialized"}');
  server.write('{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}');
  server.write('this is not JSON');
  server.write('[{"jsonrpc":"2.0","id":90,"method":"ping"}]');
  server.write('{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}');
  assert.deepEqual((await server.request('ping')).result, {}, 'the server goes on after them');
  assert.deepEqual(server.unasked.map((m) => [m.id, m.error.code]), [[null, -32700], [null, -32600], [null, -32600]]);
  assert.equal(await server.close(), 0);
});

test('a call in hand when the input ends is answered before the server ends', async () => {
  const server = startServer(fake);
  const answer = server.call('read_product', { product_id: 'gid://shopify/Product/1' });
  const code = await server.close();
  assert.equal((await answer).data.title, 'Mug');
  assert.equal(code, 0);
});

test('--version gives the version of package.json; --help names the settings and no credential', async () => {
  const version = await runToEnd(['--version'], {});
  assert.deepEqual([version.code, version.stdout.trim()], [0, pkg.version]);
  const help = await runToEnd(['--help'], {});
  assert.equal(help.code, 0);
  for (const name of ['SHOPIFY_SHOP', 'SHOPIFY_CLIENT_ID_FILE', 'SHOPIFY_CLIENT_SECRET_FILE']) assert.ok(help.stdout.includes(name), name);
});

test('the server does not start: with an argument, without its settings, with a credential given twice, or with a test address that is not this computer', async () => {
  const folder = mkdtempSync(join(tmpdir(), 'provared-shopify-start-'));
  try {
    const idFile = join(folder, 'id');
    const secretFile = join(folder, 'secret');
    const emptyFile = join(folder, 'empty');
    const twoLines = join(folder, 'two-lines');
    writeFileSync(idFile, CLIENT_ID);
    writeFileSync(secretFile, `${CLIENT_SECRET}\r\n`);
    writeFileSync(emptyFile, '\n');
    writeFileSync(twoLines, `${CLIENT_SECRET}\nsecond line\n`);
    const good = { SHOPIFY_SHOP: 'made-up-store', SHOPIFY_TEST_ORIGIN: fake.origin, SHOPIFY_CLIENT_ID_FILE: idFile, SHOPIFY_CLIENT_SECRET_FILE: secretFile };
    const cases = [
      [['--client-secret', CLIENT_SECRET], good, /takes no arguments/],
      [[], { ...good, SHOPIFY_SHOP: undefined }, /SHOPIFY_SHOP is not set/],
      [[], { ...good, SHOPIFY_SHOP: 'made-up-store.myshopify.com' }, /SHOPIFY_SHOP must be/],
      [[], { ...good, SHOPIFY_SHOP: 'evil.example/x' }, /SHOPIFY_SHOP must be/],
      [[], { ...good, SHOPIFY_CLIENT_ID_FILE: undefined }, /SHOPIFY_CLIENT_ID is not set, nor SHOPIFY_CLIENT_ID_FILE/],
      [[], { ...good, SHOPIFY_CLIENT_SECRET_FILE: undefined }, /SHOPIFY_CLIENT_SECRET is not set, nor SHOPIFY_CLIENT_SECRET_FILE/],
      [[], { ...good, SHOPIFY_CLIENT_SECRET: CLIENT_SECRET }, /SHOPIFY_CLIENT_SECRET and SHOPIFY_CLIENT_SECRET_FILE are both set/],
      [[], { ...good, SHOPIFY_CLIENT_SECRET_FILE: join(folder, 'missing') }, /SHOPIFY_CLIENT_SECRET_FILE: the file could not be read \(ENOENT\)/],
      [[], { ...good, SHOPIFY_CLIENT_SECRET_FILE: emptyFile }, /SHOPIFY_CLIENT_SECRET_FILE: must hold/],
      [[], { ...good, SHOPIFY_CLIENT_SECRET_FILE: twoLines }, /SHOPIFY_CLIENT_SECRET_FILE: must hold/],
      [[], { ...good, SHOPIFY_TEST_ORIGIN: 'https://shop.example' }, /SHOPIFY_TEST_ORIGIN is for tests alone/],
      [[], { ...good, SHOPIFY_TEST_ORIGIN: 'http://127.0.0.1:80/elsewhere' }, /SHOPIFY_TEST_ORIGIN is for tests alone/],
    ];
    for (const [args, env, said] of cases) {
      const clean = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined));
      const run = await runToEnd(args, clean);
      assert.equal(run.code, 1, String(said));
      assert.match(run.stderr, said);
      assert.equal(run.stdout, '', String(said));
      assert.ok(!(run.stdout + run.stderr).includes(CLIENT_SECRET), `the client secret is not in what is said: ${said}`);
    }
    // With the same good settings it does start, and ends when its input ends.
    const run = await runToEnd([], good);
    assert.equal(run.code, 0);
    assert.match(run.stderr, /provared-shopify: 0\.1\.0, store made-up-store, Admin API 2026-10, at the made-up server/);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
