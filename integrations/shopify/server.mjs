#!/usr/bin/env node
// provared-shopify: a small MCP server for one Shopify store's Admin API.
// It speaks the Model Context Protocol over its standard input and output
// (one JSON-RPC message to a line) and is meant to be started by
// provared-mcp-executor, which stands in front of it, checks each tool
// call against a signed permission and writes a signed receipt.
//
// Its settings come from its environment, never from its arguments:
//
//   SHOPIFY_SHOP                 the store: the part of its myshopify.com
//                                address before ".myshopify.com"
//   SHOPIFY_CLIENT_ID            the app's client ID, or
//   SHOPIFY_CLIENT_ID_FILE       the file that holds it
//   SHOPIFY_CLIENT_SECRET        the app's client secret, or
//   SHOPIFY_CLIENT_SECRET_FILE   the file that holds it
//   SHOPIFY_MIN_PRICE_MINOR      the lowest price it will set, in the
//                                currency's smallest unit (1 unless given)
//   SHOPIFY_MAX_PRICE_CUT_PERCENT  how far below the present price one call
//                                may set a price, from 0 to 100 (0 unless
//                                given: a price may be raised, not lowered)
//
// It uses nothing but Node.js itself. The only requests it makes are to
// that store's token address and Admin API (admin.mjs).

import { readFileSync } from 'node:fs';
import { API_VERSION, ToolError, openAdmin } from './admin.mjs';
import { TOOLS, runTool, toolNamed } from './tools.mjs';

const NAME = 'provared-shopify';
const VERSION = '0.1.0';

/** The revision of the protocol this server is written to, and the earlier ones whose messages for tools are the same. */
const PROTOCOL = '2025-11-25';
const PROTOCOLS = [PROTOCOL, '2025-06-18', '2025-03-26'];

const INSTRUCTIONS = 'Tools for one Shopify store: its products, discount codes and orders. Money is always a whole number of the currency\'s smallest unit (1250 is 12.50 GBP) with its currency beside it; a percentage is a whole number from 1 to 100. A change is sent to Shopify once and never tried again: where an answer says the outcome is not known, read the product, the discount codes or the order before sending the call again.';

const USAGE = `${NAME} ${VERSION}: an MCP server for one Shopify store's Admin API (version ${API_VERSION}), over standard input and output.
It takes no arguments but --version and --help. Its settings are read from its environment:
  SHOPIFY_SHOP                 the store: the part of its myshopify.com address before ".myshopify.com"
  SHOPIFY_CLIENT_ID            the app's client ID, or SHOPIFY_CLIENT_ID_FILE, the file that holds it
  SHOPIFY_CLIENT_SECRET        the app's client secret, or SHOPIFY_CLIENT_SECRET_FILE, the file that holds it
  SHOPIFY_MIN_PRICE_MINOR      the lowest price it will set, a whole number of the currency's smallest unit (1 unless given)
  SHOPIFY_MAX_PRICE_CUT_PERCENT  how far below the present price one call may set a price, a whole number from 0 to 100
                               (0 unless given: a price may be raised, not lowered)
Any other variable whose name begins SHOPIFY_ stops the start, so that a misspelt setting is not passed over.
`;

function stop(message) {
  process.stderr.write(`${NAME}: ${message}\n`);
  process.exit(1);
}

/** A setting given as itself (NAME) or as the file that holds it (NAME_FILE): exactly one of the two. Its value is never written anywhere. */
function credential(env, name) {
  const given = env[name];
  const file = env[`${name}_FILE`];
  delete env[name];
  if (given !== undefined && file !== undefined) stop(`${name} and ${name}_FILE are both set. Give one.`);
  let value = given;
  if (file !== undefined) {
    try {
      value = readFileSync(file, 'utf8');
    } catch (e) {
      stop(`${name}_FILE: the file could not be read (${e?.code ?? 'error'}).`);
    }
    // One line ending at the end is dropped, as the guard does with a credential's file.
    value = value.replace(/\r?\n$/, '');
  }
  if (value === undefined) stop(`${name} is not set, nor ${name}_FILE. ${NAME} --help says what is needed.`);
  if (!/^[\x21-\x7e]{1,512}$/.test(value)) stop(`${name}${file !== undefined ? '_FILE' : ''}: must hold 1 to 512 printable characters with no space, on one line.`);
  return value;
}

/** The store's address. A made-up server on this computer may stand in for Shopify, for tests alone. */
function storeOrigin(env) {
  const shop = env.SHOPIFY_SHOP;
  if (shop === undefined) stop(`SHOPIFY_SHOP is not set. ${NAME} --help says what is needed.`);
  if (!/^[a-z0-9][a-z0-9-]{0,59}$/.test(shop)) stop('SHOPIFY_SHOP must be the part of the store\'s myshopify.com address before ".myshopify.com": lower-case letters, digits and hyphens.');
  const test = env.SHOPIFY_TEST_ORIGIN;
  if (test === undefined) return { shop, origin: `https://${shop}.myshopify.com` };
  if (!/^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(test)) stop('SHOPIFY_TEST_ORIGIN is for tests alone and must be http://127.0.0.1:<port>. Take it out to reach Shopify.');
  return { shop, origin: test, madeUp: true };
}

/** A whole number from the environment, from 0 to `most`; `unless` where the variable is not set. Anything else stops the start: a limit that cannot be read is not guessed. */
function wholeNumber(env, name, unless, most) {
  const given = env[name];
  if (given === undefined) return unless;
  const value = /^[0-9]{1,16}$/.test(given) ? Number(given) : NaN;
  if (!Number.isSafeInteger(value) || value > most) stop(`${name} must be a whole number from 0 to ${most}, in digits alone.`);
  return value;
}

/** Every setting the server reads. A variable that begins SHOPIFY_ and is none of these stops the start: a misspelt limit must not be passed over. */
const SETTINGS = ['SHOPIFY_SHOP', 'SHOPIFY_CLIENT_ID', 'SHOPIFY_CLIENT_ID_FILE', 'SHOPIFY_CLIENT_SECRET', 'SHOPIFY_CLIENT_SECRET_FILE', 'SHOPIFY_MIN_PRICE_MINOR', 'SHOPIFY_MAX_PRICE_CUT_PERCENT', 'SHOPIFY_TEST_ORIGIN'];

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === '--version') return void process.stdout.write(`${VERSION}\n`);
  if (argv.length === 1 && argv[0] === '--help') return void process.stdout.write(USAGE);
  if (argv.length > 0) stop('takes no arguments but --version and --help. Its settings, and the files that hold the client ID and the client secret, are named in its environment.');

  // Only the name of such a variable is said, never its value.
  const unknown = Object.keys(process.env).filter((name) => name.toUpperCase().startsWith('SHOPIFY_') && !SETTINGS.includes(name));
  if (unknown.length > 0) stop(`${unknown.map((name) => name.slice(0, 60)).join(', ')}: not a setting of this server, so it will not start. Its settings are ${SETTINGS.slice(0, -1).join(', ')}. Take the variable out, or correct its name.`);

  const { shop, origin, madeUp } = storeOrigin(process.env);
  const clientId = credential(process.env, 'SHOPIFY_CLIENT_ID');
  const clientSecret = credential(process.env, 'SHOPIFY_CLIENT_SECRET');
  // The floor under a price: the server's own, which no call can change. Unless set otherwise, no price of nothing and no cut at all.
  const limits = {
    minPriceMinor: wholeNumber(process.env, 'SHOPIFY_MIN_PRICE_MINOR', 1, Number.MAX_SAFE_INTEGER),
    maxPriceCutPercent: wholeNumber(process.env, 'SHOPIFY_MAX_PRICE_CUT_PERCENT', 0, 100),
  };
  let scrub = String;
  const log = (message) => process.stderr.write(`${NAME}: ${scrub(message)}\n`);
  const admin = openAdmin({ origin, clientId, clientSecret, userAgent: `${NAME}/${VERSION}`, log });
  scrub = admin.scrub;

  const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const answer = (id, result) => send({ jsonrpc: '2.0', id, result });
  const refuse = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });
  /** A tool's answer: text, with the client secret and every access token taken out whatever put them there. */
  const told = (value, isError) => ({ content: [{ type: 'text', text: admin.scrub(value) }], ...(isError ? { isError: true } : {}) });

  log(`${VERSION}, store ${shop}, Admin API ${API_VERSION}${madeUp ? `, at the made-up server ${origin} (a test: Shopify is not reached)` : ''}.`);
  log(`a price: none below ${limits.minPriceMinor} of the currency's smallest unit, and ${limits.maxPriceCutPercent === 0 ? 'no cut' : `no cut of more than ${limits.maxPriceCutPercent}% in one call`}.`);

  async function call(id, tool, args) {
    try {
      // The secrets are taken out of each text before the answer is written as JSON, and out of the JSON after.
      answer(id, told(JSON.stringify(admin.scrubAll(await runTool(tool, args, admin, limits)), null, 2), false));
    } catch (e) {
      if (e instanceof ToolError) return void answer(id, told(e.message, true));
      log(`${tool.name} failed: ${e?.stack ?? e}`);
      answer(id, told(`This server failed while it handled the call (${e?.name ?? 'error'}). Where the call makes a change, whether it was made is not known: read the product, the discount codes or the order before sending it again.`, true));
    }
  }

  // Tool calls are handled one at a time, in the order they arrive.
  let turn = Promise.resolve();

  function handle(line) {
    if (line.trim() === '') return;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return void refuse(null, -32700, 'Parse error: the line is not JSON.');
    }
    if (m === null || typeof m !== 'object' || Array.isArray(m)) return void refuse(null, -32600, 'Invalid request: one JSON-RPC message to a line, not a list.');
    if (typeof m.method !== 'string') return; // an answer to a request; this server makes none
    if (!Object.hasOwn(m, 'id')) return; // a notification: nothing to answer; a cancellation stops nothing (DESIGN.md, S27)
    const { id, method, params } = m;
    if (typeof id !== 'string' && !Number.isSafeInteger(id)) return void refuse(null, -32600, 'Invalid request: the id must be text or a whole number.');
    if (method === 'initialize') {
      const asked = params?.protocolVersion;
      return void answer(id, {
        protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: { name: NAME, version: VERSION },
        instructions: INSTRUCTIONS,
      });
    }
    if (method === 'ping') return void answer(id, {});
    if (method === 'tools/list') return void answer(id, { tools: TOOLS.map(({ name, description, inputSchema, annotations }) => ({ name, description, inputSchema, annotations })) });
    if (method === 'tools/call') {
      const tool = typeof params?.name === 'string' ? toolNamed(params.name) : null;
      if (!tool) return void refuse(id, -32602, `Unknown tool: ${admin.scrub(String(params?.name)).slice(0, 100)}`);
      turn = turn.then(() => call(id, tool, params.arguments ?? {}));
      return;
    }
    refuse(id, -32601, `Method not found: ${admin.scrub(method).slice(0, 100)}`);
  }

  // Where the reader of the output has gone, what is written is lost and the
  // server goes on until its input ends, so that a change in hand is finished.
  process.stdout.on('error', () => {});
  // One message to a line, and a line ends at a line feed and nowhere else
  // (one carriage return before it is dropped). A carriage return alone is
  // white space inside a JSON message, and U+2028 and U+2029 may stand
  // inside its text, so none of them ends a line here.
  let rest = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    const from = rest.length;
    rest += chunk;
    for (let at = rest.indexOf('\n', from); at !== -1; at = rest.indexOf('\n')) {
      const line = rest.slice(0, at);
      rest = rest.slice(at + 1);
      handle(line.endsWith('\r') ? line.slice(0, -1) : line);
    }
  });
  // When the input ends, the calls in hand are answered and the server then
  // ends by itself: nothing else keeps it running.
  process.stdin.on('end', () => {
    if (rest !== '') handle(rest);
    rest = '';
  });
}

main();
