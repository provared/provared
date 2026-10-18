// What the tests share: a made-up upstream on 127.0.0.1, a slip signed with
// the library's development stand-in for a passkey, a gateway opened on it,
// and a made-up agent client. Nothing leaves this computer: every server
// listens on 127.0.0.1, on a port the system chooses.
//
// Imported with import(), after local-library.mjs.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assembleSlip, formatTime, generateKeySet, generateSealKeySet, prepareSlip, signerFromKey, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
import { openGateway, secretHash } from '../gateway.mjs';

// A temporary folder for a test file, removed when the test process ends.
const made = [];
process.on('exit', () => {
  for (const dir of made) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // Still in use: left for the computer's own clearing of its temporary folder.
    }
  }
});
export function tempFolder() {
  const dir = mkdtempSync(join(tmpdir(), 'provared-gw-'));
  made.push(dir);
  return dir;
}

/**
 * A made-up upstream. Each call is kept (method, address, headers, body),
 * and answered by the test's own function, which may also do something
 * unkind (close the connection half way, never answer).
 */
export async function upstream(answer = (call, res) => json(res, 200, { ok: true })) {
  const calls = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const call = { method: req.method, url: req.url, headers: req.headers, rawHeaders: req.rawHeaders, body: Buffer.concat(chunks) };
      calls.push(call);
      server.answer(call, res, req);
    });
  });
  server.answer = answer;
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  server.unref();
  return { server, calls, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((d) => server.close(() => d())) };
}

export function json(res, status, value, headers = {}) {
  const body = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, ...headers });
  res.end(body);
}

/** A call from the made-up agent: the address is sent exactly as given. */
export function call(port, method, path, { secret, headers = {}, body, rawHeaders } = {}) {
  return new Promise((done, failed) => {
    const all = { ...(secret ? { authorization: `Bearer ${secret}` } : {}), ...headers };
    const data = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    if (data && all['content-length'] === undefined && all['transfer-encoding'] === undefined) all['content-length'] = data.length;
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: rawHeaders ? ['Host', `127.0.0.1:${port}`, ...rawHeaders] : all, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let value;
        try {
          value = JSON.parse(text);
        } catch {
          value = undefined;
        }
        done({ status: res.statusCode, headers: res.headers, text, json: value });
      });
    });
    req.on('error', failed);
    req.end(data);
  });
}

export const ACTIONS = ['provared.data.read', 'ticket.update', 'patch.apply', 'host.reboot', 'provared.data.delete'];

/** A slip for an agent's keys, signed with the development stand-in for a passkey. */
export async function signSlip({ passkey, agentKeys, actions = ACTIONS, limits = [], never = [], requires = [], with: services = [{ id: 'tickets', name: 'The ticket system' }, { id: 'patch', name: 'The patch service' }], from = Date.now() - 60000, until = Date.now() + 3600000 }) {
  const prepared = await prepareSlip({
    issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
    agent: { name: 'A patching agent, through the gateway at 127.0.0.1', keys: agentKeys },
    actions,
    limits,
    requires,
    never,
    with: services,
    validFrom: formatTime(from),
    validUntil: formatTime(until),
    purpose: 'Test the gateway.',
  });
  return assembleSlip(prepared, await passkey.sign(prepared.challenge));
}

export const SECRET = 'agent-secret-for-the-tests-0123456789abcdef';
export const OTHER_SECRET = 'second-agent-secret-for-the-tests-0123456789';
export const ADMIN_SECRET = 'administrator-secret-for-the-tests-0123456789';
export const TOKEN = 'upstream-token-held-by-the-gateway-only';

export const RULES = (u) => [
  { upstream: 'tickets', method: 'GET', path: '/api/now/table/:table', action: 'provared.data.read' },
  { upstream: 'tickets', method: 'PATCH', path: '/api/now/table/change_request/:id', action: 'ticket.update' },
  { upstream: 'tickets', method: 'DELETE', path: '/api/now/table/:table/:id', action: 'provared.data.delete' },
  { upstream: 'patch', method: 'POST', path: '/v1/waves', action: 'patch.apply', amount: { unit: 'hosts', count: '/hosts' } },
  { upstream: 'patch', method: 'POST', path: '/v1/hosts/:id/reboot', action: 'host.reboot', amount: { unit: 'hosts', value: 1 } },
  { upstream: 'patch', method: 'POST', path: '/v1/budget', action: 'patch.apply', amount: { unit: 'hosts', pointer: '/plan/hosts' } },
  ...(u ?? []),
];

/**
 * A gateway on two made-up upstreams ("tickets" and "patch"), with one agent
 * ("patching") or more, listening on 127.0.0.1.
 * @param {object} [o]
 */
export async function world(o = {}) {
  const folder = tempFolder();
  const passkey = await developmentPasskey();
  const tickets = await upstream(o.ticketsAnswer);
  const patch = await upstream(o.patchAnswer);
  const agentSet = await generateKeySet();
  const slip = await signSlip({ passkey, agentKeys: agentSet.keys, ...(o.slip ?? {}) });
  const slipPath = join(folder, 'slip.json');
  writeFileSync(slipPath, JSON.stringify(slip));
  const tokenFile = join(folder, 'patch-token');
  writeFileSync(tokenFile, `${TOKEN}-patch\r\n`);
  const envName = `PROVARED_GW_TEST_TOKEN_${Math.random().toString(36).slice(2)}`;
  process.env[envName] = TOKEN;
  const sealSet = await generateSealKeySet();
  const issuerKeys = [await thumbprint(passkey.key)];
  const agentSigners = [signerFromKey('Ed25519', agentSet.privateKeys[0], agentSet.keys[0]), signerFromKey('ML-DSA-87', agentSet.privateKeys[1], agentSet.keys[1])];
  const config = {
    listen: { host: '127.0.0.1', port: 0 },
    admin: { secretHash: await secretHash(ADMIN_SECRET) },
    recorder: { name: 'The test gateway', keySet: sealSet.keys, privateKeys: sealSet.privateKeys },
    upstreams: {
      tickets: { base: tickets.base, service: 'tickets', credential: { header: 'Authorization', env: envName, prefix: 'Bearer ' }, eventIdHeader: 'X-Request-Id', ...(o.tickets ?? {}) },
      patch: { base: `${patch.base}/svc`, service: 'patch', credential: { header: 'X-Api-Key', file: tokenFile }, requestIdHeader: 'X-Gateway-Call', ...(o.patch ?? {}) },
    },
    rules: o.rules ?? RULES(),
    ...(o.unlisted ? { unlisted: o.unlisted } : {}),
    ...(o.bodyLimit !== undefined ? { bodyLimit: o.bodyLimit } : {}),
    agents: {
      patching: { secretHash: await secretHash(SECRET), slip: slipPath, book: join(folder, 'books', 'patching.jsonl'), privateKeys: o.agentKeys ?? agentSigners, issuerKeys },
      ...(o.agents ?? {}),
    },
    ...(o.config ?? {}),
  };
  const logs = [];
  const gateway = await openGateway(config, { root: folder, log: (e) => logs.push(e), ...(o.more ?? {}) });
  const at = await gateway.listen({ host: '127.0.0.1', port: 0 });
  return {
    folder,
    passkey,
    tickets,
    patch,
    agentSet,
    sealSet,
    slip,
    issuerKeys,
    config,
    logs,
    gateway,
    port: at.port,
    bookPath: join(folder, 'books', 'patching.jsonl'),
    call: (method, path, more = {}) => call(at.port, method, path, { secret: SECRET, ...more }),
    async close() {
      await gateway.close();
      await tickets.close();
      await patch.close();
    },
  };
}
