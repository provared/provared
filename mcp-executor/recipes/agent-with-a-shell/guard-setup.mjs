// guard-setup.mjs: runs in the guard container (pv3-guard). Makes keys, a slip, settings, the upstream token file and one agent secret. Prints no secret.
// The slip is signed with the library's DEVELOPMENT STAND-IN for a passkey (provared/dev). A real slip is signed by a person with a real passkey.
import { mkdirSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { assembleSlip, formatTime, prepareSlip, thumbprint } from 'provared';
import { developmentPasskey } from 'provared/dev';
const P = '/data/node_modules/provared-mcp-executor';
const { makeKeyFile } = await import(`${P}/files.mjs`);
const { newSecret, secretHash } = await import(`${P}/http.mjs`);

const D = '/data/guard';
for (const d of ['keys', 'slips', 'books', 'copies', 'secrets', 'out']) mkdirSync(`${D}/${d}`, { recursive: true });
const executorKeys = await makeKeyFile(`${D}/keys/executor.jwk`, 'agent');
const agentKeys = await makeKeyFile(`${D}/keys/alpha.jwk`, 'agent');
const passkey = await developmentPasskey();
const prepared = await prepareSlip({
  issuer: { name: 'Sam (development)', key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
  agent: { name: 'An agent, through the MCP executor', keys: agentKeys },
  actions: ['allowed.act'], limits: [], requires: [{ need: 'countersignature' }], never: [],
  with: [{ id: 'executor', name: 'The Provared MCP executor', keys: executorKeys }],
  validFrom: formatTime(Date.now() - 60000), validUntil: formatTime(Date.now() + 3600000),
  purpose: 'Recipe: an agent with a shell.',
});
const slip = await assembleSlip(prepared, await passkey.sign(prepared.challenge));
writeFileSync(`${D}/slips/alpha.json`, JSON.stringify(slip));
const token = 'UPSTREAM-TOKEN-' + randomBytes(24).toString('hex');
writeFileSync(`${D}/secrets/upstream`, token + '\n');
writeFileSync('/data/out-token', token + '\n'); // copied to the tool server's own folder by the runner, then removed
const secret = newSecret();
writeFileSync('/data/out-agent-secret', secret);
const settings = {
  name: 'Recipe guard', service: 'executor',
  listen: { host: '127.0.0.1', port: 8796 },
  upstream: { url: 'http://pv3-tools-server:9000/mcp', credential: { file: 'secrets/upstream' } },
  agents: { alpha: { secretHash: secretHash(secret), slip: 'slips/alpha.json', book: 'books/alpha.jsonl', keys: 'keys/alpha.jwk', issuerKeys: [await thumbprint(passkey.key)], copy: 'copies/alpha.jsonl', copyKey: 'copies/alpha.jsonl.key' } },
  executor: { keys: 'keys/executor.jwk' },
  tools: { allowed_tool: { action: 'allowed.act' }, other_tool: { action: 'other.act' } },
  timeout: 20000,
};
writeFileSync(`${D}/executor-http.json`, JSON.stringify(settings, null, 1));
console.log('setup done. NOTE: the slip was signed with the development stand-in for a passkey; a real slip is signed by a person with a passkey.');
