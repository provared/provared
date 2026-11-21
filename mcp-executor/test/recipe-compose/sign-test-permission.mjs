// For the Docker check of the compose recipe (docker-check.sh, beside this
// file) only: stands in for the person. It signs the permission for the
// agent "connection-1" with the library's development stand-in for a
// passkey, saves it where the settings say, and puts the stand-in's
// thumbprint in the agent's "issuerKeys". The records it leads to prove
// nothing about any person. It is run in the guard's image, from /guard,
// where the library is installed, as the guard's user.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { assembleSlip, formatTime, prepareSlip, thumbprint } from 'provared';
import { DEVELOPMENT_MARK, developmentPasskey } from 'provared/dev';

const data = process.env.PROVARED_DATA ?? '/data';
const agent = 'connection-1';
const entries = JSON.parse(readFileSync(`${data}/permission-entries.json`, 'utf8'))[agent];
const settings = JSON.parse(readFileSync(`${data}/executor-http.json`, 'utf8'));
const passkey = await developmentPasskey();
const now = Date.now();
const prepared = await prepareSlip({
  issuer: { name: `The compose recipe's Docker check ${DEVELOPMENT_MARK}`, key: passkey.key, rpId: passkey.rpId, origin: passkey.origin },
  agent: entries.agent,
  actions: ['demo.echo', 'demo.add'],
  limits: [],
  requires: entries.requires,
  never: [],
  with: [entries.with],
  validFrom: formatTime(now - 60 * 1000),
  validUntil: formatTime(now + 3600 * 1000),
  purpose: 'A test of the compose recipe. Signed by a development stand-in for a passkey, which no person signed: it proves nothing about anyone.',
});
writeFileSync(`${data}/${settings.agents[agent].slip}`, `${JSON.stringify(assembleSlip(prepared, await passkey.sign(prepared.challenge)))}\n`, { mode: 0o600 });
settings.agents[agent].issuerKeys = [await thumbprint(passkey.key)];
writeFileSync(`${data}/executor-http.json.new`, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
renameSync(`${data}/executor-http.json.new`, `${data}/executor-http.json`);
process.stdout.write(`signed the permission for "${agent}" with the development stand-in, and set its issuerKeys\n`);
