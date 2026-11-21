// A time-stamp service on this computer, for tests: an HTTP server on
// 127.0.0.1 that hands each request to the OpenSSL program ("openssl ts
// -reply"), which answers it as RFC 3161 sets out, signed with a key and a
// certificate made for the test. It can also be told to answer wrongly.
// Nothing here reaches beyond this computer.
//
// The OpenSSL program is looked for as PROVARED_OPENSSL names it, or as
// "openssl" on the PATH. Where there is none, findOpenssl gives null, and a
// test that needs it says so and is skipped.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { tempFolder } from './temp.mjs';

let found;
/** The OpenSSL program, or null where there is none that makes time-stamps. */
export function findOpenssl() {
  if (found !== undefined) return found;
  const program = process.env.PROVARED_OPENSSL || 'openssl';
  const r = spawnSync(program, ['ts', '-help'], { encoding: 'utf8' });
  found = r.error ? null : program;
  return found;
}

/** Why a test is skipped where there is no OpenSSL program. */
export const NO_OPENSSL = 'the OpenSSL program is not on this computer (or set PROVARED_OPENSSL to it), so no local time-stamp service can be run';

const CONFIG = `
[ req ]
distinguished_name = dn
prompt = no
x509_extensions = ext
[ dn ]
CN = Test time-stamp service on this computer
[ ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
[ tsa ]
default_tsa = good
[ good ]
serial = serial
signer_cert = cert.pem
signer_key = key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
[ refuse ]
serial = serial
signer_cert = cert.pem
signer_key = key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha384
`;

function run(program, args, cwd) {
  const r = spawnSync(program, args, { cwd, encoding: 'utf8' });
  if (r.error || r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${r.error?.message ?? r.stderr}`);
  return r;
}

// The 32 bytes a request asks to be stamped: those after the SHA-256 method and the tag and length of 32 bytes.
function imprintOf(query) {
  const at = Buffer.from(query).indexOf(Buffer.from('0609608648016503040201', 'hex'));
  const start = Buffer.from(query).indexOf(Buffer.from('0420', 'hex'), at) + 2;
  return Buffer.from(query).subarray(start, start + 32);
}

/**
 * Start the service. "mode" says how the next requests are answered:
 * "good"; "refuse" (the service takes no SHA-256, so it refuses);
 * "wrong-nonce" (a time-stamp for the same fingerprint, with another number
 * used once); "no-nonce" (with none); "wrong-imprint" (for another
 * fingerprint); "big" (a body larger than is read, with its length given);
 * "big-unsized" (the same, its length not given); "redirect" (to another
 * address that would answer well); "slow" (a good answer after "delay"
 * milliseconds); "status-500"; "garbage" (bytes that are not an answer);
 * "trailing" (a good answer with two bytes after it); "status-1" (a good
 * answer whose status is 1, "granted with changes"); "big-token" (an answer
 * within the size read whose time-stamp is larger than the format allows);
 * "drip" (a good answer's first bytes, then the rest after "delay"
 * milliseconds); "gzip" (a good answer, compressed); "gzip-bomb" (a small
 * compressed body that opens to 100,000 bytes); "answer" (the bytes of
 * "answer", as they are).
 * @returns {Promise<{address: string, authority: string, requests: number, queries: Buffer[], reachedElsewhere: number, mode: string, delay: number, answer: Uint8Array|null, close: () => Promise<void>}>}
 */
export async function startTestTsa() {
  const program = findOpenssl();
  if (!program) throw new Error(NO_OPENSSL);
  const folder = tempFolder('provared-tsa-');
  writeFileSync(join(folder, 'ts.cnf'), CONFIG);
  writeFileSync(join(folder, 'serial'), '01\n');
  run(program, ['req', '-x509', '-config', 'ts.cnf', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '3', '-sha256'], folder);
  // The fingerprint a checker is told in order to trust this service: the SHA-256 of its certificate, in base64url.
  const pem = readFileSync(join(folder, 'cert.pem'), 'utf8');
  const certificate = Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ''), 'base64');
  const authority = createHash('sha256').update(certificate).digest('base64url');
  let count = 0;
  const reply =(query, section = 'good') => {
    const n = ++count;
    writeFileSync(join(folder, `q${n}.der`), query);
    run(program, ['ts', '-reply', '-config', 'ts.cnf', '-section', section, '-queryfile', `q${n}.der`, '-out', `r${n}.der`], folder);
    return readFileSync(join(folder, `r${n}.der`));
  };
  const queryFor = (digest, nonce) => {
    const n = ++count;
    run(program, ['ts', '-query', '-config', 'ts.cnf', '-sha256', '-digest', Buffer.from(digest).toString('hex'), '-cert', ...(nonce ? [] : ['-no_nonce']), '-out', `m${n}.der`], folder);
    return readFileSync(join(folder, `m${n}.der`));
  };

  const state = { address: '', authority, requests: 0, queries: [], reachedElsewhere: 0, mode: 'good', delay: 0, answer: null, close: null };
  const elsewhere = http.createServer((q, a) => {
    state.reachedElsewhere += 1;
    q.resume();
    a.writeHead(500).end();
  });
  await new Promise((done) => elsewhere.listen(0, '127.0.0.1', done));

  const server = http.createServer((q, a) => {
    const pieces = [];
    q.on('data', (p) => pieces.push(p));
    q.on('end', () => {
      state.requests += 1;
      const query = Buffer.concat(pieces);
      state.queries.push(query);
      const send = (bytes) => a.writeHead(200, { 'content-type': 'application/timestamp-reply', 'content-length': bytes.length }).end(bytes);
      try {
        switch (state.mode) {
          case 'good':
            return send(reply(query));
          case 'refuse':
            return send(reply(query, 'refuse'));
          case 'wrong-nonce':
            return send(reply(queryFor(imprintOf(query), true)));
          case 'no-nonce':
            return send(reply(queryFor(imprintOf(query), false)));
          case 'wrong-imprint':
            return send(reply(queryFor(Buffer.alloc(32, 7), true)));
          case 'big':
            return send(Buffer.alloc(20000, 0x30));
          case 'big-unsized':
            a.writeHead(200, { 'content-type': 'application/timestamp-reply' });
            for (let i = 0; i < 20; i++) a.write(Buffer.alloc(1000, 0x30));
            return a.end();
          case 'redirect':
            return a.writeHead(302, { location: `http://127.0.0.1:${elsewhere.address().port}/` }).end();
          case 'slow': {
            const bytes = reply(query);
            const timer = setTimeout(() => send(bytes), state.delay);
            a.on('close', () => clearTimeout(timer));
            return undefined;
          }
          case 'status-500':
            return a.writeHead(500).end();
          case 'garbage':
            return send(Buffer.from('not an answer'));
          case 'trailing':
            return send(Buffer.concat([reply(query), Buffer.from([0, 0])]));
          case 'status-1': {
            // The status is the first thing in the answer: SEQUENCE { INTEGER 0 }, after the answer's own tag and length.
            const bytes = Buffer.from(reply(query));
            const at = bytes.indexOf(Buffer.from('3003020100', 'hex'));
            if (at < 0 || at > 4) throw new Error('the status was not where it was looked for');
            bytes[at + 4] = 1;
            return send(bytes);
          }
          case 'big-token': {
            // SEQUENCE { SEQUENCE { INTEGER 0 }, SEQUENCE of 12,298 bytes }: a time-stamp of 12,302 bytes, in an answer of 12,311.
            const token = Buffer.concat([Buffer.from('3082300a', 'hex'), Buffer.alloc(0x300a)]);
            const inner = Buffer.concat([Buffer.from('3003020100', 'hex'), token]);
            const length = Buffer.alloc(2);
            length.writeUInt16BE(inner.length);
            return send(Buffer.concat([Buffer.from('3082', 'hex'), length, inner]));
          }
          case 'drip': {
            const bytes = reply(query);
            a.writeHead(200, { 'content-type': 'application/timestamp-reply', 'content-length': bytes.length });
            a.write(bytes.subarray(0, 10));
            const timer = setTimeout(() => a.end(bytes.subarray(10)), state.delay);
            a.on('close', () => clearTimeout(timer));
            return undefined;
          }
          case 'gzip':
          case 'gzip-bomb': {
            const bytes = gzipSync(state.mode === 'gzip' ? reply(query) : Buffer.alloc(100000));
            return a.writeHead(200, { 'content-type': 'application/timestamp-reply', 'content-encoding': 'gzip', 'content-length': bytes.length }).end(bytes);
          }
          case 'answer':
            return send(Buffer.from(state.answer));
          default:
            return a.writeHead(500).end();
        }
      } catch (e) {
        return a.writeHead(500).end(String(e.message));
      }
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  state.address = `http://127.0.0.1:${server.address().port}/tsa`;
  state.close = async () => {
    server.closeAllConnections();
    elsewhere.closeAllConnections();
    await new Promise((done) => server.close(done));
    await new Promise((done) => elsewhere.close(done));
  };
  return state;
}
