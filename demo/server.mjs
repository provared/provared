// The demonstration's local server. It does two jobs:
//
//   1. serves the pages and the library to a browser on this computer;
//   2. plays the agent, the supplier, the keeper of the book and a made-up
//      time-stamp service of demo/scenario.mjs, with keys made at start-up
//      and kept only in this process's memory.
//
// It listens on this computer only (127.0.0.1), keeps nothing on disk and
// makes no outside request. It is a demonstration, not the recorder service.
//
//   npm run demo            then open http://localhost:8787

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBook, checkSlip, entryLine, fingerprint, fromBase64url, generateKeySet, generateSealKeySet, keySetFingerprint, thumbprint, writeBook } from '../src/index.js';
import { makeStampService } from '../test/helpers/stamp.mjs';
import { STEPS, finishRun, sealBook, slipFields, startRun } from './scenario.mjs';

const PORT = Number(process.env.PORT) || 8787;
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ORIGINS = [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`];
const HOSTS = [`localhost:${PORT}`, `127.0.0.1:${PORT}`];

// Only these folders are served, and only these kinds of file.
const SERVED = ['page', 'src', 'samples'];
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jsonl': 'text/plain; charset=utf-8',
};

const HEADERS = {
  // The pages load only their own files and talk only to this server.
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

// The demonstration's state, in memory only.
const agent = await generateKeySet();
const supplier = await generateKeySet();
const recorder = await generateSealKeySet();
const stampService = await makeStampService();
// What a person checking the demonstration's record is told to trust: the
// demonstration's own keeper of the book and its made-up time-stamp
// service, and, once the slip is signed, the passkey that signed it.
const trust = { sealKeys: [await keySetFingerprint(recorder.keys)], stampServices: [stampService.fingerprint] };
let signedSlip = null;
let run = null;
let book = null;

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { ...HEADERS, 'Content-Type': type });
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), TYPES['.json']);
}

async function readBody(req, limit = 100000) {
  const parts = [];
  let size = 0;
  for await (const part of req) {
    size += part.length;
    if (size > limit) throw new Error('too large');
    parts.push(part);
  }
  return Buffer.concat(parts).toString('utf8');
}

async function serveFile(res, path) {
  // The short addresses lead to the two pages.
  const short = { '/': '/page/demo.html', '/check': '/page/index.html' }[path];
  if (short) {
    res.writeHead(302, { ...HEADERS, Location: short });
    return res.end();
  }
  const relative = normalize(decodeURIComponent(path)).replace(/^[\\/]+/, '');
  const folder = relative.split(sep)[0];
  const type = TYPES[extname(relative)];
  if (!SERVED.includes(folder) || !type || relative.includes('..')) return send(res, 404, 'Not found');
  try {
    send(res, 200, await readFile(join(ROOT, relative)), type);
  } catch {
    send(res, 404, 'Not found');
  }
}

const routes = {
  // What the page needs to show and sign the slip.
  'GET /demo/start': async (req, res) => {
    sendJson(res, 200, {
      fields: slipFields({ agentKeys: agent.keys, serviceKeys: supplier.keys }, Date.now()),
      steps: STEPS.map((s) => ({ what: s.what, value: s.kind === 'order' ? s.value : null })),
      trust,
    });
  },
  // The person hands the signed slip to the agent.
  'POST /demo/slip': async (req, res) => {
    let record;
    try {
      record = JSON.parse(await readBody(req));
    } catch {
      return sendJson(res, 400, { error: 'The slip could not be read.' });
    }
    const check = await checkSlip(record);
    if (check.problems.length) return sendJson(res, 400, { error: check.problems[0].message, code: check.problems[0].code });
    // The agent acts only under a slip that names its own keys.
    if (JSON.stringify(check.content.agent.keys) !== JSON.stringify(agent.keys)) {
      return sendJson(res, 400, { error: 'This slip is for another agent. Reload the page and sign again.' });
    }
    signedSlip = { record, fingerprint: check.fingerprint, from: Date.parse(check.content.validFrom), issuer: await thumbprint(check.content.issuer.key) };
    run = null;
    book = null;
    sendJson(res, 200, { fingerprint: check.fingerprint });
  },
  // The agent starts its work, and stops to ask the person's approval of
  // one order above the amount the slip names.
  'POST /demo/run': async (req, res) => {
    if (!signedSlip) return sendJson(res, 400, { error: 'Sign the slip first.' });
    const started = await startRun({
      slipFingerprint: signedSlip.fingerprint,
      agentPrivateKeys: agent.privateKeys,
      serviceKeys: supplier.keys,
      servicePrivateKeys: supplier.privateKeys,
      start: signedSlip.from + 60 * 1000,
    });
    run = started.run;
    book = null;
    sendJson(res, 200, { ask: started.ask });
  },
  // The person hands over the approval. The agent finishes, and the record
  // is written.
  'POST /demo/approve': async (req, res) => {
    if (!run) return sendJson(res, 400, { error: 'Run the agent first.' });
    let record;
    let name;
    try {
      record = JSON.parse(await readBody(req));
      name = await fingerprint(fromBase64url(record.payload));
    } catch {
      return sendJson(res, 400, { error: 'The approval could not be read.' });
    }
    const entries = await finishRun(run, { record, fingerprint: name });
    run = null;
    const written = writeBook([{ slip: signedSlip.record }, ...entries]);
    // The agent takes only an approval that checks.
    const result = await checkBook(written);
    const fault = result.entries.flatMap((e) => e.problems).find((p) => p.code.startsWith('approval') || p.code === 'bad-envelope');
    if (fault) return sendJson(res, 400, { error: fault.message, code: fault.code });
    // Whoever keeps the book seals it, and the made-up time-stamp service
    // states when.
    const seal = await sealBook(written, { recorder, stampService, when: signedSlip.from + 75 * 60 * 1000 });
    book = written + entryLine(seal) + '\n';
    send(res, 200, book);
  },
  // The same check as the page makes, by this Node.js, which has ML-DSA.
  'GET /demo/check': async (req, res) => {
    if (!book) return sendJson(res, 400, { error: 'Run the agent first.' });
    sendJson(res, 200, await checkBook(book, { ...trust, issuerKeys: [signedSlip.issuer] }));
  },
};

const server = createServer(async (req, res) => {
  try {
    // Refuse a request that reached this server under another name, and a
    // change sent from another site's page.
    if (!HOSTS.includes(req.headers.host)) return send(res, 400, 'Bad request');
    const url = new URL(req.url, ORIGINS[0]);
    const route = routes[`${req.method} ${url.pathname}`];
    if (route) {
      if (req.method === 'POST' && !ORIGINS.includes(req.headers.origin)) return send(res, 403, 'Forbidden');
      return await route(req, res);
    }
    if (req.method !== 'GET') return send(res, 405, 'Method not allowed');
    await serveFile(res, url.pathname);
  } catch {
    if (!res.headersSent) send(res, 500, 'The demonstration server met an error.');
    else res.end();
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Provared demonstration. Evidence, not a verdict.');
  console.log(`  The demonstration:  http://localhost:${PORT}`);
  console.log(`  The checking page:  http://localhost:${PORT}/check`);
  console.log('Press Ctrl and C to stop.');
});
