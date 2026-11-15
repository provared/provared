// For the tests of a book sealed by a central sealer: a real sealer (the
// program in sealer/, in this process or as a process of its own, on
// 127.0.0.1), a world whose settings name it, and a stand-in that holds
// the recorder's token and answers as a test tells it to.

import './local-library.mjs'; // first: "provared" is this repository's own library
import { spawn, spawnSync } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const { checkBook, fromBase64url, keySetFingerprint, leafFingerprint, toBase64url } = await import('provared');
const { world, openWorld, tempFolder, until } = await import('./world.mjs');
const { addRecorder, makeKeys, startSealer } = await import('../../sealer/sealer.mjs');
const { connectSealer, sealerHmac } = await import('../sealer-client.mjs');

export const SEALER_BIN = fileURLToPath(new URL('../../sealer/bin.mjs', import.meta.url));
/** The name the sealer knows the tests' recorder by. */
export const RECORDER = 'guard-one';
/** The label of the proof on a sealer's answer (sealer/README.md, "What a recorder asks"). */
const ANSWER_LABEL = 'provared sealer v1: the sealer\'s answer';

/** The worlds and stand-ins made in this process, for closeAll. */
const opened = { worlds: [], standIns: [] };

/**
 * After each test: whatever a test left open, because it failed before it
 * closed it, is closed (the executor, the stand-ins, the sealer), so that a
 * failure is reported and the test file still ends.
 */
export async function closeAll() {
  const worlds = opened.worlds.splice(0);
  const standIns = opened.standIns.splice(0);
  for (const w of worlds) {
    if (w.client && !w.client.toExecutor.writableEnded) {
      w.client.end();
      let timer;
      await Promise.race([w.ended, new Promise((done) => (timer = setTimeout(done, 10000)))]).finally(() => clearTimeout(timer));
    }
  }
  for (const s of standIns) await s.close();
  for (const w of worlds) await w.sealer?.stop();
}

/** A port on 127.0.0.1 that was free a moment ago. */
export function freePort() {
  return new Promise((done, failed) => {
    const s = net.createServer();
    s.once('error', failed);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => done(port));
    });
  });
}

/** A sealer's folder: its settings, its keys, and one recorder named for these agents' key sets. Gives {folder, token, port}. */
export async function sealerFolder(agents, { name = RECORDER } = {}) {
  const folder = tempFolder();
  const port = await freePort();
  writeFileSync(join(folder, 'sealer.json'), JSON.stringify({ name: 'The test central sealer (invented)', port }));
  await makeKeys(folder);
  const token = await addRecorder(folder, name, { agents: await Promise.all(agents.map((keys) => keySetFingerprint(keys))) });
  return { folder, token, port };
}

/**
 * A world (world.mjs) whose settings name a central sealer, which runs in
 * this process. "sealer": more settings for recorder.sealer; "recorder":
 * more for recorder. The sealer can be stopped (w.sealer.stop) and started
 * again on the same port and folder (w.sealer.start).
 */
export async function centralWorld({ sealer = {}, recorder = {}, open = true, more = {}, ...o } = {}) {
  const w = await world({ ...o, open: false });
  // Until an executor is open there is nothing to close: so a test whose start fails reports that, and not "w.close is not a function".
  w.close = async () => {};
  opened.worlds.push(w);
  const s = await sealerFolder([w.agentKeys]);
  w.sealer = {
    ...s,
    running: null,
    async start(how = {}) {
      this.running = await startSealer({ folder: s.folder, port: s.port, ...how });
      this.keySet = this.running.fingerprint;
      return this.running;
    },
    async stop() {
      await this.running?.close();
      this.running = null;
    },
  };
  await w.sealer.start();
  w.sealKeys = [w.sealer.keySet];
  mkdirSync(join(w.folder, 'keys'), { recursive: true });
  writeFileSync(join(w.folder, 'keys', 'sealer-token'), `${s.token}\n`);
  // The sealer and the executor share this process's one thread, and each holds it while a line goes to the disk (fsync):
  // on a slow disk 100 to 400 ms a time, and a question can wait for several. So a question may take 2 seconds here; a test
  // that sets less fails on such a disk for no fault of the program.
  w.settings.recorder = { sealer: { address: `http://127.0.0.1:${s.port}`, name: RECORDER, token: { file: 'keys/sealer-token' }, keySet: w.sealer.keySet, timeout: 2000, ...sealer }, ...recorder };
  writeFileSync(w.configPath, JSON.stringify(w.settings));
  /** The sealer asked directly, as the recorder: what it holds of this world's book. */
  w.ask = () => connectSealer({ address: `http://127.0.0.1:${s.port}`, recorder: RECORDER, token: s.token });
  w.bookText = () => readFileSync(join(w.folder, 'book.jsonl'), 'utf8');
  w.lines = () => w.bookText().split('\n').filter(Boolean);
  w.first = async () => toBase64url(await leafFingerprint(w.lines()[0]));
  w.held = async () => w.ask().held(await w.first());
  w.checked = (more = {}) => checkBook(w.bookText(), { issuerKeys: w.settings.agent.issuerKeys, sealKeys: w.sealKeys, ...more });
  /** Wait until the sealer holds every line of the book file. */
  w.level = () => until(async () => (await w.held())?.size === w.lines().length);
  if (open) await openWorld(w, more);
  return w;
}

/** The text of a tool result the executor refused, and its code, or null where the call was taken. */
export function refusal(answer) {
  const code = answer.result?._meta?.['red.prova/refused'];
  return code ? { code, text: answer.result.content[0].text, denial: answer.result._meta['red.prova/denial'] ?? null } : null;
}

/**
 * A stand-in for the sealer that holds the recorder's token, so that its
 * answers prove themselves as the sealer's do, and answers each question
 * as "answer" says: (path, body, forward) gives the answer's body (an
 * object, with status 200), {status, body}, or null to close the
 * connection with no answer. "forward()" asks the real sealer the same
 * question and gives its answer's body, where "real" names its address.
 */
export async function standIn({ token, real = null, answer }) {
  const key = Buffer.from(token, 'base64url');
  const client = real ? connectSealer({ address: real, recorder: RECORDER, token }) : null;
  const leaves = (body) => body.leaves.map((l) => fromBase64url(l));
  const forward = async (path, body) => {
    if (path === '/about') return client.about();
    if (path === '/held') return { held: await client.held(body.book) };
    if (path === '/latest') return { latest: await client.latest(body.book) };
    if (path === '/extend') return client.extend(body.book, body.at, leaves(body), Object.hasOwn(body, 'line') ? { line: body.line } : {});
    if (path === '/seal') return client.seal(body.book, { previous: body.previous, ...(Object.hasOwn(body, 'when') ? { when: body.when } : {}) });
    throw new Error(`The stand-in forwards no question to ${path}.`);
  };
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      seen.push({ path: req.url, body });
      let got;
      try {
        got = await answer(req.url, body, () => forward(req.url, body));
      } catch (e) {
        got = { status: 500, body: { refused: { code: 'check-failed', message: e.message } } };
      }
      if (got === null) return req.socket.destroy();
      const whole = Object.keys(got).length === 2 && Object.hasOwn(got, 'status') && Object.hasOwn(got, 'body');
      const status = whole ? got.status : 200;
      const bytes = Buffer.from(JSON.stringify(whole ? got.body : got));
      const proof = sealerHmac(key, ANSWER_LABEL, req.headers['provared-sealer-proof'], String(status), nodeCrypto.createHash('sha256').update(bytes).digest('base64url')).toString('base64url');
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': bytes.length, 'provared-sealer-proof': proof });
      res.end(bytes);
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const made = {
    address: `http://127.0.0.1:${server.address().port}`,
    seen,
    async close() {
      server.closeAllConnections?.();
      await new Promise((done) => server.close(() => done()));
    },
  };
  opened.standIns.push(made);
  return made;
}

/** Run the sealer's command to its end: {code, stdout, stderr}. */
export function sealerCommand(args) {
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', SEALER_BIN, ...args], { encoding: 'utf8', windowsHide: true });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Start the sealer's program as a process of its own: {address, keySet, stop()}. */
export async function sealerProcess(folder, port) {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', SEALER_BIN, 'start', '--folder', folder, '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  const ended = new Promise((done) => child.on('exit', done));
  const said = await Promise.race([until(() => /listens at (\S+), with the key set (\S+)\./.exec(out), { timeout: 30000 }), ended.then(() => null)]);
  if (!said) throw new Error(`The sealer did not start: ${err || out}`);
  return {
    address: said[1],
    keySet: said[2],
    async stop() {
      child.kill();
      await ended;
    },
  };
}
