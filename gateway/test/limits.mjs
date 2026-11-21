// Limits on the tests' waits, so that no test waits for ever on a gateway
// that never answers, and nothing a test started outlives its test file: a
// gateway opened here, or a gateway program started here, that a failing
// test did not close is closed or stopped when the file's tests end.
//
// Imported with import(), after local-library.mjs.

import { spawn } from 'node:child_process';
import { after } from 'node:test';
import { openGateway as open } from '../gateway.mjs';

/** How long a test waits for a gateway to answer a call: generous, since an answered call signs a receipt, which can take many seconds on a busy computer. */
export const ANSWER_LIMIT = 120000;
/** How long a test waits for a command of the gateway to finish. */
export const RUN_LIMIT = 60000;
/** How long a test waits for a gateway started as a program to listen, or to stop. */
export const START_LIMIT = 30000;
/** How long a gateway may take to close. */
export const CLOSE_LIMIT = 10000;

const left = new Set();
after(async () => {
  for (const stop of [...left]) await stop();
});

/** The promise, or a failure naming what was waited for once the limit has passed. */
export function within(promise, limit, what) {
  let timer;
  const late = new Promise((_, no) => {
    timer = setTimeout(() => no(new Error(`${what}: nothing after ${limit / 1000} seconds`)), limit);
    timer.unref();
  });
  return Promise.race([promise, late]).finally(() => clearTimeout(timer));
}

/** openGateway, the gateway kept so that it is closed when the file's tests end, if a test did not close it. */
export async function openGateway(config, options) {
  const g = await open(config, options);
  const close = g.close.bind(g);
  let closing = null;
  const stop = () => {
    left.delete(stop);
    closing ??= within(close(), CLOSE_LIMIT, 'closing the gateway');
    return closing;
  };
  left.add(stop);
  g.close = stop;
  return g;
}

/** A gateway that must not start: where it does start, it is closed, and the test fails as assert.rejects would. */
export async function refusedStart(promise, matcher, message) {
  const assert = (await import('node:assert/strict')).default;
  await assert.rejects(async () => {
    const g = await promise;
    await g.close();
  }, matcher, message);
}

/** A program of the tests' own, kept so that it is stopped when the file's tests end, if a test did not stop it. */
export function keep(child) {
  const stop = async () => {
    left.delete(stop);
    if (child.exitCode !== null || child.signalCode !== null) return;
    const gone = new Promise((d) => child.once('exit', d));
    child.kill('SIGKILL');
    await within(gone, START_LIMIT, 'stopping a program the test started');
  };
  left.add(stop);
  child.once('exit', () => left.delete(stop));
  return child;
}

/** Run the gateway's command to its end, stopped once RUN_LIMIT has passed: { code, out, err, timedOut }. */
export function runCommand(bin, args, env = {}) {
  return new Promise((done) => {
    const child = keep(spawn(process.execPath, ['--disable-warning=ExperimentalWarning', bin, ...args], { env: { ...process.env, ...env } }));
    let out = '';
    let err = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, RUN_LIMIT);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ code, out, err: timedOut ? `${err}\n(stopped after ${RUN_LIMIT / 1000} seconds)` : err, timedOut });
    });
  });
}

/** Wait until the test's own condition holds, or fail once the limit has passed. */
export async function until(condition, what, limit = ANSWER_LIMIT) {
  const end = Date.now() + limit;
  while (!condition()) {
    if (Date.now() > end) throw new Error(`${what}: not so after ${limit / 1000} seconds`);
    await new Promise((d) => setTimeout(d, 20));
  }
}
