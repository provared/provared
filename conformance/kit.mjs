// The conformance kit: hands each case of the shared test files to an
// implementation under test, through a program of its own (its adapter),
// and compares each answer with the answer stored in the file.
//
// The adapter is started once and kept running. The kit writes one case to
// its standard input as one line of JSON, and reads one line of JSON back
// from its standard output (JSON Lines). conformance/README.md describes
// the lines. Only Node.js's own modules are used.

import { spawn } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** The lists whose texts are this library's own sentences (test-vectors/README.md). */
const SENTENCE_LISTS = new Set(['notes', 'limits']);

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const show = (v) => {
  const text = JSON.stringify(v);
  return text === undefined ? 'nothing' : text.length > 120 ? `${text.slice(0, 117)}...` : text;
};
const step = (path, key) => (typeof key === 'number' ? `${path}[${key}]` : path ? `${path}.${key}` : key);

/**
 * The first place where an answer differs from the stored one, or null where
 * they match. With words false, the text of each member named "message"
 * need only be a text, and in a list named "notes" or "limits" the texts are
 * neither compared nor counted: only the items that are not texts (a slip's
 * limits, for example) are compared, in order (choice K-6).
 */
export function difference(expected, got, words = false, path = 'answer', key = null) {
  if (!words && key === 'message' && typeof expected === 'string') {
    return typeof got === 'string' ? null : `${path}: expected a text, got ${show(got)}`;
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(got)) return `${path}: expected a list, got ${show(got)}`;
    if (!words && SENTENCE_LISTS.has(key)) {
      // Sentences for people: any number of them, in any words. The items
      // that are not texts are compared as in any other list.
      const kept = (list) => list.map((item, at) => ({ item, at })).filter((x) => typeof x.item !== 'string');
      const want = kept(expected);
      const have = kept(got);
      if (have.length !== want.length) {
        return `${path}: expected ${want.length} item(s) that are not texts, got ${have.length}`;
      }
      for (let i = 0; i < want.length; i++) {
        const d = difference(want[i].item, have[i].item, words, step(path, have[i].at), null);
        if (d) return d;
      }
      return null;
    }
    if (got.length !== expected.length) return `${path}: expected a list of ${expected.length}, got a list of ${got.length}`;
    for (let i = 0; i < expected.length; i++) {
      const d = difference(expected[i], got[i], words, step(path, i), null);
      if (d) return d;
    }
    return null;
  }
  if (isObject(expected)) {
    if (!isObject(got)) return `${path}: expected an object, got ${show(got)}`;
    for (const name of Object.keys(expected)) {
      if (!Object.hasOwn(got, name)) return `${step(path, name)}: missing`;
    }
    for (const name of Object.keys(got)) {
      if (!Object.hasOwn(expected, name)) return `${step(path, name)}: not expected, got ${show(got[name])}`;
    }
    for (const name of Object.keys(expected)) {
      const d = difference(expected[name], got[name], words, step(path, name), name);
      if (d) return d;
    }
    return null;
  }
  return expected === got ? null : `${path}: expected ${show(expected)}, got ${show(got)}`;
}

/** The shared test files in a folder, in name order: [{file, about, function, cases}]. */
export function readSets(folder, only = []) {
  const names = readdirSync(folder).filter((f) => f.endsWith('.json')).sort();
  for (const want of only) {
    if (!names.includes(want)) throw new Error(`there is no file ${want} in ${folder}`);
  }
  return names
    .filter((f) => only.length === 0 || only.includes(f))
    .map((file) => {
      const set = JSON.parse(readFileSync(join(folder, file), 'utf8'));
      if (typeof set.function !== 'string' || !Array.isArray(set.cases)) throw new Error(`${file} is not a set of cases`);
      return { file, about: set.about, function: set.function, cases: set.cases };
    });
}

/**
 * JSON with every character outside ASCII written as an escape, so that a
 * line holds no character that some readers take as the end of a line
 * (U+2028 and U+2029 among them), whatever the case holds.
 */
export function asciiJson(value) {
  return JSON.stringify(value).replace(/[\u007f-￿]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** One running adapter: ask() sends a request and waits for its line. */
class Adapter {
  constructor(command, args, cwd) {
    this.exited = false;
    this.stderr = [];
    this.lines = [];
    this.waiting = null;
    this.child = spawn(command, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    this.child.on('error', (e) => this.end(`could not be started: ${e.message}`));
    this.child.on('exit', (code, signal) => this.end(`stopped (${signal ? `signal ${signal}` : `exit code ${code}`})`));
    this.child.stdin.on('error', () => {});
    let rest = '';
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => {
      rest += chunk;
      let at;
      while ((at = rest.indexOf('\n')) >= 0) {
        const line = rest.slice(0, at).replace(/\r$/, '');
        rest = rest.slice(at + 1);
        if (line.trim() !== '') this.deliver({ line });
      }
    });
    let errRest = '';
    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', (chunk) => {
      errRest += chunk;
      const parts = errRest.split('\n');
      errRest = parts.pop();
      for (const p of parts) this.keep(p);
      if (errRest.length > 2000) {
        this.keep(errRest);
        errRest = '';
      }
    });
    this.child.stderr.on('end', () => errRest && this.keep(errRest));
  }

  keep(line) {
    this.stderr.push(line.replace(/\r$/, ''));
    if (this.stderr.length > 20) this.stderr.shift();
  }

  deliver(item) {
    if (this.waiting) {
      const w = this.waiting;
      this.waiting = null;
      w(item);
    } else this.lines.push(item);
  }

  end(why) {
    if (this.exited) return;
    this.exited = why;
    // Give the last output a moment to arrive before saying it stopped.
    setTimeout(() => this.deliver({ stopped: why }), 50);
  }

  ask(request, timeout) {
    if (this.exited) return Promise.resolve({ stopped: this.exited });
    this.child.stdin.write(`${asciiJson(request)}\n`);
    if (this.lines.length) return Promise.resolve(this.lines.shift());
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.waiting = null;
        resolve({ timeout: true });
      }, timeout);
      this.waiting = (item) => {
        clearTimeout(timer);
        resolve(item);
      };
    });
  }

  stop() {
    if (!this.exited) {
      this.exited = 'stopped by the kit';
      this.child.stdin.end();
      this.child.kill();
    }
  }
}

/** What the adapter's line says: {answer}, {skip}, or {problem} where the line is not one of those. */
function readReply(item, id, timeout) {
  if (item.timeout) return { problem: `no answer within ${timeout / 1000} seconds`, restart: true };
  if (item.stopped) return { problem: `the adapter ${item.stopped}`, restart: true };
  let reply;
  try {
    reply = JSON.parse(item.line);
  } catch {
    return { problem: `the adapter printed a line that is not JSON: ${show(item.line)}`, restart: true };
  }
  if (!isObject(reply)) return { problem: `the adapter's line is not a JSON object: ${show(reply)}`, restart: true };
  if (reply.id !== id) return { problem: `the adapter answered request ${show(reply.id)}, not request ${id}`, restart: true };
  if (Object.hasOwn(reply, 'skip')) return { skip: typeof reply.skip === 'string' ? reply.skip : 'set aside by the adapter' };
  if (!Object.hasOwn(reply, 'answer')) return { problem: 'the adapter\'s line holds neither "answer" nor "skip"' };
  return { answer: reply.answer };
}

/**
 * Runs every case of the sets through the adapter. Returns a report:
 * {files: [{file, function, passed, failed, skipped, notRun}], failures:
 * [{file, name, why}], totals, ok}. ok is true only where at least one case
 * was compared and every case compared matched.
 */
export async function runKit({ command, args = [], cwd, sets, words = false, timeout = 60000, maxRestarts = 3, onCase }) {
  const files = [];
  const failures = [];
  let adapter = null;
  let restartsInARow = 0;
  let gaveUp = null;
  let id = 0;
  for (const set of sets) {
    const tally = { file: set.file, function: set.function, passed: 0, failed: 0, skipped: 0, notRun: 0 };
    files.push(tally);
    for (const c of set.cases) {
      if (gaveUp) {
        tally.notRun++;
        continue;
      }
      if (!adapter) adapter = new Adapter(command, args, cwd);
      id++;
      const { expected, ...given } = c;
      const reply = readReply(await adapter.ask({ id, file: set.file, function: set.function, case: given }, timeout), id, timeout);
      let why = null;
      if (reply.skip !== undefined) tally.skipped++;
      else if (reply.problem) why = reply.problem;
      else why = difference(expected, reply.answer, words);
      if (reply.skip === undefined) {
        if (why) {
          tally.failed++;
          const failure = { file: set.file, name: c.name, why };
          if (reply.restart && adapter.stderr.length) failure.stderr = adapter.stderr.slice(-5);
          failures.push(failure);
        } else tally.passed++;
      }
      if (onCase) onCase(set.file, c.name, why);
      if (reply.restart) {
        adapter.stop();
        adapter = null;
        restartsInARow++;
        if (restartsInARow > maxRestarts) gaveUp = `the adapter failed ${restartsInARow} times in a row; the kit stopped asking it`;
      } else restartsInARow = 0;
    }
  }
  if (adapter) adapter.stop();
  const totals = { passed: 0, failed: 0, skipped: 0, notRun: 0 };
  for (const f of files) for (const k of Object.keys(totals)) totals[k] += f[k];
  const ok = totals.failed === 0 && totals.notRun === 0 && totals.passed > 0;
  return { words, files, failures, totals, gaveUp, ok };
}

/** The report in plain words, as lines of text. */
export function describe(report, { showFailures = 20 } = {}) {
  const out = [];
  out.push(`Compared: ${report.words ? 'every value, words included' : 'codes and the shape of each answer (not the words meant for people)'}`);
  out.push('');
  const width = Math.max(4, ...report.files.map((f) => f.file.length));
  out.push(`${'File'.padEnd(width)}  passed  failed  skipped  not run`);
  for (const f of report.files) {
    out.push(`${f.file.padEnd(width)}  ${String(f.passed).padStart(6)}  ${String(f.failed).padStart(6)}  ${String(f.skipped).padStart(7)}  ${String(f.notRun).padStart(7)}`);
  }
  out.push('');
  if (report.failures.length) {
    const shown = showFailures === Infinity ? report.failures : report.failures.slice(0, showFailures);
    out.push(`Failures${shown.length < report.failures.length ? ` (the first ${shown.length} of ${report.failures.length}; --show-all for every one)` : ''}:`);
    for (const f of shown) {
      out.push(`- ${f.file}: ${f.name}`);
      out.push(`    ${f.why}`);
      for (const line of f.stderr ?? []) out.push(`    adapter said: ${line}`);
    }
    out.push('');
  }
  if (report.gaveUp) out.push(`Stopped early: ${report.gaveUp}.`);
  const t = report.totals;
  out.push(`Files: ${report.files.length}. Cases: ${t.passed + t.failed + t.skipped + t.notRun}. Passed: ${t.passed}. Failed: ${t.failed}. Skipped: ${t.skipped}. Not run: ${t.notRun}.`);
  if (report.ok) out.push('Every case compared matched. This shows agreement on these cases only; it is not a certificate.');
  else if (t.passed + t.failed === 0) out.push('No case was compared.');
  else out.push('Not every case matched.');
  return out;
}
