// Every test file loads on a clean checkout, where nothing is installed (the
// repository's workflow installs nothing): the name "provared" must come
// from local-library.mjs, which a file imports first. Each file is loaded
// in a program of its own, with "provared" kept out of node_modules
// (no-installed-library.mjs) and every test skipped, so only the loading
// is tried.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BLOCKER = pathToFileURL(join(HERE, 'no-installed-library.mjs')).href;

/** Load one test file with every test skipped: {file, status, output}. */
function load(file) {
  return new Promise((done) => {
    // NODE_OPTIONS is left out: this program's own (set by local-library.mjs, where a file imports it) would load the library before the file does. So is NODE_TEST_CONTEXT, which the test runner gives this program: with it, the child would report to this run rather than run as a run of its own.
    const env = { ...process.env };
    delete env.NODE_OPTIONS;
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', `--import=${BLOCKER}`, '--test', '--test-skip-pattern=.', '--test-force-exit', join(HERE, file)], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (c) => (output += c));
    child.stderr.on('data', (c) => (output += c));
    const timer = setTimeout(() => child.kill(), 60000);
    child.on('close', (status) => {
      clearTimeout(timer);
      done({ file, status, output });
    });
  });
}

test('test files: each loads with nothing installed, the name "provared" coming from this repository', async () => {
  const files = readdirSync(HERE).filter((f) => f.endsWith('.test.mjs') && f !== 'test-files.test.mjs');
  assert.ok(files.length > 10);
  const failed = [];
  for (let i = 0; i < files.length; i += 8) {
    for (const r of await Promise.all(files.slice(i, i + 8).map(load))) {
      if (r.status !== 0) failed.push(`${r.file}: ${(r.output.match(/Error[^\n]*/) ?? [r.output.slice(0, 200)])[0]}`);
    }
  }
  assert.deepEqual(failed, []);
});
