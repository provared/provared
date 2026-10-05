// The rules of this repository, as tests: no outside code, no network, no
// markup written from a record, and a library that runs in a browser as it
// is.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

function files(dir, pattern) {
  const out = [];
  for (const name of readdirSync(join(root, dir))) {
    const path = join(dir, name);
    if (statSync(join(root, path)).isDirectory()) out.push(...files(path, pattern));
    else if (pattern.test(name)) out.push(path);
  }
  return out;
}
const read = (path) => readFileSync(join(root, path), 'utf8');

test('no outside code: the package depends on nothing', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.deepEqual(pkg.dependencies, {});
  for (const kind of ['devDependencies', 'peerDependencies', 'optionalDependencies', 'bundledDependencies']) {
    assert.equal(pkg[kind], undefined, kind);
  }
  assert.equal(pkg.name, 'provared');
  assert.equal(pkg.private, undefined, 'published on npm as provared');
  // The code under the Apache licence; the format description and the other documents under CC BY 4.0.
  assert.equal(pkg.license, 'Apache-2.0 AND CC-BY-4.0');
  assert.equal(pkg.repository.url, 'git+https://github.com/provared/provared.git');
});

test('the library imports only its own files', () => {
  for (const path of files('src', /\.js$/)) {
    for (const [, from] of read(path).matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+'([^']+)'/gm)) {
      assert.match(from, /^\.\/[a-z-]+\.js$/, `${path} imports ${from}`);
    }
    assert.doesNotMatch(read(path), /\brequire\(|\bimport\(/, path);
  }
});

test('the library and the pages make no network request and report nothing', () => {
  for (const path of [...files('src', /\.js$/), ...files('page', /\.(js|html)$/)]) {
    const text = read(path);
    for (const word of ['XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'importScripts']) {
      assert.ok(!text.includes(word), `${path} uses ${word}`);
    }
    // The pages of the demonstration talk to the demonstration's own local
    // server, and the checking page loads the sample. The library never fetches.
    if (path.startsWith('src')) assert.ok(!/\bfetch\(/.test(text), `${path} uses fetch`);
    assert.doesNotMatch(text, /https?:\/\/(?!localhost|sign\.example\.org|www\.w3\.org\/2000\/svg)[a-z]/i, `${path} names an outside address`);
  }
});

test('only the command that fetches block headers makes requests, and only through net/', () => {
  // The library, the pages and the checker never reach the network themselves.
  for (const path of [...files('src', /\.js$/), ...files('page', /\.(js|html)$/), ...files('bin', /\.mjs$/)]) {
    const text = read(path);
    assert.doesNotMatch(text, /'node:(net|http|https|http2|dgram|tls|dns)'/, path);
    if (path !== join('bin', 'provared-headers.mjs')) assert.doesNotMatch(text, /\bfrom\s+'[^']*\bnet\//, path);
  }
  // net/ holds the one file that does, and it reaches only the nodes it is handed.
  assert.deepEqual(files('net', /\.js$/), [join('net', 'headers.js')]);
  assert.doesNotMatch(read(join('net', 'headers.js')), /https?:\/\/|seed/i);
});

test('nothing from a record is ever written as markup', () => {
  for (const path of [...files('src', /\.js$/), ...files('page', /\.(js|html)$/)]) {
    const text = read(path);
    for (const word of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'srcdoc', 'eval(', 'new Function', 'setAttribute(\'on', 'DOMParser']) {
      assert.ok(!text.includes(word), `${path} uses ${word}`);
    }
  }
});

test('only one file of the library touches the page, and it is not part of the checker', () => {
  for (const path of files('src', /\.js$/)) {
    const touches = /\b(document|window|navigator|location)\b\s*[.[]/.test(read(path));
    assert.equal(touches, path.endsWith('passkey-browser.js'), path);
  }
  const checker = read(join('src', 'check.js'));
  assert.ok(!checker.includes('passkey-browser'));
  assert.ok(!checker.includes('stub.js'), 'the checker exports nothing that signs');
});

test('the honest line is on every document and page', () => {
  for (const path of ['README.md', join('spec', 'provared-format.md'), join('docs', 'threat-model.md'), ...files('page', /\.html$/)]) {
    assert.match(read(path), /Evidence, not a verdict/, path);
  }
});

test('the type declarations name exactly what the library exports', async () => {
  const declared = (path) => new Set([...read(path).matchAll(/^export (?:declare )?(?:function|const|class) ([A-Za-z_0-9]+)/gm)].map((m) => m[1]));
  const all = declared(join('src', 'types.d.ts'));
  const library = await import('../src/index.js');
  assert.deepEqual([...all].sort(), Object.keys(library).sort());
  // The checker's own declarations list each of its exports by name.
  const checker = await import('../src/check.js');
  const checkerDeclared = read(join('src', 'check.d.ts'));
  for (const name of Object.keys(checker)) assert.ok(checkerDeclared.split(/[^A-Za-z0-9_]+/).includes(name), name);
  assert.ok(!/writeStub|prepareSlip|generateKeySet/.test(checkerDeclared.split('export type')[0]), 'the checker declares nothing that signs');
  const browser = declared(join('src', 'passkey-browser.d.ts'));
  assert.deepEqual([...browser].sort(), ['PasskeyError', 'approveWithPasskey', 'cancelWithPasskey', 'createPasskey', 'signChallengeWithPasskey', 'signSlipWithPasskey']);
  const pkg = JSON.parse(read('package.json'));
  for (const entry of Object.values(pkg.exports)) {
    if (typeof entry === 'object') for (const file of Object.values(entry)) assert.ok(statSync(join(root, file)).isFile(), file);
  }
});
