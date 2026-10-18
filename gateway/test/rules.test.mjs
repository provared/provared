// The rules file: every call in test/rules.json maps to the action, amount
// and service it must, or is refused with the code it must; and settings
// that are wrong are said to be wrong.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const { amountOf, lookUp, matchRule, pointerTokens, readRules, readTarget, repeatedName, stripParameters, upstreamAddress, CREDENTIAL_HEADERS } = await import('../rules.mjs');

const fixture = JSON.parse(readFileSync(new URL('rules.json', import.meta.url), 'utf8'));

/** What the gateway makes of one call, by the same steps it takes. */
function mapCall(read, c) {
  const t = readTarget(c.target, (name) => read.upstreams.get(name)?.semicolons === true);
  if (t.problem) return { refused: t.problem.code };
  const upstream = read.upstreams.get(t.upstream);
  if (!upstream) return { unlisted: true };
  const { query, removed } = stripParameters(t.query, read.stripQuery);
  const rule = matchRule(read.rules, { upstream: t.upstream, method: c.method, rest: t.match, query });
  if (!rule) return { unlisted: true };
  const body = c.bodyBase64 !== undefined ? Buffer.from(c.bodyBase64, 'base64') : c.body !== undefined ? Buffer.from(c.body, 'utf8') : undefined;
  const asList = (v) => (v === undefined ? undefined : Array.isArray(v) ? v : [v]);
  const got = amountOf(rule.amount, { body, contentType: asList(c.contentType), contentEncoding: asList(c.contentEncoding) });
  if (got.problem) return { refused: got.problem.code };
  return { action: rule.action, amount: got.amount, service: upstream.service, forwarded: upstreamAddress(upstream, t.rest, query), removed };
}

test('Node.js has the URL Pattern standard built in', () => {
  assert.equal(typeof URLPattern, 'function');
  // Two of the standard's own examples.
  assert.ok(new URLPattern({ pathname: '/books/:id' }).test({ pathname: '/books/123' }));
  assert.equal(new URLPattern({ pathname: '/books/:id' }).exec({ pathname: '/books/123' }).pathname.groups.id, '123');
});

test('the settings of the fixture are read with no problem', () => {
  const read = readRules(fixture.settings);
  assert.deepEqual(read.problems, []);
});

test(`every call in rules.json maps as it must (${fixture.calls.length} calls)`, () => {
  const read = readRules(fixture.settings);
  for (const c of fixture.calls) {
    const got = mapCall(read, c);
    const what = `${c.method} ${c.target}`;
    if (c.expect.refused) {
      assert.deepEqual(got, { refused: c.expect.refused }, what);
      continue;
    }
    if (c.expect.unlisted) {
      assert.deepEqual(got, { unlisted: true }, what);
      continue;
    }
    assert.equal(got.action, c.expect.action, what);
    assert.deepEqual(got.amount, c.expect.amount, what);
    if ('service' in c.expect) assert.equal(got.service, c.expect.service, what);
    if (c.expect.forwarded) assert.equal(got.forwarded, c.expect.forwarded, what);
    assert.deepEqual(got.removed, c.expect.removed ?? [], what);
  }
});

test('the address is forwarded in the form that was matched: a decoded letter, capitals in the rest', () => {
  assert.deepEqual(readTarget('/a/b%7e%7Ec%2d%3a'), { upstream: 'a', rest: '/b~~c-%3A', match: '/b~~c-%3A', query: null });
  assert.deepEqual(readTarget('/a?x=%2F'), { upstream: 'a', rest: '/', match: '/', query: 'x=%2F' });
  assert.deepEqual(readTarget('/a/?'), { upstream: 'a', rest: '/', match: '/', query: '' });
  assert.equal(readTarget('/a/b#c').problem.code, 'address-refused');
  assert.equal(readTarget('/').problem.code, 'address-refused');
  assert.equal(readTarget('*').problem.code, 'address-refused');
  assert.equal(readTarget('/a/%1F').problem.code, 'address-refused');
  assert.equal(readTarget('/a/%7F').problem.code, 'address-refused');
  assert.equal(readTarget('/a/%2E/b').problem.code, 'address-refused');
  assert.equal(readTarget('/a/%2E%2E').problem.code, 'address-refused');
  assert.equal(readTarget('/a/café').problem.code, 'address-refused');
  assert.equal(readTarget('/a/x y').problem.code, 'address-refused');
  // A percent sign written as itself, not before two hexadecimal digits of an encoding of one, is kept.
  assert.deepEqual(readTarget('/a/100%25'), { upstream: 'a', rest: '/100%25', match: '/100%25', query: null });
});

test('credential parameters are removed whatever their case or encoding, and the rest of the query is kept exactly', () => {
  const names = ['token', 'api_key'];
  assert.deepEqual(stripParameters('a=1&b=2', names), { query: 'a=1&b=2', removed: [] });
  assert.deepEqual(stripParameters('TOKEN=1&b=%20', names), { query: 'b=%20', removed: ['token'] });
  assert.deepEqual(stripParameters('api%5Fkey=1&api_key=2&c', names), { query: 'c', removed: ['api_key'] });
  assert.deepEqual(stripParameters('token', names), { query: null, removed: ['token'] });
  assert.deepEqual(stripParameters('to%zzken=1', names), { query: 'to%zzken=1', removed: [] });
  assert.deepEqual(stripParameters(null, names), { query: null, removed: [] });
});

test('JSON Pointer (RFC 6901), with the standard\'s own examples', () => {
  const doc = { foo: ['bar', 'baz'], '': 0, 'a/b': 1, 'c%d': 2, 'e^f': 3, 'g|h': 4, 'i\\j': 5, 'k"l': 6, ' ': 7, 'm~n': 8 };
  const at = (p) => lookUp(doc, pointerTokens(p));
  assert.deepEqual(at(''), { found: true, value: doc });
  assert.deepEqual(at('/foo'), { found: true, value: ['bar', 'baz'] });
  assert.deepEqual(at('/foo/0'), { found: true, value: 'bar' });
  for (const [p, v] of [['/', 0], ['/a~1b', 1], ['/c%d', 2], ['/e^f', 3], ['/g|h', 4], ['/i\\j', 5], ['/k"l', 6], ['/ ', 7], ['/m~0n', 8]]) assert.deepEqual(at(p), { found: true, value: v }, p);
  assert.deepEqual(at('/foo/2'), { found: false });
  assert.deepEqual(at('/foo/-'), { found: false });
  assert.deepEqual(at('/foo/00'), { found: false });
  assert.deepEqual(at('/nothing'), { found: false });
  assert.equal(pointerTokens('foo'), null);
  assert.equal(pointerTokens('/a~2'), null);
  assert.equal(pointerTokens('/a~'), null);
  assert.deepEqual(lookUp({ a: 1 }, ['constructor']), { found: false });
  assert.deepEqual(lookUp({ a: 1 }, ['toString']), { found: false });
});

test('a repeated member name is found at any depth, after escapes, and not inside a text', () => {
  assert.equal(repeatedName('{"a":1,"a":2}'), 'a');
  assert.equal(repeatedName('{"a":1,"\\u0061":2}'), 'a');
  assert.equal(repeatedName('[{"a":1},{"a":2}]'), null);
  assert.equal(repeatedName('{"a":{"b":1},"b":2}'), null);
  assert.equal(repeatedName('{"a":"\\",\\"a\\":","b":1}'), null);
  assert.equal(repeatedName('{"x":[1,{"y":2,"y":3}]}'), 'y');
  assert.equal(repeatedName('{"x":{},"x":[]}'), 'x');
  assert.equal(repeatedName('"text"'), null);
});

test('settings that are wrong are said to be wrong, each in a sentence', () => {
  const base = { upstreams: { u: { base: 'https://u.example.invalid' } }, rules: [] };
  const problems = (change) => readRules({ ...base, ...change }).problems;
  assert.deepEqual(problems({}), []);
  const cases = [
    [{ upstreams: {} }, /at least one/],
    [{ upstreams: { provared: { base: 'https://x.invalid' } } }, /kept for the gateway's own addresses/],
    [{ upstreams: { U: { base: 'https://x.invalid' } } }, /lower-case/],
    [{ upstreams: { u: { base: 'ftp://x.invalid' } } }, /http or https/],
    [{ upstreams: { u: { base: 'https://me:pw@x.invalid' } } }, /user name or a password/],
    [{ upstreams: { u: { base: 'https://x.invalid/?a=1' } } }, /no query/],
    [{ upstreams: { u: { base: 'https://x.invalid', credential: { header: 'Authorization' } } } }, /exactly one of "file" or "env"/],
    [{ upstreams: { u: { base: 'https://x.invalid', credential: { header: 'Authorization', file: 'a', env: 'B' } } } }, /exactly one of "file" or "env"/],
    [{ upstreams: { u: { base: 'https://x.invalid', countersign: 'https://elsewhere.invalid/c' } } }, /path on the upstream's own address/],
    [{ upstreams: { u: { base: 'https://x.invalid', countersign: '//elsewhere.invalid/c' } } }, /path on the upstream's own address/],
    [{ upstreams: { u: { base: 'https://x.invalid', extra: 1 } } }, /"extra" is not a setting/],
    [{ unlisted: 'allow' }, /"unlisted" must be/],
    [{ bodyLimit: -1 }, /"bodyLimit"/],
    [{ rules: [{ upstream: 'v', method: 'GET', path: '/', action: 'a' }] }, /must name one of the upstreams/],
    [{ rules: [{ upstream: 'u', method: 'get', path: '/', action: 'a' }] }, /in capitals/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: 'x', action: 'a' }] }, /begins "\/"/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/(', action: 'a' }] }, /not a URL Pattern/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'Read' }] }, /action name/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'provared.data.readish' }] }, /not on the shared list/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', amount: { unit: 'x' } }] }, /exactly one of/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', amount: { unit: 'x', value: 1, count: '/a' } }] }, /exactly one of/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', amount: { unit: 'two words', value: 1 } }] }, /no spaces/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', amount: { unit: 'x', value: 1.5 } }] }, /whole number/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', amount: { unit: 'x', pointer: 'a' } }] }, /JSON Pointer/],
    [{ rules: [{ upstream: 'u', method: 'GET', path: '/', action: 'a', other: 1 }] }, /"other" is not a setting/],
    [{ rules: {} }, /must be a list/],
  ];
  for (const [change, words] of cases) {
    const found = problems(change);
    assert.ok(found.some((p) => words.test(p)), `${JSON.stringify(change)}: ${JSON.stringify(found)}`);
  }
  const twice = readRules({ ...base, rules: [{ upstream: 'u', method: 'GET', path: '/a', action: 'a' }, { upstream: 'u', method: 'GET', path: '/a', action: 'b' }] });
  assert.ok(twice.warnings.some((w) => /never used/.test(w)));
  assert.ok(readRules({ ...base, unlisted: 'forward' }).warnings.some((w) => /no receipt/.test(w)));
  assert.ok(readRules({ upstreams: { u: { base: 'http://u.example.invalid' } }, rules: [] }).warnings.some((w) => /unencrypted/.test(w)));
});

test('the headers named in the settings are removed with the standard ones, in small letters', () => {
  const read = readRules({ upstreams: { u: { base: 'https://u.invalid', stripHeaders: ['X-Other-Key'] } }, rules: [], stripHeaders: ['X-Team-Token'] });
  const u = read.upstreams.get('u');
  for (const h of [...CREDENTIAL_HEADERS, 'x-team-token', 'x-other-key']) assert.ok(u.stripHeaders.includes(h), h);
});
