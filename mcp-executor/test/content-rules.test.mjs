// Rules on the content of a change (F-157, F-158): how a rules file is
// read, how the fingerprint reaches the records and the permission, and
// what each kind of rule lets through and refuses.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { checkBook, identifierFingerprint, argumentsFingerprint } = await import('provared');
const { world, openWorld, TOOLS, ACTIONS } = await import('./world.mjs');
const { CALL_DOCUMENT, TOOL_DOCUMENT, RULES_DOCUMENT, RULE_DOCUMENT, checkConfig, readSettings, softwareEntry } = await import('../executor.mjs');
const { readRules, rulesFingerprint, globMatch, testCall, MAX_MATCH_TEXT } = await import('../rules.mjs');
const { readCopy, loadCopyKey } = await import('../copy.mjs');
const { compareCopyWithBook } = await import('../compare.mjs');

const BIN = fileURLToPath(new URL('../bin.mjs', import.meta.url));

/** The tools of the tests, with two that write files, and the actions the slip must allow for them. */
const WRITE_TOOLS = { ...TOOLS, write_file: { action: 'provared.data.change' }, edit_file: { action: 'provared.data.change' } };
const WRITE_ACTIONS = [...ACTIONS, 'provared.data.change'];

/** The rules of the worked example: the scan setting in settings.json stays off; settings.json is never edited in part. */
const SCAN_RULES = {
  version: 1,
  rules: [
    {
      name: 'the scan setting in settings.json stays off',
      tool: 'write_file',
      when: { pointer: '/path', matches: '**settings.json' },
      content: { pointer: '/content', as: 'json' },
      test: { pointer: '/scan', equals: false, orAbsent: true },
    },
    { name: 'settings.json is written whole, never edited in part', tool: 'edit_file', when: { pointer: '/path', matches: '**settings.json' } },
  ],
};

/** A world with a rules file, the write tools, and (unless told otherwise) a slip whose agent.software states the rules. */
async function ruledWorld({ rules = SCAN_RULES, software = 'stated', slip = {}, config = {} } = {}) {
  const fingerprint = await rulesFingerprint(rules);
  const stated = software === 'stated' ? [softwareEntry('The test executor', fingerprint)] : software === 'other' ? [{ name: 'Some other program', sha256: await identifierFingerprint('other') }] : undefined;
  const w = await world({ open: false, slip: { actions: WRITE_ACTIONS, software: stated, ...slip }, config: { tools: WRITE_TOOLS, contentRules: 'rules.json', ...config } });
  writeFileSync(join(w.folder, 'rules.json'), JSON.stringify(rules, null, 2));
  w.rulesFingerprint = fingerprint;
  await openWorld(w);
  return w;
}

async function bookOf(w) {
  return checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
}
function docs(entry) {
  return Object.fromEntries(entry.content.details.map((d) => [d.name, d.sha256]));
}
function copyOf(w) {
  return readCopy(join(w.folder, 'copy.jsonl'), loadCopyKey(join(w.folder, 'copy.jsonl.key')), w.settings.name);
}

test('F-157: a label change in settings.json is let through; the same edit with the hidden scan setting switched on is refused, with a denial that names the rules file and the rule', async () => {
  const w = await ruledWorld();
  try {
    const label = await w.client.call('write_file', { path: 'config/settings.json', content: JSON.stringify({ label: 'Night mode', scan: false }) });
    assert.equal(label.result.content[0].text, 'Written.', 'the label change went through');
    const hidden = await w.client.call('write_file', { path: 'config/settings.json', content: JSON.stringify({ label: 'Night mode', scan: true }) });
    assert.equal(hidden.result.isError, true);
    assert.equal(hidden.result._meta['red.prova/refused'], 'content-rule');
    assert.equal(hidden.result._meta['red.prova/rule'], 'the scan setting in settings.json stays off');
    assert.match(hidden.result.content[0].text, /^Not taken by the Provared executor: Content rule "the scan setting in settings.json stays off": the value at "\/scan" in the content at "\/content" must equal false, or be absent\./);
    assert.ok(!hidden.result.content[0].text.includes('true'), 'the value found is not echoed');
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 1, 'the refused call never reached the server');
    const checked = await bookOf(w);
    assert.equal(checked.summary.problemFound, false);
    assert.equal(checked.summary.withinSlips, true);
    const stubs = checked.entries.filter((e) => e.kind === 'stub');
    const denials = checked.entries.filter((e) => e.kind === 'denial');
    assert.equal(stubs.length, 1);
    assert.equal(denials.length, 1);
    // The receipt names the rules file in force; the denial names it and the rule, and what was asked for.
    const sd = docs(stubs[0]);
    assert.equal(sd[RULES_DOCUMENT], w.rulesFingerprint);
    assert.equal(sd[RULE_DOCUMENT], undefined, 'a receipt names no refusing rule');
    const dd = docs(denials[0]);
    assert.equal(denials[0].content.source, 'rule');
    assert.equal(denials[0].content.action, 'provared.data.change');
    assert.equal(dd[RULES_DOCUMENT], w.rulesFingerprint);
    assert.equal(dd[RULE_DOCUMENT], await identifierFingerprint('the scan setting in settings.json stays off'));
    assert.equal(dd[TOOL_DOCUMENT], await identifierFingerprint('write_file'));
    assert.equal(dd['provared.arguments'], await argumentsFingerprint({ path: 'config/settings.json', content: JSON.stringify({ label: 'Night mode', scan: true }) }));
    assert.equal(dd[CALL_DOCUMENT], undefined, 'the identifier was never sent');
    assert.equal(hidden.result._meta['red.prova/denial'], denials[0].fingerprint);
    // The slip states the rules, so a reader can see that the rules in force were approved.
    const slip = checked.entries.find((e) => e.kind === 'slip');
    assert.deepEqual(slip.content.agent.software, [{ name: 'Content rules of The test executor', sha256: w.rulesFingerprint }]);
    assert.ok(!w.logs.some((e) => e.event === 'warning' && e.message.includes('agent.software')), 'no warning where the slip states the rules');
    // The copy and the log name the rule, never a value from the arguments.
    const refused = copyOf(w).lines.find((l) => l.entry.kind === 'refused');
    assert.equal(refused.entry.reason, 'content-rule');
    assert.equal(refused.entry.rule, 'the scan setting in settings.json stays off');
    assert.deepEqual(refused.entry.amount, undefined);
    assert.ok(!JSON.stringify(copyOf(w).lines).includes('Night mode'), 'no argument in the copy');
    assert.ok(!JSON.stringify(w.logs).includes('Night mode'), 'no argument in the log');
    assert.ok(w.logs.some((e) => e.event === 'refused' && e.code === 'content-rule' && e.rule === 'the scan setting in settings.json stays off'));
    // The comparison reports the rules the records name, and that the slip states them.
    const compared = await compareCopyWithBook({ copyPath: join(w.folder, 'copy.jsonl'), copyKey: loadCopyKey(join(w.folder, 'copy.jsonl.key')), name: w.settings.name, service: 'executor', book: w.executor.writer.book(), options: { issuerKeys: w.settings.agent.issuerKeys } });
    assert.equal(compared.summary.agree, true);
    assert.deepEqual(compared.contentRules, [{ sha256: w.rulesFingerprint, receipts: 1, denials: 1, statedInSlip: true }]);
  } finally {
    await w.close();
  }
});

test('a rule applies only where its "when" holds: another file may switch scan on; a partial edit of settings.json is refused outright, of another file let through', async () => {
  const w = await ruledWorld();
  try {
    const other = await w.client.call('write_file', { path: 'config/other.json', content: JSON.stringify({ scan: true }) });
    assert.equal(other.result.content[0].text, 'Written.');
    const edit = await w.client.call('edit_file', { path: 'settings.json', old: 'a', new: 'b' });
    assert.equal(edit.result.isError, true);
    assert.equal(edit.result._meta['red.prova/refused'], 'content-rule');
    assert.equal(edit.result.content[0].text, 'Not taken by the Provared executor: Content rule "settings.json is written whole, never edited in part" does not allow this call to "edit_file". The call was not taken.');
    const editOther = await w.client.call('edit_file', { path: 'notes.txt', old: 'a', new: 'b' });
    assert.equal(editOther.result.content[0].text, 'Edited.');
    // A call with no arguments: the "when" does not hold (nothing at /path), so the rule does not apply.
    const none = await w.client.call('edit_file');
    assert.equal(none.result.content[0].text, 'Edited.');
    const checked = await bookOf(w);
    assert.equal(checked.entries.filter((e) => e.kind === 'stub').length, 3);
    assert.equal(checked.entries.filter((e) => e.kind === 'denial').length, 1);
  } finally {
    await w.close();
  }
});

test('content a rule cannot read exactly refuses the call: not JSON, a member named twice or twice once folded, a number two readers hold differently, nothing at the pointer, not text, or arguments with folded names', async () => {
  const w = await ruledWorld();
  const expectUnreadable = async (args, words) => {
    const r = await w.client.call('write_file', args);
    assert.equal(r.result.isError, true, `refused: ${words}`);
    assert.equal(r.result._meta['red.prova/refused'], 'content-unreadable');
    assert.match(r.result.content[0].text, new RegExp(`^Not taken by the Provared executor: Content rule "the scan setting in settings.json stays off" could not read what it tests: ${words}`));
  };
  try {
    await expectUnreadable({ path: 'settings.json', content: '{"scan": false, // a comment\n}' }, 'the content at "/content" is not JSON');
    await expectUnreadable({ path: 'settings.json', content: '{"scan": false, "scan": true}' }, 'the content at "/content" names one member twice');
    await expectUnreadable({ path: 'settings.json', content: '{"scan": false, "SCAN": true}' }, 'the content at "/content" names one member twice');
    await expectUnreadable({ path: 'settings.json', content: '{"scan": false, "n": 9007199254740993}' }, 'the content at "/content" holds a whole number beyond');
    await expectUnreadable({ path: 'settings.json' }, 'nothing is found at "/content" in the arguments');
    await expectUnreadable({ path: 'settings.json', content: { scan: false } }, 'what is found at "/content" in the arguments is not text');
    // The arguments themselves: two names that differ only in capitals, where a rule reads them.
    const answer = await w.client.call('write_file', { path: 'notes.txt', PATH: 'settings.json', content: '{}' });
    assert.equal(answer.result._meta['red.prova/refused'], 'content-unreadable');
    assert.match(answer.result.content[0].text, /the arguments name one member twice in one object, or two that differ only in capitals/);
    // A byte-order mark at the start of the content is not JSON either.
    await expectUnreadable({ path: 'settings.json', content: '\uFEFF{"scan": false}' }, 'the content at "/content" is not JSON');
    assert.equal(w.fakeSeen().filter((s) => s.seen?.method === 'tools/call').length, 0, 'none reached the server');
    const checked = await bookOf(w);
    assert.equal(checked.entries.filter((e) => e.kind === 'denial').length, 8);
    assert.ok(checked.entries.filter((e) => e.kind === 'denial').every((d) => d.content.source === 'rule' && docs(d)[RULE_DOCUMENT] !== undefined));
  } finally {
    await w.close();
  }
});

test('each kind of condition: equals (deep), oneOf, absent, matches; orAbsent; a rule over the arguments with no "content"; "as": "value"; a text too long to match is unreadable', async () => {
  const rules = {
    version: 1,
    rules: [
      { name: 'equals', tool: 'write_file', when: { pointer: '/kind', equals: 'equals' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '/nested', equals: { a: [1, { b: 'x' }], c: null } } },
      { name: 'oneOf', tool: 'write_file', when: { pointer: '/kind', equals: 'oneOf' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '/mode', oneOf: ['off', 'manual', 2] } },
      { name: 'absent', tool: 'write_file', when: { pointer: '/kind', equals: 'absent' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '/debug', absent: true } },
      { name: 'matches', tool: 'write_file', when: { pointer: '/kind', equals: 'matches' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '/target', matches: 'reports/*.csv' } },
      { name: 'orAbsent', tool: 'write_file', when: { pointer: '/kind', equals: 'orAbsent' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '/level', oneOf: [1, 2], orAbsent: true } },
      { name: 'arguments', tool: 'write_file', when: { pointer: '/kind', equals: 'arguments' }, test: [{ pointer: '/path', matches: 'out/**' }, { pointer: '/mode', equals: 'append' }] },
      { name: 'whenList', tool: 'write_file', when: [{ pointer: '/kind', equals: 'whenList' }, { pointer: '/flag', equals: true }] },
      { name: 'whole', tool: 'write_file', when: { pointer: '/kind', equals: 'whole' }, content: { pointer: '/data', as: 'value' }, test: { pointer: '', equals: [1, 2] } },
    ],
  };
  const w = await ruledWorld({ rules });
  const ok = async (args) => {
    const r = await w.client.call('write_file', args);
    assert.equal(r.result.content[0].text, 'Written.', `let through: ${JSON.stringify(args)}`);
  };
  const no = async (args, code, words) => {
    const r = await w.client.call('write_file', args);
    assert.equal(r.result.isError, true, `refused: ${JSON.stringify(args)}`);
    assert.equal(r.result._meta['red.prova/refused'], code);
    assert.match(r.result.content[0].text, words);
  };
  try {
    await ok({ kind: 'equals', data: { nested: { c: null, a: [1, { b: 'x' }] } } });
    await no({ kind: 'equals', data: { nested: { c: null, a: [1, { b: 'y' }] } } }, 'content-rule', /must equal \{"a":\[1,\{"b":"x"\}\],"c":null\}\./);
    await no({ kind: 'equals', data: {} }, 'content-rule', /must equal/);
    await ok({ kind: 'oneOf', data: { mode: 'manual' } });
    await ok({ kind: 'oneOf', data: { mode: 2 } });
    await no({ kind: 'oneOf', data: { mode: 'on' } }, 'content-rule', /must be one of \["off","manual",2\]\./);
    await no({ kind: 'oneOf', data: { mode: '2' } }, 'content-rule', /must be one of/);
    await ok({ kind: 'absent', data: { other: true } });
    await no({ kind: 'absent', data: { debug: false } }, 'content-rule', /the value at "\/debug" in the content at "\/data" must not be present\./);
    await ok({ kind: 'matches', data: { target: 'reports/march.csv' } });
    await no({ kind: 'matches', data: { target: 'reports/2026/march.csv' } }, 'content-rule', /must match the pattern "reports\/\*\.csv"\./);
    await no({ kind: 'matches', data: { target: ['reports/march.csv'] } }, 'content-rule', /must match the pattern/);
    await no({ kind: 'matches', data: { target: 'x'.repeat(MAX_MATCH_TEXT + 1) } }, 'content-unreadable', /is text longer than 4096 characters/);
    await ok({ kind: 'orAbsent', data: {} });
    await ok({ kind: 'orAbsent', data: { level: 2 } });
    await no({ kind: 'orAbsent', data: { level: 3 } }, 'content-rule', /must be one of \[1,2\], or be absent\./);
    await ok({ kind: 'arguments', path: 'out/a/b.txt', mode: 'append' });
    await no({ kind: 'arguments', path: 'out/a/b.txt', mode: 'replace' }, 'content-rule', /the value at "\/mode" in the arguments must equal "append"\./);
    await no({ kind: 'arguments', path: 'in/a.txt', mode: 'append' }, 'content-rule', /the value at "\/path" in the arguments must match the pattern "out\/\*\*"\./);
    await ok({ kind: 'whenList', flag: false });
    await no({ kind: 'whenList', flag: true }, 'content-rule', /does not allow this call/);
    await ok({ kind: 'whole', data: [1, 2] });
    await no({ kind: 'whole', data: [1, 2, 3] }, 'content-rule', /the value at "" in the content at "\/data" must equal \[1,2\]\./);
    await ok({ kind: 'none', data: { anything: true } });
  } finally {
    await w.close();
  }
});

test('a "when" that cannot be judged (a text too long to match) refuses the call rather than letting it past the rule', () => {
  const { rules } = readRules(JSON.stringify({ version: 1, rules: [{ name: 'r', tool: 't', when: { pointer: '/p', matches: 'a*' } }] }));
  const long = 'a'.repeat(MAX_MATCH_TEXT + 1);
  const r = testCall(rules, 't', { p: long }, JSON.stringify({ p: long }));
  assert.equal(r.reason.code, 'content-unreadable');
  assert.match(r.reason.message, /in its "when", what is found at "\/p" is text longer than 4096 characters/);
  assert.equal(testCall(rules, 't', { p: 'a'.repeat(MAX_MATCH_TEXT) }, undefined).reason.code, 'content-rule');
  assert.equal(testCall(rules, 't', { p: 'b' }, undefined), null);
  assert.equal(testCall(rules, 'other', { p: long }, undefined), null, 'a tool no rule names is not read');
});

test('the first refusing rule, in the file\'s order, is the one named; a tool may be named by several rules and a rule may name several tools', async () => {
  const rules = {
    version: 1,
    rules: [
      { name: 'first', tool: ['write_file', 'edit_file'], test: { pointer: '/a', equals: 1 } },
      { name: 'second', tool: 'write_file', test: { pointer: '/b', equals: 2 } },
    ],
  };
  const w = await ruledWorld({ rules });
  try {
    const both = await w.client.call('write_file', { a: 0, b: 0 });
    assert.equal(both.result._meta['red.prova/rule'], 'first');
    const second = await w.client.call('write_file', { a: 1, b: 0 });
    assert.equal(second.result._meta['red.prova/rule'], 'second');
    const edit = await w.client.call('edit_file', { a: 0, b: 0 });
    assert.equal(edit.result._meta['red.prova/rule'], 'first');
    const editOk = await w.client.call('edit_file', { a: 1, b: 0 });
    assert.equal(editOk.result.content[0].text, 'Edited.', 'the second rule does not name edit_file');
    const ok = await w.client.call('write_file', { a: 1, b: 2 });
    assert.equal(ok.result.content[0].text, 'Written.');
  } finally {
    await w.close();
  }
});

test('the rules are tested after the amount and before the check before acting: an amount that cannot be read is refused first; a call a rule lets through is still refused by the permission', async () => {
  const rules = { version: 1, rules: [{ name: 'small orders', tool: 'order', test: { pointer: '/total', oneOf: [10, 20, 500] } }] };
  const w = await ruledWorld({ rules, slip: { limits: [{ action: 'supplies.order', max: 100, unit: 'GBP' }] } });
  try {
    const noAmount = await w.client.call('order', { total: 'ten' });
    assert.equal(noAmount.result._meta['red.prova/refused'], 'amount-not-found');
    const ruled = await w.client.call('order', { total: 15 });
    assert.equal(ruled.result._meta['red.prova/refused'], 'content-rule');
    const over = await w.client.call('order', { total: 500 });
    assert.equal(over.result._meta['red.prova/refused'], 'not-allowed', 'the rule let 500 through; the permission did not');
    assert.deepEqual(over.result._meta['red.prova/codes'], ['over-limit']);
    const ok = await w.client.call('order', { total: 20 });
    assert.equal(ok.result.content[0].text, 'Ordered for 20.');
    const checked = await bookOf(w);
    const denials = checked.entries.filter((e) => e.kind === 'denial');
    assert.deepEqual(denials.map((d) => d.content.source), ['rule', 'rule', 'check']);
    // The denial by a content rule names the amount that was asked for; every denial names the rules file.
    assert.deepEqual(denials[1].content.amount, { unit: 'GBP', value: 15 });
    assert.ok(denials.every((d) => docs(d)[RULES_DOCUMENT] === w.rulesFingerprint));
    assert.equal(docs(denials[0])[RULE_DOCUMENT], undefined, 'the amount refusal names no rule');
    assert.equal(docs(denials[2])[RULE_DOCUMENT], undefined, 'the check\'s refusal names no rule');
  } finally {
    await w.close();
  }
});

test('the permission must state the rules in force, or nothing: other software stated stops the start; nothing stated warns and says what to add; the fingerprint is of the parsed file, so spacing does not change it', async () => {
  // Nothing stated: a warning with the entry to add.
  const silent = await ruledWorld({ software: 'none' });
  try {
    const warning = silent.logs.find((e) => e.event === 'warning' && e.message.includes('agent.software'));
    assert.ok(warning, 'warned');
    assert.ok(warning.message.includes(JSON.stringify({ name: 'Content rules of The test executor', sha256: silent.rulesFingerprint })));
    const r = await silent.client.call('write_file', { path: 'settings.json', content: '{"scan": false}' });
    assert.equal(r.result.content[0].text, 'Written.', 'the executor runs, and tests the rules');
    const report = await checkConfig(silent.settings, silent.folder);
    assert.deepEqual(report.problems, []);
    assert.deepEqual(report.contentRules, { path: join(silent.folder, 'rules.json'), fingerprint: silent.rulesFingerprint, rules: SCAN_RULES.rules.map((x) => x.name), statedInSlip: null });
  } finally {
    await silent.close();
  }
  // Other software stated, not these rules: the executor does not start.
  await assert.rejects(ruledWorld({ software: 'other' }), /states the agent's software \(agent\.software\), and the rules on content in force .* are not among what it states: the person approved other rules than these/);
  // The rules changed after signing: the same.
  const w = await ruledWorld();
  try {
    assert.equal((await checkConfig(w.settings, w.folder)).contentRules.statedInSlip, true);
    const changed = { ...SCAN_RULES, rules: [...SCAN_RULES.rules, { name: 'one more', tool: 'edit_file' }] };
    writeFileSync(join(w.folder, 'rules.json'), JSON.stringify(changed));
    const report = await checkConfig(w.settings, w.folder);
    assert.equal(report.problems.length, 1);
    assert.match(report.problems[0], /the person approved other rules than these/);
    // Only the spacing changed: the fingerprint is the same, and the executor starts.
    writeFileSync(join(w.folder, 'rules.json'), `\uFEFF${JSON.stringify(SCAN_RULES)}`);
    const same = await checkConfig(w.settings, w.folder);
    assert.deepEqual(same.problems, []);
    assert.equal(same.contentRules.fingerprint, w.rulesFingerprint);
  } finally {
    await w.close();
  }
});

test('the rules file is read strictly: each malformed form is a problem that stops the start, with its place named', () => {
  const problem = (file, words) => {
    const { rules, problems } = readRules(typeof file === 'string' ? file : JSON.stringify(file));
    assert.equal(rules, null, `refused: ${words}`);
    assert.ok(problems.some((p) => p.includes(words)), `${words}; got ${JSON.stringify(problems)}`);
  };
  const rule = (more) => ({ version: 1, rules: [{ name: 'r', tool: 't', ...more }] });
  problem('not json', 'is not JSON');
  problem('[1]', 'must be a JSON object');
  problem('{"version": 1, "rules": [], "version": 1}', 'names the member "version" twice');
  problem('{"version": 1, "rules": [{"name": "r", "tool": "t", "test": {"pointer": "/n", "equals": 9007199254740993}}]}', 'beyond 9,007,199,254,740,991');
  problem({ version: 2, rules: [] }, 'version: must be 1.');
  problem({ version: 1 }, 'rules: must be a list');
  problem({ version: 1, rules: [], extra: 1 }, 'extra: is not part of a rules file.');
  problem({ version: 1, rules: [1] }, 'rules[0]: must be an object');
  problem(rule({ nmae: 'x' }), 'rules[0].nmae: is not part of a rule.');
  problem({ version: 1, rules: [{ tool: 't' }] }, 'rules[0].name: must be text');
  problem({ version: 1, rules: [{ name: 'r', tool: 't' }, { name: 'r', tool: 'u' }] }, 'rules[1].name: is the name of another rule');
  problem({ version: 1, rules: [{ name: 'r', tool: 'a b' }] }, 'rules[0].tool: must be a tool name');
  problem({ version: 1, rules: [{ name: 'r', tool: ['t', 't'] }] }, 'rules[0].tool: names one tool twice.');
  problem({ version: 1, rules: [{ name: 'r', tool: [] }] }, 'rules[0].tool: must be a tool name');
  problem(rule({ when: { pointer: 'scan', equals: 1 } }), 'rules[0].when.pointer: must be a JSON Pointer');
  problem(rule({ when: { pointer: '/a' } }), 'rules[0].when: must hold exactly one of');
  problem(rule({ when: { pointer: '/a', equals: 1, absent: true } }), 'rules[0].when: must hold exactly one of');
  problem(rule({ when: { pointer: '/a', equals: 1, extra: true } }), 'rules[0].when.extra: is not part of a condition.');
  problem(rule({ when: [] }), 'rules[0].when: must be a condition, or a list of 1 to 16 conditions.');
  problem(rule({ when: [{ pointer: '/a', equals: 1 }, { pointer: '/b', oneOf: [] }] }), 'rules[0].when[1].oneOf: must be a list of 1 to 64 values.');
  problem(rule({ when: { pointer: '/a', absent: false } }), 'rules[0].when.absent: must be true.');
  problem(rule({ when: { pointer: '/a', absent: true, orAbsent: true } }), 'rules[0].when.orAbsent: has no meaning with "absent".');
  problem(rule({ when: { pointer: '/a', equals: 1, orAbsent: 'yes' } }), 'rules[0].when.orAbsent: must be true or false.');
  problem(rule({ when: { pointer: '/a', matches: '' } }), 'rules[0].when.matches: must be a pattern of 1 to 1,000 characters');
  problem(rule({ content: { pointer: '/c', as: 'json' } }), 'rules[0].content: is given with no "test"');
  problem(rule({ content: { pointer: '/c', as: 'yaml' }, test: { pointer: '/a', equals: 1 } }), 'rules[0].content.as: must be "json"');
  problem(rule({ content: { pointer: 'c', as: 'json' }, test: { pointer: '/a', equals: 1 } }), 'rules[0].content.pointer: must be a JSON Pointer');
  problem(rule({ content: { pointer: '/c', as: 'json', more: 1 }, test: { pointer: '/a', equals: 1 } }), 'rules[0].content: must be {"pointer"');
  problem(rule({ test: [] }), 'rules[0].test: must be a condition, or a list of 1 to 64 conditions.');
  problem({ version: 1, rules: Array.from({ length: 1001 }, (_, i) => ({ name: `r${i}`, tool: 't' })) }, 'must be a list of up to 1000 rules');
  // Sound forms.
  const good = readRules(JSON.stringify({ version: 1, rules: [{ name: 'r', tool: 't', when: [{ pointer: '/a', equals: 1 }], content: { pointer: '', as: 'value' }, test: [{ pointer: '/x~1y~0z', absent: true }] }, { name: 's', tool: ['t', 'u'] }] }));
  assert.deepEqual(good.problems, []);
  assert.equal(good.rules.length, 2);
  assert.deepEqual(good.rules[0].tests[0].tokens, ['x/y~z'], 'the pointer\'s escapes are read');
  assert.equal(good.rules[1].tests, null);
  assert.deepEqual(good.rules[1].tools, ['t', 'u']);
  assert.deepEqual(readRules(JSON.stringify({ version: 1, rules: [] })).rules, [], 'an empty list is allowed');
});

test('patterns: "*" stays within one path part, "**" crosses parts, "?" is one character; nothing else is special; both separators count', () => {
  const yes = (p, t) => assert.equal(globMatch(p, t), true, `${p} should match ${t}`);
  const no = (p, t) => assert.equal(globMatch(p, t), false, `${p} should not match ${t}`);
  yes('settings.json', 'settings.json');
  no('settings.json', 'config/settings.json');
  yes('*.json', 'settings.json');
  no('*.json', 'config/settings.json');
  no('*.json', 'config\\settings.json');
  yes('**settings.json', 'config/settings.json');
  yes('**settings.json', 'C:\\app\\config\\settings.json');
  yes('**/settings.json', 'config/settings.json');
  no('**/settings.json', 'settings.json');
  yes('**', '');
  yes('**', 'anything/at/all');
  yes('*', '');
  no('*', 'a/b');
  yes('a?c', 'abc');
  no('a?c', 'a/c');
  no('a?c', 'ac');
  yes('***.json', 'a/b/c.json');
  yes('reports/*.csv', 'reports/march.csv');
  no('reports/*.csv', 'reports/2026/march.csv');
  yes('reports/**.csv', 'reports/2026/march.csv');
  no('a.json', 'a_json');
  yes('a[b].json', 'a[b].json');
  no('a[b].json', 'ab.json');
  yes('caf?', 'café');
  yes('*é', 'café');
  no('*', 'a\\b');
});

test('the keys command prints the agent.software entry to put into the permission; check lists the rules; a rule for a tool no rule in "tools" names is warned about', async () => {
  const w = await ruledWorld({ rules: { ...SCAN_RULES, rules: [...SCAN_RULES.rules, { name: 'spare', tool: 'nowhere' }] } });
  try {
    const warning = w.logs.find((e) => e.event === 'warning' && e.message.includes('"spare"'));
    assert.ok(warning && warning.message.includes('names the tool "nowhere", which no rule in "tools" names'));
    const out = await new Promise((done) => {
      const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', BIN, 'keys', '--config', w.configPath], { cwd: w.folder, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      const chunks = [];
      child.stdout.on('data', (c) => chunks.push(c));
      child.on('exit', (code) => done({ code, text: Buffer.concat(chunks).toString('utf8') }));
      child.stdin.end();
    });
    assert.equal(out.code, 0);
    const printed = JSON.parse(out.text);
    assert.deepEqual(printed.agent.software, [{ name: 'Content rules of The test executor', sha256: w.rulesFingerprint }]);
    assert.equal(printed.agent.keys.length, 2, 'the agent\'s keys are still printed');
    const report = await checkConfig(w.settings, w.folder);
    assert.deepEqual(report.contentRules.rules, [...SCAN_RULES.rules.map((x) => x.name), 'spare']);
    assert.ok(report.warnings.some((m) => m.includes('"spare"')));
  } finally {
    await w.close();
  }
  // The setting itself, and a missing or faulty file.
  assert.ok(readSettings({ contentRules: 7 }, '.').problems.some((p) => p.startsWith('contentRules: must be the path')));
  const missing = await world({ open: false, config: { contentRules: 'nowhere.json' } });
  const r1 = await checkConfig(missing.settings, missing.folder);
  assert.match(r1.problems[0], /The rules file .*nowhere\.json \(contentRules\) is missing or empty\./);
  writeFileSync(join(missing.folder, 'nowhere.json'), '{"version": 1, "rules": [{"name": "r", "tool": "t", "when": {"pointer": "x"}}]}');
  const r2 = await checkConfig(missing.settings, missing.folder);
  assert.match(r2.problems[0], /has problems:\n- rules\[0\]\.when\.pointer: must be a JSON Pointer/);
});

test('without a rules file nothing changes: no executor.rules document, no warning about agent.software', async () => {
  const w = await world();
  try {
    await w.client.call('echo', { a: 1 });
    const [stub] = (await bookOf(w)).entries.filter((e) => e.kind === 'stub');
    assert.equal(docs(stub)[RULES_DOCUMENT], undefined);
    assert.ok(!w.logs.some((e) => e.event === 'warning' && e.message.includes('agent.software')));
    assert.equal((await checkConfig(w.settings, w.folder)).contentRules, null);
  } finally {
    await w.close();
  }
});
