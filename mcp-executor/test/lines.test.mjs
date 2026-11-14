// One message, one line (DESIGN.md, X248). A message the executor writes
// to the tool server's standard input is one line for a reader of UTF-8.
// A tool server that ends a line at more than the line feed
// (node:readline ends one at a bare carriage return, U+2028 and U+2029; a
// text reader with universal newlines, which Python's io.TextIOWrapper
// gives unless told otherwise, as the official Python SDK's stdio server
// uses, and how Python opens its standard input on Windows, ends one at a
// bare carriage return) was otherwise
// handed one message of the agent's as several lines, and read a piece of
// it as a message of its own: a call the executor never checked. These
// tests send such messages in front of a made-up server that reads each
// way (FAKE_LINE_ENDS in fake-server.mjs). Nothing leaves this computer.

import './local-library.mjs'; // first: "provared" is this repository's own library
import assert from 'node:assert/strict';
import { test } from 'node:test';

const { checkBook } = await import('provared');
const { RESULT_DOCUMENT } = await import('../executor.mjs');
const { oneLine } = await import('../jsonrpc.mjs');
const { until, world } = await import('./world.mjs');

const stubsOf = (checked) => checked.entries.filter((e) => e.kind === 'stub');
const docs = (stub) => Object.fromEntries(stub.content.details.map((d) => [d.name, d.sha256]));
const ODD = 'a\u2028b\u2029c\u0085d';
const HIDDEN = { jsonrpc: '2.0', id: 'hidden', method: 'tools/call', params: { name: 'order', arguments: { total: 999999 } } };
/** A ping that holds a whole tools/call between two line ends, where JSON allows them: between the values of a list. */
const carrier = (lineEnd, id = 'outer') => `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"method":"ping","params":{"a":[${lineEnd}${JSON.stringify(HIDDEN)}${lineEnd}]}}`;

test('oneLine: the same JSON, with no line end of any kind in it', () => {
  for (const text of [carrier('\n'), carrier('\r'), carrier('\r\n'), JSON.stringify({ a: ODD, [ODD]: [ODD] }), '{"a":\t1 }', '{"a":"\\n\\r\\u2028"}']) {
    const line = oneLine(text);
    assert.ok(!/[\n\r\u0085\u2028\u2029]/.test(line), JSON.stringify(text));
    assert.deepEqual(JSON.parse(line), JSON.parse(text));
  }
  assert.equal(oneLine('{"a":"\u2028"}'), '{"a":"\\u2028"}');
  assert.equal(oneLine('{"a":1}'), '{"a":1}');
});

for (const [reader, how] of [['readline', 'with node:readline'], ['universal', 'as a text reader with universal newlines does (Python\'s io.TextIOWrapper, unless told otherwise)']]) {
  test(`stdio, in front of a server that reads ${how}: a call hidden between carriage returns is not run, and a text with U+2028, U+2029 or U+0085 is answered`, async () => {
    const w = await world({ env: { FAKE_LINE_ENDS: { value: reader } } });
    const book = () => checkBook(w.executor.writer.book(), { issuerKeys: w.settings.agent.issuerKeys });
    try {
      // One ping to the executor; to a reader that ends a line at a carriage return, three lines, the second a call of "order" for 999,999.
      w.client.raw(`${carrier('\r', 'outer-1')}\n`);
      w.client.raw(`${carrier(' \r\t\r ', 'outer-2')}\n`);
      for (const id of ['outer-1', 'outer-2']) assert.deepEqual((await until(() => w.client.others.find((m) => m.id === id))).result, {}, 'the ping is answered');
      assert.equal(w.client.others.find((m) => m.id === 'hidden'), undefined, 'no answer to a call the agent never sent as one');
      assert.equal(stubsOf(await book()).length, 0);
      // A text with the odd line ends reaches the tool whole, and comes back as it was sent.
      w.client.raw(`${JSON.stringify({ jsonrpc: '2.0', id: 'odd', method: 'tools/call', params: { name: 'echo', arguments: { text: ODD } } })}\n`);
      const echoed = await until(() => w.client.others.find((m) => m.id === 'odd'));
      assert.equal(echoed.result?.structuredContent.args.text, ODD, JSON.stringify(echoed));
      const seen = w.fakeSeen();
      assert.deepEqual(seen.filter((e) => e.seen).map((e) => e.seen.method), ['ping', 'ping', 'tools/call'], 'the server read each message once');
      assert.equal(seen.filter((e) => e.seen?.params?.name === 'order').length, 0, 'and ran no call of "order"');
      assert.equal(seen.filter((e) => e.notJson).length, 0, 'and read no piece of a message');
      const [stub] = stubsOf(await book());
      assert.ok(docs(stub)[RESULT_DOCUMENT], 'the receipt names the result, not an outcome that is not known');
    } finally {
      await w.close();
    }
  });
}
