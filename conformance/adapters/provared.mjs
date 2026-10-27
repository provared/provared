#!/usr/bin/env node
// The adapter for Provared's own JavaScript library: it answers each case
// exactly as test/vectors.test.mjs does, through the same table of answers
// (test/helpers/vectors.mjs), so the kit can be run against Provared
// itself. It needs a copy of the repository, not the npm package.
//
//   node conformance/run.mjs --words -- node --disable-warning=ExperimentalWarning conformance/adapters/provared.mjs
//
// It reads one request to a line from standard input and writes one reply
// to a line to standard output, in the order asked (conformance/README.md).
// A line ends only at a line feed; the kit writes every other character
// outside ASCII as an escape.

import { ANSWER } from '../../test/helpers/vectors.mjs';

async function reply(line) {
  const request = JSON.parse(line);
  const answer = ANSWER[request.function];
  return answer
    ? { id: request.id, answer: await answer(request.case) }
    : { id: request.id, skip: `no answer for the function ${request.function}` };
}

let rest = '';
let queue = Promise.resolve();
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  rest += chunk;
  let at;
  while ((at = rest.indexOf('\n')) >= 0) {
    const line = rest.slice(0, at).trim();
    rest = rest.slice(at + 1);
    if (line === '') continue;
    queue = queue.then(async () => process.stdout.write(`${JSON.stringify(await reply(line))}\n`));
  }
});
