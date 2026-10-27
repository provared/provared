// An adapter that goes wrong on purpose, for the kit's own tests. It
// answers as Provared's own library does, except as its first argument
// says:
//   wrong-code    every refusal gets another code
//   wrong-words   every refusal gets other words (the codes stay right)
//   skip          every case is set aside
//   crash         stops at the case named by the second argument
//   hang          never answers the case named by the second argument
//   junk          prints a line that is not JSON for that case
//   wrong-id      answers that case under another number
//   crash-always  stops at once, every time it is started

import { ANSWER } from '../../../test/helpers/vectors.mjs';

const [mode, target] = process.argv.slice(2);
if (mode === 'crash-always') process.exit(3);

const write = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);

async function handle(request) {
  const hit = request.case.name === target;
  if (mode === 'skip') return write({ id: request.id, skip: 'not built here' });
  if (hit && mode === 'crash') {
    process.stderr.write('the faulty adapter stops here\n');
    process.exit(5);
  }
  if (hit && mode === 'hang') return new Promise(() => {});
  if (hit && mode === 'junk') return process.stdout.write('this is not JSON\n');
  const answer = await ANSWER[request.function](request.case);
  if (answer.refused && mode === 'wrong-code') answer.refused.code = 'not-the-right-code';
  if (answer.refused && mode === 'wrong-words') answer.refused.message = 'Other words that say the same.';
  write({ id: hit && mode === 'wrong-id' ? request.id + 1000 : request.id, answer });
}

let rest = '';
let queue = Promise.resolve();
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  rest += chunk;
  let at;
  while ((at = rest.indexOf('\n')) >= 0) {
    const line = rest.slice(0, at);
    rest = rest.slice(at + 1);
    if (line.trim()) queue = queue.then(() => handle(JSON.parse(line)));
  }
});
