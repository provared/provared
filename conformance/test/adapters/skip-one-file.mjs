// An adapter for the kit's own tests: answers as Provared's own library
// does, but sets aside every case of canonical-json.json.
import { ANSWER } from '../../../test/helpers/vectors.mjs';

let rest = '';
let queue = Promise.resolve();
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  rest += chunk;
  let at;
  while ((at = rest.indexOf('\n')) >= 0) {
    const line = rest.slice(0, at);
    rest = rest.slice(at + 1);
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    queue = queue.then(async () => {
      const reply = r.file === 'canonical-json.json' ? { id: r.id, skip: 'not built here' } : { id: r.id, answer: await ANSWER[r.function](r.case) };
      process.stdout.write(`${JSON.stringify(reply)}\n`);
    });
  }
});
