// guard-checkbook.mjs: runs in the guard container. Reads the agent's book with the library and prints whether it found a problem.
import { readFileSync } from 'node:fs';
import { checkBook } from 'provared';
const cfg = JSON.parse(readFileSync('/data/guard/executor-http.json', 'utf8'));
const text = readFileSync('/data/guard/books/alpha.jsonl', 'utf8');
const b = await checkBook(text, { issuerKeys: cfg.agents.alpha.issuerKeys });
console.log('lines', text.split('\n').filter(Boolean).length, 'problemFound:', b.summary.problemFound);
console.log('entries', JSON.stringify(b.entries.map((e) => [e.kind, e.countersignature?.state])));
