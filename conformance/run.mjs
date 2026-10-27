#!/usr/bin/env node
// The conformance kit's command. conformance/README.md says how to use it.
//
//   node conformance/run.mjs [options] -- <command> [arguments...]
//
// Ends with code 0 only where every case compared matched, 1 where any did
// not (or none was compared), and 2 where the command itself was wrong.

import { writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, readSets, runKit } from './kit.mjs';

const HELP = `The Provared conformance kit.

  node conformance/run.mjs [options] -- <command> [arguments...]

The command after "--" starts your adapter. The kit writes one case to it
as one line of JSON, and reads one line of JSON back (conformance/README.md).

Options:
  --words             compare every value, words meant for people included
                      (Provared's own libraries must pass this way)
  --file <name>       only this file of test-vectors/ (may be given again)
  --vectors <folder>  the folder of shared test files (default: test-vectors/)
  --timeout <seconds> the longest wait for one answer (default: 60)
  --show-all          list every failure, not only the first 20
  --report <file>     also write the whole report as JSON to this file
  --quiet             print only the totals and the verdict
  --help              this text
`;

function fail(text) {
  process.stderr.write(`${text}\n\nnode conformance/run.mjs --help says how to use it.\n`);
  process.exit(2);
}

const argv = process.argv.slice(2);
const split = argv.indexOf('--');
const options = split < 0 ? argv : argv.slice(0, split);
const adapter = split < 0 ? [] : argv.slice(split + 1);

const settings = { words: false, files: [], vectors: null, timeout: 60, showAll: false, report: null, quiet: false };
for (let i = 0; i < options.length; i++) {
  const o = options[i];
  const value = () => {
    if (i + 1 >= options.length) fail(`${o} needs a value.`);
    return options[++i];
  };
  if (o === '--help' || o === '-h') {
    process.stdout.write(HELP);
    process.exit(0);
  } else if (o === '--words') settings.words = true;
  else if (o === '--file') settings.files.push(value());
  else if (o === '--vectors') settings.vectors = value();
  else if (o === '--timeout') {
    const t = Number(value());
    if (!Number.isFinite(t) || t <= 0) fail('--timeout takes a number of seconds above 0.');
    settings.timeout = t;
  } else if (o === '--show-all') settings.showAll = true;
  else if (o === '--report') settings.report = value();
  else if (o === '--quiet') settings.quiet = true;
  else fail(`Unknown option: ${o}`);
}
if (adapter.length === 0) fail('Give the command that starts your adapter after "--".');

const folder = settings.vectors ? resolve(settings.vectors) : join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');
let sets;
try {
  sets = readSets(folder, settings.files);
} catch (e) {
  fail(`Could not read the shared test files: ${e.message}`);
}

const report = await runKit({
  command: adapter[0],
  args: adapter.slice(1),
  sets,
  words: settings.words,
  timeout: settings.timeout * 1000,
});
const lines = describe(report, { showFailures: settings.showAll ? Infinity : 20 });
process.stdout.write(`${(settings.quiet ? lines.slice(-2) : lines).join('\n')}\n`);
if (settings.report) writeFileSync(settings.report, `${JSON.stringify(report, null, 1)}\n`);
process.exit(report.ok ? 0 : 1);
