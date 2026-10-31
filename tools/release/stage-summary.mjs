// Says what "npm stage publish" staged, so that the founder approves on
// npmjs.com exactly the version this run staged, and no other.
//
//   node tools/release/stage-summary.mjs <file with the output of "npm stage publish --json"> <version>
//
// It reads the stage ID and the package's integrity value (the SHA-512 of
// the package file, as npm writes it) from npm's own answer, and writes
// both in a notice on the run's page and in the job's summary, with the
// commands that check and approve that one stage. Anything of an
// unexpected form stops the job with a message in words: the version is
// then staged, but cannot be told apart from another, so it must not be
// approved without checking.
//
// npm's answer, as read on 31 October 2026 from npm's own code
// (lib/commands/publish.js): with --json, the package's summary (with
// "id", "integrity" and "shasum") gains "stageId". Some versions of npm
// write that summary under the package's name; both shapes are read.

import { readFileSync, appendFileSync } from 'node:fs';
import { fail, VERSION } from './lib.mjs';

const [file, version] = process.argv.slice(2);
if (!file) fail('the file with the output of "npm stage publish --json" was not given.');
if (!version || !VERSION.test(version)) fail('the version was not given as three whole numbers.');

let answer;
try {
  const text = readFileSync(file, 'utf8');
  const start = text.indexOf('{');
  if (start < 0) throw new Error('no JSON object');
  answer = JSON.parse(text.slice(start));
} catch (error) {
  fail(`npm's answer could not be read as JSON (${error.message}).`);
}

// The summary itself, or the one summary written under the package's name.
const summary = typeof answer?.integrity === 'string' ? answer : answer?.provared;
if (!summary || typeof summary !== 'object') fail('npm\'s answer does not hold a summary of the package "provared".');

const { stageId, integrity, id } = summary;
if (id !== undefined && id !== `provared@${version}`) fail(`npm staged "${id}", not provared@${version}.`);
if (typeof stageId !== 'string' || !/^[A-Za-z0-9._-]{1,200}$/.test(stageId)) fail('npm\'s answer gives no stage ID, or one of an unexpected form. Do not approve any staged version before checking it with "npm stage list provared".');
if (typeof integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity)) fail('npm\'s answer gives no SHA-512 integrity value, or one of an unexpected form.');

console.log(`::notice title=Staged on npm, not public yet::provared ${version} is staged with the stage ID ${stageId} and the integrity value ${integrity}. Approve only this stage ID; see the job summary.`);

const lines = [
  `## provared ${version} is staged on npm, and is not public yet`,
  '',
  `- Stage ID: \`${stageId}\``,
  `- Integrity value: \`${integrity}\``,
  '',
  'To approve it, with your passkey, approve only this stage ID:',
  '',
  '```',
  'npm stage list provared',
  `npm stage view ${stageId}`,
  `npm stage approve ${stageId}`,
  '```',
  '',
  'Check first that the integrity value npm shows for that stage is the one above. Reject any other staged version of provared with `npm stage reject <stage-id>`.',
  '',
];
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`);
console.log(lines.join('\n'));
