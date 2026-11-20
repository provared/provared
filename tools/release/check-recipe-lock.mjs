// Checks that the claude.ai recipe's lockfile can be built from npm, before
// a release tag carries the recipe (mcp-executor/recipes/claude-ai/compose).
//
//   node tools/release/check-recipe-lock.mjs              the files alone
//   node tools/release/check-recipe-lock.mjs --registry   and npm's own hash
//
// It fails where the lockfile's entry for provared-mcp-executor names
// another version than package.json; where package-lock.provisional.json is
// still beside it (the entry was made from a pack of the working tree, before
// that version was on npm, and its hash is not npm's); and, with
// --registry, where the entry's hash is not the one npm gives for that
// version (npm view provared-mcp-executor@<version> dist.integrity: the one
// request this makes, by the npm command). --recipe <folder> names another
// folder, for its tests.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ROOT, fail } from './lib.mjs';

const PACKAGE = 'provared-mcp-executor';
const args = process.argv.slice(2);
const at = args.indexOf('--recipe');
// Only the word after --recipe is its folder: without --recipe, every word must be an option (X367).
const allowed = ['--registry', ...(at >= 0 ? ['--recipe', args[at + 1]] : [])];
for (const a of args) if (!allowed.includes(a)) fail(`"${a}" is not an option: give --registry, --recipe <folder>, or nothing.`);
if (at >= 0 && (args[at + 1] === undefined || args[at + 1].startsWith('--'))) fail('--recipe needs a folder after it.');
const folder = at >= 0 ? resolve(args[at + 1]) : join(ROOT, 'mcp-executor', 'recipes', 'claude-ai', 'compose');
const registry = args.includes('--registry');

const json = (name) => {
  try {
    return JSON.parse(readFileSync(join(folder, name), 'utf8'));
  } catch (e) {
    return fail(`${join(folder, name)} could not be read as JSON (${e.code ?? e.message}).`);
  }
};
const wanted = json('package.json').dependencies?.[PACKAGE];
const entry = json('package-lock.json').packages?.[`node_modules/${PACKAGE}`];
if (typeof wanted !== 'string') fail(`package.json names no version of ${PACKAGE}.`);
if (!entry || entry.version !== wanted) fail(`package-lock.json gives ${PACKAGE} ${entry?.version ?? '(none)'}, and package.json ${wanted}.`);
if (entry.resolved !== `https://registry.npmjs.org/${PACKAGE}/-/${PACKAGE}-${wanted}.tgz`) fail(`package-lock.json resolves ${PACKAGE} at ${entry.resolved}, not at npm.`);
if (existsSync(join(folder, 'package-lock.provisional.json'))) {
  fail(`the recipe's lockfile is provisional: its entry for ${PACKAGE} ${wanted} was made from a pack of the working tree, not from npm, and npm ci would stop on it. Publish ${PACKAGE} ${wanted}, run "npm install --package-lock-only --ignore-scripts" in ${folder}, take package-lock.provisional.json away, and run this check again with --registry.`);
}
if (registry) {
  let published;
  try {
    published = execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['view', `${PACKAGE}@${wanted}`, 'dist.integrity'], { encoding: 'utf8', shell: process.platform === 'win32' }).trim();
  } catch (e) {
    fail(`npm could not say the hash of ${PACKAGE} ${wanted} (${String(e.stderr ?? e.message).trim().split('\n')[0]}): is it published?`);
  }
  if (published !== entry.integrity) fail(`package-lock.json gives ${PACKAGE} ${wanted} the hash ${entry.integrity}, and npm gives ${published}. Make the lockfile again from npm.`);
}
console.log(`The recipe's lockfile gives ${PACKAGE} ${wanted} from npm${registry ? ', with the hash npm gives' : ' (its hash not compared with npm: --registry does that)'}.`);
