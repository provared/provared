// Small helpers shared by the release scripts in tools/release/. They use
// only Node.js itself: no package is installed to run them.

import { readFileSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const ROOT = fileURLToPath(new URL('../..', import.meta.url));

// The three Python projects that may be published from this repository, by
// their folder. The library is always first.
export const PYTHON_PROJECTS = [
  'python',
  'python/integrations/provared-langchain',
  'python/integrations/pydantic-ai-provared',
];

// A version as the tags and the packages write it: three whole numbers,
// with no "pre-release" part. Anything else is refused.
export const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

export function readText(path) {
  return readFileSync(ROOT + path, 'utf8').replace(/\r\n/g, '\n');
}

/**
 * The name and the version in the [project] table of a pyproject.toml.
 * Only the plain form `key = "value"` is read, which is how this
 * repository writes them; anything else is an error, never a guess.
 */
export function pythonProject(folder) {
  const lines = readText(`${folder}/pyproject.toml`).split('\n');
  const start = lines.findIndex((line) => line.trim() === '[project]');
  if (start < 0) throw new Error(`${folder}/pyproject.toml has no [project] table.`);
  const found = {};
  for (const line of lines.slice(start + 1)) {
    if (/^\s*\[/.test(line)) break;
    const match = /^(name|version)\s*=\s*"([^"]*)"\s*$/.exec(line);
    if (match) {
      if (found[match[1]] !== undefined) throw new Error(`${folder}/pyproject.toml gives "${match[1]}" twice.`);
      found[match[1]] = match[2];
    }
  }
  if (!found.name || !found.version) throw new Error(`${folder}/pyproject.toml does not give both name and version in [project].`);
  if (!VERSION.test(found.version)) throw new Error(`${folder}/pyproject.toml gives the version "${found.version}", which is not three whole numbers.`);
  return { folder, name: found.name, version: found.version };
}

/** The name and version in package.json. */
export function npmPackage() {
  const json = JSON.parse(readText('package.json'));
  if (typeof json.name !== 'string' || typeof json.version !== 'string') throw new Error('package.json does not give a name and a version.');
  return { name: json.name, version: json.version, private: json.private === true };
}

/**
 * The newest section of CHANGELOG.md: its heading line and the lines under
 * it, up to the next heading of the same level.
 */
export function changelogTop() {
  const lines = readText('CHANGELOG.md').split('\n');
  const start = lines.findIndex((line) => line.startsWith('## '));
  if (start < 0) throw new Error('CHANGELOG.md has no section headed "## ".');
  let end = lines.findIndex((line, i) => i > start && line.startsWith('## '));
  if (end < 0) end = lines.length;
  return { heading: lines[start], body: lines.slice(start + 1, end) };
}

/** Writes name=value for the next steps of a GitHub workflow, where there is one. */
export function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const text = String(value);
  if (/[\r\n]/.test(text)) throw new Error(`the output ${name} holds a line break.`);
  if (file) appendFileSync(file, `${name}=${text}\n`);
  console.log(`${name}=${text}`);
}

/** Stops with a message in words, and the code 1. */
export function fail(message) {
  console.error(`Stopped: ${message}`);
  process.exit(1);
}

/** A tag name, from the first argument or from the workflow's own tag. */
export function tagArgument() {
  const tag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
  if (!tag) fail('no tag was given. Give it as the first argument, for example v0.7.0.');
  const match = /^v(.*)$/.exec(tag);
  if (!match || !VERSION.test(match[1])) fail(`the tag "${tag}" is not "v" followed by three whole numbers, such as v0.7.0.`);
  return { tag, version: match[1] };
}
