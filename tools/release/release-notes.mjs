// Writes the text of a GitHub release from the change log, in the shape of
// the releases made by hand up to version 0.6.0.
//
//   node tools/release/release-notes.mjs <tag> <SHA-256 of provared-check.html>
//
// Read from the environment, as the publishing workflow sets them (each
// may be empty):
//   NPM_STAGED        "true" where this run staged the npm package; it is
//                     public only once the founder approves it on npmjs.com
//   NPM_PRESENT       "true" where npm already held this version when the
//                     run began, so that nothing was staged
//   PYTHON_PUBLISHED  the Python projects this run published, as
//                     "name version" separated by commas
//   PYTHON_KEPT       the Python projects already on the index at their
//                     version, and so not published again, in the same form
//
// The text: one line saying what the version is; the opening paragraphs of
// the change log's newest section (the text before its first item), or,
// where it has none, the bold first words of each item; what this run
// published and from where; the checking page as one file and its
// fingerprint; and where the full list of changes is. Lines that the
// change log wraps are joined, one paragraph to a line.

import { changelogTop, fail, tagArgument } from './lib.mjs';

const { tag, version } = tagArgument();
const sha256 = process.argv[3];
if (!sha256 || !/^[0-9a-f]{64}$/.test(sha256)) fail('the SHA-256 of provared-check.html was not given as 64 hexadecimal characters.');

const list = (text) => (text ?? '').split(',').map((item) => item.trim()).filter(Boolean).map((item) => {
  const [name, itemVersion, ...rest] = item.split(' ');
  if (!name || !itemVersion || rest.length) fail(`"${item}" is not "name version".`);
  return `\`${name}\` ${itemVersion}`;
});
const and = (items) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);

const { body } = changelogTop();
const paragraphs = [];
let current = [];
for (const line of body) {
  if (/^- /.test(line)) break;
  if (line.trim() === '') {
    if (current.length) paragraphs.push(current.join(' '));
    current = [];
  } else {
    current.push(line.trim());
  }
}
if (current.length) paragraphs.push(current.join(' '));

const opening = [];
if (paragraphs.length) {
  opening.push(...paragraphs);
} else {
  // Each top-level item, with its wrapped lines (indented by two spaces) joined.
  const items = [];
  for (const line of body) {
    if (/^- /.test(line)) items.push(line.slice(2).trim());
    else if (/^ {2}\S/.test(line) && items.length) items[items.length - 1] += ` ${line.trim()}`;
  }
  const leads = items.filter((item) => item.startsWith('**')).map((item) => {
    const end = item.indexOf('**', 2);
    return end > 2 ? `- ${item.slice(0, end + 2)}` : null;
  }).filter(Boolean);
  if (leads.length) opening.push(`The main changes:\n\n${leads.join('\n')}`);
}

const npmStaged = process.env.NPM_STAGED === 'true';
const npmPresent = process.env.NPM_PRESENT === 'true';
const pythonPublished = list(process.env.PYTHON_PUBLISHED);
const pythonKeptItems = (process.env.PYTHON_KEPT ?? '').split(',').map((item) => item.trim()).filter(Boolean);
const pythonKept = list(process.env.PYTHON_KEPT);
// The library itself already on the index at this very version: the tag is
// new, so an earlier attempt of this run, or a publication by hand, put it there.
const libraryKept = pythonKeptItems.includes(`provared ${version}`);

const repository = process.env.GITHUB_REPOSITORY || 'provared/provared';
const text = [
  `Version ${version}${version.startsWith('0.') ? ', a draft' : ''}. Published as it is, by one author in their own time.`,
  ...opening,
];
if (npmStaged || pythonPublished.length) {
  const done = [];
  if (pythonPublished.length) done.push(`it published ${and(pythonPublished)} on the Python Package Index, where each file has an attestation naming this repository and this workflow`);
  if (npmStaged) done.push(`it staged \`provared\` ${version} on npm, where it becomes public, and installable, only once the author approves it on npmjs.com with their passkey; until then \`npm install provared@${version}\` does not find it`);
  text.push(`**From the signed tag ${tag}**, the workflow \`.github/workflows/publish.yml\` used each registry's trusted publishing, with no stored password or token: ${done.join('; and ')}.`);
}
if (npmPresent) {
  text.push(`Not staged on npm again, because npm already held \`provared\` ${version} when this run began: an earlier attempt of this run staged it and it was approved, or it was published by hand.`);
}
if (pythonKept.length) {
  text.push(`Not published again, because the Python Package Index already holds that version: ${and(pythonKept)}.${libraryKept ? ` The library itself, \`provared\` ${version}, was put there by an earlier attempt of this run or by hand.` : ''}`);
}
text.push(
  'Every published version stays on npm and the Python Package Index.',
  `Attached: \`provared-check.html\`, the checking page as one file, which opens from the disk and makes no request. SHA-256: \`${sha256}\`.`,
  `The full list of changes is in [\`CHANGELOG.md\`](https://github.com/${repository}/blob/${tag}/CHANGELOG.md). *Evidence, not a verdict.*`,
);
process.stdout.write(`${text.join('\n\n')}\n`);
