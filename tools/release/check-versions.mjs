// Checks that a release tag, the packages and the change log all name the
// same version, before anything is published.
//
//   node tools/release/check-versions.mjs <tag>
//
// The tag v0.7.0 needs: "version": "0.7.0" in package.json, which must not
// be marked private; version = "0.7.0" in python/pyproject.toml; and, as
// the first section heading of CHANGELOG.md, "## 0.7.0 (<day> <month>
// <year>)", so that a change log still headed "## Unreleased" stops the
// release. The framework packages have versions of their own and are not
// compared with the tag. The version is written out for the next steps.

import { npmPackage, pythonProject, changelogTop, setOutput, fail, tagArgument } from './lib.mjs';

const MONTHS = 'January|February|March|April|May|June|July|August|September|October|November|December';

const { tag, version } = tagArgument();
let npm, python, top;
try {
  npm = npmPackage();
  python = pythonProject('python');
  top = changelogTop();
} catch (error) {
  fail(error.message);
}

if (npm.name !== 'provared') fail(`package.json names the package "${npm.name}", not "provared".`);
if (npm.private) fail('package.json is marked private, so npm would refuse to publish it.');
if (npm.version !== version) fail(`the tag is ${tag}, but package.json gives the version ${npm.version}.`);
if (python.name !== 'provared') fail(`python/pyproject.toml names the project "${python.name}", not "provared".`);
if (python.version !== version) fail(`the tag is ${tag}, but python/pyproject.toml gives the version ${python.version}.`);

// eslint-disable-next-line security/detect-non-literal-regexp -- built from a version that tagArgument() has checked is three whole numbers, its full stops escaped.
const heading = new RegExp(`^## ${version.replace(/\./g, '\\.')} \\((0?[1-9]|[12][0-9]|3[01]) (${MONTHS}) (20[0-9]{2})\\)$`);
if (!heading.test(top.heading)) fail(`the first section of CHANGELOG.md is headed "${top.heading}", not "## ${version} (<day> <month> <year>)".`);
if (!top.body.some((line) => line.trim())) fail('the first section of CHANGELOG.md is empty.');

console.log(`${tag}: package.json, python/pyproject.toml and CHANGELOG.md all give ${version}.`);
setOutput('version', version);
