// Asks npm or the Python Package Index whether a version of a package is
// already published.
//
//   node tools/release/registry-has.mjs npm provared 0.7.0
//   node tools/release/registry-has.mjs pypi provared-langchain 0.3.0
//
// It prints "present" or "absent". It decides only on a clear answer: the
// registry's page for that exact version is found (200, and the page names
// that version) or is not found (404). Any other answer is asked again,
// three times in all, a few seconds apart, and then stops everything with
// code 1, so that a registry that is down is never read as "absent".
// A version that was published and then yanked on the Python Package Index
// counts as present: its file names cannot be used again.

import { fileURLToPath } from 'node:url';

const ADDRESS = {
  npm: (name, version) => `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
  pypi: (name, version) => `https://pypi.org/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`,
};
const VERSION_OF = {
  npm: (json) => json.version,
  pypi: (json) => json.info && json.info.version,
};
const TRIES = 3;

/** True where the version is published, false where it is not; throws on anything unclear. */
export async function registryHas(registry, name, version) {
  if (!ADDRESS[registry]) throw new Error(`unknown registry "${registry}"; use npm or pypi.`);
  const address = ADDRESS[registry](name, version);
  let last = '';
  for (let attempt = 1; attempt <= TRIES; attempt++) {
    try {
      const answer = await fetch(address, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(30_000) });
      if (answer.status === 404) return false;
      if (answer.status === 200) {
        const json = await answer.json();
        if (VERSION_OF[registry](json) !== version) throw new Error(`${address} answered for the version ${VERSION_OF[registry](json)}, not ${version}.`);
        return true;
      }
      last = `${address} answered ${answer.status}.`;
    } catch (error) {
      if (/answered for the version/.test(error.message)) throw error;
      last = `${address} could not be read: ${error.message}`;
    }
    if (attempt < TRIES) await new Promise((resolve) => setTimeout(resolve, 5_000 * attempt));
  }
  throw new Error(`no clear answer after ${TRIES} tries. ${last}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [registry, name, version] = process.argv.slice(2);
  if (!registry || !name || !version) {
    console.error('Give the registry (npm or pypi), the package name and the version.');
    process.exit(1);
  }
  try {
    console.log((await registryHas(registry, name, version)) ? 'present' : 'absent');
  } catch (error) {
    console.error(`Stopped: ${error.message}`);
    process.exit(1);
  }
}
