// The library "provared", for the Claude Code plugin: found by an exact
// path, and installed by the plugin itself where Claude Code did not.
//
// Every file of this recorder names its library "provared". Installed from
// npm, Node.js finds it in the package's own node_modules. In Claude Code's
// plugin cache it may not be there: Claude Code installs a plugin's
// dependencies from its package-lock.json in some versions and for some
// kinds of marketplace, and not in others (version 2.1.167 did not, for a
// plugin fetched from a git repository). Left to Node.js, the name would
// then be looked for in the folders above the plugin, such as the person's
// home folder, and an unrelated copy could be loaded.
//
// So the plugin's entry (plugin.mjs) never leaves the name to Node.js. It
// takes the library from one of two places, by their exact paths:
//
//   1. node_modules/provared in the plugin's own folder, where Claude Code
//      (or the person, from a copy of the repository) put it;
//   2. library-<fingerprint>/node_modules/provared in the plugin's data
//      folder (Claude Code's ${CLAUDE_PLUGIN_DATA}, kept across updates),
//      which the plugin installs itself, at a session's start or at a
//      command the person runs, with "npm ci --ignore-scripts" from this
//      folder's package-lock.json: the exact version and fingerprint the
//      lockfile names, with no install script run. <fingerprint> is the
//      SHA-256 of the lockfile, so that a lockfile changed by an update
//      gets a library of its own.
//
// It then registers a resolver (Node.js's module.registerHooks) that maps
// "provared" and "provared/..." to that copy's own files, through its
// package.json "exports", in this process, and through NODE_OPTIONS in
// every program it starts (the recorder started in the background, the
// checker). Where no copy is there, the name cannot be loaded, and the error
// says plainly what to do; it is never looked for anywhere else.
//
// Imported by plugin.mjs, and by NODE_OPTIONS ("--import") in the programs
// it starts, where PROVARED_LIBRARY names the copy to use.

import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = dirname(fileURLToPath(import.meta.url));
const LOCK = join(ROOT, 'package-lock.json');

// The SHA-256 of the lockfile, in short: it names the folder the plugin installs the library into.
export const lockFingerprint = () => createHash('sha256').update(readFileSync(LOCK)).digest('hex').slice(0, 16);

/** The version of the library that package-lock.json names. */
export const lockedVersion = () => JSON.parse(readFileSync(LOCK, 'utf8')).packages['node_modules/provared'].version;

/**
 * The plugin's data folder: Claude Code's ${CLAUDE_PLUGIN_DATA} where it
 * names one (to the hooks), or, for a copy in Claude Code's plugin cache
 * (<plugins>/cache/<marketplace>/<plugin>/<version>), the folder Claude
 * Code names for it (<plugins>/data/<plugin>-<marketplace>, every
 * character but a letter, digit, "_" or "-" made "-"), so that the person's
 * own commands find the same copy. Null where neither is known.
 */
export function dataFolder(root = ROOT) {
  if (process.env.CLAUDE_PLUGIN_DATA) return process.env.CLAUDE_PLUGIN_DATA;
  const version = root;
  const plugin = dirname(version);
  const marketplace = dirname(plugin);
  const cache = dirname(marketplace);
  if (basename(cache) !== 'cache' || !existsSync(join(root, '.claude-plugin', 'plugin.json'))) return null;
  const id = `${basename(plugin)}@${basename(marketplace)}`.replace(/[^A-Za-z0-9_-]/g, '-');
  return join(dirname(cache), 'data', id);
}

/** The folder of a copy of the library, by its exact path, or null where none is there. */
export function findLibrary(root = ROOT) {
  const own = join(root, 'node_modules', 'provared');
  if (existsSync(join(own, 'package.json'))) return own;
  const data = dataFolder(root);
  if (!data) return null;
  const installed = join(data, `library-${lockFingerprint()}`, 'node_modules', 'provared');
  return existsSync(join(installed, 'package.json')) ? installed : null;
}

/**
 * Install the library into the plugin's data folder, from package-lock.json,
 * with "npm ci --ignore-scripts", in a folder of its own that holds only a
 * copy of package.json's dependencies and the lockfile, then moved into
 * place whole. Gives the copy's folder, or throws with words a person can
 * act on.
 * @param {{timeoutMs?: number, root?: string}} [o]
 */
export function installLibrary({ timeoutMs = 20000, root = ROOT } = {}) {
  const data = dataFolder(root);
  if (!data) throw new Error(`Provared's library is not installed beside the plugin (${join(root, 'node_modules', 'provared')}), and the plugin's data folder is not known here. In ${root}, run: npm ci --ignore-scripts --omit=dev`);
  const target = join(data, `library-${lockFingerprint()}`);
  if (existsSync(join(target, 'node_modules', 'provared', 'package.json'))) return join(target, 'node_modules', 'provared');
  mkdirSync(data, { recursive: true });
  const work = join(data, `.installing-${randomUUID()}`);
  mkdirSync(work);
  try {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    writeFileSync(join(work, 'package.json'), JSON.stringify({ name: pkg.name, version: pkg.version, private: true, dependencies: pkg.dependencies }, null, 2));
    copyFileSync(LOCK, join(work, 'package-lock.json'));
    // npm on Windows is a command file, which Node.js starts only through the shell; the words are fixed here.
    const windows = process.platform === 'win32';
    const ran = spawnSync(windows ? 'npm.cmd' : 'npm', ['ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund'], { cwd: work, timeout: timeoutMs, encoding: 'utf8', shell: windows, windowsHide: true });
    if (ran.error?.code === 'ETIMEDOUT' || ran.signal) throw new Error(`npm did not finish installing Provared's library within ${Math.round(timeoutMs / 1000)} seconds`);
    if (ran.error) throw new Error(`npm could not be started (${ran.error.code ?? ran.error.message}): it comes with Node.js, and must be on the path`);
    if (ran.status !== 0) throw new Error(`npm could not install Provared's library: ${(ran.stderr || ran.stdout || '').trim().split('\n').slice(-3).join(' ')}`);
    const got = JSON.parse(readFileSync(join(work, 'node_modules', 'provared', 'package.json'), 'utf8'));
    if (got.version !== lockedVersion()) throw new Error(`npm installed version ${got.version} of Provared's library, not ${lockedVersion()}`);
    try {
      renameSync(work, target);
    } catch (e) {
      // Another session put it in place meanwhile: that one is used.
      if (!existsSync(join(target, 'node_modules', 'provared', 'package.json'))) throw e;
    }
    return join(target, 'node_modules', 'provared');
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/**
 * Map "provared" and "provared/..." to one copy's files, through its
 * package.json "exports", in this process and in every program it starts.
 * With no copy, the name fails to load with the words given.
 * @param {string|null} library the copy's folder
 * @param {string} [missing] what the error says where there is no copy
 */
export function useLibrary(library, missing = 'Provared\'s library is not installed for the plugin.') {
  process.env.PROVARED_LIBRARY = library ?? '';
  process.env.PROVARED_LIBRARY_MISSING = missing;
  const option = `--import=${import.meta.url}`;
  const options = process.env.NODE_OPTIONS ?? '';
  if (!options.includes(option)) process.env.NODE_OPTIONS = `${options} ${option}`.trim();
  register();
}

let registered = false;
function register() {
  if (registered) return;
  registered = true;
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier !== 'provared' && !specifier.startsWith('provared/')) return nextResolve(specifier, context);
      const library = process.env.PROVARED_LIBRARY;
      if (!library) throw Object.assign(new Error(process.env.PROVARED_LIBRARY_MISSING || 'Provared\'s library is not installed for the plugin.'), { code: 'ERR_MODULE_NOT_FOUND' });
      const { exports: map } = JSON.parse(readFileSync(join(library, 'package.json'), 'utf8'));
      const entry = map[specifier === 'provared' ? '.' : `.${specifier.slice('provared'.length)}`];
      const target = typeof entry === 'string' ? entry : entry?.default;
      if (!target) throw Object.assign(new Error(`Provared's library at ${library} does not export "${specifier}".`), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
      return { url: pathToFileURL(join(library, target)).href, shortCircuit: true };
    },
  });
}

// Imported through NODE_OPTIONS in a program the plugin started: the copy it was told to use.
if (process.env.PROVARED_LIBRARY !== undefined) register();
