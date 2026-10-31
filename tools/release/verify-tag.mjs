// Checks that a release tag was signed by the founder's release key, and by
// nothing else, before anything is published from it.
//
//   node tools/release/verify-tag.mjs <tag> [<commit>]
//
// The commit is the one the tag must point at; in the publishing workflow
// it is the commit the run was started for (GITHUB_SHA). The checks, in
// order, each stopping everything if it fails:
//
//   1. the tag exists here as an annotated tag (a tag object of its own,
//      not a bare name for a commit), and the name written inside the tag
//      object is the tag's own name;
//   2. it points at the expected commit;
//   3. it carries an SSH signature, and no other kind;
//   4. the file of allowed signers, .github/release-signers, holds exactly
//      one key, and that key's fingerprint is the one written below;
//   5. git, told to trust that file alone, finds the signature good, made
//      by that key.
//
// It reads no private key, and needs none: only the public key in the file.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, readText, fail, tagArgument } from './lib.mjs';

// The fingerprint of the key that has signed every release tag since
// version 0.1.0, as GitHub lists it among the signing keys of the account
// sealwright. To change the release key, change this line and the file
// .github/release-signers together, in a commit of their own.
const RELEASE_KEY = 'SHA256:64cQtHklVRtDUPmbUWpRls28kFcpUnDhFJtpqMHiLbU';
const SIGNERS = '.github/release-signers';
const PRINCIPAL = 'sealwright';

function run(command, args, { allowFailure = false } = {}) {
  const result = spawnSync(command, args, { cwd: ROOT, encoding: 'utf8' });
  if (result.error) fail(`could not run ${command}: ${result.error.message}`);
  if (result.status !== 0 && !allowFailure) fail(`${command} ${args.join(' ')} ended with code ${result.status}: ${(result.stderr || result.stdout).trim()}`);
  return result;
}

const { tag } = tagArgument();
const expected = process.argv[3] ?? process.env.GITHUB_SHA;
if (!expected || !/^[0-9a-f]{40}$/.test(expected)) fail('the commit the tag must point at was not given as 40 hexadecimal characters (second argument, or GITHUB_SHA).');

// 1. An annotated tag, whose own name is the tag's name.
const ref = `refs/tags/${tag}`;
if (run('git', ['rev-parse', '--verify', '--quiet', ref], { allowFailure: true }).status !== 0) fail(`there is no tag ${tag} here.`);
const kind = run('git', ['cat-file', '-t', ref]).stdout.trim();
if (kind !== 'tag') fail(`${tag} is a bare name for a ${kind}, not a signed tag. Make it with "git tag -s".`);
const object = run('git', ['cat-file', 'tag', ref]).stdout;
const header = object.slice(0, object.indexOf('\n\n'));
const field = (name) => {
  const lines = header.split('\n').filter((line) => line.startsWith(`${name} `));
  if (lines.length !== 1) fail(`the tag object of ${tag} does not hold exactly one "${name}" line.`);
  return lines[0].slice(name.length + 1);
};
if (field('tag') !== tag) fail(`the tag object pushed as ${tag} names itself "${field('tag')}".`);
if (field('type') !== 'commit') fail(`${tag} points at a ${field('type')}, not a commit.`);

// 2. The expected commit.
if (field('object') !== expected) fail(`${tag} points at ${field('object')}, not at ${expected}.`);

// 3. An SSH signature, and no other kind.
const sshSignatures = object.split('-----BEGIN SSH SIGNATURE-----').length - 1;
if (sshSignatures !== 1) fail(`${tag} carries ${sshSignatures} SSH signatures; exactly one is needed.`);
if (/-----BEGIN PGP SIGNATURE-----|-----BEGIN SIGNED MESSAGE-----/.test(object)) fail(`${tag} carries a signature of another kind as well.`);

// 4. The file of allowed signers holds the release key alone.
const entries = readText(SIGNERS).split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
if (entries.length !== 1) fail(`${SIGNERS} holds ${entries.length} keys; it must hold exactly one.`);
const parts = entries[0].split(/\s+/);
if (parts[0] !== PRINCIPAL || parts[1] !== 'namespaces="git"' || parts.length !== 4) fail(`${SIGNERS} does not read "${PRINCIPAL} namespaces="git" <type> <key>".`);
const folder = mkdtempSync(join(tmpdir(), 'release-key-'));
let fingerprint;
try {
  writeFileSync(join(folder, 'key.pub'), `${parts[2]} ${parts[3]}\n`);
  fingerprint = run('ssh-keygen', ['-l', '-E', 'sha256', '-f', join(folder, 'key.pub')]).stdout.trim().split(/\s+/)[1];
} finally {
  rmSync(folder, { recursive: true, force: true });
}
if (fingerprint !== RELEASE_KEY) fail(`the key in ${SIGNERS} has the fingerprint ${fingerprint}, not the release key ${RELEASE_KEY}.`);

// 5. The signature itself, with that file as the only trust.
const verify = run('git', ['-c', `gpg.ssh.allowedSignersFile=${join(ROOT, SIGNERS)}`, 'verify-tag', ref], { allowFailure: true });
const said = `${verify.stdout}${verify.stderr}`.trim();
const good = `Good "git" signature for ${PRINCIPAL} with ED25519 key ${RELEASE_KEY}`;
if (verify.status !== 0 || !said.includes(good)) fail(`git did not find a good signature by the release key on ${tag}. It said: ${said || '(nothing)'}`);

console.log(`${tag} is signed by the release key ${RELEASE_KEY} and points at ${expected}.`);
