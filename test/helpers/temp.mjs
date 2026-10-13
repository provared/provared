// A temporary folder for a test file, removed when that file's tests end,
// so that test runs leave nothing behind in the computer's temporary folder.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const made = [];
process.on('exit', () => {
  for (const dir of made) rmSync(dir, { recursive: true, force: true });
});

export function tempFolder(prefix = 'provared-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}
