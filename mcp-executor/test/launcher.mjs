// A launcher, for the tests: it starts the program named in its arguments
// as a child of its own, on its own standard input and output, and passes
// no signal on, as a wrapper script does that does not "exec" its server.
// It writes the child's process id, on a line, to the file LAUNCHER_PIDS
// names, so that a test can see whether the child is still there.

import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';

const child = spawn(process.execPath, process.argv.slice(2), { stdio: 'inherit' });
if (process.env.LAUNCHER_PIDS) appendFileSync(process.env.LAUNCHER_PIDS, `${child.pid}\n`);
child.on('exit', (code) => process.exit(code ?? 1));
// With LAUNCHER_LEAVES the launcher ends by itself after that many milliseconds, and leaves its child running.
if (process.env.LAUNCHER_LEAVES) setTimeout(() => process.exit(0), Number(process.env.LAUNCHER_LEAVES));
