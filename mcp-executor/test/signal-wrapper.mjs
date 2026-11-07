// Runs bin.mjs with the arguments given, and raises in this process the
// signal the parent names in a message over the IPC channel. Windows
// delivers no SIGINT or SIGTERM to a child process (kill is final), so a
// test of the command's signal handlers sends the name here instead and
// the same handlers run. On other platforms the test sends the real signal.

process.on('message', (m) => {
  if (m === 'SIGINT' || m === 'SIGTERM') process.emit(m, m);
});
await import('../bin.mjs');
