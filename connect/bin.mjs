#!/usr/bin/env node
// provared-connect: connect a recorder to a book of the application.
//
//   npx provared-connect <line> [--feed <address> --feed-token <file> | --book <file>]
//       the line copied from the book's page: saves the connection beside the
//       recorder, readable by its owner only, and starts the uploader in the
//       background (connect.mjs)
//   npx provared-connect --connection <file> [--feed <address> --feed-token <file> | --book <file>] [--once | --ensure | --same-book]
//       the uploader itself, with a connection file saved before (upload.mjs);
//       this is also how the command started in the background runs
//
// With neither --feed nor --book, the recorder beside Claude Code is taken.
// A word that is not an option is taken for a line, and never printed back.

import { bareWords, connect } from './connect.mjs';
import { USAGE, main } from './upload.mjs';

const argv = process.argv.slice(2);
const bare = bareWords(argv);

let run;
if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
  console.log(USAGE);
  run = Promise.resolve(argv.length === 0 ? 2 : 0);
} else if (bare.length > 0) {
  run = connect(argv);
} else {
  run = main(argv);
}
run.then((code) => { if (code !== null) process.exit(code); }, (e) => { console.error(`provared-connect: ${e.message}`); process.exit(2); });
