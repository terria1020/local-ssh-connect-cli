#!/usr/bin/env node
'use strict';

const { main } = require('./lib/cli');

// Ctrl-C / SIGTERM: exit through process 'exit' so child ssh process groups get cleaned up.
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => process.exit(sig === 'SIGINT' ? 130 : 143));

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`[lssh] unexpected error: ${e && e.stack ? e.stack : e}\n`);
    process.exitCode = 70;
  }
);
