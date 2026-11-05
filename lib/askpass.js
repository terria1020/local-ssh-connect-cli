'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Temporary SSH_ASKPASS helper that answers *passphrase* prompts from $LSSH_PASSPHRASE.
 * The secret is never written to disk or argv -- only the environment of the ssh child.
 * Any other prompt (host-key confirmation, password, ...) is refused, so it fails closed.
 */
const SCRIPT = `#!/bin/sh
case "$1" in
  *assphrase*) printf '%s\\n' "$LSSH_PASSPHRASE" ;;
  *) exit 1 ;;
esac
`;

let current = null;

function createAskpass() {
  if (current) return current;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lssh-askpass-'));
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, 'askpass.sh');
  fs.writeFileSync(file, SCRIPT, { mode: 0o700 });
  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    if (current && current.path === file) current = null;
  };
  current = { path: file, cleanup };
  process.on('exit', cleanup);
  return current;
}

module.exports = { createAskpass, SCRIPT };
