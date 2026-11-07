'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { ConfigError } = require('./errors');

/**
 * Temporary SSH_ASKPASS helper that answers *passphrase* prompts from $LSSH_PASSPHRASE.
 * The secret is never written to disk or argv -- only the environment of the ssh child.
 * Any other prompt (host-key confirmation, password, ...) is refused, so it fails closed.
 */
const SCRIPT = `#!/bin/sh
[ -n "\${LSSH_PASSPHRASE+x}" ] || exit 1
case "$1" in
  *assphrase*) printf '%s\\n' "$LSSH_PASSPHRASE" ;;
  *) exit 1 ;;
esac
`;

let current = null;
let exitHookInstalled = false;

/** Create (or reuse) the helper. Throws ConfigError if it cannot be created. */
function createAskpass() {
  if (current) return current;
  let dir;
  let file;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lssh-askpass-'));
    fs.chmodSync(dir, 0o700);
    file = path.join(dir, 'askpass.sh');
    fs.writeFileSync(file, SCRIPT, { mode: 0o700 });
  } catch (e) {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    throw new ConfigError(`Cannot create the temporary SSH_ASKPASS helper (needed for passphrase keys): ${e.message}`);
  }
  const cleanup = () => {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    if (current && current.path === file) current = null;
  };
  current = { path: file, cleanup };
  if (!exitHookInstalled) {
    exitHookInstalled = true;
    process.on('exit', () => { if (current) current.cleanup(); }); // safety net, installed once
  }
  return current;
}

module.exports = { createAskpass, SCRIPT };
