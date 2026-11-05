'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

/** Collects everything written to it (stand-in for process.stdout/stderr). */
class Sink {
  constructor() { this.data = ''; }
  write(s) { this.data += s; return true; }
}

function mkTmp(prefix = 'lssh-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * Fake `ssh`: the last two args are `user@host` and the remote command.
 *   host "authfail"  -> Permission denied, exit 255
 *   host "flaky"     -> first call "Connection reset by ...", exit 255; then succeeds
 *   host "alwaysreset" -> always "Connection reset by ...", exit 255
 *   host "remote3"   -> prints to stdout, stderr "Permission denied" (from remote), exit 3
 *   host "slow"      -> sleeps 5s
 *   host "localexec*" -> actually runs the remote command locally with sh -c (transfer tests)
 *   otherwise        -> echoes "host=<h> cmd=<c>" and, if stdin is piped, "stdin=<data>"
 * All argv is appended (one line) to $FAKE_LOG when set.
 */
function writeFakeSsh(dir) {
  const p = path.join(dir, 'fake-ssh');
  fs.writeFileSync(p, `#!/bin/bash
[ -n "$FAKE_LOG" ] && echo "ssh $*" >> "$FAKE_LOG"
if [ -n "$FAKE_ENV_FILE" ]; then
  { printf 'askpass=%s\nrequire=%s\npassphrase=%s\n' "$SSH_ASKPASS" "$SSH_ASKPASS_REQUIRE" "$LSSH_PASSPHRASE"
    [ -x "$SSH_ASKPASS" ] && printf 'prompt_answer=%s\n' "$("$SSH_ASKPASS" "Enter passphrase for key 'k':")"; } > "$FAKE_ENV_FILE"
fi
cmd="\${@: -1}"
target="\${@: -2:1}"
host="\${target#*@}"
[ -n "$FAKE_ENV_LOG" ] && echo "$host|$LSSH_PASSPHRASE|$SSH_ASKPASS" >> "$FAKE_ENV_LOG"
case "$host" in
  authfail) echo "Permission denied (publickey,password)." >&2; exit 255;;
  flaky)
    n=$(cat "$FAKE_COUNT" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$FAKE_COUNT"
    if [ "$n" -lt 2 ]; then echo "kex_exchange_identification: Connection reset by peer" >&2; exit 255; fi
    echo "recovered";;
  alwaysreset)
    n=$(cat "$FAKE_COUNT" 2>/dev/null || echo 0); echo $((n+1)) > "$FAKE_COUNT"
    echo "Connection reset by 1.2.3.4 port 22" >&2; exit 255;;
  remote3) echo "out-line"; echo "ls: cannot open: Permission denied" >&2; exit 3;;
  slow) sleep 5;;
  localexec*) exec sh -c "$cmd";;
  *)
    echo "host=$host cmd=$cmd"
    if [ -p /dev/stdin ] || [ -S /dev/stdin ]; then echo "stdin=$(cat)"; fi;;
esac
`, { mode: 0o755 });
  return p;
}

/** Fake `sshpass -e <ssh> args...`: records $SSHPASS to $FAKE_PW_FILE and execs ssh. */
function writeFakeSshpass(dir) {
  const p = path.join(dir, 'fake-sshpass');
  fs.writeFileSync(p, `#!/bin/bash
[ -n "$FAKE_PW_FILE" ] && printf '%s' "$SSHPASS" > "$FAKE_PW_FILE"
[ -n "$FAKE_LOG" ] && echo "sshpass $*" >> "$FAKE_LOG"
shift
exec "$@"
`, { mode: 0o755 });
  return p;
}

function writeCreds(dir, extra = []) {
  const key = path.join(dir, 'id_test');
  fs.writeFileSync(key, 'fake-key');
  const file = path.join(dir, 'ssh-credentials.json');
  const pw = Buffer.from('s3cret pw').toString('base64');
  fs.writeFileSync(file, JSON.stringify({
    version: '1.0',
    credentials: [
      { id: 'k1', host: 'host1', port: 22, username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'k2', host: 'host2', port: 2222, username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'p1', host: 'pwhost', port: 22, username: 'admin', authType: 'password', password: pw },
      { id: 'authfail', host: 'authfail', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'flaky', host: 'flaky', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'alwaysreset', host: 'alwaysreset', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'remote3', host: 'remote3', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'slow', host: 'slow', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'nokey', host: 'nokey', username: 'u', authType: 'key', privateKeyPath: path.join(dir, 'missing') },
      { id: 'pp', host: 'host1', username: 'u', authType: 'key', privateKeyPath: key, passphrase: Buffer.from('pa ss\n').toString('base64') },
      { id: 'local1', host: 'localexec1', username: 'u', authType: 'key', privateKeyPath: key },
      { id: 'local2', host: 'localexec2', username: 'u', authType: 'key', privateKeyPath: key },
      ...extra,
    ],
  }));
  return file;
}

module.exports = { Sink, mkTmp, writeFakeSsh, writeFakeSshpass, writeCreds };
