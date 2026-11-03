'use strict';

/**
 * Failure kinds (stable contract, documented in --help):
 *   ok, remote_nonzero, auth_failed, too_many_auth, host_key, dns, connection_refused,
 *   connect_timeout, connection_reset, connection_lost, ssh_error,
 *   exec_timeout, spawn_error, config_error
 * `retryable` kinds never executed the remote command, so retrying is safe.
 */
const RETRYABLE = new Set(['connect_timeout', 'connection_reset']);

const SSH_PATTERNS = [
  ['too_many_auth', /Too many authentication failures/i],
  ['auth_failed', /Permission denied/i],
  ['host_key', /Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/i],
  ['dns', /Could not resolve hostname|Name or service not known|nodename nor servname/i],
  ['connection_refused', /Connection refused/i],
  ['connect_timeout', /Connection timed out|Operation timed out|timed out during banner/i],
  ['connection_reset', /kex_exchange_identification|Connection reset by|Connection closed by|banner exchange/i],
  ['connection_lost', /Timeout, server .* not responding|Broken pipe|Connection to .* closed/i],
];

function matchSsh(stderr) {
  for (const [kind, re] of SSH_PATTERNS) if (re.test(stderr)) return kind;
  return null;
}

/**
 * Classify a finished process.
 * ssh-level patterns are only trusted when ssh itself failed (exit 255, or sshpass's own
 * codes 5/6/7) -- otherwise "Permission denied" printed by the *remote* command
 * (e.g. `ls /root`) would be mistaken for an authentication failure.
 */
function classify({ code, timedOut, spawnError, stderr = '', viaSshpass = false }) {
  if (spawnError) return { kind: 'spawn_error', retryable: false };
  if (timedOut) return { kind: 'exec_timeout', retryable: false };
  if (code === 0) return { kind: 'ok', retryable: false };

  const sshLevel = code === 255 || (viaSshpass && (code === 5 || code === 6 || code === 7));
  if (sshLevel) {
    const kind = matchSsh(stderr) || (viaSshpass && code === 5 ? 'auth_failed' : null);
    if (kind) return { kind, retryable: RETRYABLE.has(kind) };
    if (viaSshpass && (code === 6 || code === 7)) return { kind: 'host_key', retryable: false };
    return { kind: 'ssh_error', retryable: false };
  }
  return { kind: 'remote_nonzero', retryable: false };
}

module.exports = { classify, RETRYABLE };
