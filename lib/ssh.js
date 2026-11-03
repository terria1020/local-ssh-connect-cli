'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { decodeBase64 } = require('./credentials');

/** Locate a binary. Returns a path or null (never throws / exits). */
function resolveBinary(name, overridePath) {
  if (overridePath) return fs.existsSync(overridePath) ? overridePath : null;
  try {
    const out = execFileSync('which', [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return out || null;
  } catch {
    return null;
  }
}

/**
 * Build the process invocation for one credential. Pure apart from file-existence checks.
 *
 * bins: { ssh, sshpass }  (resolved paths or null)
 * Returns { bin, args, env, input, viaSshpass, remoteCommand, warnings, errors }.
 * `errors` non-empty means the target cannot be executed.
 */
function buildExec(cred, { command, script }, opts, bins, { knownHostsPath } = {}) {
  const warnings = [];
  const errors = [];
  const port = opts.port || cred.port || 22;
  const timeout = Number.isFinite(opts.timeout) && opts.timeout > 0 ? opts.timeout : 15;

  if (!bins.ssh) errors.push('Cannot locate "ssh" in PATH (or --ssh-path does not exist).');

  const args = [
    '-p', String(port),
    '-o', `ConnectTimeout=${timeout}`,
    '-o', 'LogLevel=ERROR',
  ];
  // Keepalive so long-running commands survive idle-connection drops (NAT/firewall timeouts).
  const keepalive = opts.keepalive === undefined ? 30 : opts.keepalive;
  if (keepalive > 0) args.push('-o', `ServerAliveInterval=${keepalive}`, '-o', 'ServerAliveCountMax=3');
  if (opts.noStrictHostKeyChecking) {
    args.push('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null');
  } else if (opts.acceptNewHostKeys) {
    // accept-new still fails on *changed* keys (safer than StrictHostKeyChecking=no).
    args.push('-o', 'StrictHostKeyChecking=accept-new');
    if (knownHostsPath) args.push('-o', `UserKnownHostsFile=${knownHostsPath}`);
  }

  const remoteCommand = script !== undefined ? `${opts.shell || 'sh'} -s` : command;
  const input = script !== undefined ? script : null;
  const target = `${cred.username}@${cred.host}`;
  let env = process.env;
  let bin = bins.ssh || 'ssh';
  let viaSshpass = false;
  let finalArgs;

  if (cred.authType === 'key') {
    if (!cred.privateKeyPath) {
      errors.push(`Credential "${cred.id}" requires privateKeyPath.`);
    } else if (!fs.existsSync(cred.privateKeyPath)) {
      errors.push(`Private key not found: ${cred.privateKeyPath}`);
    }
    // Only offer the configured key: otherwise ssh-agent keys burn MaxAuthTries
    // ("Too many authentication failures"). BatchMode avoids hanging on prompts.
    args.push(
      '-o', 'BatchMode=yes',
      '-o', 'IdentitiesOnly=yes',
      '-o', 'PreferredAuthentications=publickey',
      '-i', cred.privateKeyPath || ''
    );
    finalArgs = [...args, '--', target, remoteCommand];
  } else if (cred.authType === 'password') {
    if (!cred.password) errors.push(`Credential "${cred.id}" requires password.`);
    if (!bins.sshpass) errors.push('Cannot locate "sshpass" in PATH (or --sshpass-path does not exist).');
    let password = '';
    try {
      password = decodeBase64(cred.password);
    } catch (e) {
      errors.push(`Credential "${cred.id}": ${e.message}`);
    }
    // One password attempt only: wrong passwords must not multiply failed-login counts.
    args.push(
      '-o', 'PubkeyAuthentication=no',
      '-o', 'PreferredAuthentications=password,keyboard-interactive',
      '-o', 'NumberOfPasswordPrompts=1'
    );
    viaSshpass = true;
    // SSHPASS env var keeps the password out of argv / process listings / logs.
    env = { ...process.env, SSHPASS: password };
    finalArgs = ['-e', bins.ssh || 'ssh', ...args, '--', target, remoteCommand];
    bin = bins.sshpass || 'sshpass';
  } else {
    errors.push(`Unsupported authType: ${cred.authType}`);
    finalArgs = [...args, '--', target, remoteCommand];
  }

  return { bin, args: finalArgs, env, input, viaSshpass, remoteCommand, warnings, errors };
}

/** Shell-quote for display only. */
function shellQuote(s) {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** Secret-free description of a planned execution (for --dry-run). */
function describePlan(cred, exec, opts) {
  const env = {};
  if (exec.viaSshpass) env.SSHPASS = '***';
  return {
    id: cred.id,
    host: cred.host,
    port: opts.port || cred.port || 22,
    authType: cred.authType,
    bin: exec.bin,
    args: exec.args,
    commandLine: [exec.bin, ...exec.args].map(shellQuote).join(' '),
    env,
    remoteCommand: exec.remoteCommand,
    stdinBytes: exec.input === null ? 0 : Buffer.byteLength(exec.input),
    problems: [...exec.errors, ...exec.warnings],
  };
}

function defaultKnownHostsPath(logDir) {
  return path.join(logDir, 'known_hosts');
}

module.exports = { resolveBinary, buildExec, describePlan, shellQuote, defaultKnownHostsPath };
