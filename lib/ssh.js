'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const { decodeBase64, decodePassphrase, hasPassphrase } = require('./credentials');

/**
 * Best-effort: is the private key file passphrase-protected?
 * Returns true / false, or null when it cannot be determined (unreadable, unknown format).
 */
function isKeyEncrypted(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
  if (/BEGIN ENCRYPTED PRIVATE KEY|Proc-Type:\s*4,ENCRYPTED/.test(text)) return true;
  const m = text.match(/-----BEGIN OPENSSH PRIVATE KEY-----([\s\S]*?)-----END OPENSSH PRIVATE KEY-----/);
  if (m) {
    try {
      const buf = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
      const magic = 'openssh-key-v1\0';
      if (buf.subarray(0, magic.length).toString('latin1') !== magic) return null;
      const len = buf.readUInt32BE(magic.length);
      // A truncated/corrupt header must read as "unknown", never as "encrypted".
      if (len === 0 || len > 64 || magic.length + 4 + len > buf.length) return null;
      return buf.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1') !== 'none';
    } catch {
      return null;
    }
  }
  return /-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----/.test(text) ? false : null;
}

/**
 * Verify a key's passphrase locally (no network): `ssh-keygen -y` answers its prompt through
 * the same SSH_ASKPASS env as the real ssh call, so the passphrase never reaches argv.
 * Returns true (decrypts), false (wrong passphrase) or null (cannot tell).
 */
function checkPassphrase(exec, keygenPath) {
  if (!keygenPath || !exec.keyPath) return null;
  try {
    const r = spawnSync(keygenPath, ['-y', '-f', exec.keyPath], {
      env: exec.env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10000, encoding: 'utf8',
    });
    if (r.error) return null;
    if (r.status === 0) return true;
    // Only a passphrase complaint proves the passphrase is wrong; a missing/corrupt key file,
    // bad permissions etc. are "unknown" so they are never blamed on the passphrase.
    return /incorrect passphrase|bad passphrase/i.test(r.stderr || '') ? false : null;
  } catch {
    return null;
  }
}

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
function buildExec(cred, { command, script, inputFile, inputBytes }, opts, bins, { knownHostsPath, askpassPath } = {}) {
  const warnings = [];
  const errors = [];
  const maskedEnv = []; // env var names whose values must never be displayed
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
    // ("Too many authentication failures").
    args.push('-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey');
    if (hasPassphrase(cred)) {
      // Passphrase-protected key: answer ssh's passphrase prompt through SSH_ASKPASS.
      // BatchMode must stay off (it disables every prompt, askpass included).
      let passphrase = '';
      try {
        passphrase = decodePassphrase(cred.passphrase);
      } catch (e) {
        errors.push(`Credential "${cred.id}": passphrase: ${e.message}`);
      }
      if (!askpassPath) errors.push('Internal error: askpass helper unavailable.');
      // One attempt only: a wrong passphrase must not be retried by ssh.
      args.push('-o', 'NumberOfPasswordPrompts=1');
      env = {
        ...process.env,
        SSH_ASKPASS: askpassPath || '',
        SSH_ASKPASS_REQUIRE: 'force', // OpenSSH >= 8.4
        DISPLAY: process.env.DISPLAY || 'lssh:0', // older OpenSSH only uses askpass when DISPLAY is set
        LSSH_PASSPHRASE: passphrase,
      };
      maskedEnv.push('LSSH_PASSPHRASE');
      if (cred.privateKeyPath && isKeyEncrypted(cred.privateKeyPath) === false) {
        warnings.push(`Credential "${cred.id}" has a "passphrase" but its private key is not passphrase-protected (the passphrase is ignored).`);
      }
    } else {
      // BatchMode avoids hanging on an unexpected prompt.
      args.push('-o', 'BatchMode=yes');
      if (cred.privateKeyPath && isKeyEncrypted(cred.privateKeyPath) === true) {
        warnings.push(
          `Private key looks passphrase-protected but credential "${cred.id}" has no "passphrase" ` +
            '(works only if the key is already loaded in ssh-agent).'
        );
      }
    }
    args.push('-i', cred.privateKeyPath || '');
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

  return { bin, args: finalArgs, env, input, inputFile: inputFile || null, inputBytes: inputBytes || 0, viaSshpass, maskedEnv: viaSshpass ? ['SSHPASS', ...maskedEnv] : maskedEnv, askpass: cred.authType === 'key' && hasPassphrase(cred), keyPath: cred.authType === 'key' ? cred.privateKeyPath || null : null, remoteCommand, warnings, errors };
}

/** Shell-quote for display only. */
function shellQuote(s) {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** Secret-free description of a planned execution (for --dry-run). */
function describePlan(cred, exec, opts) {
  const env = {};
  for (const name of exec.maskedEnv || []) env[name] = '***';
  if (exec.askpass) env.SSH_ASKPASS = exec.env.SSH_ASKPASS;
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
    stdinBytes: exec.inputFile ? exec.inputBytes : exec.input === null ? 0 : Buffer.byteLength(exec.input),
    stdinFile: exec.inputFile || null,
    problems: [...exec.errors, ...exec.warnings],
  };
}

function defaultKnownHostsPath(logDir) {
  return path.join(logDir, 'known_hosts');
}

module.exports = { checkPassphrase, isKeyEncrypted, resolveBinary, buildExec, describePlan, shellQuote, defaultKnownHostsPath };
