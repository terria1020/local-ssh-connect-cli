'use strict';

const { spawn } = require('child_process');
const { classify } = require('./classify');

const DEFAULT_MAX_BUFFER = 10 * 1024 * 1024;

// Children run in their own process group so a timeout (or our own exit) also stops
// grandchildren such as the ssh started by sshpass.
const IS_POSIX = process.platform !== 'win32';
const active = new Set();
process.on('exit', () => {
  for (const child of active) killTree(child, 'SIGKILL');
});

function killTree(child, signal) {
  try {
    if (IS_POSIX && child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* already gone */ }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Run one process, streaming chunks via callbacks while also capturing (capped) output.
 * Never rejects: failures are reported in the result.
 */
function runCommand(exec, { execTimeoutMs = 0, maxBuffer = DEFAULT_MAX_BUFFER, onStdout, onStderr } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const res = { code: null, signal: null, stdout: '', stderr: '', timedOut: false, truncated: false, spawnError: null };
    let settled = false;
    let killTimer = null;
    let hardKill = null;

    const finish = () => {
      if (settled) return;
      settled = true;
      if (child) active.delete(child);
      clearTimeout(killTimer);
      clearTimeout(hardKill);
      res.durationMs = Date.now() - started;
      resolve(res);
    };

    let child = null;
    try {
      child = spawn(exec.bin, exec.args, {
        env: exec.env,
        detached: IS_POSIX,
        stdio: [exec.input === null || exec.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      });
    } catch (e) {
      res.spawnError = e.message;
      finish();
      return;
    }

    const capture = (key, cb) => (chunk) => {
      if (res[key].length < maxBuffer) {
        res[key] += chunk.slice(0, maxBuffer - res[key].length);
        if (res[key].length >= maxBuffer) res.truncated = true;
      } else {
        res.truncated = true;
      }
      if (cb) cb(chunk);
    };
    active.add(child);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', capture('stdout', onStdout));
    child.stderr.on('data', capture('stderr', onStderr));

    if (child.stdin) {
      child.stdin.on('error', () => {}); // EPIPE when the remote closes early
      child.stdin.end(exec.input);
    }

    if (execTimeoutMs > 0) {
      killTimer = setTimeout(() => {
        res.timedOut = true;
        killTree(child, 'SIGTERM');
        hardKill = setTimeout(() => killTree(child, 'SIGKILL'), 2000);
      }, execTimeoutMs);
    }

    child.on('error', (e) => {
      res.spawnError = e.message;
      finish();
    });
    child.on('close', (code, signal) => {
      res.code = code;
      res.signal = signal;
      finish();
    });
  });
}

/**
 * Run with bounded retries for transient connection failures (never for auth/host-key
 * failures or after the remote command produced output).
 */
async function runWithRetry(exec, opts = {}) {
  const { retries = 0, retryDelayMs = 0, onRetry, sleepFn = sleep, ...runOpts } = opts;
  let attempt = 0;
  for (;;) {
    attempt++;
    const result = await runCommand(exec, runOpts);
    const cls = classify({ ...result, viaSshpass: exec.viaSshpass });
    const canRetry = cls.retryable && attempt <= retries && result.stdout.length === 0;
    if (!canRetry) return { ...result, attempts: attempt, kind: cls.kind };
    const delayMs = retryDelayMs * 2 ** (attempt - 1);
    if (onRetry) onRetry({ attempt, kind: cls.kind, delayMs });
    await sleepFn(delayMs);
  }
}

/** Run `worker(item, index)` over items with bounded concurrency; results keep input order. */
async function runPool(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  const lanes = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });
  await Promise.all(lanes);
  return results;
}

module.exports = { runCommand, runWithRetry, runPool };
