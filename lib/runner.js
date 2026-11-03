'use strict';

const fs = require('fs');
const crypto = require('crypto');
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

function hasInput(exec) {
  return !!exec.inputFile || (exec.input !== null && exec.input !== undefined);
}

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
function runCommand(exec, { execTimeoutMs = 0, maxBuffer = DEFAULT_MAX_BUFFER, onStdout, onStderr, openStdoutStream } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const res = { bytes: 0, sha256: null, ioError: null, code: null, signal: null, stdout: '', stderr: '', timedOut: false, truncated: false, spawnError: null };
    let settled = false;
    let killTimer = null;
    let hardKill = null;

    let sink = null; // binary stdout sink (file download)
    let sinkDone = Promise.resolve();
    let hash = null;

    const finish = () => {
      if (settled) return;
      settled = true;
      if (child) active.delete(child);
      clearTimeout(killTimer);
      clearTimeout(hardKill);
      res.durationMs = Date.now() - started;
      if (hash) res.sha256 = hash.digest('hex');
      sinkDone.then(() => resolve(res));
    };

    let child = null;
    try {
      child = spawn(exec.bin, exec.args, {
        env: exec.env,
        detached: IS_POSIX,
        stdio: [hasInput(exec) ? 'pipe' : 'ignore', 'pipe', 'pipe'],
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
    child.stderr.setEncoding('utf8');
    if (openStdoutStream) {
      // Binary download: bytes go straight to the sink, never through utf8 decoding.
      hash = crypto.createHash('sha256');
      try {
        sink = openStdoutStream();
      } catch (e) {
        res.ioError = e.message;
        killTree(child, 'SIGKILL');
      }
      if (sink) {
        sinkDone = new Promise((r) => sink.on('close', r));
        sink.on('error', (e) => { res.ioError = e.message; killTree(child, 'SIGKILL'); });
        child.stdout.on('data', (c) => { res.bytes += c.length; hash.update(c); });
        child.stdout.pipe(sink);
      }
    } else {
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', capture('stdout', onStdout));
    }
    child.stderr.on('data', capture('stderr', onStderr));

    if (child.stdin) {
      child.stdin.on('error', () => {}); // EPIPE when the remote closes early
      if (exec.inputFile) {
        const rs = fs.createReadStream(exec.inputFile);
        rs.on('error', (e) => { res.ioError = e.message; killTree(child, 'SIGKILL'); });
        rs.pipe(child.stdin);
      } else {
        child.stdin.end(exec.input);
      }
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
  const { retries = 0, retryDelayMs = 0, onRetry, sleepFn = sleep, timeoutOk = false, ...runOpts } = opts;
  let attempt = 0;
  for (;;) {
    attempt++;
    const result = await runCommand(exec, runOpts);
    let cls = classify({ ...result, viaSshpass: exec.viaSshpass });
    if (result.ioError) cls = { kind: 'io_error', retryable: false };
    // A bounded `tail --follow` is expected to end by timeout.
    if (timeoutOk && cls.kind === 'exec_timeout') cls = { kind: 'ok', retryable: false };
    const canRetry = cls.retryable && attempt <= retries && result.stdout.length === 0 && result.bytes === 0;
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
