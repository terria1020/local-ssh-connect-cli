'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { runCommand, runWithRetry, runPool } = require('../lib/runner');
const { mkTmp, writeFakeSsh } = require('./helpers');

const sh = (script, extra = {}) => ({ bin: '/bin/sh', args: ['-c', script], env: process.env, input: null, ...extra });

test('runCommand captures stdout/stderr/exit code and streams chunks', async () => {
  const out = [];
  const r = await runCommand(sh('echo hi; echo err >&2; exit 4'), { onStdout: (c) => out.push(c) });
  assert.equal(r.code, 4);
  assert.equal(r.stdout, 'hi\n');
  assert.equal(r.stderr, 'err\n');
  assert.equal(out.join(''), 'hi\n');
});

test('runCommand feeds stdin input', async () => {
  const r = await runCommand(sh('cat', { input: 'from stdin' }));
  assert.equal(r.stdout, 'from stdin');
});

test('runCommand reports spawn errors without throwing', async () => {
  const r = await runCommand({ bin: '/no/such/binary', args: [], env: process.env, input: null });
  assert.ok(r.spawnError);
});

test('runCommand enforces execTimeout', async () => {
  const r = await runCommand(sh('sleep 5'), { execTimeoutMs: 100 });
  assert.ok(r.timedOut);
  assert.ok(r.durationMs < 4000);
});

test('runCommand caps captured output but still streams it', async () => {
  let streamed = 0;
  const r = await runCommand(sh('head -c 5000 /dev/zero | tr "\\0" a'), { maxBuffer: 100, onStdout: (c) => { streamed += c.length; } });
  assert.equal(r.stdout.length, 100);
  assert.ok(r.truncated);
  assert.equal(streamed, 5000);
});

function fakeSshExec(host) {
  const dir = mkTmp();
  return { bin: writeFakeSsh(dir), args: ['--', `u@${host}`, 'cmd'], env: { ...process.env }, input: null, viaSshpass: false };
}

test('runWithRetry retries transient failures with backoff, then succeeds', async () => {
  const dir = mkTmp();
  const exec = fakeSshExec('flaky');
  exec.env.FAKE_COUNT = path.join(dir, 'count');
  const delays = [];
  const retries = [];
  const r = await runWithRetry(exec, {
    retries: 2, retryDelayMs: 100, sleepFn: async (ms) => { delays.push(ms); }, onRetry: (i) => retries.push(i),
  });
  assert.equal(r.kind, 'ok');
  assert.equal(r.attempts, 2);
  assert.deepEqual(delays, [100]);
  assert.equal(retries[0].kind, 'connection_reset');
});

test('runWithRetry gives up after the retry budget (exponential delays)', async () => {
  const dir = mkTmp();
  const exec = fakeSshExec('alwaysreset');
  exec.env.FAKE_COUNT = path.join(dir, 'count');
  const delays = [];
  const r = await runWithRetry(exec, { retries: 2, retryDelayMs: 50, sleepFn: async (ms) => { delays.push(ms); } });
  assert.equal(r.kind, 'connection_reset');
  assert.equal(r.attempts, 3);
  assert.deepEqual(delays, [50, 100]);
});

test('runWithRetry never retries auth failures', async () => {
  const r = await runWithRetry(fakeSshExec('authfail'), { retries: 5, sleepFn: async () => { throw new Error('must not sleep'); } });
  assert.equal(r.kind, 'auth_failed');
  assert.equal(r.attempts, 1);
});

test('runWithRetry does not misread remote "Permission denied" and keeps remote exit code', async () => {
  const r = await runWithRetry(fakeSshExec('remote3'), { retries: 3 });
  assert.equal(r.kind, 'remote_nonzero');
  assert.equal(r.code, 3);
  assert.equal(r.attempts, 1);
});

test('runPool respects the concurrency limit and keeps result order', async () => {
  let active = 0;
  let peak = 0;
  const results = await runPool([30, 5, 20, 1, 10], 2, async (ms, i) => {
    active++; peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, ms));
    active--;
    return i;
  });
  assert.deepEqual(results, [0, 1, 2, 3, 4]);
  assert.equal(peak, 2);
});

test('runPool handles empty input', async () => {
  assert.deepEqual(await runPool([], 4, async () => 1), []);
});
