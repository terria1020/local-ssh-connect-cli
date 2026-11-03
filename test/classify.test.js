'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { classify } = require('../lib/classify');

const k = (o) => classify(o).kind;

test('ok / spawn / timeout take precedence', () => {
  assert.equal(k({ code: 0 }), 'ok');
  assert.equal(k({ code: null, spawnError: 'ENOENT' }), 'spawn_error');
  assert.equal(k({ code: null, timedOut: true }), 'exec_timeout');
});

test('ssh-level failures (exit 255) are classified by stderr', () => {
  assert.equal(k({ code: 255, stderr: 'u@h: Permission denied (publickey,password).' }), 'auth_failed');
  assert.equal(k({ code: 255, stderr: 'Received disconnect: Too many authentication failures' }), 'too_many_auth');
  assert.equal(k({ code: 255, stderr: 'Host key verification failed.' }), 'host_key');
  assert.equal(k({ code: 255, stderr: '@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @' }), 'host_key');
  assert.equal(k({ code: 255, stderr: 'ssh: Could not resolve hostname x: Name or service not known' }), 'dns');
  assert.equal(k({ code: 255, stderr: 'connect to host h port 22: Connection refused' }), 'connection_refused');
  assert.equal(k({ code: 255, stderr: 'connect to host h port 22: Connection timed out' }), 'connect_timeout');
  assert.equal(k({ code: 255, stderr: 'kex_exchange_identification: read: Connection reset by peer' }), 'connection_reset');
  assert.equal(k({ code: 255, stderr: 'Timeout, server h not responding.' }), 'connection_lost');
  assert.equal(k({ code: 255, stderr: 'something odd' }), 'ssh_error');
});

test('only transient connection failures are retryable', () => {
  assert.equal(classify({ code: 255, stderr: 'Connection timed out' }).retryable, true);
  assert.equal(classify({ code: 255, stderr: 'Connection reset by x' }).retryable, true);
  assert.equal(classify({ code: 255, stderr: 'Permission denied' }).retryable, false);
  assert.equal(classify({ code: 255, stderr: 'Host key verification failed' }).retryable, false);
});

test('"Permission denied" from the REMOTE command is not an auth failure', () => {
  const c = classify({ code: 1, stderr: 'ls: cannot open directory /root: Permission denied' });
  assert.equal(c.kind, 'remote_nonzero');
  assert.equal(c.retryable, false);
});

test('sshpass exit codes 5/6/7 map to auth / host key', () => {
  assert.equal(k({ code: 5, viaSshpass: true, stderr: 'Permission denied, please try again.' }), 'auth_failed');
  assert.equal(k({ code: 5, viaSshpass: true, stderr: '' }), 'auth_failed');
  assert.equal(k({ code: 7, viaSshpass: true, stderr: '' }), 'host_key');
  assert.equal(k({ code: 5, viaSshpass: false, stderr: '' }), 'remote_nonzero');
});
