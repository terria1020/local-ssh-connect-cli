'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeResult, configErrorResult, exitCodeFor, createReporter, summarize } = require('../lib/output');
const { Sink } = require('./helpers');

const ok = (id = 'a') => makeResult({ id, host: 'h' }, { kind: 'ok', code: 0, stdout: 'o', stderr: '', attempts: 1, durationMs: 5 });
const bad = (kind, code = null, id = 'b') => makeResult({ id, host: 'h' }, { kind, code, stdout: '', stderr: 'e', attempts: 1, durationMs: 5 });

test('makeResult contract', () => {
  assert.deepEqual(Object.keys(ok()).sort(), [
    'attempts', 'durationMs', 'errorKind', 'exitCode', 'host', 'id', 'ok', 'stderr', 'stdout', 'timedOut', 'truncated',
  ]);
  assert.equal(ok().errorKind, null);
  assert.equal(bad('auth_failed', 255).errorKind, 'auth_failed');
  assert.equal(configErrorResult({ id: 'x', host: 'h' }, 'boom').errorKind, 'config_error');
});

test('exitCodeFor', () => {
  assert.equal(exitCodeFor([ok(), ok('c')]), 0);
  assert.equal(exitCodeFor([bad('remote_nonzero', 3)]), 3);
  assert.equal(exitCodeFor([bad('auth_failed', 255)]), 255);
  assert.equal(exitCodeFor([bad('connect_timeout', 255)]), 255);
  assert.equal(exitCodeFor([bad('exec_timeout')]), 124);
  assert.equal(exitCodeFor([bad('spawn_error')]), 127);
  assert.equal(exitCodeFor([configErrorResult({ id: 'x', host: 'h' }, 'm')]), 2);
  assert.equal(exitCodeFor([ok(), bad('remote_nonzero', 3)]), 1);
});

test('summarize', () => {
  assert.deepEqual(summarize([ok(), bad('dns', 255)]), { total: 2, succeeded: 1, failed: 1 });
});

test('text reporter, single target: raw passthrough', () => {
  const out = new Sink(); const err = new Sink();
  const r = createReporter('text', { multi: false, out, err });
  r.stdout('a', 'hello\npart'); r.stdout('a', 'ial\n'); r.stderr('a', 'warn\n');
  r.finish(ok());
  assert.equal(out.data, 'hello\npartial\n');
  assert.equal(err.data, 'warn\n');
});

test('text reporter, multi target: line prefixes, split chunks, flushed tail', () => {
  const out = new Sink(); const err = new Sink();
  const r = createReporter('text', { multi: true, out, err });
  r.stdout('a', 'one\ntw'); r.stdout('b', 'x\n'); r.stdout('a', 'o\nlast');
  r.finish(ok('a')); r.finish(ok('b'));
  assert.equal(out.data, '[a] one\n[b] x\n[a] two\n[a] last\n');
});

test('text reporter prints a diagnostic for ssh-level failures but not for remote exit codes', () => {
  const err = new Sink();
  const r = createReporter('text', { multi: false, out: new Sink(), err });
  r.finish(bad('remote_nonzero', 2));
  assert.equal(err.data, '');
  r.finish(bad('auth_failed', 255));
  assert.match(err.data, /\[lssh\] b: auth_failed/);
});

test('json reporter prints exactly one document at the end', () => {
  const out = new Sink();
  const r = createReporter('json', { multi: true, out, err: new Sink() });
  r.stdout('a', 'ignored'); r.finish(ok());
  assert.equal(out.data, '');
  r.summary([ok(), bad('auth_failed', 255)]);
  const doc = JSON.parse(out.data);
  assert.equal(doc.ok, false);
  assert.equal(doc.total, 2);
  assert.equal(doc.failed, 1);
  assert.equal(doc.results[1].errorKind, 'auth_failed');
});

test('ndjson reporter emits one valid JSON event per line', () => {
  const out = new Sink();
  const r = createReporter('ndjson', { multi: true, out, err: new Sink() });
  r.start('a', 'h'); r.stdout('a', 'x\n'); r.retry('a', { attempt: 1, kind: 'connection_reset', delayMs: 10 });
  r.finish(ok()); r.summary([ok()]);
  const events = out.data.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(events.map((e) => e.event), ['start', 'stdout', 'retry', 'exit', 'summary']);
  assert.equal(events[1].data, 'x\n');
  assert.equal(events[2].delayMs, 10);
  assert.equal(events[4].ok, true);
});
