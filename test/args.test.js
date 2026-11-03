'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseArgs, sniffOutputMode } = require('../lib/args');
const { UsageError } = require('../lib/errors');

test('defaults', () => {
  const o = parseArgs([]);
  assert.equal(o.output, 'text');
  assert.equal(o.concurrency, 4);
  assert.equal(o.retries, 2);
  assert.equal(o.keepalive, 30);
  assert.deepEqual(o.ids, []);
});

test('ids: comma separated, repeated, trimmed and de-duplicated', () => {
  const o = parseArgs(['-i', 'a, b', '--id', 'b,c', '--id=d']);
  assert.deepEqual(o.ids, ['a', 'b', 'c', 'd']);
});

test('--opt=value form and numeric options', () => {
  const o = parseArgs(['--timeout=150', '--concurrency', '8', '--retries=0', '--keepalive=0', '--port', '2200']);
  assert.equal(o.timeout, 150);
  assert.equal(o.concurrency, 8);
  assert.equal(o.retries, 0);
  assert.equal(o.keepalive, 0);
  assert.equal(o.port, 2200);
});

test('command values may start with a dash or contain $ and quotes', () => {
  assert.equal(parseArgs(['-c', '-']).command, '-');
  assert.equal(parseArgs(['-c', 'echo "$HOME" -x']).command, 'echo "$HOME" -x');
});

test('output mode flags', () => {
  assert.equal(parseArgs(['--json']).output, 'json');
  assert.equal(parseArgs(['--ndjson']).output, 'ndjson');
  assert.equal(parseArgs(['--output', 'json']).output, 'json');
  assert.throws(() => parseArgs(['--output', 'xml']), UsageError);
});

test('flags', () => {
  const o = parseArgs(['--dry-run', '--all', '--verbose', '--accept-new-host-keys']);
  assert.ok(o.dryRun && o.all && o.verbose && o.acceptNewHostKeys);
});

test('errors: unknown arg, missing value, bad numbers, conflicting command sources', () => {
  assert.throws(() => parseArgs(['--nope']), /Unknown argument/);
  assert.throws(() => parseArgs(['-i']), /requires a value/);
  assert.throws(() => parseArgs(['--timeout', 'abc']), /integer/);
  assert.throws(() => parseArgs(['--timeout', '0']), /between/);
  assert.throws(() => parseArgs(['--port', '70000']), /between/);
  assert.throws(() => parseArgs(['--concurrency', '0']), /between/);
  assert.throws(() => parseArgs(['--shell', 'sh; rm -rf /']), /plain shell/);
  assert.throws(() => parseArgs(['-c', 'x', '--script-file', 'f']), /not both/);
});

test('sniffOutputMode works even when parsing fails', () => {
  assert.equal(sniffOutputMode(['--bogus', '--json']), 'json');
  assert.equal(sniffOutputMode(['--output=ndjson']), 'ndjson');
  assert.equal(sniffOutputMode(['--output', 'json']), 'json');
  assert.equal(sniffOutputMode([]), 'text');
});
