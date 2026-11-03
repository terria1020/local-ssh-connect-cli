'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadCredentials, decodeBase64, resolveTargets, listCredentials } = require('../lib/credentials');
const { ConfigError } = require('../lib/errors');
const { mkTmp } = require('./helpers');

test('decodeBase64 decodes and strips trailing newline (echo | base64 pitfall)', () => {
  assert.equal(decodeBase64(Buffer.from('pw').toString('base64')), 'pw');
  assert.equal(decodeBase64(Buffer.from('pw\n').toString('base64')), 'pw');
  assert.equal(decodeBase64(Buffer.from('pw\r\n').toString('base64')), 'pw');
  assert.equal(decodeBase64(Buffer.from(' keep inner  spaces').toString('base64')), ' keep inner  spaces');
  assert.equal(decodeBase64(''), '');
});

test('decodeBase64 rejects non-Base64 input', () => {
  assert.throws(() => decodeBase64('not base64!!'), ConfigError);
  assert.throws(() => decodeBase64('abcde'), ConfigError);
});

test('loadCredentials: missing / invalid / wrong shape / ok', () => {
  const dir = mkTmp();
  assert.throws(() => loadCredentials(path.join(dir, 'nope.json')), /not found/);
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, '{oops');
  assert.throws(() => loadCredentials(bad), /not valid JSON/);
  fs.writeFileSync(bad, '{"credentials": 1}');
  assert.throws(() => loadCredentials(bad), /"credentials" array/);
  fs.writeFileSync(bad, '{"credentials": []}');
  assert.deepEqual(loadCredentials(bad).credentials, []);
});

test('resolveTargets: ids, --all, unknown id', () => {
  const data = { credentials: [{ id: 'a' }, { id: 'b' }] };
  assert.deepEqual(resolveTargets(data, { ids: ['b', 'a'], all: false }).map((c) => c.id), ['b', 'a']);
  assert.deepEqual(resolveTargets(data, { ids: [], all: true }).map((c) => c.id), ['a', 'b']);
  assert.throws(() => resolveTargets(data, { ids: ['zzz'], all: false }), /Available: a, b/);
});

test('listCredentials never exposes secrets', () => {
  const out = JSON.stringify(listCredentials({
    credentials: [{ id: 'a', host: 'h', username: 'u', authType: 'password', password: 'c2VjcmV0', privateKeyPath: '/k', passphrase: 'x' }],
  }));
  assert.ok(!out.includes('c2VjcmV0'));
  assert.ok(!out.includes('/k'));
  assert.ok(!out.includes('passphrase'));
});
