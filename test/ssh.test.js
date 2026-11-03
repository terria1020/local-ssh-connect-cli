'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { buildExec, describePlan, shellQuote, resolveBinary } = require('../lib/ssh');
const { defaults } = require('../lib/args');
const { mkTmp } = require('./helpers');

const bins = { ssh: '/usr/bin/ssh', sshpass: '/usr/bin/sshpass' };
const dir = mkTmp();
const keyPath = path.join(dir, 'id');
fs.writeFileSync(keyPath, 'k');
const keyCred = { id: 'k', host: 'h', port: 2200, username: 'u', authType: 'key', privateKeyPath: keyPath };
const pwCred = { id: 'p', host: 'h', username: 'u', authType: 'password', password: Buffer.from('hunter2').toString('base64') };

const opt = (o = {}) => ({ ...defaults(), ...o });
const has = (args, a, b) => args.some((x, i) => x === a && args[i + 1] === b);

test('key auth: pins identity, batch mode, keepalive, target after --', () => {
  const e = buildExec(keyCred, { command: 'uptime' }, opt(), bins);
  assert.deepEqual(e.errors, []);
  assert.equal(e.bin, '/usr/bin/ssh');
  assert.ok(has(e.args, '-p', '2200'));
  assert.ok(e.args.includes('IdentitiesOnly=yes'));
  assert.ok(e.args.includes('BatchMode=yes'));
  assert.ok(e.args.includes('PreferredAuthentications=publickey'));
  assert.ok(e.args.includes('ServerAliveInterval=30'));
  assert.ok(e.args.includes('ServerAliveCountMax=3'));
  assert.ok(has(e.args, '-i', keyPath));
  assert.deepEqual(e.args.slice(-3), ['--', 'u@h', 'uptime']);
  assert.equal(e.input, null);
  assert.equal(e.viaSshpass, false);
});

test('keepalive is configurable and can be disabled', () => {
  const a = buildExec(keyCred, { command: 'x' }, opt({ keepalive: 10 }), bins).args;
  assert.ok(a.includes('ServerAliveInterval=10'));
  const b = buildExec(keyCred, { command: 'x' }, opt({ keepalive: 0 }), bins).args;
  assert.ok(!b.some((x) => x.startsWith('ServerAlive')));
});

test('password auth: sshpass -e, password only in env, single attempt, no pubkey', () => {
  const e = buildExec(pwCred, { command: 'id' }, opt(), bins);
  assert.deepEqual(e.errors, []);
  assert.equal(e.bin, '/usr/bin/sshpass');
  assert.equal(e.args[0], '-e');
  assert.equal(e.args[1], '/usr/bin/ssh');
  assert.equal(e.env.SSHPASS, 'hunter2');
  assert.ok(!e.args.join(' ').includes('hunter2'));
  assert.ok(e.args.includes('NumberOfPasswordPrompts=1'));
  assert.ok(e.args.includes('PubkeyAuthentication=no'));
  assert.ok(e.viaSshpass);
});

test('script mode sends "<shell> -s" and stdin input', () => {
  const e = buildExec(keyCred, { script: 'echo $HOME\n' }, opt({ shell: 'bash' }), bins);
  assert.equal(e.args[e.args.length - 1], 'bash -s');
  assert.equal(e.input, 'echo $HOME\n');
});

test('host-key options', () => {
  const none = buildExec(keyCred, { command: 'x' }, opt({ noStrictHostKeyChecking: true }), bins).args;
  assert.ok(none.includes('StrictHostKeyChecking=no'));
  const acc = buildExec(keyCred, { command: 'x' }, opt({ acceptNewHostKeys: true }), bins, { knownHostsPath: '/k/kh' }).args;
  assert.ok(acc.includes('StrictHostKeyChecking=accept-new'));
  assert.ok(acc.includes('UserKnownHostsFile=/k/kh'));
});

test('errors: missing key file, missing binaries, bad base64, unsupported auth', () => {
  assert.match(buildExec({ ...keyCred, privateKeyPath: '/nope/key' }, { command: 'x' }, opt(), bins).errors[0], /Private key not found/);
  assert.match(buildExec({ ...keyCred, privateKeyPath: undefined }, { command: 'x' }, opt(), bins).errors[0], /requires privateKeyPath/);
  assert.match(buildExec(keyCred, { command: 'x' }, opt(), { ssh: null }).errors[0], /"ssh"/);
  assert.ok(buildExec(pwCred, { command: 'x' }, opt(), { ssh: '/s', sshpass: null }).errors.some((m) => /sshpass/.test(m)));
  assert.ok(buildExec({ ...pwCred, password: '***' }, { command: 'x' }, opt(), bins).errors.some((m) => /Base64/.test(m)));
  assert.match(buildExec({ ...keyCred, authType: 'kerberos' }, { command: 'x' }, opt(), bins).errors[0], /Unsupported authType/);
});

test('describePlan masks the password and reports stdin size', () => {
  const e = buildExec(pwCred, { script: 'héllo' }, opt(), bins);
  const plan = describePlan(pwCred, e, opt());
  const json = JSON.stringify(plan);
  assert.ok(!json.includes('hunter2'));
  assert.equal(plan.env.SSHPASS, '***');
  assert.equal(plan.stdinBytes, Buffer.byteLength('héllo'));
  assert.ok(plan.commandLine.startsWith('/usr/bin/sshpass -e'));
});

test('shellQuote', () => {
  assert.equal(shellQuote('abc-1.2/x'), 'abc-1.2/x');
  assert.equal(shellQuote('a b'), "'a b'");
  assert.equal(shellQuote("it's"), `'it'\\''s'`);
});

test('resolveBinary: override path and PATH lookup', () => {
  assert.equal(resolveBinary('ssh', '/definitely/not/here'), null);
  assert.equal(resolveBinary('ssh', keyPath), keyPath);
  assert.equal(resolveBinary('no-such-binary-xyz'), null);
});
