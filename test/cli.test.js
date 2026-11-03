'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { main } = require('../lib/cli');
const { Sink, mkTmp, writeFakeSsh, writeFakeSshpass, writeCreds } = require('./helpers');

const dir = mkTmp();
const ssh = writeFakeSsh(dir);
const sshpass = writeFakeSshpass(dir);
const creds = writeCreds(dir);
const base = ['--credentials-path', creds, '--ssh-path', ssh, '--sshpass-path', sshpass, '--retry-delay', '0'];

async function run(args, io = {}) {
  const stdout = new Sink();
  const stderr = new Sink();
  const prev = { ...process.env };
  Object.assign(process.env, io.env || {});
  try {
    const code = await main([...base, ...args], { stdout, stderr, noLog: true, ...io, env: { ...process.env, LSSH_LOG_DIR: path.join(dir, 'logs') } });
    return { code, out: stdout.data, err: stderr.data };
  } finally {
    for (const k of Object.keys(io.env || {})) { if (k in prev) process.env[k] = prev[k]; else delete process.env[k]; }
  }
}

test('--help prints the agent guide and exits 0', async () => {
  const r = await main(['--help'], { stdout: new Sink(), stderr: new Sink() });
  assert.equal(r, 0);
});

test('--get-credential-list is JSON without secrets', async () => {
  const r = await run(['--get-credential-list']);
  assert.equal(r.code, 0);
  const list = JSON.parse(r.out);
  assert.ok(list.find((c) => c.id === 'k1'));
  assert.ok(!r.out.includes('privateKeyPath'));
});

test('single host text mode: raw passthrough', async () => {
  const r = await run(['-i', 'k1', '-c', 'uptime']);
  assert.equal(r.code, 0);
  assert.equal(r.out, 'host=host1 cmd=uptime\n');
});

test('single host json contract', async () => {
  const r = await run(['-i', 'k1', '--json', '-c', 'uptime']);
  assert.equal(r.code, 0);
  const doc = JSON.parse(r.out);
  assert.equal(doc.ok, true);
  assert.equal(doc.results[0].id, 'k1');
  assert.equal(doc.results[0].stdout, 'host=host1 cmd=uptime\n');
  assert.equal(doc.results[0].exitCode, 0);
  assert.equal(doc.results[0].errorKind, null);
});

test('multi host runs in parallel, prefixes lines, exit 1 when any fails', async () => {
  const r = await run(['-i', 'k1,k2,authfail', '-c', 'hostname']);
  assert.equal(r.code, 1);
  assert.match(r.out, /\[k1\] host=host1 cmd=hostname/);
  assert.match(r.out, /\[k2\] host=host2 cmd=hostname/);
  assert.match(r.err, /authfail: auth_failed/);
  assert.match(r.err, /2\/3 succeeded/);
});

test('multi host json reports per-host errorKind', async () => {
  const r = await run(['-i', 'k1,authfail,remote3', '--json', '-c', 'x']);
  assert.equal(r.code, 1);
  const doc = JSON.parse(r.out);
  assert.equal(doc.total, 3);
  assert.equal(doc.failed, 2);
  const by = Object.fromEntries(doc.results.map((x) => [x.id, x]));
  assert.equal(by.authfail.errorKind, 'auth_failed');
  assert.equal(by.remote3.errorKind, 'remote_nonzero');
  assert.equal(by.remote3.exitCode, 3);
  assert.equal(by.k1.ok, true);
});

test('single host propagates the remote exit code / ssh-level 255', async () => {
  assert.equal((await run(['-i', 'remote3', '-c', 'x'])).code, 3);
  assert.equal((await run(['-i', 'authfail', '-c', 'x'])).code, 255);
});

test('ndjson stream has start/stdout/exit/summary events', async () => {
  const r = await run(['-i', 'k1,k2', '--ndjson', '-c', 'x']);
  const ev = r.out.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(ev.filter((e) => e.event === 'start').length, 2);
  assert.equal(ev.filter((e) => e.event === 'exit').length, 2);
  assert.equal(ev[ev.length - 1].event, 'summary');
  assert.ok(ev.some((e) => e.event === 'stdout' && e.data.includes('host=host1')));
});

test('--all targets every credential (dry-run)', async () => {
  const r = await run(['--all', '--dry-run', '--json', '-c', 'x']);
  const doc = JSON.parse(r.out);
  assert.equal(doc.dryRun, true);
  assert.ok(doc.plans.length >= 9);
});

test('transient failure is retried transparently', async () => {
  const count = path.join(dir, 'flaky-count');
  fs.rmSync(count, { force: true });
  const r = await run(['-i', 'flaky', '--json', '-c', 'x'], { env: { FAKE_COUNT: count } });
  assert.equal(r.code, 0);
  const res = JSON.parse(r.out).results[0];
  assert.equal(res.attempts, 2);
  assert.equal(res.stdout, 'recovered\n');
});

test('--retries 0 disables retry', async () => {
  const count = path.join(dir, 'flaky-count2');
  fs.rmSync(count, { force: true });
  const r = await run(['-i', 'flaky', '--retries', '0', '--json', '-c', 'x'], { env: { FAKE_COUNT: count } });
  assert.equal(r.code, 255);
  assert.equal(JSON.parse(r.out).results[0].errorKind, 'connection_reset');
});

test('--exec-timeout kills slow targets', async () => {
  const r = await run(['-i', 'slow', '--exec-timeout', '1', '--json', '-c', 'x']);
  assert.equal(r.code, 124);
  assert.equal(JSON.parse(r.out).results[0].errorKind, 'exec_timeout');
});

test('password auth passes the decoded password only via SSHPASS env', async () => {
  const pwFile = path.join(dir, 'pw');
  const log = path.join(dir, 'argv.log');
  fs.rmSync(log, { force: true });
  const r = await run(['-i', 'p1', '-c', 'id'], { env: { FAKE_PW_FILE: pwFile, FAKE_LOG: log } });
  assert.equal(r.code, 0);
  assert.equal(fs.readFileSync(pwFile, 'utf8'), 's3cret pw');
  assert.ok(!fs.readFileSync(log, 'utf8').includes('s3cret'));
});

test('script on stdin (-c -) is delivered verbatim, untouched by any shell', async () => {
  const script = 'echo "$HOME" `date` !!\n';
  const r = await run(['-i', 'k1', '-c', '-'], { readStdin: () => script });
  assert.equal(r.code, 0);
  assert.match(r.out, /cmd=sh -s/);
  assert.ok(r.out.includes(`stdin=${script.trim()}`));
});

test('--script-file works and --shell selects the interpreter', async () => {
  const f = path.join(dir, 's.sh');
  fs.writeFileSync(f, 'echo hi\n');
  const r = await run(['-i', 'k1', '--script-file', f, '--shell', 'bash']);
  assert.match(r.out, /cmd=bash -s/);
  assert.match(r.out, /stdin=echo hi/);
});

test('empty stdin script / unreadable script file are usage errors', async () => {
  assert.equal((await run(['-i', 'k1', '-c', '-'], { readStdin: () => '  \n' })).code, 2);
  assert.equal((await run(['-i', 'k1', '--script-file', '/no/such/file'])).code, 2);
});

test('dry-run: nothing is executed, password is masked', async () => {
  const log = path.join(dir, 'dry.log');
  fs.rmSync(log, { force: true });
  const r = await run(['-i', 'p1,k1', '--dry-run', '-c', 'rm -rf /'], { env: { FAKE_LOG: log } });
  assert.equal(r.code, 0);
  assert.equal(fs.existsSync(log), false);
  assert.match(r.out, /\[dry-run\] id=p1/);
  assert.match(r.out, /SSHPASS=\*\*\*/);
  assert.ok(!r.out.includes('s3cret'));
});

test('dry-run json lists problems instead of failing', async () => {
  const r = await run(['-i', 'nokey', '--dry-run', '--json', '-c', 'x']);
  assert.equal(r.code, 0);
  const doc = JSON.parse(r.out);
  assert.equal(doc.ok, false);
  assert.match(doc.plans[0].problems[0], /Private key not found/);
});

test('a broken target does not stop the others (config_error)', async () => {
  const r = await run(['-i', 'nokey,k1', '--json', '-c', 'x']);
  assert.equal(r.code, 1);
  const by = Object.fromEntries(JSON.parse(r.out).results.map((x) => [x.id, x]));
  assert.equal(by.nokey.errorKind, 'config_error');
  assert.equal(by.k1.ok, true);
});

test('usage/config errors exit 2; JSON mode reports them as JSON', async () => {
  let r = await run(['-i', 'nope', '-c', 'x']);
  assert.equal(r.code, 2);
  assert.match(r.err, /not found/);
  r = await run(['-i', 'k1']);
  assert.equal(r.code, 2);
  r = await run([ '--json', '-c', 'x']);
  assert.equal(r.code, 2);
  assert.equal(JSON.parse(r.out).error.kind, 'usage');
  r = await run(['--bogus', '--json']);
  assert.equal(r.code, 2);
  assert.equal(JSON.parse(r.out).ok, false);
});

test('missing credentials file is a config error', async () => {
  const stdout = new Sink();
  const code = await main(['--credentials-path', '/no/creds.json', '--get-credential-list', '--json'], { stdout, stderr: new Sink(), noLog: true });
  assert.equal(code, 2);
  assert.equal(JSON.parse(stdout.data).error.kind, 'config_error');
});

test('--check needs no command, runs only the no-op, and works across hosts', async () => {
  const r = await run(['-i', 'k1,authfail', '--check', '--json']);
  assert.equal(r.code, 1);
  const by = Object.fromEntries(JSON.parse(r.out).results.map((x) => [x.id, x]));
  assert.equal(by.k1.ok, true);
  assert.equal(by.k1.stdout, 'host=host1 cmd=true\n');
  assert.equal(by.authfail.errorKind, 'auth_failed');
});

test('--check rejects a command and --check --all covers every credential', async () => {
  assert.equal((await run(['-i', 'k1', '--check', '-c', 'x'])).code, 2);
  const r = await run(['--all', '--check', '--dry-run', '--json']);
  assert.ok(JSON.parse(r.out).plans.every((p) => p.remoteCommand === 'true'));
});

test('--print-alias prints an absolute-path alias line without needing credentials', async () => {
  const stdout = new Sink();
  const code = await main(['--print-alias', '--credentials-path', '/no/creds.json'], { stdout, stderr: new Sink(), noLog: true });
  assert.equal(code, 0);
  assert.match(stdout.data, /^alias lssh='node \/.+\/local-ssh-connect-cli\.js'\n$/);
});

test('package.json exposes the lssh bin and help documents setup', async () => {
  const pkg = require('../package.json');
  assert.equal(pkg.bin.lssh, './local-ssh-connect-cli.js');
  const stdout = new Sink();
  await main(['--help'], { stdout, stderr: new Sink() });
  assert.match(stdout.data, /FIRST-TIME SETUP/);
  assert.match(stdout.data, /--check/);
  assert.match(stdout.data, /npm link/);
});
