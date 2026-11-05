'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildExec, describePlan, isKeyEncrypted, checkPassphrase } = require('../lib/ssh');
const { createAskpass } = require('../lib/askpass');
const { defaults } = require('../lib/args');
const { main } = require('../lib/cli');
const { Sink, mkTmp, writeFakeSsh, writeFakeSshpass, writeCreds } = require('./helpers');

const bins = { ssh: '/usr/bin/ssh', sshpass: '/usr/bin/sshpass' };
const dir = mkTmp();
const key = path.join(dir, 'id');
fs.writeFileSync(key, 'k');
const b64 = (s) => Buffer.from(s).toString('base64');
const cred = (extra = {}) => ({ id: 'k', host: 'h', username: 'u', authType: 'key', privateKeyPath: key, ...extra });
const opt = (o = {}) => ({ ...defaults(), ...o });
const has = (args, a, b) => args.some((x, i) => x === a && args[i + 1] === b);

const KEYGEN = spawnSync('ssh-keygen', ['-V'], { encoding: 'utf8' }).error ? null : 'ssh-keygen';
const keygen = { skip: KEYGEN ? false : 'ssh-keygen not installed' };

function genKey(type, passphrase, extra = []) {
  const f = path.join(mkTmp(), 'key');
  const r = spawnSync('ssh-keygen', ['-q', '-t', type, '-N', passphrase, '-f', f, ...extra]);
  assert.equal(r.status, 0, String(r.stderr));
  return f;
}

// ---------- buildExec ----------
test('passphrase credential: askpass env, no BatchMode, single prompt, nothing secret in argv', () => {
  const e = buildExec(cred({ passphrase: b64('s3 cret\n') }), { command: 'id' }, opt(), bins, { askpassPath: '/tmp/ap.sh' });
  assert.deepEqual(e.errors, []);
  assert.equal(e.env.SSH_ASKPASS, '/tmp/ap.sh');
  assert.equal(e.env.SSH_ASKPASS_REQUIRE, 'force');
  assert.ok(e.env.DISPLAY);
  assert.equal(e.env.LSSH_PASSPHRASE, 's3 cret'); // trailing newline stripped
  assert.ok(!e.args.includes('BatchMode=yes'));
  assert.ok(e.args.includes('NumberOfPasswordPrompts=1'));
  assert.ok(e.args.includes('IdentitiesOnly=yes'));
  assert.ok(has(e.args, '-i', key));
  assert.ok(!e.args.join(' ').includes('s3 cret'));
  assert.equal(e.viaSshpass, false);
});

test('credential without passphrase keeps BatchMode and the real environment', () => {
  const e = buildExec(cred(), { command: 'id' }, opt(), bins);
  assert.ok(e.args.includes('BatchMode=yes'));
  assert.equal(e.env.SSH_ASKPASS, process.env.SSH_ASKPASS);
  assert.equal(e.env.LSSH_PASSPHRASE, undefined);
});

test('passphrase errors: invalid Base64, missing askpass helper', () => {
  assert.ok(buildExec(cred({ passphrase: '***' }), { command: 'x' }, opt(), bins, { askpassPath: '/a' }).errors.some((m) => /passphrase.*Base64/.test(m)));
  assert.ok(buildExec(cred({ passphrase: b64('x') }), { command: 'x' }, opt(), bins).errors.some((m) => /askpass/.test(m)));
});

test('describePlan masks the passphrase', () => {
  const e = buildExec(cred({ passphrase: b64('topsecret') }), { command: 'x' }, opt(), bins, { askpassPath: '/tmp/ap.sh' });
  const plan = describePlan(cred(), e, opt());
  assert.equal(plan.env.LSSH_PASSPHRASE, '***');
  assert.equal(plan.env.SSH_ASKPASS, '/tmp/ap.sh');
  assert.ok(!JSON.stringify(plan).includes('topsecret'));
});

test('passphrase does not affect password auth', () => {
  const e = buildExec({ id: 'p', host: 'h', username: 'u', authType: 'password', password: b64('pw'), passphrase: b64('zzz') },
    { command: 'x' }, opt(), bins, { askpassPath: '/a' });
  assert.equal(e.env.LSSH_PASSPHRASE, undefined);
  assert.equal(e.env.SSHPASS, 'pw');
});

// ---------- askpass helper ----------
test('askpass helper: answers passphrase prompts only, holds no secret, cleans up', () => {
  const ap = createAskpass();
  try {
    assert.equal(fs.statSync(ap.path).mode & 0o777, 0o700);
    assert.ok(!fs.readFileSync(ap.path, 'utf8').includes('secret'));
    const env = { ...process.env, LSSH_PASSPHRASE: "p'a $s" };
    const ok = spawnSync(ap.path, ["Enter passphrase for key '/k':"], { env, encoding: 'utf8' });
    assert.equal(ok.stdout, "p'a $s\n");
    for (const prompt of ['user@h password:', "Are you sure you want to continue connecting (yes/no)?"]) {
      const no = spawnSync(ap.path, [prompt], { env, encoding: 'utf8' });
      assert.notEqual(no.status, 0);
      assert.equal(no.stdout, '');
    }
    assert.equal(createAskpass(), ap); // reused within a process
  } finally {
    ap.cleanup();
  }
  assert.equal(fs.existsSync(ap.path), false);
});

// ---------- key inspection (real ssh-keygen) ----------
test('isKeyEncrypted: OpenSSH and PEM formats, with and without passphrase', keygen, () => {
  assert.equal(isKeyEncrypted(genKey('ed25519', '')), false);
  assert.equal(isKeyEncrypted(genKey('ed25519', 'passw0rd')), true);
  assert.equal(isKeyEncrypted(genKey('rsa', '', ['-b', '2048', '-m', 'PEM'])), false);
  assert.equal(isKeyEncrypted(genKey('rsa', 'passw0rd', ['-b', '2048', '-m', 'PEM'])), true);
  assert.equal(isKeyEncrypted('/no/such/key'), null);
  assert.equal(isKeyEncrypted(key), null); // not a key
});

test('checkPassphrase: right, wrong, and unknown', keygen, () => {
  const k = genKey('ed25519', 'right pw');
  const ap = createAskpass();
  try {
    const mk = (pw) => buildExec(cred({ privateKeyPath: k, passphrase: b64(pw) }), { command: 'x' }, opt(), bins, { askpassPath: ap.path });
    assert.equal(checkPassphrase(mk('right pw'), 'ssh-keygen'), true);
    assert.equal(checkPassphrase(mk('wrong'), 'ssh-keygen'), false);
    assert.equal(checkPassphrase(mk('x'), null), null);
  } finally {
    ap.cleanup();
  }
});

// ---------- end to end through the CLI ----------
const tdir = mkTmp();
const ssh = writeFakeSsh(tdir);
const sshpass = writeFakeSshpass(tdir);
const creds = writeCreds(tdir);
const base = ['--credentials-path', creds, '--ssh-path', ssh, '--sshpass-path', sshpass, '--retry-delay', '0'];

async function run(args, env = {}, credsFile = creds) {
  const stdout = new Sink();
  const stderr = new Sink();
  const prev = {};
  for (const [k, v] of Object.entries(env)) { prev[k] = process.env[k]; process.env[k] = v; }
  try {
    const argv = ['--credentials-path', credsFile, '--ssh-path', ssh, '--sshpass-path', sshpass, '--retry-delay', '0', ...args];
    const code = await main(argv, { stdout, stderr, noLog: true, env: { ...process.env, LSSH_LOG_DIR: path.join(tdir, 'logs') } });
    return { code, out: stdout.data, err: stderr.data };
  } finally {
    for (const [k, v] of Object.entries(prev)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

test('CLI: ssh receives a working askpass helper and the decoded passphrase; helper is removed afterwards', async () => {
  const envFile = path.join(tdir, 'env.txt');
  const r = await run(['-i', 'pp', '--json', '-c', 'x'], { FAKE_ENV_FILE: envFile });
  assert.equal(r.code, 0, r.err + r.out);
  const seen = Object.fromEntries(fs.readFileSync(envFile, 'utf8').trim().split('\n').map((l) => l.split(/=(.*)/s).slice(0, 2)));
  assert.equal(seen.require, 'force');
  assert.equal(seen.passphrase, 'pa ss');
  assert.equal(seen.prompt_answer, 'pa ss'); // the helper really answers the prompt
  assert.equal(fs.existsSync(seen.askpass), false); // cleaned up after the run
  assert.ok(!r.out.includes('pa ss'));
});

test('CLI: --dry-run creates no helper and masks the passphrase', async () => {
  const r = await run(['-i', 'pp', '--dry-run', '--json', '-c', 'x']);
  const plan = JSON.parse(r.out).plans[0];
  assert.equal(plan.env.LSSH_PASSPHRASE, '***');
  assert.equal(plan.env.SSH_ASKPASS, '<temporary askpass helper>');
  assert.ok(!r.out.includes('pa ss'));
});

test('CLI: wrong passphrase is reported as bad_passphrase; right one stays auth_failed on a denying server', keygen, async () => {
  const k = genKey('ed25519', 'right');
  const f = path.join(mkTmp(), 'creds.json');
  const mk = (id, pw) => ({ id, host: 'authfail', username: 'u', authType: 'key', privateKeyPath: k, passphrase: b64(pw) });
  fs.writeFileSync(f, JSON.stringify({ credentials: [mk('wrong', 'nope'), mk('right', 'right')] }));
  const r = await run(['-i', 'wrong,right', '--json', '-c', 'x'], {}, f);
  const by = Object.fromEntries(JSON.parse(r.out).results.map((x) => [x.id, x]));
  assert.equal(by.wrong.errorKind, 'bad_passphrase');
  assert.match(by.wrong.stderr, /does not decrypt/);
  assert.equal(by.right.errorKind, 'auth_failed');
});

test('CLI: protected key without a configured passphrase gets a hint on auth failure and a dry-run warning', keygen, async () => {
  const k = genKey('ed25519', 'passw0rd');
  const f = path.join(mkTmp(), 'creds.json');
  fs.writeFileSync(f, JSON.stringify({ credentials: [{ id: 'np', host: 'authfail', username: 'u', authType: 'key', privateKeyPath: k }] }));
  const r = await run(['-i', 'np', '--json', '-c', 'x'], {}, f);
  assert.match(JSON.parse(r.out).results[0].stderr, /passphrase-protected but credential "np" has no "passphrase"/);
  const d = await run(['-i', 'np', '--dry-run', '--json', '-c', 'x'], {}, f);
  assert.match(JSON.parse(d.out).plans[0].problems.join(' '), /passphrase-protected/);
});
