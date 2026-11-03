'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const T = require('../lib/transfer');
const { parseArgs } = require('../lib/args');
const { main } = require('../lib/cli');
const { Sink, mkTmp, writeFakeSsh, writeFakeSshpass, writeCreds } = require('./helpers');

const dir = mkTmp();
const ssh = writeFakeSsh(dir);
const sshpass = writeFakeSshpass(dir);
const creds = writeCreds(dir);
const base = ['--credentials-path', creds, '--ssh-path', ssh, '--sshpass-path', sshpass, '--retry-delay', '0'];
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function run(args) {
  const stdout = new Sink();
  const stderr = new Sink();
  const code = await main([...base, ...args], { stdout, stderr, noLog: true, env: { ...process.env, LSSH_LOG_DIR: path.join(dir, 'logs') } });
  return { code, out: stdout.data, err: stderr.data };
}

// All 256 byte values, twice: proves downloads/uploads are binary-safe.
const BIN = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256));

// ---------- argument parsing ----------
test('subcommand parsing: tail / get / put', () => {
  let o = parseArgs(['tail', '-i', 'a', '--file', '/var/log/x', '-n', '20', '--follow', '--duration', '10', '--grep', 'ERR']);
  assert.equal(o.mode, 'tail');
  assert.deepEqual([o.file, o.lines, o.follow, o.duration, o.grep], ['/var/log/x', 20, true, 10, 'ERR']);
  o = parseArgs(['get', '-i', 'a', '/r/file', './out', '--force']);
  assert.deepEqual([o.mode, o.operands, o.force], ['get', ['/r/file', './out'], true]);
  o = parseArgs(['put', '-i', 'a', './f', '/r/dir/', '--mode', '0640']);
  assert.deepEqual([o.mode, o.operands, o.fileMode], ['put', ['./f', '/r/dir/'], '0640']);
});

test('subcommand validation errors', () => {
  assert.throws(() => parseArgs(['tail', '-i', 'a']), /--file/);
  assert.throws(() => parseArgs(['get', '-i', 'a', '/r']), /Usage: get/);
  assert.throws(() => parseArgs(['put', '-i', 'a', './f']), /Usage: put/);
  assert.throws(() => parseArgs(['get', '-i', 'a', '/r', './l', '-c', 'x']), /does not take/);
  assert.throws(() => parseArgs(['put', '-i', 'a', './f', '/r', '--check']), /does not take/);
  assert.throws(() => parseArgs(['-i', 'a', 'stray']), /Unknown argument|Unexpected/);
  assert.throws(() => parseArgs(['put', '-i', 'a', './f', '/r', '--mode', '9z']), /octal/);
});

// ---------- command builders ----------
test('shQuote neutralises quotes and shell metacharacters', () => {
  const out = spawnSync('sh', ['-c', `printf %s ${T.shQuote("a'b $HOME `x` ; rm")}`], { encoding: 'utf8' });
  assert.equal(out.stdout, "a'b $HOME `x` ; rm");
});

test('tailCommand', () => {
  assert.equal(T.tailCommand({ file: '/v/l', lines: 5, follow: false }), "tail -n 5 -- '/v/l'");
  assert.equal(T.tailCommand({ file: '/v/l', lines: 5, follow: true }), "tail -n 5 -f -- '/v/l'");
  assert.match(T.tailCommand({ file: '/v/l', lines: 5, grep: "it's" }), /grep --line-buffered -e 'it'\\''s' \|\| \[ \$\? -eq 1 \]$/);
});

function remotePut(args, input) {
  return spawnSync('sh', ['-c', T.putCommand(args)], { input, encoding: 'buffer' });
}

test('putCommand: writes atomically, refuses overwrite (exit 17), --force, dir destination, chmod', () => {
  const d = mkTmp();
  const dest = path.join(d, 'a.bin');
  assert.equal(remotePut({ remotePath: dest, baseName: 'a.bin' }, BIN).status, 0);
  assert.deepEqual(fs.readFileSync(dest), BIN);
  assert.deepEqual(fs.readdirSync(d), ['a.bin']); // no leftover partial file

  const again = remotePut({ remotePath: dest, baseName: 'a.bin' }, Buffer.from('new'));
  assert.equal(again.status, 17);
  assert.match(again.stderr.toString(), /exists/);
  assert.deepEqual(fs.readFileSync(dest), BIN);

  assert.equal(remotePut({ remotePath: dest, baseName: 'a.bin', force: true }, Buffer.from('new')).status, 0);
  assert.equal(fs.readFileSync(dest, 'utf8'), 'new');

  const sub = path.join(d, 'sub');
  fs.mkdirSync(sub);
  assert.equal(remotePut({ remotePath: `${sub}/`, baseName: 'f.txt', fileMode: '0640' }, Buffer.from('x')).status, 0);
  assert.equal(fs.statSync(path.join(sub, 'f.txt')).mode & 0o777, 0o640);
});

test('putCommand handles awkward paths', () => {
  const d = mkTmp();
  const dest = path.join(d, "it's a file $x.txt");
  assert.equal(remotePut({ remotePath: dest, baseName: 'f' }, Buffer.from('ok')).status, 0);
  assert.equal(fs.readFileSync(dest, 'utf8'), 'ok');
});

test('localTargetFor / remoteBaseName', () => {
  const d = mkTmp();
  assert.equal(T.localTargetFor({ dest: d, id: 'x', baseName: 'f', multi: false }), path.join(d, 'f'));
  assert.equal(T.localTargetFor({ dest: path.join(d, 'new.txt'), id: 'x', baseName: 'f', multi: false }), path.join(d, 'new.txt'));
  assert.equal(T.localTargetFor({ dest: d, id: 'x', baseName: 'f', multi: true }), path.join(d, 'x', 'f'));
  assert.equal(T.remoteBaseName('/a/b/c.log'), 'c.log');
  assert.equal(T.remoteBaseName('/a/b/'), 'b');
});

// ---------- end to end through the CLI (fake ssh executes remote commands locally) ----------
test('get: binary-safe download with sha256, atomic (no partial left)', async () => {
  const d = mkTmp();
  const remote = path.join(d, 'remote.bin');
  fs.writeFileSync(remote, BIN);
  const local = path.join(d, 'local.bin');
  const r = await run(['get', '-i', 'local1', '--json', remote, local]);
  assert.equal(r.code, 0, r.err + r.out);
  assert.deepEqual(fs.readFileSync(local), BIN);
  assert.equal(fs.existsSync(`${local}.lssh-partial`), false);
  const t = JSON.parse(r.out).results[0].transfer;
  assert.deepEqual([t.direction, t.bytes, t.sha256], ['get', 512, sha(BIN)]);
});

test('get: refuses to overwrite without --force, overwrites with it', async () => {
  const d = mkTmp();
  const remote = path.join(d, 'r.txt');
  fs.writeFileSync(remote, 'new');
  const local = path.join(d, 'l.txt');
  fs.writeFileSync(local, 'old');
  let r = await run(['get', '-i', 'local1', remote, local]);
  assert.equal(r.code, 2);
  assert.match(r.err, /Local file exists/);
  assert.equal(fs.readFileSync(local, 'utf8'), 'old');
  r = await run(['get', '-i', 'local1', '--force', remote, local]);
  assert.equal(r.code, 0);
  assert.equal(fs.readFileSync(local, 'utf8'), 'new');
});

test('get: failed download leaves no file behind and reports the remote error', async () => {
  const d = mkTmp();
  const local = path.join(d, 'out', 'x');
  const r = await run(['get', '-i', 'local1', '--json', path.join(d, 'missing'), local]);
  assert.equal(r.code, 1);
  const res = JSON.parse(r.out).results[0];
  assert.equal(res.errorKind, 'remote_nonzero');
  assert.equal(res.transfer, undefined);
  assert.equal(fs.existsSync(local), false);
  assert.equal(fs.existsSync(`${local}.lssh-partial`), false);
});

test('get from several hosts lands in <dest>/<id>/<name>', async () => {
  const d = mkTmp();
  const remote = path.join(d, 'shared.txt');
  fs.writeFileSync(remote, 'hello');
  const dest = path.join(d, 'got');
  const r = await run(['get', '-i', 'local1,local2', remote, dest]);
  assert.equal(r.code, 0, r.err);
  assert.equal(fs.readFileSync(path.join(dest, 'local1', 'shared.txt'), 'utf8'), 'hello');
  assert.equal(fs.readFileSync(path.join(dest, 'local2', 'shared.txt'), 'utf8'), 'hello');
  assert.match(r.out, /\[local1\] get: 5 bytes sha256=/);
});

test('put: binary-safe upload with sha256; second put needs --force', async () => {
  const d = mkTmp();
  const src = path.join(d, 'src.bin');
  fs.writeFileSync(src, BIN);
  const remote = path.join(d, 'up.bin');
  let r = await run(['put', '-i', 'local1', '--json', src, remote]);
  assert.equal(r.code, 0, r.err + r.out);
  assert.deepEqual(fs.readFileSync(remote), BIN);
  const t = JSON.parse(r.out).results[0].transfer;
  assert.deepEqual([t.direction, t.bytes, t.sha256], ['put', 512, sha(BIN)]);

  r = await run(['put', '-i', 'local1', '--json', src, remote]);
  assert.equal(r.code, 17);
  assert.equal(JSON.parse(r.out).results[0].errorKind, 'remote_nonzero');
  assert.match(JSON.parse(r.out).results[0].stderr, /use --force/);

  r = await run(['put', '-i', 'local1', '--force', '--mode', '0600', src, remote]);
  assert.equal(r.code, 0);
  assert.equal(fs.statSync(remote).mode & 0o777, 0o600);
});

test('put to several hosts at once', async () => {
  const d = mkTmp();
  const src = path.join(d, 's.txt');
  fs.writeFileSync(src, 'deploy me');
  const r = await run(['put', '-i', 'local1,local2', '--force', src, path.join(d, 'dst.txt')]);
  assert.equal(r.code, 0, r.err);
  assert.equal(fs.readFileSync(path.join(d, 'dst.txt'), 'utf8'), 'deploy me');
  assert.match(r.out, /\[local2\] put: 9 bytes/);
});

test('put: missing local file and directories are config errors', async () => {
  const d = mkTmp();
  assert.equal((await run(['put', '-i', 'local1', path.join(d, 'nope'), '/tmp/x'])).code, 2);
  const r = await run(['put', '-i', 'local1', d, '/tmp/x']);
  assert.equal(r.code, 2);
  assert.match(r.err, /Not a regular file/);
});

test('get/put --dry-run show the transfer and run nothing', async () => {
  const d = mkTmp();
  const src = path.join(d, 's.txt');
  fs.writeFileSync(src, 'abc');
  const r = await run(['put', '-i', 'k1', '--dry-run', '--json', src, '/srv/s.txt']);
  assert.equal(r.code, 0);
  const plan = JSON.parse(r.out).plans[0];
  assert.deepEqual([plan.transfer.direction, plan.stdinBytes, plan.stdinFile], ['put', 3, src]);
  const g = await run(['get', '-i', 'k1', '--dry-run', path.join(d, 'x'), path.join(d, 'y')]);
  assert.match(g.out, /xfer : get/);
  assert.equal(fs.existsSync(path.join(d, 'y')), false);
});

test('tail: last N lines with grep (no match is not an error)', async () => {
  const d = mkTmp();
  const f = path.join(d, 'app.log');
  fs.writeFileSync(f, ['a ok', 'b ERROR one', 'c ok', 'd ERROR two', 'e ok'].join('\n') + '\n');
  let r = await run(['tail', '-i', 'local1', '--file', f, '-n', '4', '--grep', 'ERROR']);
  assert.equal(r.code, 0, r.err);
  assert.equal(r.out, 'b ERROR one\nd ERROR two\n');
  r = await run(['tail', '-i', 'local1', '--file', f, '--grep', 'NOPE']);
  assert.equal(r.code, 0);
  assert.equal(r.out, '');
});

test('tail: multi-host output is prefixed; missing file is remote_nonzero', async () => {
  const d = mkTmp();
  const f = path.join(d, 'a.log');
  fs.writeFileSync(f, 'one\ntwo\n');
  let r = await run(['tail', '-i', 'local1,local2', '--file', f, '-n', '1']);
  assert.equal(r.out, '[local1] two\n[local2] two\n');
  r = await run(['tail', '-i', 'local1', '--json', '--file', path.join(d, 'none')]);
  assert.equal(JSON.parse(r.out).results[0].errorKind, 'remote_nonzero');
});

test('tail --follow ends after --duration and counts as success', async () => {
  const d = mkTmp();
  const f = path.join(d, 'f.log');
  fs.writeFileSync(f, 'first\n');
  const started = Date.now();
  const r = await run(['tail', '-i', 'local1', '--file', f, '-n', '1', '--follow', '--duration', '1', '--json']);
  assert.equal(r.code, 0, r.err);
  assert.ok(Date.now() - started < 4000);
  const res = JSON.parse(r.out).results[0];
  assert.equal(res.ok, true);
  assert.equal(res.timedOut, true);
  assert.equal(res.stdout, 'first\n');
});
