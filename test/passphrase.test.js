'use strict';

/**
 * Specification of the credential "passphrase" feature (passphrase-protected private keys).
 *
 * Contract being pinned down here:
 *   - The Base64 `passphrase` of an authType:"key" credential is delivered to ssh through a
 *     temporary SSH_ASKPASS helper: environment only, never argv, disk, logs or output.
 *   - Invalid/unsupported passphrases are rejected up front with a clear config_error
 *     (they would otherwise fail silently or be truncated by ssh's askpass interface).
 *   - Authentication failures are explained: bad_passphrase (verified locally with ssh-keygen),
 *     or a hint when a protected key has no passphrase configured.
 *   - Everything fails closed and cleans up after itself.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildExec, describePlan, isKeyEncrypted, checkPassphrase } = require('../lib/ssh');
const { hasPassphrase, decodePassphrase, PASSPHRASE_MAX_BYTES } = require('../lib/credentials');
const { createAskpass, SCRIPT } = require('../lib/askpass');
const { classify } = require('../lib/classify');
const { exitCodeFor } = require('../lib/output');
const { defaults } = require('../lib/args');
const { ConfigError } = require('../lib/errors');
const { main } = require('../lib/cli');
const { Sink, mkTmp, writeFakeSsh, writeFakeSshpass, writeCreds } = require('./helpers');

// ---------------------------------------------------------------- fixtures
const bins = { ssh: '/usr/bin/ssh', sshpass: '/usr/bin/sshpass' };
const tmp = mkTmp();
const keyFile = path.join(tmp, 'id');
fs.writeFileSync(keyFile, 'k');
const b64 = (s) => Buffer.from(s).toString('base64');
const cred = (extra = {}) => ({ id: 'k', host: 'h', username: 'u', authType: 'key', privateKeyPath: keyFile, ...extra });
const opt = (o = {}) => ({ ...defaults(), ...o });
const has = (args, a, b) => args.some((x, i) => x === a && args[i + 1] === b);
const build = (c, o = {}, deps = { askpassPath: '/tmp/ap.sh' }) => buildExec(c, { command: 'id' }, opt(o), bins, deps);

const HAVE_KEYGEN = !spawnSync('ssh-keygen', ['-V'], { encoding: 'utf8' }).error;
const needsKeygen = { skip: HAVE_KEYGEN ? false : 'ssh-keygen not installed' };

function genKey(type, passphrase, extra = []) {
  const f = path.join(mkTmp(), 'key');
  const r = spawnSync('ssh-keygen', ['-q', '-t', type, '-N', passphrase, '-f', f, ...extra]);
  assert.equal(r.status, 0, String(r.stderr));
  return f;
}

/** Hand-made OpenSSH private key file (only the header fields isKeyEncrypted reads). */
function opensshKey({ cipher = 'none', magic = 'openssh-key-v1\0', crlf = false, truncateAt, lenOverride } = {}) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(lenOverride === undefined ? Buffer.byteLength(cipher) : lenOverride);
  let body = Buffer.concat([Buffer.from(magic, 'latin1'), len, Buffer.from(cipher), Buffer.alloc(40, 1)]);
  if (truncateAt !== undefined) body = body.subarray(0, truncateAt);
  const lines = body.toString('base64').match(/.{1,70}/g) || [];
  const nl = crlf ? '\r\n' : '\n';
  return `-----BEGIN OPENSSH PRIVATE KEY-----${nl}${lines.join(nl)}${nl}-----END OPENSSH PRIVATE KEY-----${nl}`;
}

function writeTmp(content) {
  const f = path.join(mkTmp(), 'k');
  fs.writeFileSync(f, content);
  return f;
}

const askpassDirs = () => fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('lssh-askpass-'));

// =========================================================================
describe('credential field semantics (hasPassphrase)', () => {
  it('null, undefined and the empty string mean "no passphrase"', () => {
    for (const v of [undefined, null, '']) assert.equal(hasPassphrase({ passphrase: v }), false, String(v));
    assert.equal(hasPassphrase({}), false);
    assert.equal(hasPassphrase(null), false);
  });

  it('any other value counts as configured (so it is validated, not silently ignored)', () => {
    for (const v of ['YQ==', 0, false, 123, {}, [], ' ']) assert.equal(hasPassphrase({ passphrase: v }), true, JSON.stringify(v));
  });
});

// =========================================================================
describe('decodePassphrase: accepted values', () => {
  const ok = (plain) => assert.equal(decodePassphrase(b64(plain)), plain, JSON.stringify(plain));

  it('plain, spaced, quoted and shell-special passphrases round-trip unchanged', () => {
    ok('simple');
    ok('with spaces inside');
    ok('  leading and trailing spaces  ');
    ok(`it's "quoted" $HOME \`id\` \\ ! * ? ; | & > < ( ) { }`);
    ok('%s %d \\n literal backslash-n');
  });

  it('unicode passphrases are preserved', () => {
    ok('pässwörd');
    ok('한글-비밀번호');
    ok('🔑 emoji 🔐');
  });

  it('a trailing newline (echo pw | base64) is stripped, once or CRLF, but only at the end', () => {
    assert.equal(decodePassphrase(b64('pw\n')), 'pw');
    assert.equal(decodePassphrase(b64('pw\r\n')), 'pw');
    assert.equal(decodePassphrase(b64('pw \n')), 'pw '); // trailing space is part of the passphrase
  });

  it('whitespace/newlines inside the Base64 text are tolerated (wrapped Base64)', () => {
    const wrapped = b64('wrapped passphrase').replace(/(.{6})/g, '$1\n');
    assert.equal(decodePassphrase(wrapped), 'wrapped passphrase');
  });

  it(`the size limit is ${PASSPHRASE_MAX_BYTES} bytes (UTF-8), inclusive`, () => {
    assert.equal(PASSPHRASE_MAX_BYTES, 1023);
    assert.equal(decodePassphrase(b64('a'.repeat(1023))).length, 1023);
    assert.equal(decodePassphrase(b64('한'.repeat(341))).length, 341); // 341 * 3 = 1023 bytes
  });
});

// =========================================================================
describe('decodePassphrase: rejected values (unhappy paths)', () => {
  const rejects = (value, re, label = JSON.stringify(value)) =>
    assert.throws(() => decodePassphrase(value), (e) => e instanceof ConfigError && re.test(e.message), label);

  it('non-string values', () => {
    for (const v of [123, true, false, 0, {}, [], ['YQ=='], null, undefined]) rejects(v, /must be a Base64 string/);
  });

  it('invalid Base64: wrong characters, URL-safe alphabet, bad length, stray padding', () => {
    rejects('not base64!!', /Base64/);
    rejects('ab-_cd==', /Base64/); // URL-safe alphabet is not accepted
    rejects('YQ===', /Base64/);
    rejects('abcde', /Base64/); // length % 4 == 1
    rejects('=YQ=', /Base64/);
  });

  it('values that decode to nothing: ignored-looking mistakes are errors, not silent empty passphrases', () => {
    rejects(' ', /empty/);
    rejects(b64('\n'), /empty/);
    rejects(b64('\r\n'), /empty/);
  });

  it('line breaks inside the passphrase (ssh askpass reads a single line, would truncate)', () => {
    rejects(b64('line1\nline2'), /line breaks/);
    rejects(b64('line1\r\nline2'), /line breaks/);
    rejects(b64('cr\rinside'), /line breaks/);
    rejects(b64('\npw'), /line breaks/); // leading newline
  });

  it('too long: 1024 bytes and above (askpass buffer), counted in bytes not characters', () => {
    rejects(b64('a'.repeat(1024)), /longer than 1023 bytes/);
    rejects(b64('한'.repeat(342)), /longer than 1023 bytes/); // 342 chars = 1026 bytes
    rejects(b64('a'.repeat(100000)), /longer than 1023 bytes/);
  });

  it('error messages never contain the secret or its Base64 form', () => {
    const secret = 'S3cr3t-do-not-leak';
    for (const value of [b64(`${secret}\n${secret}`), b64(secret.repeat(100)), `${b64(secret)}***`]) {
      try {
        decodePassphrase(value);
        assert.fail('should throw');
      } catch (e) {
        assert.ok(!e.message.includes(secret), e.message);
        assert.ok(!e.message.includes(b64(secret)), e.message);
      }
    }
  });
});

// =========================================================================
describe('buildExec with a passphrase', () => {
  it('delivers the passphrase through the askpass environment only', () => {
    const e = build(cred({ passphrase: b64('s3 cret') }));
    assert.deepEqual(e.errors, []);
    assert.equal(e.env.SSH_ASKPASS, '/tmp/ap.sh');
    assert.equal(e.env.SSH_ASKPASS_REQUIRE, 'force');
    assert.equal(e.env.LSSH_PASSPHRASE, 's3 cret');
    assert.equal(e.askpass, true);
    assert.equal(e.viaSshpass, false);
    assert.ok(!JSON.stringify(e.args).includes('s3 cret'));
    assert.ok(!JSON.stringify(e.args).includes(b64('s3 cret')));
  });

  it('turns BatchMode off (it would disable the prompt) and allows exactly one prompt', () => {
    const a = build(cred({ passphrase: b64('x1x1x') })).args;
    assert.ok(!a.includes('BatchMode=yes'));
    assert.ok(a.includes('NumberOfPasswordPrompts=1'));
  });

  it('keeps the other hardening options: pinned identity, publickey only, -i last before the target', () => {
    const a = build(cred({ passphrase: b64('x1x1x') })).args;
    assert.ok(a.includes('IdentitiesOnly=yes'));
    assert.ok(a.includes('PreferredAuthentications=publickey'));
    assert.ok(has(a, '-i', keyFile));
    assert.deepEqual(a.slice(-3), ['--', 'u@h', 'id']);
  });

  it('combines with the other options (port, host-key mode, script mode, keepalive)', () => {
    const e = buildExec(
      cred({ passphrase: b64('x1x1x'), port: 2200 }),
      { script: 'echo hi\n' },
      opt({ acceptNewHostKeys: true, shell: 'bash', keepalive: 5 }),
      bins,
      { askpassPath: '/tmp/ap.sh', knownHostsPath: '/k/kh' }
    );
    assert.deepEqual(e.errors, []);
    assert.ok(has(e.args, '-p', '2200'));
    assert.ok(e.args.includes('StrictHostKeyChecking=accept-new'));
    assert.ok(e.args.includes('ServerAliveInterval=5'));
    assert.equal(e.args[e.args.length - 1], 'bash -s');
    assert.equal(e.input, 'echo hi\n');
  });

  it('without a passphrase: BatchMode stays on and no askpass variables are added', () => {
    const e = build(cred(), {}, {});
    assert.ok(e.args.includes('BatchMode=yes'));
    assert.equal(e.askpass, false);
    assert.equal(e.env, process.env);
    assert.deepEqual(e.maskedEnv, []);
  });

  it('null / empty-string passphrase behaves exactly like no passphrase', () => {
    for (const v of [null, '']) {
      const e = build(cred({ passphrase: v }), {}, {});
      assert.ok(e.args.includes('BatchMode=yes'), String(v));
      assert.equal(e.askpass, false);
      assert.deepEqual(e.errors, []);
    }
  });

  it('is ignored for password credentials (sshpass path untouched)', () => {
    const e = buildExec(
      { id: 'p', host: 'h', username: 'u', authType: 'password', password: b64('pw'), passphrase: b64('zzzzz') },
      { command: 'x' }, opt(), bins, { askpassPath: '/a' }
    );
    assert.equal(e.env.LSSH_PASSPHRASE, undefined);
    assert.equal(e.env.SSH_ASKPASS, process.env.SSH_ASKPASS);
    assert.equal(e.env.SSHPASS, 'pw');
    assert.equal(e.askpass, false);
    assert.equal(e.keyPath, null);
  });

  it('reports every kind of bad passphrase as an exec error, never crashes or silently proceeds', () => {
    const cases = [
      [123, /must be a Base64 string/],
      [false, /must be a Base64 string/],
      [{}, /must be a Base64 string/],
      ['***', /Base64/],
      [b64('a\nb'), /line breaks/],
      [b64('a'.repeat(1024)), /longer than/],
      [b64('\n'), /empty/],
    ];
    for (const [v, re] of cases) {
      const e = build(cred({ passphrase: v }));
      assert.equal(e.errors.length >= 1, true, JSON.stringify(v));
      assert.ok(e.errors.some((m) => re.test(m)), `${JSON.stringify(v)} -> ${e.errors}`);
      assert.ok(e.errors.every((m) => m.includes('"k"') || !m.includes('undefined')), e.errors.join('|'));
    }
  });

  it('error text is attributable to the credential and leaks no secret', () => {
    const e = build(cred({ id: 'prod', passphrase: b64('Sup3rS3cret\nX') }));
    assert.ok(e.errors.some((m) => m.includes('"prod"')));
    assert.ok(!e.errors.join('\n').includes('Sup3rS3cret'));
  });

  it('missing askpass helper path is an internal error, not a silent empty SSH_ASKPASS', () => {
    const e = build(cred({ passphrase: b64('x1x1x') }), {}, {});
    assert.ok(e.errors.some((m) => /askpass/.test(m)));
  });

  it('does not mutate the parent environment and isolates targets from each other', () => {
    delete process.env.LSSH_PASSPHRASE;
    const a = build(cred({ id: 'a', passphrase: b64('first-secret') }));
    const b = build(cred({ id: 'b', passphrase: b64('second-secret') }));
    const c = build(cred({ id: 'c' }), {}, {});
    assert.equal(process.env.LSSH_PASSPHRASE, undefined);
    assert.equal(a.env.LSSH_PASSPHRASE, 'first-secret');
    assert.equal(b.env.LSSH_PASSPHRASE, 'second-secret');
    assert.equal(c.env.LSSH_PASSPHRASE, undefined);
  });

  it('DISPLAY: keeps an existing value, otherwise supplies one (old OpenSSH needs it)', () => {
    const saved = process.env.DISPLAY;
    try {
      process.env.DISPLAY = ':7';
      assert.equal(build(cred({ passphrase: b64('x1x1x') })).env.DISPLAY, ':7');
      delete process.env.DISPLAY;
      assert.ok(build(cred({ passphrase: b64('x1x1x') })).env.DISPLAY);
    } finally {
      if (saved === undefined) delete process.env.DISPLAY; else process.env.DISPLAY = saved;
    }
  });

  it('overrides a pre-existing SSH_ASKPASS of the user (ours must win)', () => {
    const saved = process.env.SSH_ASKPASS;
    try {
      process.env.SSH_ASKPASS = '/usr/bin/some-gui-askpass';
      assert.equal(build(cred({ passphrase: b64('x1x1x') })).env.SSH_ASKPASS, '/tmp/ap.sh');
    } finally {
      if (saved === undefined) delete process.env.SSH_ASKPASS; else process.env.SSH_ASKPASS = saved;
    }
  });

  it('a passphrase on a key that is not protected is flagged (ignored), a protected key without one is flagged', () => {
    const plain = writeTmp(opensshKey({ cipher: 'none' }));
    const prot = writeTmp(opensshKey({ cipher: 'aes256-ctr' }));
    const w1 = build(cred({ privateKeyPath: plain, passphrase: b64('x1x1x') })).warnings.join(' ');
    assert.match(w1, /not passphrase-protected \(the passphrase is ignored\)/);
    const w2 = build(cred({ privateKeyPath: prot })).warnings.join(' ');
    assert.match(w2, /passphrase-protected but credential "k" has no "passphrase"/);
    assert.deepEqual(build(cred({ privateKeyPath: prot, passphrase: b64('x1x1x') })).warnings, []);
    assert.deepEqual(build(cred({ privateKeyPath: plain }), {}, {}).warnings, []);
  });

  it('an unreadable/unknown key file produces no misleading protection warning', () => {
    assert.deepEqual(build(cred({ privateKeyPath: writeTmp('garbage'), passphrase: b64('x1x1x') })).warnings, []);
  });

  it('missing key file is still reported (and not hidden by the passphrase path)', () => {
    const e = build(cred({ privateKeyPath: '/no/such/key', passphrase: b64('x1x1x') }));
    assert.ok(e.errors.some((m) => /Private key not found/.test(m)));
  });
});

// =========================================================================
describe('describePlan (--dry-run) secrecy', () => {
  it('masks the passphrase and shows the helper path, never the secret or its Base64', () => {
    const plan = describePlan(cred(), build(cred({ passphrase: b64('topsecret') })), opt());
    assert.equal(plan.env.LSSH_PASSPHRASE, '***');
    assert.equal(plan.env.SSH_ASKPASS, '/tmp/ap.sh');
    const text = JSON.stringify(plan);
    assert.ok(!text.includes('topsecret'));
    assert.ok(!text.includes(b64('topsecret')));
  });

  it('plans without a passphrase have no askpass entries', () => {
    const plan = describePlan(cred(), build(cred(), {}, {}), opt());
    assert.deepEqual(plan.env, {});
  });

  it('includes warnings and errors as problems', () => {
    const plan = describePlan(cred(), build(cred({ passphrase: b64('a\nb') })), opt());
    assert.ok(plan.problems.some((m) => /line breaks/.test(m)));
  });
});

// =========================================================================
describe('askpass helper', () => {
  const run = (prompt, env) => spawnSync(helper.path, prompt === undefined ? [] : [prompt], { env, encoding: 'utf8' });
  let helper;
  const env = (pw) => ({ PATH: process.env.PATH, ...(pw === undefined ? {} : { LSSH_PASSPHRASE: pw }) });

  it('creates an owner-only executable under a private directory and holds no secret', () => {
    helper = createAskpass();
    try {
      assert.equal(fs.statSync(helper.path).mode & 0o777, 0o700);
      assert.equal(fs.statSync(path.dirname(helper.path)).mode & 0o777, 0o700);
      assert.ok(path.basename(path.dirname(helper.path)).startsWith('lssh-askpass-'));
      assert.equal(fs.readFileSync(helper.path, 'utf8'), SCRIPT);
      assert.ok(!/s3cret/i.test(SCRIPT));
    } finally {
      helper.cleanup();
    }
  });

  it('answers passphrase prompts exactly, byte for byte, with a single trailing newline', () => {
    helper = createAskpass();
    try {
      for (const pw of ['plain', "p'a $s `x` \\ !", '  spaces  ', '한글 🔑', 'a'.repeat(1023)]) {
        const r = run("Enter passphrase for key '/home/u/.ssh/id_ed25519': ", env(pw));
        assert.equal(r.status, 0);
        assert.equal(r.stdout, `${pw}\n`, pw.slice(0, 20));
      }
    } finally {
      helper.cleanup();
    }
  });

  it('recognises the prompt variants OpenSSH uses (case/wording)', () => {
    helper = createAskpass();
    try {
      for (const prompt of ['Enter passphrase for /k:', 'Enter passphrase for "/k" (will not be echoed):', 'Passphrase:', 'Bad passphrase, try again for /k:']) {
        assert.equal(run(prompt, env('pw')).stdout, 'pw\n', prompt);
      }
    } finally {
      helper.cleanup();
    }
  });

  it('refuses every other prompt (password, host-key confirmation, agent confirmation) and prints nothing', () => {
    helper = createAskpass();
    try {
      for (const prompt of [
        "user@host's password:",
        'Are you sure you want to continue connecting (yes/no/[fingerprint])?',
        'Allow use of key /k?\nKey fingerprint SHA256:abc.',
        'Verification code:',
        '',
      ]) {
        const r = run(prompt, env('pw'));
        assert.notEqual(r.status, 0, JSON.stringify(prompt));
        assert.equal(r.stdout, '', JSON.stringify(prompt));
      }
      const noArg = run(undefined, env('pw'));
      assert.notEqual(noArg.status, 0);
      assert.equal(noArg.stdout, '');
    } finally {
      helper.cleanup();
    }
  });

  it('fails closed when the passphrase variable is not set at all', () => {
    helper = createAskpass();
    try {
      const r = run('Enter passphrase for /k:', env(undefined));
      assert.notEqual(r.status, 0);
      assert.equal(r.stdout, '');
    } finally {
      helper.cleanup();
    }
  });

  it('is reused within a process, removed by cleanup(), idempotent, and re-creatable', () => {
    const a = createAskpass();
    assert.equal(createAskpass(), a);
    a.cleanup();
    assert.equal(fs.existsSync(a.path), false);
    assert.equal(fs.existsSync(path.dirname(a.path)), false);
    a.cleanup(); // second call must not throw
    const b = createAskpass();
    try {
      assert.notEqual(b.path, a.path);
      assert.equal(fs.existsSync(b.path), true);
    } finally {
      b.cleanup();
    }
  });

  it('does not stack process "exit" listeners on repeated create/cleanup cycles', () => {
    createAskpass().cleanup();
    const before = process.listenerCount('exit');
    for (let i = 0; i < 20; i++) createAskpass().cleanup();
    assert.equal(process.listenerCount('exit'), before);
  });

  it('creation failure is a ConfigError that names the cause', () => {
    const saved = process.env.TMPDIR;
    process.env.TMPDIR = '/no/such/dir/for/lssh';
    try {
      assert.throws(() => createAskpass(), (e) => e instanceof ConfigError && /Cannot create the temporary SSH_ASKPASS helper/.test(e.message));
    } finally {
      if (saved === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = saved;
    }
  });
});

// =========================================================================
describe('isKeyEncrypted: detection from the key file', () => {
  it('OpenSSH format: cipher "none" is unprotected, any real cipher is protected', () => {
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'none' }))), false);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'aes256-ctr' }))), true);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'aes256-gcm@openssh.com' }))), true);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'chacha20-poly1305@openssh.com' }))), true);
  });

  it('OpenSSH format with Windows (CRLF) line endings', () => {
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'none', crlf: true }))), false);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ cipher: 'aes256-ctr', crlf: true }))), true);
  });

  it('corrupt OpenSSH headers read as unknown (null), never as "encrypted"', () => {
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ magic: 'not-an-openssh-key' }))), null);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ truncateAt: 5 }))), null);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ truncateAt: 17 }))), null); // length field cut
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ truncateAt: 21 }))), null); // cipher name cut
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ lenOverride: 0 }))), null);
    assert.equal(isKeyEncrypted(writeTmp(opensshKey({ lenOverride: 5000 }))), null);
    assert.equal(isKeyEncrypted(writeTmp('-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n')), null);
  });

  it('legacy PEM: ENCRYPTED headers are protected, plain RSA/DSA/EC/PKCS8 are not', () => {
    assert.equal(isKeyEncrypted(writeTmp('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB\n\nxx\n-----END RSA PRIVATE KEY-----\n')), true);
    assert.equal(isKeyEncrypted(writeTmp('-----BEGIN ENCRYPTED PRIVATE KEY-----\nxx\n-----END ENCRYPTED PRIVATE KEY-----\n')), true);
    for (const kind of ['RSA ', 'DSA ', 'EC ', '']) {
      assert.equal(isKeyEncrypted(writeTmp(`-----BEGIN ${kind}PRIVATE KEY-----\nxx\n-----END ${kind}PRIVATE KEY-----\n`)), false, kind);
    }
  });

  it('unreadable or unrecognised files give null', () => {
    assert.equal(isKeyEncrypted('/no/such/file'), null);
    assert.equal(isKeyEncrypted(os.tmpdir()), null); // a directory
    assert.equal(isKeyEncrypted(writeTmp('')), null);
    assert.equal(isKeyEncrypted(writeTmp('just some text')), null);
    assert.equal(isKeyEncrypted(writeTmp('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n')), null);
    assert.equal(isKeyEncrypted(writeTmp(Buffer.from([0, 255, 254, 1, 2, 3]).toString('latin1'))), null);
  });
});

// =========================================================================
describe('real key files (ssh-keygen)', needsKeygen, () => {
  it('isKeyEncrypted agrees with ssh-keygen for OpenSSH, PEM and PKCS8 formats', () => {
    assert.equal(isKeyEncrypted(genKey('ed25519', '')), false);
    assert.equal(isKeyEncrypted(genKey('ed25519', 'passw0rd')), true);
    assert.equal(isKeyEncrypted(genKey('rsa', '', ['-b', '2048', '-m', 'PEM'])), false);
    assert.equal(isKeyEncrypted(genKey('rsa', 'passw0rd', ['-b', '2048', '-m', 'PEM'])), true);
    assert.equal(isKeyEncrypted(genKey('ecdsa', '', ['-m', 'PKCS8'])), false);
    assert.equal(isKeyEncrypted(genKey('ecdsa', 'passw0rd', ['-m', 'PKCS8'])), true);
  });

  /** Round-trips a passphrase through buildExec -> askpass helper -> real ssh-keygen. */
  function roundTrip(helperPath, keyPath, configured) {
    const e = buildExec(cred({ privateKeyPath: keyPath, passphrase: b64(configured) }), { command: 'x' }, opt(), bins, { askpassPath: helperPath });
    assert.deepEqual(e.errors, [], 'configured passphrase must be accepted');
    return checkPassphrase(e, 'ssh-keygen');
  }

  it('every accepted kind of passphrase actually unlocks a real key through the helper', () => {
    const helper = createAskpass();
    try {
      for (const pw of [
        'plain pass',
        "it's \"q\" $HOME `id` \\ !!",
        'pässwörd-한글-🔑',
        '  spaced  ',
        'a'.repeat(1023),
        '한'.repeat(341),
        '-----BEGIN-----',
        '-leading-dash',
      ]) {
        const k = genKey('ed25519', pw);
        assert.equal(roundTrip(helper.path, k, pw), true, `${pw.slice(0, 24)} (${Buffer.byteLength(pw)} bytes)`);
      }
    } finally {
      helper.cleanup();
    }
  });

  it('a wrong passphrase is reported as false, including near-misses', () => {
    const helper = createAskpass();
    try {
      const k = genKey('ed25519', 'right pass');
      for (const wrong of ['wrong pass', 'right pas', 'right pass ', ' right pass', 'RIGHT PASS', 'right passs']) {
        assert.equal(roundTrip(helper.path, k, wrong), false, JSON.stringify(wrong));
      }
      assert.equal(roundTrip(helper.path, k, 'right pass'), true);
    } finally {
      helper.cleanup();
    }
  });

  it('a configured passphrase on an unprotected key is harmless (never asked)', () => {
    const helper = createAskpass();
    try {
      assert.equal(roundTrip(helper.path, genKey('ed25519', ''), 'whatever'), true);
    } finally {
      helper.cleanup();
    }
  });

  it('only a passphrase failure yields false: missing, corrupt or unreadable keys are "unknown" (null)', () => {
    const helper = createAskpass();
    try {
      const mk = (keyPath) => buildExec(cred({ privateKeyPath: keyPath, passphrase: b64('x1x1x') }), { command: 'x' }, opt(), bins, { askpassPath: helper.path });
      assert.equal(checkPassphrase(mk('/no/such/key'), 'ssh-keygen'), null);
      assert.equal(checkPassphrase(mk(writeTmp('this is not a key')), 'ssh-keygen'), null);
      assert.equal(checkPassphrase(mk(writeTmp('')), 'ssh-keygen'), null);
      assert.equal(checkPassphrase(mk(os.tmpdir()), 'ssh-keygen'), null);
    } finally {
      helper.cleanup();
    }
  });

  it('cannot-tell cases: no ssh-keygen binary, binary path invalid, exec without a key path', () => {
    const e = build(cred({ passphrase: b64('x1x1x') }));
    assert.equal(checkPassphrase(e, null), null);
    assert.equal(checkPassphrase(e, '/no/such/ssh-keygen'), null);
    assert.equal(checkPassphrase({ ...e, keyPath: null }, 'ssh-keygen'), null);
  });
});

// =========================================================================
describe('classification and exit codes', () => {
  it('ssh output alone cannot prove a bad passphrase: a denied key stays auth_failed', () => {
    assert.equal(classify({ code: 255, stderr: 'u@h: Permission denied (publickey).' }).kind, 'auth_failed');
    assert.equal(classify({ code: 255, stderr: 'Load key "/k": incorrect passphrase supplied to decrypt private key\nPermission denied (publickey).' }).kind, 'auth_failed');
  });

  it('bad_passphrase is a single-target SSH-level failure (255), 1 among several', () => {
    const r = (id) => ({ id, ok: false, errorKind: 'bad_passphrase', exitCode: null });
    assert.equal(exitCodeFor([r('a')]), 255);
    assert.equal(exitCodeFor([r('a'), { id: 'b', ok: true }]), 1);
  });
});

// =========================================================================
describe('CLI end to end (fake ssh)', () => {
  const dir = mkTmp();
  const ssh = writeFakeSsh(dir);
  const sshpass = writeFakeSshpass(dir);
  const baseCreds = writeCreds(dir);

  const credsFile = (list) => {
    const f = path.join(mkTmp(), 'creds.json');
    fs.writeFileSync(f, JSON.stringify({ credentials: list }));
    return f;
  };
  const kc = (id, host, extra = {}) => ({ id, host, username: 'u', authType: 'key', privateKeyPath: path.join(dir, 'id_test'), ...extra });

  async function run(args, { env = {}, creds = baseCreds, logs = false } = {}) {
    const stdout = new Sink();
    const stderr = new Sink();
    const prev = {};
    for (const [k, v] of Object.entries(env)) { prev[k] = process.env[k]; process.env[k] = v; }
    const logDir = path.join(dir, `logs-${Math.random().toString(36).slice(2)}`);
    try {
      const code = await main(
        ['--credentials-path', creds, '--ssh-path', ssh, '--sshpass-path', sshpass, '--retry-delay', '0', ...args],
        { stdout, stderr, noLog: !logs, env: { ...process.env, LSSH_LOG_DIR: logDir } }
      );
      return { code, out: stdout.data, err: stderr.data, logDir };
    } finally {
      for (const [k, v] of Object.entries(prev)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
  }

  it('ssh gets a working helper and the decoded passphrase; the helper is deleted afterwards', async () => {
    const envFile = path.join(dir, 'env.txt');
    const before = askpassDirs();
    const r = await run(['-i', 'pp', '--json', '-c', 'x'], { env: { FAKE_ENV_FILE: envFile } });
    assert.equal(r.code, 0, r.err + r.out);
    const seen = Object.fromEntries(fs.readFileSync(envFile, 'utf8').trim().split('\n').map((l) => l.split(/=(.*)/s).slice(0, 2)));
    assert.equal(seen.require, 'force');
    assert.equal(seen.passphrase, 'pa ss'); // trailing newline of the Base64 source stripped
    assert.equal(seen.prompt_answer, 'pa ss'); // the helper really answers
    assert.equal(fs.existsSync(seen.askpass), false);
    assert.deepEqual(askpassDirs(), before);
  });

  it('several targets: each gets its own passphrase; non-passphrase targets get none; one shared helper', async () => {
    const log = path.join(dir, 'envlog.txt');
    fs.rmSync(log, { force: true });
    const f = credsFile([
      kc('a', 'host-a', { passphrase: b64('alpha-secret') }),
      kc('b', 'host-b', { passphrase: b64('beta-secret') }),
      kc('c', 'host-c'),
    ]);
    const r = await run(['-i', 'a,b,c', '--json', '-c', 'x', '--concurrency', '3'], { env: { FAKE_ENV_LOG: log }, creds: f });
    assert.equal(r.code, 0, r.err);
    const lines = Object.fromEntries(fs.readFileSync(log, 'utf8').trim().split('\n').map((l) => { const [h, p, ap] = l.split('|'); return [h, { p, ap }]; }));
    assert.equal(lines['host-a'].p, 'alpha-secret');
    assert.equal(lines['host-b'].p, 'beta-secret');
    assert.equal(lines['host-c'].p, '');
    assert.equal(lines['host-a'].ap, lines['host-b'].ap);
    assert.ok(lines['host-a'].ap.includes('lssh-askpass-'));
  });

  it('an invalid passphrase fails only that target (config_error), others still run, no secret echoed', async () => {
    const before = askpassDirs();
    const f = credsFile([
      kc('good', 'host-good', { passphrase: b64('good-secret') }),
      kc('multiline', 'host-ml', { passphrase: b64('Secr3t-line1\nSecr3t-line2') }),
      kc('toolong', 'host-tl', { passphrase: b64('x'.repeat(2000)) }),
      kc('badb64', 'host-bb', { passphrase: 'not*base64' }),
      kc('numeric', 'host-n', { passphrase: 12345 }),
    ]);
    const r = await run(['--all', '--json', '-c', 'x'], { creds: f });
    assert.equal(r.code, 1);
    const by = Object.fromEntries(JSON.parse(r.out).results.map((x) => [x.id, x]));
    assert.equal(by.good.ok, true);
    for (const id of ['multiline', 'toolong', 'badb64', 'numeric']) {
      assert.equal(by[id].errorKind, 'config_error', id);
      assert.equal(by[id].attempts, 0, id); // nothing was executed
    }
    assert.match(by.multiline.stderr, /line breaks/);
    assert.match(by.toolong.stderr, /longer than 1023/);
    assert.match(by.badb64.stderr, /Base64/);
    assert.match(by.numeric.stderr, /must be a Base64 string/);
    assert.ok(!r.out.includes('Secr3t') && !r.err.includes('Secr3t'));
    assert.deepEqual(askpassDirs(), before);
  });

  it('a single target with an invalid passphrase exits 2 and cleans up the helper', async () => {
    const before = askpassDirs();
    const f = credsFile([kc('only', 'host-x', { passphrase: b64('a\nb') })]);
    const r = await run(['-i', 'only', '-c', 'x'], { creds: f });
    assert.equal(r.code, 2);
    assert.match(r.err, /config_error.*line breaks/s);
    assert.deepEqual(askpassDirs(), before);
  });

  it('a passphrase on a password credential does not create a helper or touch the passphrase path', async () => {
    const before = askpassDirs();
    const f = credsFile([{ id: 'pw', host: 'pwhost', username: 'u', authType: 'password', password: b64('pw'), passphrase: 'garbage***' }]);
    const r = await run(['-i', 'pw', '--json', '-c', 'x'], { creds: f });
    assert.equal(r.code, 0, r.err + r.out);
    assert.deepEqual(askpassDirs(), before);
  });

  it('if the helper cannot be created the run is a config error (exit 2), not a crash', async () => {
    const r = await run(['-i', 'pp', '--json', '-c', 'x'], { env: { TMPDIR: '/no/such/dir/for/lssh' } });
    assert.equal(r.code, 2);
    const doc = JSON.parse(r.out);
    assert.equal(doc.ok, false);
    assert.equal(doc.error.kind, 'config_error');
    assert.match(doc.error.message, /SSH_ASKPASS helper/);
  });

  it('--dry-run creates no helper, executes nothing, and masks the secret in text and JSON', async () => {
    const before = askpassDirs();
    const log = path.join(dir, 'dry-envlog.txt');
    fs.rmSync(log, { force: true });
    const secret = 'pa ss';
    const j = await run(['-i', 'pp', '--dry-run', '--json', '-c', 'x'], { env: { FAKE_ENV_LOG: log } });
    const t = await run(['-i', 'pp', '--dry-run', '-c', 'x']);
    assert.equal(j.code, 0);
    assert.equal(JSON.parse(j.out).plans[0].env.SSH_ASKPASS, '<temporary askpass helper>');
    for (const out of [j.out, t.out, j.err, t.err]) {
      assert.ok(!out.includes(secret));
      assert.ok(!out.includes(b64(secret)));
    }
    assert.equal(fs.existsSync(log), false);
    assert.deepEqual(askpassDirs(), before);
  });

  it('--dry-run surfaces a bad passphrase as a problem and still exits 0', async () => {
    const f = credsFile([kc('bad', 'h', { passphrase: b64('a'.repeat(1500)) })]);
    const r = await run(['-i', 'bad', '--dry-run', '--json', '-c', 'x'], { creds: f });
    assert.equal(r.code, 0);
    const doc = JSON.parse(r.out);
    assert.equal(doc.ok, false);
    assert.match(doc.plans[0].problems.join(' '), /longer than 1023/);
  });

  it('--check, tail-style streaming and retries all work with a passphrase credential', async () => {
    const envFile = path.join(dir, 'env-check.txt');
    const c = await run(['-i', 'pp', '--check', '--json'], { env: { FAKE_ENV_FILE: envFile } });
    assert.equal(c.code, 0, c.err);
    assert.equal(JSON.parse(c.out).results[0].stdout, 'host=host1 cmd=true\n');

    const count = path.join(dir, 'flaky-pp-count');
    fs.rmSync(count, { force: true });
    const f = credsFile([kc('fl', 'flaky', { passphrase: b64('retry-secret') })]);
    const log = path.join(dir, 'retry-envlog.txt');
    fs.rmSync(log, { force: true });
    const r = await run(['-i', 'fl', '--json', '-c', 'x'], { env: { FAKE_COUNT: count, FAKE_ENV_LOG: log }, creds: f });
    assert.equal(r.code, 0, r.err);
    const res = JSON.parse(r.out).results[0];
    assert.equal(res.attempts, 2);
    const seen = fs.readFileSync(log, 'utf8').trim().split('\n');
    assert.equal(seen.length, 2);
    assert.ok(seen.every((l) => l.split('|')[1] === 'retry-secret')); // present on the retry too
  });

  it('put and get stream over stdin/stdout unharmed by the askpass setup (binary-safe)', async () => {
    const d = mkTmp();
    const blob = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 7) % 256));
    const src = path.join(d, 'src.bin');
    fs.writeFileSync(src, blob);
    const f = credsFile([kc('xfer', 'localexec1', { passphrase: b64('xfer-secret') })]);
    const remote = path.join(d, 'remote.bin');
    const up = await run(['put', '-i', 'xfer', '--json', src, remote], { creds: f });
    assert.equal(up.code, 0, up.err + up.out);
    assert.deepEqual(fs.readFileSync(remote), blob);
    const local = path.join(d, 'back.bin');
    const down = await run(['get', '-i', 'xfer', '--json', remote, local], { creds: f });
    assert.equal(down.code, 0, down.err + down.out);
    assert.deepEqual(fs.readFileSync(local), blob);
  });

  it('a denying server stays auth_failed (not bad_passphrase) when ssh-keygen cannot be consulted or the key is unprotected', async () => {
    const f = credsFile([kc('den', 'authfail', { passphrase: b64('some-pass') })]); // key file is "fake-key" text
    const r = await run(['-i', 'den', '--json', '-c', 'x'], { creds: f });
    const res = JSON.parse(r.out).results[0];
    assert.equal(res.errorKind, 'auth_failed');
    assert.equal(res.attempts, 1); // auth failures are never retried
  });

  it('the secret never reaches stdout, stderr, NDJSON events or the log files', async () => {
    const secret = 'Zx9-leak-canary';
    const f = credsFile([kc('ok', 'host-ok', { passphrase: b64(secret) }), kc('den', 'authfail', { passphrase: b64(secret) })]);
    const outputs = [];
    let logDir;
    for (const mode of [['--json'], ['--ndjson'], []]) {
      const r = await run(['-i', 'ok,den', ...mode, '-c', 'x'], { creds: f, logs: true });
      outputs.push(r.out, r.err);
      logDir = r.logDir;
    }
    for (const text of outputs) {
      assert.ok(!text.includes(secret));
      assert.ok(!text.includes(b64(secret)));
    }
    const logs = fs.existsSync(logDir) ? fs.readdirSync(logDir).map((n) => fs.readFileSync(path.join(logDir, n), 'utf8')).join('\n') : '';
    assert.ok(logs.length > 0, 'log files should have been written');
    assert.ok(!logs.includes(secret));
    assert.ok(!logs.includes(b64(secret)));
  });
});

// =========================================================================
describe('CLI end to end: bad_passphrase diagnosis (real ssh-keygen)', needsKeygen, () => {
  const dir = mkTmp();
  const ssh = writeFakeSsh(dir);
  const k = genKey('ed25519', 'right-pass');
  const plain = genKey('ed25519', '');
  const mk = (id, keyPath, pw, host = 'authfail') => ({ id, host, username: 'u', authType: 'key', privateKeyPath: keyPath, ...(pw === undefined ? {} : { passphrase: b64(pw) }) });

  async function run(list, args = []) {
    const f = path.join(mkTmp(), 'creds.json');
    fs.writeFileSync(f, JSON.stringify({ credentials: list }));
    const stdout = new Sink();
    const stderr = new Sink();
    const code = await main(['--credentials-path', f, '--ssh-path', ssh, '--retry-delay', '0', '--json', '-c', 'x', ...args], { stdout, stderr, noLog: true });
    return { code, doc: JSON.parse(stdout.data), err: stderr.data };
  }

  it('wrong passphrase -> bad_passphrase with a hint; right passphrase on a denying server -> auth_failed', async () => {
    const r = await run([mk('wrong', k, 'nope-nope'), mk('right', k, 'right-pass')], ['-i', 'wrong,right']);
    const by = Object.fromEntries(r.doc.results.map((x) => [x.id, x]));
    assert.equal(by.wrong.errorKind, 'bad_passphrase');
    assert.match(by.wrong.stderr, /does not decrypt the private key of "wrong"/);
    assert.equal(by.right.errorKind, 'auth_failed');
    assert.equal(r.doc.failed, 2);
    assert.equal(r.code, 1);
  });

  it('single target exit code is 255 for bad_passphrase', async () => {
    const r = await run([mk('wrong', k, 'nope-nope')], ['-i', 'wrong']);
    assert.equal(r.code, 255);
  });

  it('bad_passphrase is not retried and does not hang on a retry budget', async () => {
    const r = await run([mk('wrong', k, 'nope-nope')], ['-i', 'wrong', '--retries', '5']);
    assert.equal(r.doc.results[0].attempts, 1);
  });

  it('unprotected key with a (useless) passphrase and a denying server is auth_failed, never bad_passphrase', async () => {
    const r = await run([mk('plain', plain, 'whatever-pass')], ['-i', 'plain']);
    assert.equal(r.doc.results[0].errorKind, 'auth_failed');
  });

  it('protected key without a configured passphrase: auth_failed plus a clear hint', async () => {
    const r = await run([mk('nopass', k, undefined)], ['-i', 'nopass']);
    const res = r.doc.results[0];
    assert.equal(res.errorKind, 'auth_failed');
    assert.match(res.stderr, /passphrase-protected but credential "nopass" has no "passphrase"/);
  });

  it('the hint is not added to unrelated auth failures of unprotected keys', async () => {
    const r = await run([mk('plain', plain, undefined)], ['-i', 'plain']);
    assert.ok(!/hint/.test(r.doc.results[0].stderr));
  });

  it('a non-authentication failure with a passphrase is never relabelled bad_passphrase', async () => {
    const r = await run([mk('rem', k, 'nope-nope', 'remote3')], ['-i', 'rem']);
    assert.equal(r.doc.results[0].errorKind, 'remote_nonzero');
  });
});
