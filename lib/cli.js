'use strict';

const fs = require('fs');
const path = require('path');
const { parseArgs, sniffOutputMode } = require('./args');
const { UsageError, ConfigError } = require('./errors');
const { loadCredentials, resolveTargets, listCredentials } = require('./credentials');
const { resolveBinary, buildExec, describePlan, defaultKnownHostsPath } = require('./ssh');
const { runWithRetry, runPool } = require('./runner');
const { makeResult, configErrorResult, createReporter, exitCodeFor } = require('./output');
const { createLogger } = require('./logger');
const { HELP_TEXT } = require('./help');

const SCRIPT_DIR = path.resolve(__dirname, '..');
const DEFAULT_CREDENTIALS_PATH = path.join(SCRIPT_DIR, 'ssh-credentials.json');

function readStdin() {
  if (process.stdin.isTTY) throw new UsageError('"-c -" expects a script on stdin (pipe or heredoc), but stdin is a TTY.');
  return fs.readFileSync(0, 'utf8');
}

/** Resolve the command source -> { command } or { script }. */
function resolveCommandSource(opts, io) {
  if (opts.scriptFile) {
    let script;
    try {
      script = fs.readFileSync(opts.scriptFile, 'utf8');
    } catch (e) {
      throw new UsageError(`Cannot read --script-file: ${e.message}`);
    }
    if (!script.trim()) throw new UsageError(`--script-file is empty: ${opts.scriptFile}`);
    return { script };
  }
  if (opts.command === '-') {
    const script = (io.readStdin || readStdin)();
    if (!script.trim()) throw new UsageError('Script read from stdin is empty.');
    return { script };
  }
  if (opts.command === null || opts.command === '') {
    throw new UsageError('Missing -c / --command (or --script-file). Provide a remote command.');
  }
  return { command: opts.command };
}

function reportFatal(io, mode, kind, message) {
  if (mode === 'json' || mode === 'ndjson') {
    io.stdout.write(`${JSON.stringify({ ok: false, error: { kind, message } })}\n`);
  } else {
    io.stderr.write(`[lssh] ${kind === 'usage' ? 'usage error' : 'error'}: ${message}\n`);
  }
}

/**
 * Entry point. Returns the process exit code; never calls process.exit itself.
 * io: { stdout, stderr, readStdin?, env? }
 */
async function main(argv, io = {}) {
  io = { stdout: process.stdout, stderr: process.stderr, env: process.env, ...io };
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    reportFatal(io, sniffOutputMode(argv), 'usage', e.message);
    return 2;
  }

  if (opts.help) {
    io.stdout.write(`${HELP_TEXT}\n`);
    return 0;
  }

  const logDir = io.env.LSSH_LOG_DIR || path.join(SCRIPT_DIR, 'logs');
  const logger = createLogger({ logDir, verbose: opts.verbose, enabled: !opts.dryRun && !io.noLog });

  try {
    const data = loadCredentials(opts.credentialsPath || DEFAULT_CREDENTIALS_PATH);

    if (opts.getCredentialList) {
      io.stdout.write(`${JSON.stringify(listCredentials(data), null, 2)}\n`);
      return 0;
    }

    if (!opts.all && opts.ids.length === 0) throw new UsageError('Missing -i / --id (or --all). Specify a credential ID.');
    const source = resolveCommandSource(opts, io);
    const targets = resolveTargets(data, opts);
    if (targets.length === 0) throw new UsageError('No credentials to run against.');

    const bins = {
      ssh: resolveBinary('ssh', opts.sshPath),
      sshpass: targets.some((c) => c.authType === 'password') ? resolveBinary('sshpass', opts.sshpassPath) : null,
    };
    const knownHostsPath = defaultKnownHostsPath(logDir);
    const execs = targets.map((cred) => buildExec(cred, source, opts, bins, { knownHostsPath }));

    if (opts.dryRun) {
      const plans = targets.map((cred, i) => describePlan(cred, execs[i], opts));
      if (opts.output === 'text') {
        for (const p of plans) {
          io.stdout.write(`[dry-run] id=${p.id} host=${p.host} port=${p.port} auth=${p.authType}\n`);
          io.stdout.write(`  exec : ${p.commandLine}\n`);
          if (p.env.SSHPASS) io.stdout.write('  env  : SSHPASS=***\n');
          io.stdout.write(`  stdin: ${p.stdinBytes ? `${p.stdinBytes} bytes (script)` : 'none'}\n`);
          for (const problem of p.problems) io.stdout.write(`  WARN : ${problem}\n`);
        }
      } else {
        io.stdout.write(`${JSON.stringify({ ok: plans.every((p) => p.problems.length === 0), dryRun: true, plans })}\n`);
      }
      return 0;
    }

    logger.info(`start targets="${targets.map((c) => c.id).join(',')}" mode=${opts.output} concurrency=${opts.concurrency}`);
    const multi = targets.length > 1;
    const reporter = createReporter(opts.output, { multi, out: io.stdout, err: io.stderr });

    const results = await runPool(targets, opts.concurrency, async (cred, i) => {
      const exec = execs[i];
      reporter.start(cred.id, cred.host);
      let result;
      if (exec.errors.length) {
        result = configErrorResult(cred, exec.errors.join('\n'));
      } else {
        const run = await runWithRetry(exec, {
          retries: opts.retries,
          retryDelayMs: opts.retryDelay * 1000,
          execTimeoutMs: opts.execTimeout * 1000,
          onStdout: (c) => reporter.stdout(cred.id, c),
          onStderr: (c) => reporter.stderr(cred.id, c),
          onRetry: (info) => reporter.retry(cred.id, info),
        });
        result = makeResult(cred, run);
      }
      logger.info(`result id="${cred.id}" ok=${result.ok} kind=${result.errorKind || 'ok'} exit=${result.exitCode} attempts=${result.attempts} ms=${result.durationMs}`);
      reporter.finish(result);
      return result;
    });

    reporter.summary(results);
    return exitCodeFor(results);
  } catch (e) {
    if (e instanceof UsageError || e instanceof ConfigError) {
      logger.error(e.message);
      reportFatal(io, opts.output, e instanceof UsageError ? 'usage' : 'config_error', e.message);
      return 2;
    }
    throw e;
  } finally {
    await logger.close();
  }
}

module.exports = { main, resolveCommandSource };
