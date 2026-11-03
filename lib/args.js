'use strict';

const { UsageError } = require('./errors');

const OUTPUT_MODES = ['text', 'json', 'ndjson'];

function defaults() {
  return {
    help: false,
    getCredentialList: false,
    check: false,
    printAlias: false,
    credentialsPath: null,
    ids: [],
    all: false,
    command: null, // string, or '-' meaning "read script from stdin"
    scriptFile: null,
    shell: 'sh',
    timeout: 15, // SSH connect timeout (seconds)
    execTimeout: 0, // overall per-target timeout (seconds, 0 = none)
    keepalive: 30, // ServerAliveInterval seconds (0 = disabled)
    sshPath: null,
    sshpassPath: null,
    port: null,
    acceptNewHostKeys: false,
    noStrictHostKeyChecking: false,
    output: 'text',
    concurrency: 4,
    retries: 2,
    retryDelay: 2, // seconds, doubled on every retry
    dryRun: false,
    verbose: false,
  };
}

function toInt(name, raw, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (raw === undefined || raw === '' || !/^-?\d+$/.test(String(raw))) {
    throw new UsageError(`${name} requires an integer value (got: ${raw === undefined ? '<missing>' : raw}).`);
  }
  const n = Number(raw);
  if (n < min || n > max) {
    throw new UsageError(`${name} must be between ${min} and ${max} (got: ${n}).`);
  }
  return n;
}

function splitIds(raw) {
  return String(raw)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Parse argv (without node + script). Supports `--opt value` and `--opt=value`.
 * Throws UsageError on invalid input.
 */
function parseArgs(args) {
  const opts = defaults();
  let i = 0;

  const takeValue = (name, inline) => {
    if (inline !== undefined) return inline;
    const v = args[++i];
    if (v === undefined) throw new UsageError(`${name} requires a value.`);
    return v;
  };

  while (i < args.length) {
    let a = args[i];
    let inline;
    if (a.startsWith('--') && a.includes('=')) {
      const eq = a.indexOf('=');
      inline = a.slice(eq + 1);
      a = a.slice(0, eq);
    }

    switch (a) {
      case '--help':
      case '-h':
        opts.help = true;
        break;
      case '--get-credential-list':
        opts.getCredentialList = true;
        break;
      case '--check':
        opts.check = true;
        break;
      case '--print-alias':
        opts.printAlias = true;
        break;
      case '--credentials-path':
        opts.credentialsPath = takeValue(a, inline);
        break;
      case '-i':
      case '--id':
        for (const id of splitIds(takeValue(a, inline))) {
          if (!opts.ids.includes(id)) opts.ids.push(id);
        }
        break;
      case '--all':
        opts.all = true;
        break;
      case '-c':
      case '--command':
        opts.command = takeValue(a, inline);
        break;
      case '--script-file':
        opts.scriptFile = takeValue(a, inline);
        break;
      case '--shell': {
        const shell = takeValue(a, inline);
        if (!/^[A-Za-z0-9_./-]+$/.test(shell)) {
          throw new UsageError(`--shell must be a plain shell name or path (got: ${shell}).`);
        }
        opts.shell = shell;
        break;
      }
      case '--timeout':
        opts.timeout = toInt(a, takeValue(a, inline), { min: 1 });
        break;
      case '--exec-timeout':
        opts.execTimeout = toInt(a, takeValue(a, inline), { min: 0 });
        break;
      case '--keepalive':
        opts.keepalive = toInt(a, takeValue(a, inline), { min: 0, max: 3600 });
        break;
      case '--ssh-path':
        opts.sshPath = takeValue(a, inline);
        break;
      case '--sshpass-path':
        opts.sshpassPath = takeValue(a, inline);
        break;
      case '--port':
        opts.port = toInt(a, takeValue(a, inline), { min: 1, max: 65535 });
        break;
      case '--accept-new-host-keys':
        opts.acceptNewHostKeys = true;
        break;
      case '--no-strict-host-key-checking':
        opts.noStrictHostKeyChecking = true;
        break;
      case '--json':
        opts.output = 'json';
        break;
      case '--ndjson':
        opts.output = 'ndjson';
        break;
      case '--output': {
        const mode = takeValue(a, inline);
        if (!OUTPUT_MODES.includes(mode)) {
          throw new UsageError(`--output must be one of: ${OUTPUT_MODES.join(', ')} (got: ${mode}).`);
        }
        opts.output = mode;
        break;
      }
      case '--concurrency':
        opts.concurrency = toInt(a, takeValue(a, inline), { min: 1, max: 64 });
        break;
      case '--retries':
        opts.retries = toInt(a, takeValue(a, inline), { min: 0, max: 10 });
        break;
      case '--retry-delay':
        opts.retryDelay = toInt(a, takeValue(a, inline), { min: 0, max: 600 });
        break;
      case '--dry-run':
        opts.dryRun = true;
        break;
      case '--verbose':
        opts.verbose = true;
        break;
      default:
        throw new UsageError(`Unknown argument: ${args[i]}\nRun with --help for usage.`);
    }
    i++;
  }

  if (opts.check && (opts.command !== null || opts.scriptFile !== null)) {
    throw new UsageError('--check does not take a command (-c / --script-file).');
  }
  if (opts.command !== null && opts.scriptFile !== null) {
    throw new UsageError('Use either -c/--command or --script-file, not both.');
  }
  return opts;
}

/** Best-effort detection of the requested output mode (used when parsing itself failed). */
function sniffOutputMode(args) {
  if (args.includes('--ndjson')) return 'ndjson';
  if (args.includes('--json')) return 'json';
  const idx = args.indexOf('--output');
  if (idx >= 0 && OUTPUT_MODES.includes(args[idx + 1])) return args[idx + 1];
  const eq = args.find((a) => a.startsWith('--output='));
  if (eq && OUTPUT_MODES.includes(eq.slice('--output='.length))) return eq.slice('--output='.length);
  return 'text';
}

module.exports = { parseArgs, sniffOutputMode, defaults, OUTPUT_MODES };
