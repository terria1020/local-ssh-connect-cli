#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const winston = require('winston');

const SCRIPT_DIR = __dirname;
const CREDENTIALS_PATH = path.join(SCRIPT_DIR, 'ssh-credentials.json');
const APP_NAME = 'local-ssh-connect-cli';
const LOG_DIR = path.join(process.cwd(), 'logs');
fs.mkdirSync(LOG_DIR, { recursive: true });

const HELP_TEXT = `
local-ssh-connect-cli - Stateless SSH wrapper for credential encapsulation
=======================================================================

DESCRIPTION
  Stateless SSH CLI that executes a single command per run using credential IDs.
  Raw host/user/key/password values are managed in ssh-credentials.json.

GLOBAL OPTIONS
  --help                        Show this help and exit
  --get-credential-list         List credential metadata (safe fields only)
  --credentials-path <path>     Override default ssh-credentials.json path

RUN OPTIONS
  -i, --id <credential-id>      Credential ID from ssh-credentials.json
  -c, --command <command>       Remote command to execute (required)
  --ssh-path <path>             Override ssh binary path
  --timeout <seconds>           SSH connect timeout (default: 15)
  --port <number>               Override credential port
  --no-strict-host-key-checking Disable strict host key checking

EXAMPLES
  node local-ssh-connect-cli.js --get-credential-list
  node local-ssh-connect-cli.js -i example-key-server -c "hostname"
  node local-ssh-connect-cli.js -i example-password-server -c "uname -a"
`;

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    if (stack) return `${timestamp} [${level.toUpperCase()}]: ${message}\n${stack}`;
    return `${timestamp} [${level.toUpperCase()}]: ${message}`;
  })
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), logFormat),
      stream: process.stderr,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'error.log'),
      level: 'error',
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'combined.log'),
      maxsize: 5242880,
      maxFiles: 5,
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.level = 'debug';
}

const CLI_EXIT = Symbol('CLI_EXIT');
let exiting = false;

function exitCli(code) {
  if (exiting) return;
  exiting = true;
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    process.exit(code);
  };
  const timer = setTimeout(finish, 5000);
  try {
    logger.end(finish);
  } catch {
    finish();
  }
}

function die(msg, code = 1) {
  logger.error(msg);
  exitCli(code);
  throw CLI_EXIT;
}

function decodeBase64(v) {
  if (!v) return '';
  try {
    return Buffer.from(v, 'base64').toString('utf8');
  } catch {
    die('Failed to decode Base64 value in credentials.');
  }
}

function parseArgs(argv) {
  const opts = {
    help: false,
    getCredentialList: false,
    credentialsPath: null,
    id: null,
    command: null,
    timeout: 15,
    sshPath: null,
    port: null,
    noStrictHostKeyChecking: false,
  };

  const args = argv.slice(2);
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    switch (a) {
      case '--help':
        opts.help = true;
        break;
      case '--get-credential-list':
        opts.getCredentialList = true;
        break;
      case '--credentials-path':
        opts.credentialsPath = args[++i];
        break;
      case '-i':
      case '--id':
        opts.id = args[++i];
        break;
      case '-c':
      case '--command':
        opts.command = args[++i];
        break;
      case '--timeout':
        opts.timeout = Number(args[++i]);
        break;
      case '--ssh-path':
        opts.sshPath = args[++i];
        break;
      case '--port':
        opts.port = Number(args[++i]);
        break;
      case '--no-strict-host-key-checking':
        opts.noStrictHostKeyChecking = true;
        break;
      default:
        die(`Unknown argument: ${a}\nRun with --help for usage.`);
    }
    i++;
  }
  return opts;
}

function loadCredentials(credentialsPath) {
  const p = credentialsPath || CREDENTIALS_PATH;
  if (!fs.existsSync(p)) {
    die(
      `ssh-credentials.json not found at: ${p}\n` +
      '  Copy ssh-credentials.example.json to ssh-credentials.json and fill values.'
    );
  }

  let raw;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch (e) {
    die(`Cannot read credential file: ${e.message}`);
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    die(`ssh-credentials.json is not valid JSON: ${e.message}`);
  }

  if (!Array.isArray(data.credentials)) {
    die('ssh-credentials.json must have a "credentials" array.');
  }
  return data;
}

function getCredential(data, id) {
  const cred = data.credentials.find((c) => c.id === id);
  if (!cred) {
    const ids = data.credentials.map((c) => c.id).join(', ');
    die(`Credential "${id}" not found.\n  Available: ${ids}`);
  }
  return cred;
}

function printCredentialList(data) {
  const list = data.credentials.map((c) => ({
    id: c.id,
    name: c.name || '',
    host: c.host,
    port: c.port || 22,
    username: c.username,
    authType: c.authType,
    note: c.note || '',
  }));
  console.log(JSON.stringify(list, null, 2));
}

function findBinary(name, overridePath) {
  if (overridePath) {
    if (!fs.existsSync(overridePath)) {
      die(`Binary not found: ${overridePath}`);
    }
    return overridePath;
  }

  try {
    const output = execFileSync('which', [name], { encoding: 'utf8' }).trim();
    if (!output) die(`Cannot locate "${name}" in PATH.`);
    return output;
  } catch {
    die(`Cannot locate "${name}" in PATH.`);
  }
}

function buildSshExec(cred, command, opts) {
  const sshPath = findBinary('ssh', opts.sshPath);
  const port = opts.port || cred.port || 22;
  const timeout = Number.isFinite(opts.timeout) && opts.timeout > 0 ? opts.timeout : 15;
  const userAtHost = `${cred.username}@${cred.host}`;

  const baseArgs = ['-p', String(port), '-o', `ConnectTimeout=${timeout}`];
  if (opts.noStrictHostKeyChecking) {
    baseArgs.push('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null');
  }

  if (cred.authType === 'key') {
    if (!cred.privateKeyPath) die(`Credential "${cred.id}" requires privateKeyPath.`);
    if (!fs.existsSync(cred.privateKeyPath)) {
      die(`Private key not found: ${cred.privateKeyPath}`);
    }
    baseArgs.push('-i', cred.privateKeyPath, userAtHost, command);
    return { bin: sshPath, args: baseArgs, env: process.env };
  }

  if (cred.authType === 'password') {
    if (!cred.password) die(`Credential "${cred.id}" requires password.`);
    const sshpassPath = findBinary('sshpass');
    const password = decodeBase64(cred.password);
    return {
      bin: sshpassPath,
      args: ['-p', password, sshPath, ...baseArgs, userAtHost, command],
      env: process.env,
    };
  }

  die(`Unsupported authType: ${cred.authType}`);
}

function runSsh(execInfo) {
  try {
    return execFileSync(execInfo.bin, execInfo.args, {
      env: execInfo.env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (e) {
    const stderr = e && e.stderr ? String(e.stderr) : (e.message || 'Unknown SSH error');
    die(`SSH command failed:\n${stderr}`);
  }
}

function main() {
  const opts = parseArgs(process.argv);
  logger.info(
    `[${APP_NAME}] start id="${opts.id || '-'}" hasCommand="${!!opts.command}" ` +
    `credentialsPath="${opts.credentialsPath || CREDENTIALS_PATH}"`
  );

  if (opts.help) {
    console.log(HELP_TEXT);
    exitCli(0);
    return;
  }

  const credData = loadCredentials(opts.credentialsPath);

  if (opts.getCredentialList) {
    printCredentialList(credData);
    exitCli(0);
    return;
  }

  if (!opts.id) die('Missing -i / --id. Specify a credential ID.');
  if (!opts.command) die('Missing -c / --command. Provide a remote command.');

  const cred = getCredential(credData, opts.id);
  logger.info(
    `[${APP_NAME}] execute id="${cred.id}" host="${cred.host}" ` +
    `authType="${cred.authType}" port="${opts.port || cred.port || 22}"`
  );

  const execInfo = buildSshExec(cred, opts.command, opts);
  const output = runSsh(execInfo);
  process.stdout.write(output || '');
  exitCli(0);
}

try {
  main();
} catch (e) {
  if (e !== CLI_EXIT) throw e;
}
