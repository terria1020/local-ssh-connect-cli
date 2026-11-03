'use strict';

const fs = require('fs');
const { ConfigError } = require('./errors');

function loadCredentials(p) {
  if (!fs.existsSync(p)) {
    throw new ConfigError(
      `ssh-credentials.json not found at: ${p}\n` +
        '  Copy ssh-credentials.example.json to ssh-credentials.json and fill values.'
    );
  }
  let raw;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch (e) {
    throw new ConfigError(`Cannot read credential file: ${e.message}`);
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    throw new ConfigError(`ssh-credentials.json is not valid JSON: ${e.message}`);
  }
  if (!data || !Array.isArray(data.credentials)) {
    throw new ConfigError('ssh-credentials.json must have a "credentials" array.');
  }
  return data;
}

/**
 * Decode a Base64 secret. Strict (rejects non-Base64 input) and strips trailing
 * CR/LF, which almost always come from `echo secret | base64` and would make
 * password authentication fail.
 */
function decodeBase64(v) {
  if (!v) return '';
  const compact = String(v).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 === 1) {
    throw new ConfigError('Failed to decode Base64 value in credentials.');
  }
  return Buffer.from(compact, 'base64').toString('utf8').replace(/[\r\n]+$/, '');
}

/** Resolve the credentials to run against. Throws ConfigError for unknown ids. */
function resolveTargets(data, { ids, all }) {
  if (all) return data.credentials.slice();
  const available = data.credentials.map((c) => c.id).join(', ');
  return ids.map((id) => {
    const cred = data.credentials.find((c) => c.id === id);
    if (!cred) throw new ConfigError(`Credential "${id}" not found.\n  Available: ${available}`);
    return cred;
  });
}

/** Safe (non-secret) credential metadata. */
function listCredentials(data) {
  return data.credentials.map((c) => ({
    id: c.id,
    name: c.name || '',
    host: c.host,
    port: c.port || 22,
    username: c.username,
    authType: c.authType,
    note: c.note || '',
  }));
}

module.exports = { loadCredentials, decodeBase64, resolveTargets, listCredentials };
