'use strict';

const fs = require('fs');
const path = require('path');

/** POSIX single-quote escaping. */
function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

/** Remote command for `tail`. grep exit 1 (no match) is not an error. */
function tailCommand({ file, lines, follow, grep }) {
  let cmd = `tail -n ${lines}${follow ? ' -f' : ''} -- ${shQuote(file)}`;
  if (grep) cmd += ` | grep --line-buffered -e ${shQuote(grep)} || [ $? -eq 1 ]`;
  return cmd;
}

/** Remote command for `get`: stream the file to stdout. */
function getCommand(remotePath) {
  return `cat -- ${shQuote(remotePath)}`;
}

/**
 * Remote command for `put`: read stdin into a temp file next to the destination, then
 * atomically rename. Refuses to overwrite unless force. A directory destination receives
 * the local file's basename. Exit 17 = destination exists.
 */
function putCommand({ remotePath, baseName, force, fileMode }) {
  const d = shQuote(remotePath);
  const b = shQuote(baseName);
  const parts = [
    `d=${d}`,
    `if [ -d "$d" ]; then d="\${d%/}/"${b}; fi`,
    force ? ':' : `if [ -e "$d" ]; then echo "lssh: remote file exists: $d (use --force)" >&2; exit 17; fi`,
    't="$d.lssh-partial.$$"',
    'trap \'rm -f "$t"\' EXIT HUP INT TERM',
    'cat > "$t" || exit 1',
    fileMode ? `chmod ${fileMode} "$t" || exit 1` : ':',
    'mv -f -- "$t" "$d" || exit 1',
    'trap - EXIT',
  ];
  return `sh -c ${shQuote(parts.join('; '))}`;
}

/**
 * Where `get` stores the file locally. One target: <dest> (or <dest>/<basename> when dest is
 * an existing directory). Several targets: <dest>/<id>/<basename>.
 */
function localTargetFor({ dest, id, baseName, multi }) {
  if (multi) return path.join(dest, id, baseName);
  try {
    if (fs.statSync(dest).isDirectory()) return path.join(dest, baseName);
  } catch { /* does not exist yet */ }
  return dest;
}

function remoteBaseName(p) {
  return path.posix.basename(String(p).replace(/\/+$/, '')) || 'file';
}

/** Streaming sha256 of a local file (sync, constant memory). */
function sha256File(file) {
  const hash = require('crypto').createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(1024 * 1024);
    for (let n = fs.readSync(fd, buf, 0, buf.length, null); n > 0; n = fs.readSync(fd, buf, 0, buf.length, null)) {
      hash.update(buf.subarray(0, n));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

module.exports = { sha256File, shQuote, tailCommand, getCommand, putCommand, localTargetFor, remoteBaseName };
