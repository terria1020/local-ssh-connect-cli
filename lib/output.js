'use strict';

/**
 * Result object (stable JSON contract):
 *   { id, host, ok, exitCode, errorKind, attempts, durationMs, stdout, stderr, truncated, timedOut }
 */
function makeResult(cred, run) {
  const kind = run.kind;
  return {
    id: cred.id,
    host: cred.host,
    ok: kind === 'ok',
    exitCode: typeof run.code === 'number' ? run.code : null,
    errorKind: kind === 'ok' ? null : kind,
    attempts: run.attempts || 0,
    durationMs: run.durationMs || 0,
    stdout: run.stdout || '',
    stderr: run.stderr || '',
    truncated: !!run.truncated,
    timedOut: !!run.timedOut,
  };
}

function configErrorResult(cred, message) {
  return {
    id: cred.id, host: cred.host, ok: false, exitCode: null, errorKind: 'config_error',
    attempts: 0, durationMs: 0, stdout: '', stderr: message, truncated: false, timedOut: false,
  };
}

function summarize(results) {
  const failed = results.filter((r) => !r.ok).length;
  return { total: results.length, succeeded: results.length - failed, failed };
}

/** Process exit code contract: 0 ok; single target -> remote code / 255 / 124 / 2; multi -> 1. */
function exitCodeFor(results) {
  if (results.every((r) => r.ok)) return 0;
  if (results.length !== 1) return 1;
  const r = results[0];
  switch (r.errorKind) {
    case 'remote_nonzero': return r.exitCode || 1;
    case 'config_error': return 2;
    case 'exec_timeout': return 124;
    case 'spawn_error': return 127;
    default: return 255;
  }
}

/** Text mode: stream raw output (single target) or `[id] `-prefixed lines (multi). */
class TextReporter {
  constructor({ multi, out, err }) {
    this.multi = multi;
    this.out = out;
    this.err = err;
    this.partial = new Map(); // `${id}:${stream}` -> incomplete trailing line
  }

  _write(stream, id, chunk) {
    const target = stream === 'stdout' ? this.out : this.err;
    if (!this.multi) return void target.write(chunk);
    const key = `${id}:${stream}`;
    const text = (this.partial.get(key) || '') + chunk;
    const lines = text.split('\n');
    this.partial.set(key, lines.pop());
    for (const l of lines) target.write(`[${id}] ${l}\n`);
  }

  start() {}
  stdout(id, chunk) { this._write('stdout', id, chunk); }
  stderr(id, chunk) { this._write('stderr', id, chunk); }
  retry(id, info) {
    this.err.write(`[lssh] ${id}: ${info.kind}, retry #${info.attempt} in ${info.delayMs}ms\n`);
  }
  finish(r) {
    for (const stream of ['stdout', 'stderr']) {
      const key = `${r.id}:${stream}`;
      const rest = this.partial.get(key);
      if (rest) (stream === 'stdout' ? this.out : this.err).write(`[${r.id}] ${rest}\n`);
      this.partial.delete(key);
    }
    if (!r.ok && r.errorKind !== 'remote_nonzero') {
      const detail = r.errorKind === 'config_error' ? `: ${r.stderr}` : '';
      this.err.write(`[lssh] ${r.id}: ${r.errorKind} (attempts=${r.attempts})${detail}\n`);
    }
  }
  summary(results) {
    if (!this.multi) return;
    const s = summarize(results);
    this.err.write(`[lssh] ${s.succeeded}/${s.total} succeeded\n`);
  }
}

/** JSON mode: nothing streamed; one document at the end. */
class JsonReporter {
  constructor({ out }) { this.out = out; }
  start() {}
  stdout() {}
  stderr() {}
  retry() {}
  finish() {}
  summary(results) {
    this.out.write(`${JSON.stringify({ ok: results.every((r) => r.ok), ...summarize(results), results })}\n`);
  }
}

/** NDJSON mode: one event per line, flushed as it happens. */
class NdjsonReporter {
  constructor({ out }) { this.out = out; }
  _emit(obj) { this.out.write(`${JSON.stringify(obj)}\n`); }
  start(id, host) { this._emit({ event: 'start', id, host }); }
  stdout(id, data) { this._emit({ event: 'stdout', id, data }); }
  stderr(id, data) { this._emit({ event: 'stderr', id, data }); }
  retry(id, info) { this._emit({ event: 'retry', id, ...info }); }
  finish(r) {
    this._emit({
      event: 'exit', id: r.id, ok: r.ok, exitCode: r.exitCode, errorKind: r.errorKind,
      attempts: r.attempts, durationMs: r.durationMs, truncated: r.truncated,
    });
  }
  summary(results) {
    this._emit({ event: 'summary', ok: results.every((r) => r.ok), ...summarize(results) });
  }
}

function createReporter(mode, { multi, out, err }) {
  if (mode === 'json') return new JsonReporter({ out });
  if (mode === 'ndjson') return new NdjsonReporter({ out });
  return new TextReporter({ multi, out, err });
}

module.exports = {
  makeResult, configErrorResult, summarize, exitCodeFor, createReporter,
  TextReporter, JsonReporter, NdjsonReporter,
};
