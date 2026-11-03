'use strict';

const fs = require('fs');
const path = require('path');

const noop = () => {};
const NOOP_LOGGER = { info: noop, warn: noop, error: noop, debug: noop, close: () => Promise.resolve() };

/**
 * File logger (winston, loaded lazily). Console output only with --verbose, so stdout/stderr
 * stay clean for machine parsing. Commands/secrets are never logged by callers.
 */
function createLogger({ logDir, verbose = false, enabled = true }) {
  if (!enabled) return NOOP_LOGGER;
  let winston;
  try {
    winston = require('winston');
    fs.mkdirSync(logDir, { recursive: true });
  } catch {
    return NOOP_LOGGER; // logging must never break the CLI
  }
  const format = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)
  );
  const transports = [
    new winston.transports.File({ filename: path.join(logDir, 'error.log'), level: 'error', maxsize: 5242880, maxFiles: 5 }),
    new winston.transports.File({ filename: path.join(logDir, 'combined.log'), maxsize: 5242880, maxFiles: 5 }),
  ];
  if (verbose) transports.push(new winston.transports.Console({ stream: process.stderr }));
  const logger = winston.createLogger({ level: process.env.LOG_LEVEL || 'info', format, transports });
  logger.close = () =>
    new Promise((resolve) => {
      const t = setTimeout(resolve, 3000);
      logger.on('finish', () => { clearTimeout(t); resolve(); });
      logger.end();
    });
  return logger;
}

module.exports = { createLogger, NOOP_LOGGER };
