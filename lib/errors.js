'use strict';

/** Invalid CLI usage (bad/missing arguments). Exit code 2. */
class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Invalid configuration (credentials file, unknown id, missing binary). Exit code 2. */
class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

module.exports = { UsageError, ConfigError };
