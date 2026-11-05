'use strict';

const HELP_TEXT = `
local-ssh-connect-cli - Stateless SSH wrapper for credential encapsulation
=======================================================================

DESCRIPTION
  Runs a command (or script) on one or more hosts using credential IDs from
  ssh-credentials.json. Raw host/user/key/password values never appear on the CLI.

FIRST-TIME SETUP (recommended)
  Install a short command so you never need the full "node /path/to/script.js":
    npm link                                   # provides: lssh   (or local-ssh-connect-cli)
  or add a shell alias (zsh: ~/.zshrc, bash: ~/.bashrc):
    node local-ssh-connect-cli.js --print-alias >> ~/.zshrc && source ~/.zshrc
  Then:  lssh --get-credential-list   |   lssh -i web1 --check   |   lssh -i web1 -c uptime

PASSPHRASE-PROTECTED KEYS
  Put the Base64 passphrase in the credential's "passphrase" field (authType "key").
  It is handed to ssh through a temporary SSH_ASKPASS helper (environment only, never argv
  or disk). If auth fails, a local ssh-keygen check reports errorKind "bad_passphrase" when the
  configured passphrase is wrong. Keys already loaded in ssh-agent need no passphrase field.

GLOBAL OPTIONS
  --help, -h                    Show this help and exit
  --get-credential-list         List credential metadata (safe fields only)
  --check                       Only verify connect + authentication (no command needed;
                                runs the no-op "true"). Works with -i/--all/--json
  --print-alias                 Print a ready-to-paste shell alias line and exit
  --credentials-path <path>     Override default ssh-credentials.json path

TARGETS
  -i, --id <id[,id...]>         Credential ID(s); comma-separated and/or repeated
  --all                         Run on every credential

SUBCOMMANDS (instead of -c)
  tail --file <remote-path> [-n 50] [--grep <text>] [--follow --duration <s>]
                                Last N lines (grep is done remotely). --follow streams for
                                --duration seconds (default 30) and then ends with success.
                                Note: after the session ends, a remote "tail -f" can linger
                                until it next writes; prefer plain -n polling if that matters.
  get <remote-path> <local-path> [--force]
                                Download a file (binary-safe, atomic, reports bytes + sha256).
                                One target: local-path is a file or existing directory.
                                Several targets: saved as <local-path>/<id>/<name>.
  put <local-path> <remote-path> [--force] [--mode 0644]
                                Upload a file (binary-safe; written to a temp file then renamed).
                                A remote directory (or trailing /) receives the local basename.
                                Refuses to overwrite unless --force (remote exit 17).
  Directories are not supported yet. All subcommands accept -i/--all, --json/--ndjson,
  --dry-run, --retries, --concurrency. get/put results carry "transfer":
  {direction, localPath, remotePath, bytes, sha256}.

COMMAND (pick one)
  -c, --command <command>       Remote command (passed to ssh as-is)
  -c -                          Read a script from stdin (avoids shell-quoting problems)
  --script-file <path>          Read a script from a local file
  --shell <name>                Interpreter for scripts: runs "<shell> -s" (default: sh)

EXECUTION
  --concurrency <n>             Parallel hosts (default: 4; one connection per host)
  --timeout <seconds>           SSH connect timeout (default: 15)
  --exec-timeout <seconds>      Kill a target after N seconds in total (default: 0 = off)
  --keepalive <seconds>         ServerAliveInterval for long-running commands (default: 30, 0 = off)
  --retries <n>                 Retries for transient connection failures (default: 2)
  --retry-delay <seconds>       Initial retry delay, doubled each retry (default: 2)
  --port <number>               Override credential port
  --ssh-path <path>             Override ssh binary path
  --sshpass-path <path>         Override sshpass binary path
  --accept-new-host-keys        Auto-accept and persist new host keys (no prompt)
  --no-strict-host-key-checking Disable strict host key checking

OUTPUT
  --output text|json|ndjson     Output format (default: text). Aliases: --json, --ndjson
  --verbose                     Also print internal logs to stderr
  --dry-run                     Print what would run (passwords masked) and exit 0

OUTPUT MODES
  text    Streams remote output live. One target: raw passthrough. Several targets:
          every line is prefixed with "[id] ". Diagnostics go to stderr as "[lssh] ...".
  json    Single document on stdout when finished:
          {"ok":bool,"total":n,"succeeded":n,"failed":n,"results":[
            {"id","host","ok","exitCode","errorKind","attempts","durationMs",
             "stdout","stderr","truncated","timedOut"}]}
  ndjson  One JSON event per line as it happens:
          start | stdout | stderr | retry | exit | summary

EXIT CODES
  0    all targets succeeded
  N    single target: the remote command's own exit code
  255  single target: SSH-level failure (auth, network, host key ...)
  124  single target: --exec-timeout hit
  127  single target: could not start ssh/sshpass
  74   single target: local I/O error (get/put file could not be read/written)
  2    usage or configuration error (nothing was executed)
  1    several targets and at least one failed (inspect results[].errorKind)

errorKind VALUES
  ok (null in json), remote_nonzero, auth_failed, bad_passphrase, too_many_auth, host_key, dns,
  connection_refused, connect_timeout*, connection_reset*, connection_lost, ssh_error,
  exec_timeout, spawn_error, io_error, config_error        (* = retried automatically)

EXAMPLES
  node local-ssh-connect-cli.js --get-credential-list
  node local-ssh-connect-cli.js -i example-key-server -c "hostname"
  node local-ssh-connect-cli.js --all --check --json
  node local-ssh-connect-cli.js -i web1 tail --file /var/log/app.log -n 100 --grep ERROR
  node local-ssh-connect-cli.js -i web1,web2 get /var/log/app.log ./logs
  node local-ssh-connect-cli.js -i web1 put ./app.conf /etc/app/app.conf --force
  node local-ssh-connect-cli.js -i web1,web2,db1 --json -c "uptime"
  node local-ssh-connect-cli.js --all --concurrency 8 --dry-run -c "df -h"
  node local-ssh-connect-cli.js -i web1 -c - <<'EOF'
  for f in /var/log/*.log; do echo "$f: $(wc -l < "$f")"; done
  EOF

TIPS FOR AI AGENTS
  - Prefer --json (or --ndjson for long runs); parse errorKind instead of stderr text.
  - Put multi-line / quote-heavy commands on stdin with "-c -" (heredoc) so zsh/bash
    never expands $vars, backticks or ! inside your command.
  - Run "--all --check --json" first to find unreachable hosts before real work.
  - Run --dry-run first when unsure what will be executed.
`;

module.exports = { HELP_TEXT };
