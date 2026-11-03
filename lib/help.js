'use strict';

const HELP_TEXT = `
local-ssh-connect-cli - Stateless SSH wrapper for credential encapsulation
=======================================================================

DESCRIPTION
  Runs a command (or script) on one or more hosts using credential IDs from
  ssh-credentials.json. Raw host/user/key/password values never appear on the CLI.

GLOBAL OPTIONS
  --help, -h                    Show this help and exit
  --get-credential-list         List credential metadata (safe fields only)
  --credentials-path <path>     Override default ssh-credentials.json path

TARGETS
  -i, --id <id[,id...]>         Credential ID(s); comma-separated and/or repeated
  --all                         Run on every credential

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
  2    usage or configuration error (nothing was executed)
  1    several targets and at least one failed (inspect results[].errorKind)

errorKind VALUES
  ok (null in json), remote_nonzero, auth_failed, too_many_auth, host_key, dns,
  connection_refused, connect_timeout*, connection_reset*, connection_lost, ssh_error,
  exec_timeout, spawn_error, config_error        (* = retried automatically)

EXAMPLES
  node local-ssh-connect-cli.js --get-credential-list
  node local-ssh-connect-cli.js -i example-key-server -c "hostname"
  node local-ssh-connect-cli.js -i web1,web2,db1 --json -c "uptime"
  node local-ssh-connect-cli.js --all --concurrency 8 --dry-run -c "df -h"
  node local-ssh-connect-cli.js -i web1 -c - <<'EOF'
  for f in /var/log/*.log; do echo "$f: $(wc -l < "$f")"; done
  EOF

TIPS FOR AI AGENTS
  - Prefer --json (or --ndjson for long runs); parse errorKind instead of stderr text.
  - Put multi-line / quote-heavy commands on stdin with "-c -" (heredoc) so zsh/bash
    never expands $vars, backticks or ! inside your command.
  - Run --dry-run first when unsure what will be executed.
`;

module.exports = { HELP_TEXT };
