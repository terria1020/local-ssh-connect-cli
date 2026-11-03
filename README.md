# local-ssh-connect-cli

`local-ssh-connect-cli`는 SSH 접속 정보를 `ssh-credentials.json`에 캡슐화하고, 실행 시에는 credential ID만 사용해 원격 명령을 실행하는 **stateless CLI**입니다. 여러 호스트 병렬 실행, JSON/NDJSON 출력, `--dry-run`을 지원해 AI 에이전트가 쓰기 좋게 만들어져 있습니다.

## 특징

- 매 실행은 독립적인 SSH 호출(세션 저장 없음)
- 민감정보(host/user/key/password) 분리: `ssh-credentials.json`
- 결과는 stdout, 진단은 stderr(`[lssh] ...`), 로그는 `logs/*.log`
- `LOG_LEVEL` 지원 (`info` 기본)

## 요구 사항

- macOS / Linux
- Node.js 20 이상
- `ssh` CLI
- password 인증 사용 시: `sshpass` CLI

## 설치

```bash
cd local-ssh-connect-cli
npm install
npm link
```

## 자격 증명 설정

```bash
cp ssh-credentials.example.json ssh-credentials.json
```

- 스키마: `ssh-credentials.schema.json`
- `ssh-credentials.json`은 `.gitignore`에 포함됨
- password/passphrase는 Base64 인코딩 문자열 사용 (끝의 개행은 자동 제거)

## 짧은 명령으로 쓰기 (설치)

`npm link`를 하면 `lssh` (또는 `local-ssh-connect-cli`) 명령이 생깁니다. link가 어려우면 alias를 쓰세요.

```bash
node local-ssh-connect-cli.js --print-alias >> ~/.zshrc && source ~/.zshrc
lssh --get-credential-list
```

## 사용법

```bash
# 도움말 (AI 에이전트용 가이드 포함)
node local-ssh-connect-cli.js --help

# credential 목록 조회
node local-ssh-connect-cli.js --get-credential-list

# 단일 호스트
node local-ssh-connect-cli.js -i example-key-server -c "hostname"

# 여러 호스트 병렬 실행 (줄마다 [id] 접두사) / 전체 호스트
node local-ssh-connect-cli.js -i web1,web2,db1 --concurrency 4 -c "uptime"
node local-ssh-connect-cli.js --all -c "df -h"

# 기계 친화 출력: 최종 JSON 1개 / 실시간 NDJSON 이벤트
node local-ssh-connect-cli.js -i web1,web2 --json -c "uptime"
node local-ssh-connect-cli.js -i web1,web2 --ndjson -c "tail -n 50 /var/log/syslog"

# 접속/인증만 점검 (명령 불필요, 원격에서는 no-op `true`만 실행)
node local-ssh-connect-cli.js --all --check --json

# 실행 전 확인 (비밀번호는 마스킹, 아무것도 실행하지 않음)
node local-ssh-connect-cli.js --all --dry-run -c "systemctl restart app"
```

### zsh/bash 인용(quote) 문제 회피

`$변수`, 백틱, `!`, 따옴표가 섞인 명령은 로컬 셸이 먼저 해석해서 깨지기 쉽습니다. 스크립트를 stdin(heredoc, 따옴표 있는 구분자)이나 파일로 넘기면 원격에 그대로 전달됩니다.

```bash
node local-ssh-connect-cli.js -i web1 -c - <<'SCRIPT'
for f in /var/log/*.log; do echo "$f: $(wc -l < "$f")"; done
SCRIPT

node local-ssh-connect-cli.js -i web1 --script-file ./check.sh --shell bash
```

### 안정성 옵션

| 옵션 | 설명 |
| --- | --- |
| `--retries <n>` / `--retry-delay <s>` | 일시적 연결 실패(`connect_timeout`, `connection_reset`)만 지수 백오프로 재시도 (기본 2회 / 2초). 인증 실패는 재시도하지 않음 |
| `--exec-timeout <s>` | 타깃당 전체 실행 시간 제한 (ssh/sshpass 프로세스 그룹 전체 종료) |
| `--keepalive <s>` | `ServerAliveInterval` (기본 30, 0이면 끔). 오래 걸리는 명령의 연결 끊김 방지 |
| `--concurrency <n>` | 동시 실행 호스트 수 (기본 4, 호스트당 연결은 1개) |

인증 방식은 고정됩니다. key는 `IdentitiesOnly` / `BatchMode` / `publickey`만 쓰고, password는 `PubkeyAuthentication=no` + `NumberOfPasswordPrompts=1`을 씁니다. 이로써 ssh-agent 키 때문에 `Too many authentication failures`가 나거나, 틀린 비밀번호가 서버의 실패 횟수를 여러 번 올리는 일을 막습니다.

### 출력 계약

- `--json`: `{"ok","total","succeeded","failed","results":[{id,host,ok,exitCode,errorKind,attempts,durationMs,stdout,stderr,truncated,timedOut}]}`
- `--ndjson`: `start` / `stdout` / `stderr` / `retry` / `exit` / `summary` 이벤트
- `errorKind`: `remote_nonzero`, `auth_failed`, `too_many_auth`, `host_key`, `dns`, `connection_refused`, `connect_timeout`, `connection_reset`, `connection_lost`, `ssh_error`, `exec_timeout`, `spawn_error`, `config_error`
- 종료 코드
  - `0`: 성공
  - 단일 호스트: 원격 명령의 종료 코드, SSH 오류 `255`, 타임아웃 `124`, 실행 불가 `127`
  - `2`: 사용/설정 오류 (아무것도 실행하지 않음)
  - `1`: 다중 호스트 중 하나라도 실패
- 로그는 기본적으로 콘솔에 나오지 않습니다 (`--verbose`로 켬).

## 개발 / 테스트

```bash
npm test   # node:test, 가짜 ssh/sshpass 스크립트 사용 (실제 서버 불필요)
```

## 로그

- 위치: 스크립트 디렉터리의 `logs/` (`LSSH_LOG_DIR`로 변경 가능). 실행 명령 본문은 기록하지 않습니다.
- `logs/combined.log`: 전체 로그, `logs/error.log`: 에러 로그

## 라이선스

MIT
