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
- passphrase가 걸린 개인 키(`authType: "key"`)는 `passphrase` 필드를 채우면 됩니다. 아래 "passphrase가 있는 키" 참고

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

### tail / 파일 전송

```bash
# 마지막 N줄 (+원격 grep). 여러 호스트면 줄마다 [id] 접두사
lssh -i web1,web2 tail --file /var/log/app.log -n 100 --grep ERROR

# 짧은 세션 follow: --duration 초 동안만 스트리밍하고 정상 종료
lssh -i web1 tail --file /var/log/app.log --follow --duration 30 --ndjson

# 다운로드 (바이너리 안전, 임시 파일 후 rename, bytes/sha256 보고)
lssh -i web1 get /var/log/app.log ./app.log
lssh -i web1,web2 get /var/log/app.log ./logs      # ./logs/web1/app.log, ./logs/web2/app.log

# 업로드 (원격에서도 임시 파일 후 rename; 기존 파일은 --force 없으면 거부)
lssh -i web1,web2 put ./app.conf /etc/app/app.conf --force --mode 0644
```

- 디렉터리 전송은 아직 지원하지 않습니다 (파일 단위).
- `get`/`put` 결과의 `transfer`: `{direction, localPath, remotePath, bytes, sha256}`
- `--follow`가 끝난 뒤 원격의 `tail -f`는 다음 출력이 있을 때까지 남아 있을 수 있습니다 (SSH 한계). 신경 쓰이면 `-n` 반복 조회를 권장합니다.

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

### passphrase가 있는 키

```json
{ "id": "prod", "host": "…", "username": "ubuntu", "authType": "key",
  "privateKeyPath": "/Users/you/.ssh/id_ed25519", "passphrase": "<base64>" }
```

- passphrase는 임시 `SSH_ASKPASS` 헬퍼로 ssh에 전달됩니다. 환경변수로만 전달하고 argv·디스크에는 남기지 않으며, 헬퍼는 실행이 끝나면 삭제됩니다. passphrase 프롬프트 외의 질문(호스트 키 확인 등)에는 답하지 않습니다.
- 인증이 실패하면 로컬 `ssh-keygen -y`로 passphrase를 검증해, 틀렸다면 `errorKind: "bad_passphrase"`로 구분합니다. 키는 암호화돼 있는데 `passphrase` 필드가 없으면 힌트(및 `--dry-run` 경고)를 보여줍니다.
- 키를 `ssh-agent`에 이미 올려 둔 경우에는 `passphrase` 필드가 필요 없습니다.
- OpenSSH 8.4+는 `SSH_ASKPASS_REQUIRE=force`를, 그보다 오래된 버전은 `DISPLAY`가 설정된 비대화형 환경을 이용합니다.
- 이전 버전에서는 `passphrase` 필드가 어디에서도 읽히지 않았습니다 (v1.1에서는 `BatchMode`까지 켜져 있어 암호 키가 항상 실패).

### 출력 계약

- `--json`: `{"ok","total","succeeded","failed","results":[{id,host,ok,exitCode,errorKind,attempts,durationMs,stdout,stderr,truncated,timedOut}]}`
- `--ndjson`: `start` / `stdout` / `stderr` / `retry` / `exit` / `summary` 이벤트
- `errorKind`: `remote_nonzero`, `auth_failed`, `bad_passphrase`, `too_many_auth`, `host_key`, `dns`, `connection_refused`, `connect_timeout`, `connection_reset`, `connection_lost`, `ssh_error`, `exec_timeout`, `spawn_error`, `config_error`
- 종료 코드
  - `0`: 성공
  - 단일 호스트: 원격 명령의 종료 코드, SSH 오류 `255`, 타임아웃 `124`, 실행 불가 `127`
  - `2`: 사용/설정 오류 (아무것도 실행하지 않음)
  - `1`: 다중 호스트 중 하나라도 실패
- `get`/`put` 전용: 로컬 입출력 오류 `74`(`io_error`), 원격 파일이 이미 있으면 원격 종료 코드 `17`
- 로그는 기본적으로 콘솔에 나오지 않습니다 (`--verbose`로 켬).

### v1.0 → v1.1 변경 사항 (종료 코드 / 동작)

| 상황 | v1.0 | v1.1 |
| --- | --- | --- |
| 성공 | `0` | `0` |
| 인자 누락·알 수 없는 인자·잘못된 값 | `1` | `2` |
| 자격 증명 파일 오류, 없는 credential ID, 바이너리 없음 | `1` | `2` |
| 원격 명령이 0이 아닌 코드로 종료 | `1` (원격 코드 소실) | 원격의 종료 코드 그대로 (단일 호스트) |
| SSH 인증 실패·접속 불가 | `1` | `255` (`errorKind`로 세부 구분) |
| `--exec-timeout` 초과 (신규) | - | `124` |
| 여러 호스트 중 하나라도 실패 (신규) | - | `1` |

- 스크립트가 `exit != 0`만 검사한다면 영향이 없습니다. `== 1`로 실패를 판별하던 곳만 수정하세요 (자동화에서는 `--json`의 `errorKind` 사용을 권장).
- 로그 파일 위치: 실행한 디렉터리의 `logs/` → 스크립트 디렉터리의 `logs/` (`LSSH_LOG_DIR`로 변경).
- 콘솔에 찍히던 `[local-ssh-connect-cli] ...` 로그는 기본적으로 사라졌습니다 (`--verbose`로 복원). 진단 메시지는 `[lssh] ...` 형식입니다.
- 비밀번호/키 인증 옵션이 고정되고(`IdentitiesOnly`, `NumberOfPasswordPrompts=1` 등) 일시적 연결 실패는 자동 재시도됩니다 (`--retries 0`으로 끔).

## 개발 / 테스트

```bash
npm test   # node:test, 가짜 ssh/sshpass 스크립트 사용 (실제 서버 불필요)
```

## 로그

- 위치: 스크립트 디렉터리의 `logs/` (`LSSH_LOG_DIR`로 변경 가능). 실행 명령 본문은 기록하지 않습니다.
- `logs/combined.log`: 전체 로그, `logs/error.log`: 에러 로그

## 라이선스

MIT
