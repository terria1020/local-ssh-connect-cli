# local-ssh-connect-cli

`local-ssh-connect-cli`는 SSH 접속 정보를 `ssh-credentials.json`에 캡슐화하고, 실행 시에는 credential ID만 사용해 원격 명령을 1회 실행하는 **stateless CLI**입니다.

## 특징

- 매 실행은 독립적인 1회 SSH 호출(세션 저장 없음)
- 민감정보(host/user/key/password) 분리: `ssh-credentials.json`
- 결과는 stdout, 로깅은 stderr + `logs/*.log`
- `LOG_LEVEL` 지원 (`info` 기본)

## 요구 사항

- macOS
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
- password/passphrase는 Base64 인코딩 문자열 사용

## 사용법

```bash
# 도움말
node local-ssh-connect-cli.js --help

# credential 목록 조회
node local-ssh-connect-cli.js --get-credential-list

# key 인증으로 단일 명령 실행
node local-ssh-connect-cli.js -i example-key-server -c "hostname"

# password 인증으로 단일 명령 실행 (sshpass 필요)
node local-ssh-connect-cli.js -i example-password-server -c "uname -a"
```

## 로그

- `logs/combined.log`: 전체 로그
- `logs/error.log`: 에러 로그

## 라이선스

MIT
