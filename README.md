# 봉수 (Bongsu)

**Self-hosted Package Vulnerability Monitoring System**

봉수대(烽燧臺)에서 이름을 따온 패키지 취약점 모니터링 시스템입니다.
각 호스트와 컨테이너에서 수집한 패키지 정보를 서버로 모아 CVSS 취약점 데이터베이스와 매칭하여 결과를 보여줍니다.

저장소: <https://github.com/ziozzang/bongsu>

## 빠른 시작

```bash
# 1. 설정
cp deploy/.env.example deploy/.env
# .env 파일에서 BONGSU_API_KEY, BONGSU_AGENT_API_KEY, BONGSU_INSTALL_TOKEN, BONGSU_DB_PASSWORD 설정

# 2. 기동
cd deploy && docker compose up -d --build

# 3. 에이전트 설치 (타겟 호스트에서)
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://your-server:5678/api/install.sh" | sudo bash
```

## 아키텍처

```
Agent (각 호스트)  →  Server + Web  →  PostgreSQL
```

- **Agent**: 내장 네이티브 스캐너로 패키지 목록 수집, 서버에 전송 (Trivy는 선택)
- **Server**: CVE 매칭 + 웹 대시보드 제공
- **Packages-only 모드**: Agent는 패키지 목록만 전송, 서버에서 CVE 매칭

## 네이티브 패키지 스캐너 (Native scanner)

에이전트는 기본적으로 외부 의존성이 없는 **네이티브 스캐너**(`internal/agent/scanner/`)로 패키지를 수집합니다. Trivy 바이너리 없이 설치된 패키지 DB를 직접 읽습니다.

- **dpkg / apk**: 순수 Go로 `var/lib/dpkg/status`, `lib/apk/db/installed`를 직접 파싱 (Debian/Ubuntu, Alpine).
- **rpm**: 현재 RPM DB(BerkeleyDB/NDB/sqlite)의 순수 Go 파싱이 없어, 대상 root를 가리키는 호스트의 `rpm` 바이너리로 조회합니다. RHEL 계열은 base OS에 `rpm`이 포함되어 있어 별도 스캐너가 필요 없습니다. 컨테이너 rootfs의 RPM DB를 읽을 수 없으면 컨테이너 자신의 `rpm`을 runtime exec로 실행합니다.
- 같은 `ScanRoot` 진입점이 호스트(root `/`)와 컨테이너(merged rootfs)에 모두 사용되어, 호스트/컨테이너 인벤토리가 하나의 코드 경로를 공유합니다.

스캐너 엔진은 `-scanner` 플래그(`BONGSU_AGENT_SCANNER`)로 전환합니다. 기본값은 `native`이며 `trivy`를 지정하면 기존 Trivy 경로를 사용합니다.

```bash
/opt/bongsu/bin/bongsu-agent --scanner native   # 기본 (외부 의존성 없음)
/opt/bongsu/bin/bongsu-agent --scanner trivy     # Trivy 바이너리 사용
```

## 호스트/컨테이너 facts

에이전트는 외부 바이너리 없이 `/proc`, `/sys`, `/etc`를 직접 읽어 포괄적인 호스트 facts를 수집해 `hosts.facts`(JSONB)에 저장합니다. os-release, kernel, cpu, memory, dmi, virtualization, network, filesystems 등을 포함하며, 각 섹션은 읽기 실패 시 우아하게 생략됩니다. 컨테이너는 distro-identity 위주의 facts(os-release/lsb-release/release files)를 `container_assets.facts`에 저장합니다.

대시보드에서는 호스트 상세의 "System Facts" 카드와 컨테이너 행 확장에서 확인할 수 있습니다.

## 컨테이너 enumeration

컨테이너는 호스트에서 발견되는 모든 runtime CLI로 열거합니다: `docker`, `podman`, `nerdctl`(docker 호환 CLI), `crictl`(CRI/Kubernetes 노드). 동일 containerd를 여러 CLI가 보는 경우 container ID로 중복을 제거합니다. 네이티브 컨테이너 rootfs 스캔은 inspect의 `GraphDriver.Data.MergedDir`를 통해 merged overlay를 읽으므로 에이전트가 runtime overlay 저장소에 대한 read 권한(root)이 필요합니다.

## 언어 의존성 스캔 (Language scanning)

OS 패키지 매니저 바깥에 설치된 언어 런타임/의존성(pyenv `~/.pyenv`, nvm `~/.nvm`, 앱 번들, vendored deps 등)을 manifest/lockfile 기반으로 추가 수집합니다.

- `-lang-scan-roots` (`BONGSU_AGENT_LANG_SCAN_ROOTS`): 탐색할 root를 쉼표로 나열. 기본값 `/opt,/srv,/usr/local,/var/www,/app,/home,/root`. 센티넬 `none`은 비활성화, `all`은 호스트 scan-root 전체를 스캔.
- `-lang-scan-depth` (`BONGSU_AGENT_LANG_SCAN_DEPTH`): 탐색 최대 디렉터리 깊이, 기본 12. 무거운/무관한 트리는 건너뛰고 깊이를 제한해 전체 파일시스템을 걷지 않습니다.

## 기능

- CVSS 기반 취약점 정렬 및 필터링
- OS 패키지와 코드 라이브러리 생태계 분류
- OSV, NVD, Trivy DB 기반 보안 데이터 수집/import/export
- 보안 DB 소스별 matchable/fixed/range/CVSS 품질 지표
- 대시보드 CVE DB 상태 카드: TEMP-* placeholder 차단, EPSS 병합률, affected/reference 인덱스 커버리지 표시
- 소스 allowlist / matchable 비율 기반 취약점 rematch 품질 게이트
- 대형 환경 CVE rematch candidate limit 및 partial-pass 표시
- 온라인 환경 시작 시/6시간 주기 업데이트와 air-gapped 환경 수동 import
- 호스트/동작 중인 컨테이너 SBOM 수집 및 이미지/컨테이너 연관정보 저장
- CycloneDX 1.5 / SPDX 2.3 SBOM export
- 스캔별 패키지/취약점/컨테이너 수와 이전 스캔 대비 inventory delta 추적
- 호스트 목록에서 최신 SBOM 수집량과 완료 스캔 시각 표시
- healthy/stale/empty/none 기준의 호스트 SBOM 상태 필터
- 대시보드에서 SBOM 수집 상태별 호스트 수 요약
- 빈 SBOM 등 inventory 상태 기반 scan.completed webhook 알림
- webhook 전송 성공/실패 audit log 기록
- 패키지별 CVE 상세 정보 (air-gapped 환경 지원)
- Docker / air-gapped 배포 지원
- One-liner 에이전트 설치
- Force scan 요청과 RBAC 데이터 모델 기반
- 보안 DB import/update 후 백그라운드 CVSS 재계산 및 rematch
- 보안 DB 업데이트로 생성된 자동 리스캔 요청의 DB revision 추적
- Agent last_seen 기반 online/stale/offline 상태 표시
- 운영 데이터 retention dry-run/prune 관리
- 장애로 고착된 force scan 요청 자동/수동 재큐잉
- 사설 실험망용 선택적 인증 없는 모드 (`BONGSU_WEB_AUTH=false`)

## 운영 흐름

```bash
# 온라인 보안 DB 동기화 예시
BONGSU_SECURITY_DB_SYNC_CMD="./scripts/sync-all-cvedb.sh http://localhost:5677"
BONGSU_SECURITY_DB_SYNC_ON_START=true
BONGSU_SECURITY_DB_INTERVAL_HOURS=6

# 개발 대시보드: API는 5677, 웹은 5678에서 실행합니다.
BONGSU_API_TARGET=http://localhost:5677 npm --prefix web run dev -- --host 0.0.0.0 --port 5678

# Airgap export/import bundle
./scripts/export-security-db-bundle.sh http://server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
./scripts/import-security-db-bundle.sh http://airgap-server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
```

The export helper writes a `.sha256` sidecar and verifies `/api/admin/security-db/status` reports a fresh bundle before the file is promoted into an air-gapped environment.

## CVE DB 유효성 기준

CVE DB에서 실제 매칭/리스캔에 사용하는 advisory는 affected package evidence가 있어야 합니다. 즉 패키지 이름, ecosystem/package type, package fixed version 또는 package fixed event가 있는 affected range가 확인되는 row만 matchable로 봅니다. `TEMP-*` 같은 임시 placeholder ID, git commit hash 같은 hash-only fixed evidence, CISA KEV/EPSS처럼 우선순위 보강만 하는 feed는 이름 기반 매칭 후보로 쓰지 않습니다. EPSS는 별도 advisory가 아니라 같은 CVE row의 `epss_score`, `epss_percentile` 컬럼으로 병합됩니다.

대시보드 첫 화면의 CVE DB 상태 카드와 CVE Search에서 총 row, matchable row, EPSS 병합률, affected/reference 인덱스 커버리지, placeholder/빈 ID 경고를 확인할 수 있습니다.

## 에이전트 설치

웹 대시보드 첫 화면과 `/api/install.sh`에서 같은 one-line 설치를 제공합니다. 이 endpoint는 agent key를 포함하므로 `BONGSU_INSTALL_TOKEN` 설정이 필요합니다.

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | sudo bash
```

설치 스크립트는 서버에서 static `bongsu-agent`와 가능한 경우 `trivy` 바이너리를 받아 `/opt/bongsu`에 배치하고, cron 또는 systemd timer로 주기 실행할 수 있습니다. 기본 네이티브 스캐너는 `trivy` 바이너리가 없어도 동작합니다. 설치 스크립트 생성과 바이너리 다운로드 인증은 URL query가 아니라 `X-Install-Token` 헤더로만 처리됩니다. 설치된 에이전트는 admin key가 아니라 `BONGSU_AGENT_API_KEY`를 사용하며, credential이 들어있는 config는 `0600` 권한으로 생성됩니다.

Force scan 요청을 즉시 받아 처리하는 상주 모드는 다음처럼 실행할 수 있습니다.

```bash
/opt/bongsu/bin/bongsu-agent --config /opt/bongsu/config.yaml --daemon --poll-interval 60s
```

### Agent configuration 참조

| Flag | Env | 기본값 | 설명 |
| --- | --- | --- | --- |
| `-scanner` | `BONGSU_AGENT_SCANNER` | `native` | 패키지 스캐너 엔진: `native`(내장, 외부 의존성 없음) 또는 `trivy` |
| `-lang-scan-roots` | `BONGSU_AGENT_LANG_SCAN_ROOTS` | `/opt,/srv,/usr/local,/var/www,/app,/home,/root` | OS 패키지 매니저 밖 언어 의존성을 탐색할 root (쉼표 구분). `none` 비활성화, `all` 호스트 scan-root 전체 |
| `-lang-scan-depth` | `BONGSU_AGENT_LANG_SCAN_DEPTH` | `12` | 언어 의존성 탐색 최대 디렉터리 깊이 |
| `-scan-root` | `BONGSU_AGENT_SCAN_ROOT` | `/` | 스캔 대상 호스트 파일시스템 root |
| `-skip-containers` | `BONGSU_AGENT_SKIP_CONTAINERS` | `false` | 컨테이너 탐지/스캔 건너뛰기 |
| `-max-containers` | `BONGSU_AGENT_MAX_CONTAINERS` | `0` | run당 스캔할 최대 실행 컨테이너 수 (0 = 무제한) |
| `-host-id` | `BONGSU_AGENT_HOST_ID` | (자동) | clone/컨테이너 환경용 host identity override |
| `-trivy-timeout` | `BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS` | `1800` | 호스트 Trivy fs 스캔 timeout |
| `-container-timeout` | `BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS` | `600` | 컨테이너 이미지 Trivy 스캔 timeout |
| `-command-timeout` | `BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS` | `30` | docker inspect, ps, uname 등 helper 명령 timeout |
| `-api-key` | `BONGSU_AGENT_API_KEY` | — | 에이전트 API key |
| (config) | `BONGSU_AGENT_TOKEN` | (자동 생성) | host 바인딩용 agent token. 미설정 시 work-dir에 생성 |

> Trivy 관련 timeout 플래그는 `-scanner trivy`일 때만 의미가 있습니다.

### Server 환경변수 (이번 주기 추가)

| Env | 기본값 | 설명 |
| --- | --- | --- |
| `BONGSU_SMTP_HOST` | — | SMTP 알림 호스트 (설정 시 email 채널 활성화) |
| `BONGSU_SMTP_PORT` | `587`(starttls) / `465`(tls) | SMTP 포트 |
| `BONGSU_SMTP_USERNAME` / `BONGSU_SMTP_PASSWORD` | — | SMTP 인증 정보 |
| `BONGSU_SMTP_FROM` | — | 발신 주소 (필수) |
| `BONGSU_SMTP_ENCRYPTION` | `starttls` | `starttls`, `tls`, `none` |
| `BONGSU_SMTP_TIMEOUT_SECONDS` | `30` | SMTP 전송 timeout |
| `BONGSU_SECURITY_DB_RETRY_BASE_MINUTES` | `5` | 보안 DB 동기화 실패 시 재시도 base 지연 (지수 backoff) |
| `BONGSU_SECURITY_DB_RETRY_MAX_MINUTES` | `60` | 재시도 최대 지연 (sync interval로도 상한) |
| `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS` | `30` | airgap import 시 stale bundle 거부 임계값 (0 = 비활성화) |

알림 채널: 기존 `webhook`/`log`에 더해 `email` 채널을 지원합니다. 규칙별 channel_config는 `{"to": "a@x,b@y", "subject_prefix"?: "..."}` 형식이며 서버 전역 `BONGSU_SMTP_*` 설정을 사용합니다.

per-finding triage 담당자(assignee)를 지정/필터할 수 있습니다. 취약점 목록은 `?assignee=` 쿼리로 필터하며, 센티넬 `unassigned`로 미지정 항목만 조회합니다.

## 상세 문서

- [배포 가이드](deploy/README.md)
- [아키텍처와 구현 상태](docs/architecture.md)
- [요구사항 감사표](docs/requirements-audit.md)
- [운영 Runbook](docs/operations-runbook.md)
- [Operator Runbook (agent/native scanner)](docs/operator-runbook.md)
- [환경변수 참조](deploy/.env.example)

## 라이선스

MIT
