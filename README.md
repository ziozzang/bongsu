# 봉수 (Bongsu)

**Self-hosted Package Vulnerability Monitoring System**

봉수대(烽燧臺)에서 이름을 따온 패키지 취약점 모니터링 시스템입니다.
각 호스트와 컨테이너에서 수집한 패키지/런타임 정보를 서버로 모아 멀티소스 CVE 데이터베이스와 매칭하여 취약점 우선순위와 트리아지 워크플로우를 제공합니다.

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

- **Agent**: 네이티브 스캐너로 OS 패키지, 언어 의존성, 런타임, host/container facts 수집 → 서버 전송
- **Server**: CVE 매칭 + 버전 비교 엔진 + 웹 대시보드
- **Packages-only 모드**: 에이전트는 패키지 목록만 전송, 서버에서 CVE 매칭

---

## 네이티브 패키지 스캐너

에이전트는 기본적으로 **외부 의존성이 없는 네이티브 스캐너**(`internal/agent/scanner/`)를 사용합니다. Trivy 바이너리 없이 설치된 패키지 DB를 직접 읽습니다.

- **dpkg** (Debian/Ubuntu): 순수 Go로 `var/lib/dpkg/status` 직접 파싱 — 실행 파일 불필요.
- **apk** (Alpine): 순수 Go로 `lib/apk/db/installed` 직접 파싱 — 실행 파일 불필요.
- **rpm** (RHEL/CentOS/Rocky/Alma 등): RPM DB(BerkeleyDB/NDB/sqlite)의 순수 Go 파싱이 없어 호스트 `rpm` 바이너리로 조회. RHEL 계열 베이스 OS에 포함되어 있어 별도 스캐너 불필요.
- 동일한 `ScanRoot` 진입점이 호스트(`/`)와 컨테이너(merged overlay rootfs) 양쪽에 사용됩니다.

스캐너 엔진은 `-scanner` 플래그(`BONGSU_AGENT_SCANNER`)로 선택합니다. 기본값은 `native`이며 `trivy` 지정 시 Trivy 바이너리를 사용합니다.

```bash
/opt/bongsu/bin/bongsu-agent --scanner native   # 기본 — 외부 의존성 없음
/opt/bongsu/bin/bongsu-agent --scanner trivy     # Trivy 바이너리 사용
```

## 언어 의존성 스캔

OS 패키지 매니저 바깥에 설치된 언어 런타임/의존성을 manifest/lockfile 기반으로 수집합니다. 지원 파일: `package-lock.json` (npm v1/v2/v3), `package.json`, `requirements.txt` (핀된 `==` 항목), `go.mod`, `Cargo.lock`, `Gemfile.lock`, PEP 503 `.dist-info/METADATA`.

- `-lang-scan-roots` (`BONGSU_AGENT_LANG_SCAN_ROOTS`): 탐색할 root (쉼표 구분). 기본값 `/opt,/srv,/usr/local,/var/www,/app,/home,/root`. `none` 비활성화, `all` 호스트 scan-root 전체.
- `-lang-scan-depth` (`BONGSU_AGENT_LANG_SCAN_DEPTH`): 최대 탐색 깊이 (기본 12). `/proc`, `/sys`, `.git`, `__pycache__`, `.gradle` 등 무거운 트리를 자동 제외.

## 런타임 탐지

OS 패키지 매니저와 lockfile 스캔 양쪽에서 누락되는 **런타임 인터프리터/VM**을 파일시스템 레이아웃에서 탐지합니다. 바이너리를 실행하지 않고 디렉터리 구조만 분석합니다.

| 런타임 | 탐지 방식 |
|---|---|
| Python | pyenv `versions/<X.Y.Z>/bin/python*`, `lib/python<X.Y>/`, `python_version` 파일 |
| Node.js | `node-vX.Y.Z` 경로 컴포넌트 (공식 tarball 레이아웃), `VERSION` 파일 |
| JDK/JRE | `release` 파일 (`JAVA_VERSION`, `IMPLEMENTOR` 기반; Oracle vs OpenJDK/Temurin 구분) |
| Ruby | `lib/ruby/<X.Y.Z>/` 레이아웃 |
| PHP | `php_version`/`VERSION` 파일 |
| Go SDK | `<goroot>/VERSION` 파일 (`go1.X.Y` 형식) |

탐지된 런타임(`PkgType=runtime`)은 NVD CPE 어드바이저리와 **버전 범위 게이팅**으로 매칭합니다 (`compatibleCPECandidate`). 버전 제약 없이 product name만 있는 CPE 항목은 false positive를 방지하기 위해 매칭하지 않습니다.

## Ecosystem-aware 버전 비교 엔진 (vercmp)

`internal/server/vercmp/` 패키지는 특수 케이스 모음이 아닌 **생태계별 실제 알고리즘**을 구현합니다.

| 생태계 | 알고리즘 |
|---|---|
| Debian / Ubuntu | dpkg `verrevcmp` (deb-version(5) 완전 구현) |
| Alpine / Wolfi | apk-tools `apk_version_compare_blob_fuzzy` 포트 |
| RHEL / CentOS / Rocky / Alma / SUSE / Amazon Linux | RPM `rpmvercmp` (tilde, caret, epoch 포함) |
| npm / PyPI / Go / crates.io / Maven 등 | generic semver-leaning 비교 |

버전 비교에는 **epoch-loss tolerance**가 적용됩니다: 에이전트가 distro epoch을 누락하고 어드바이저리 버전에 epoch이 있을 때, epoch을 제거하고 비교해 false positive를 감소시킵니다.

## 호스트/컨테이너 Facts

에이전트는 외부 바이너리 없이 `/proc`, `/sys`, `/etc`를 직접 읽어 포괄적인 facts를 수집합니다.

**호스트 facts** (`hosts.facts` JSONB): `os_release`, `kernel` (release/version/hostname/cmdline), `cpu` (model/vendor/cores/flags), `memory` (MB 단위 총/가용/swap), `dmi` (vendor/product/bios/chassis), `virtualization` (hypervisor 탐지: KVM/VMware/Hyper-V/AWS/GCP 등, container 탐지: docker/kubernetes/lxc/containerd), `network` (인터페이스/MAC/주소/nameserver), `filesystems` (실제 마운트만, pseudo-fs 제외), `system` (uptime/load/boot_id/timezone).

**컨테이너 facts** (`container_assets.facts` JSONB): distro-identity 위주 (`os_release`, `lsb_release`, release files) — 호스트 레벨 facts는 의도적으로 제외.

대시보드에서 호스트 상세의 "System Facts" 카드와 컨테이너 행 확장에서 확인할 수 있습니다.

## 컨테이너 열거

실행 중인 컨테이너를 열거할 때 다음 CLI 모두를 시도합니다: `docker`, `podman`, `nerdctl` (docker 호환), `crictl` (CRI/Kubernetes 노드). 동일 containerd를 여러 CLI가 볼 때 container ID로 중복 제거합니다. 네이티브 컨테이너 rootfs 스캔은 `GraphDriver.Data.MergedDir` overlay 경로를 통해 수행하므로 에이전트가 overlay 저장소에 대한 read 권한(통상 root)이 필요합니다.

## CVE DB 소스

| 소스 | 역할 |
|---|---|
| OSV | 코드 라이브러리 + OS 배포판 어드바이저리 (PyPI/npm/Go/Rust/Debian/Ubuntu/Alpine/RHEL 등) |
| NVD | CPE 기반 general CVE; 런타임 CPE 매칭의 주요 소스 |
| EPSS (FIRST) | CVE row에 `epss_score`/`epss_percentile` 컬럼으로 병합; 별도 어드바이저리 아님 |
| CISA KEV | `exploited` 플래그로 병합; 패키지 이름 매칭에 사용 안 함 |
| Trivy DB | Trivy scanner에서 파생한 추가 OS/라이브러리 어드바이저리 |

## False Positive 감소 메커니즘

1. **Epoch-loss tolerance**: 에이전트가 epoch 누락 시 어드바이저리 epoch 제거 후 비교.
2. **Version-gated CPE matching**: CPE product name 일치만으로는 매칭 불가; 버전 범위 제약 필수.
3. **고품질 fixed-version 필터**: hash-only, URL, branch, literal `0` fixed evidence는 매칭 인덱스에서 제외.
4. **Ecosystem 분리**: `debian` vs `ubuntu` 패키지를 동일 ecosystem으로 붕괴하지 않음.
5. **Pre-release 순서**: `alpha`, `beta`, `rc`는 해당 final release보다 오래된 버전으로 처리.

## 취약점 관리 및 트리아지

- **Per-finding assignee**: 취약점마다 담당자(`assignee`) 지정. `?assignee=` 쿼리로 필터, `unassigned` 센티넬로 미지정 항목만 조회.
- **Owner auto-assign**: 호스트 owner 설정 시 스캔 완료 후 해당 호스트의 신규 findings에 owner를 자동으로 assignee로 설정 (기존 triage 덮어쓰기 않음). `BONGSU_AUTO_ASSIGN_BY_OWNER=false`로 비활성화.
- **Triage 상태**: `open`, `in_progress`, `accepted_risk`, `false_positive`, `fixed`, `ignored`. 억제 상태는 reason 필수.
- **SLA**: severity별 기본 기한 — critical 7일, high 30일, medium 90일, low 180일 (`BONGSU_SLA_*_DAYS`).
- **Risk score**: CVSS + EPSS + KEV + host criticality 조합으로 계산.

## 알림

### 알림 채널

| 채널 | 설정 |
|---|---|
| webhook | 규칙별 URL; HMAC 서명 (`X-Bongsu-Signature-256`) 지원 |
| email (SMTP) | `BONGSU_SMTP_HOST/PORT/USERNAME/PASSWORD/FROM/ENCRYPTION`; 규칙별 `{"to": "a@x,b@y"}` |
| log | 서버 로그 기록 |

SMTP 암호화: `starttls` (기본, 포트 587), `tls` (implicit TLS, 포트 465), `none` (실험망용).

### 알림 트리거

`scan.completed`, `scan.failed`, `vuln.new_critical`, `vuln.new_high`, `sla.breach`, `security_db.updated`, `schedule.daily`

**scan.failed**: 스캔이 `degraded`/`failed` 상태이거나 ingest 에러가 있을 때 발송. 운영팀이 에이전트 수집 실패를 즉시 인지할 수 있습니다.

## 상세 검색 및 CVE→Assets Reverse Lookup

취약점 목록 필터:

| 필터 | 설명 |
|---|---|
| `assignee` / `unassigned` | 담당자 필터 |
| `ecosystem` | 패키지 생태계 (pypi, npm, debian 등) |
| `pkg_type` | 패키지 타입 (debian, alpine, runtime, npm 등) |
| `vuln_id_like` | CVE ID 패턴 (예: `CVE-2024`, `DEBIAN-`) |
| `has_fix` | `yes` / `no` (수정본 유무) |
| `min_cvss` / `max_cvss`, `min_epss`, `risk_level` | 점수 기반 |
| `exploited`, `overdue` | KEV/SLA 기반 |

**`GET /api/vulnerabilities/affected-assets?vulnerability_id=...`**: 특정 CVE에 현재 영향받는 호스트/컨테이너 목록 (CVE→assets reverse lookup). 대시보드 CVE 팝업에서 확인할 수 있습니다.

## Airgap Export/Import

```bash
# 연결 환경에서 bundle 생성
./scripts/export-security-db-bundle.sh http://server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
# 에어갭 환경에 import
./scripts/import-security-db-bundle.sh http://airgap-server:5677 "$BONGSU_API_KEY" bongsu-security-db-bundle.tar.gz
```

bundle은 `.sha256` 사이드카를 포함하며, import 시 `exporter_version` 검증과 `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS`(기본 30일) 기준 stale 거부를 수행합니다.

## 기타 주요 기능

- **RBAC**: viewer API key/OIDC bearer token/trusted-header 인증, 호스트/컨테이너/이미지/asset-group 스코프
- **Audit log**: 모든 admin/agent 이벤트 기록
- **SBOM export**: CycloneDX 1.5 / SPDX 2.3
- **예약 스캔**: 5-field cron 표현식 기반
- **Asset group**: static 및 owner/team/environment/criticality/tag 기반 dynamic 그룹
- **Vulnerability export**: CSV/JSON, 동일 필터 적용, `BONGSU_VULN_EXPORT_MAX_ROWS`(기본 100000)
- **Trend**: 일별 취약점 스냅샷, top-risk 호스트, SLA 보고서
- **보안 DB 재시도**: 동기화 실패 시 지수 backoff (`BONGSU_SECURITY_DB_RETRY_BASE_MINUTES`, 기본 5분)
- **프로젝트 소개 페이지**: `docs/index.html` — 한국어/영어/중국어/일본어/프랑스어/독일어/스페인어/포르투갈어 8개 언어 지원

## 운영 흐름

```bash
# 보안 DB 동기화 (온라인)
BONGSU_SECURITY_DB_SYNC_CMD="./scripts/sync-all-cvedb.sh http://localhost:5677"
BONGSU_SECURITY_DB_SYNC_ON_START=true
BONGSU_SECURITY_DB_INTERVAL_HOURS=6

# 개발 대시보드
BONGSU_API_TARGET=http://localhost:5677 npm --prefix web run dev -- --host 0.0.0.0 --port 5678
```

## 에이전트 설치

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | sudo bash
```

설치 스크립트는 서버에서 `bongsu-agent` 정적 바이너리를 받아 `/opt/bongsu`에 배치하고 cron 또는 systemd timer로 주기 실행합니다. 기본 네이티브 스캐너는 Trivy 바이너리가 없어도 동작합니다.

상주(daemon) 모드로 force scan 요청을 즉시 처리:

```bash
/opt/bongsu/bin/bongsu-agent --config /opt/bongsu/config.yaml --daemon --poll-interval 60s
```

### Agent 플래그 참조

| 플래그 | 환경변수 | 기본값 | 설명 |
|---|---|---|---|
| `-scanner` | `BONGSU_AGENT_SCANNER` | `native` | 스캐너 엔진: `native`(외부 의존성 없음) 또는 `trivy` |
| `-lang-scan-roots` | `BONGSU_AGENT_LANG_SCAN_ROOTS` | `/opt,/srv,/usr/local,/var/www,/app,/home,/root` | 언어 의존성 탐색 root (쉼표 구분). `none` 비활성화, `all` 전체 |
| `-lang-scan-depth` | `BONGSU_AGENT_LANG_SCAN_DEPTH` | `12` | 언어/런타임 탐색 최대 디렉터리 깊이 |
| `-packages-only` | — | `false` | 패키지만 전송 (서버 측 CVE 매칭) |
| `-scan-root` | `BONGSU_AGENT_SCAN_ROOT` | `/` | 스캔 대상 파일시스템 root |
| `-skip-containers` | `BONGSU_AGENT_SKIP_CONTAINERS` | `false` | 컨테이너 탐지/스캔 건너뛰기 |
| `-max-containers` | `BONGSU_AGENT_MAX_CONTAINERS` | `0` (무제한) | run당 최대 스캔 컨테이너 수 |
| `-host-id` | `BONGSU_AGENT_HOST_ID` | (자동) | clone/컨테이너 환경용 host identity override |
| `-daemon` | — | `false` | Force scan 요청 polling 모드 |
| `-poll-interval` | — | `60s` | Daemon 모드 polling 간격 |
| `-trivy-timeout` | `BONGSU_AGENT_TRIVY_TIMEOUT_SECONDS` | `1800` | Trivy fs 스캔 timeout (`-scanner trivy`에만 적용) |
| `-container-timeout` | `BONGSU_AGENT_CONTAINER_TIMEOUT_SECONDS` | `600` | 컨테이너 Trivy 스캔 timeout |
| `-command-timeout` | `BONGSU_AGENT_COMMAND_TIMEOUT_SECONDS` | `30` | helper 명령 timeout |
| `-api-key` | `BONGSU_AGENT_API_KEY` | — | 에이전트 API key |

### Server 환경변수 (주요)

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `BONGSU_SMTP_HOST` | — | SMTP 호스트 (미설정 시 email 채널 비활성) |
| `BONGSU_SMTP_PORT` | `587`/`465` | SMTP 포트 |
| `BONGSU_SMTP_FROM` | — | 발신 주소 (필수) |
| `BONGSU_SMTP_ENCRYPTION` | `starttls` | `starttls`, `tls`, `none` |
| `BONGSU_SMTP_TIMEOUT_SECONDS` | `30` | SMTP 전송 timeout |
| `BONGSU_AUTO_ASSIGN_BY_OWNER` | `true` | 스캔 후 host owner를 findings assignee로 자동 설정 |
| `BONGSU_SECURITY_DB_RETRY_BASE_MINUTES` | `5` | 보안 DB 동기화 실패 재시도 base 지연 |
| `BONGSU_SECURITY_DB_RETRY_MAX_MINUTES` | `60` | 재시도 최대 지연 |
| `BONGSU_SECURITY_DB_BUNDLE_MAX_AGE_DAYS` | `30` | Airgap import stale bundle 거부 임계값 |

## CVE DB 유효성 기준

매칭에 사용되는 어드바이저리는 **패키지 이름 + ecosystem/target + fixed-version 또는 range 데이터**가 모두 있어야 합니다. `TEMP-*`/`CVD-*` placeholder, hash-only fixed evidence, CISA KEV/EPSS 같은 priority-only 피드는 패키지 이름 매칭 후보로 사용하지 않습니다.

## 상세 문서

- [배포 가이드](deploy/README.md)
- [아키텍처와 구현 상태](docs/architecture.md)
- [Agent Handoff (엔지니어 온보딩)](docs/agent-handoff.md)
- [취약점 매칭 규칙](docs/vulnerability-matching-rules.md)
- [운영 Runbook](docs/operations-runbook.md)
- [Operator Runbook (agent/native scanner)](docs/operator-runbook.md)
- [요구사항 감사표](docs/requirements-audit.md)
- [프로젝트 소개 페이지](docs/index.html) — 8개 언어
- [환경변수 참조](deploy/.env.example)

## 라이선스

MIT
