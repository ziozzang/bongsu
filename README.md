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
Agent (각 호스트)  →  Server + Trivy + Web  →  PostgreSQL
```

- **Agent**: Trivy로 패키지 목록 수집, 서버에 전송
- **Server**: CVE 매칭 + 웹 대시보드 제공
- **Packages-only 모드**: Agent는 패키지 목록만 전송, 서버에서 CVE 매칭

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

## CVE DB 유효성 기준

CVE DB에서 실제 매칭/리스캔에 사용하는 advisory는 affected package evidence가 있어야 합니다. 즉 패키지 이름, ecosystem/package type, package fixed version 또는 package fixed event가 있는 affected range가 확인되는 row만 matchable로 봅니다. `TEMP-*` 같은 임시 placeholder ID, git commit hash 같은 hash-only fixed evidence, CISA KEV/EPSS처럼 우선순위 보강만 하는 feed는 이름 기반 매칭 후보로 쓰지 않습니다. EPSS는 별도 advisory가 아니라 같은 CVE row의 `epss_score`, `epss_percentile` 컬럼으로 병합됩니다.

대시보드 첫 화면의 CVE DB 상태 카드와 CVE Search에서 총 row, matchable row, EPSS 병합률, affected/reference 인덱스 커버리지, placeholder/빈 ID 경고를 확인할 수 있습니다.

## 에이전트 설치

웹 대시보드 첫 화면과 `/api/install.sh`에서 같은 one-line 설치를 제공합니다. 이 endpoint는 agent key를 포함하므로 `BONGSU_INSTALL_TOKEN` 설정이 필요합니다.

```bash
curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "http://server:5678/api/install.sh" | sudo bash
```

설치 스크립트는 서버에서 static `bongsu-agent`와 가능한 경우 `trivy` 바이너리를 받아 `/opt/bongsu`에 배치하고, cron 또는 systemd timer로 주기 실행할 수 있습니다. 설치 스크립트 생성과 바이너리 다운로드 인증은 URL query가 아니라 `X-Install-Token` 헤더로만 처리됩니다. 설치된 에이전트는 admin key가 아니라 `BONGSU_AGENT_API_KEY`를 사용하며, credential이 들어있는 config는 `0600` 권한으로 생성됩니다.

Force scan 요청을 즉시 받아 처리하는 상주 모드는 다음처럼 실행할 수 있습니다.

```bash
/opt/bongsu/bin/bongsu-agent --config /opt/bongsu/config.yaml --daemon --poll-interval 60s
```

## 상세 문서

- [배포 가이드](deploy/README.md)
- [아키텍처와 구현 상태](docs/architecture.md)
- [요구사항 감사표](docs/requirements-audit.md)
- [운영 Runbook](docs/operations-runbook.md)
- [환경변수 참조](deploy/.env.example)

## 라이선스

MIT
