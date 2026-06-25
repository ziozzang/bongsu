<!-- Trinity panel (codex, glm-coding, kimi, deepseek-pro, claude-opus) round-1 proposals were unanimous on the plane split below; the deepseek verifier ACCEPT step could not render because the ollama.com verifier call hit a transient network timeout (context deadline) — a network failure, not a design gap. Synthesized by claude-opus from the recovered round-1 proposals + code-grounded analysis, with adversarial self-verification. -->

# Bongsu secdb 평면 분리 설계 명세

## 1. 목표·범위

`cve_database` 한 테이블에 `source` 컬럼으로 혼재된 **개념이 다른 4종**(어드바이저리 osv/nvd/trivy, KEV 신호, EPSS 점수)을 개념별 평면으로 분리한다. 운영 상태(systems: scans/findings/packages/hosts)와 참조 데이터(secdb)의 경계를 명확히 하고, 어드바이저리 쿼리 전반의 `WHERE source != 'epss'` / `NOT IN ('cisa-kev','epss')` 필터를 제거한다. 파괴적 변경 허용, 단일 Postgres 유지, 단계적 비파괴 마이그레이션.

## 2. 3 평면 데이터모델

### 2.1 Advisory plane — `cve_database` 정제 (이름 유지)
osv/nvd/trivy/custom 어드바이저리 전용. 패널은 `advisories`로의 개명도 제안했으나, 본 명세는 **이름 유지**(`cve_database`)로 채택 — 수십 개 쿼리/조인의 churn 대비 이득 미흡(트레이드오프 §8).
- `source` 값 제약: `CHECK (source IN ('osv','nvd','trivy','custom'))` (마이그레이션에서 cisa-kev/epss 행 이관 후 추가).
- `epss_score`, `epss_percentile` 컬럼 **드롭**(signal plane으로 이동).
- `cve_affected_packages`는 그대로(매칭 인덱스, classify.go 게이트의 JOIN 대상).

### 2.2 Signal plane — 신규 `cve_kev` + `cve_epss` (CVE-id 키)
```sql
CREATE TABLE cve_kev (
    vulnerability_id   TEXT PRIMARY KEY,
    source             TEXT NOT NULL DEFAULT 'cisa-kev',
    known_ransomware   BOOLEAN NOT NULL DEFAULT false,
    date_added         TIMESTAMPTZ,
    due_date           TIMESTAMPTZ,
    raw_data           JSONB NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE cve_epss (
    vulnerability_id TEXT PRIMARY KEY,
    score            REAL NOT NULL DEFAULT 0,
    percentile       REAL NOT NULL DEFAULT 0,
    model_date       DATE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cve_epss_score ON cve_epss(score DESC);
```
KEV는 "이 CVE가 실악용됐는가"의 boolean 신호, EPSS는 "악용 확률" 점수 — 둘 다 CVE-id 단일 키. 어드바이저리가 아니므로 `affected_products`/`cvss` 등이 없다.

### 2.3 IOC plane — `exposure_catalog_*` (이미 분리)
migration 071에서 완성. 동일 "secdb source" 추상화에 편입(§3).

## 3. 소스 인터페이스 추상화

`securitySourceRegistryMetadata`의 category를 **plane**으로 승격:
- `advisory` (code-library/os-package/general-cve) — 버전레인지 매칭 참조.
- `signal` (priority-exploit=KEV, priority-risk=EPSS) — CVE-id 키 enrich.
- `ioc` (exposure-catalog) — 정확 매칭.

각 secdb 소스의 공통 계약(Go): `Plane()`, `Ingest()/Upsert()`, `Freshness()`(updated_at/age), `Attribution()`(source name/display). `secdb.Manager`(외부 동기화 스케줄러)는 그대로; 차이는 ingest 라우팅이 plane별 테이블로 분기.

## 4. systems↔secdb read 경계 (변경분)

- `vulnExploitedExpr`: `EXISTS(SELECT 1 FROM cve_database kev WHERE kev.source='cisa-kev' AND kev.vulnerability_id=v.vulnerability_id)` → `EXISTS(SELECT 1 FROM cve_kev k WHERE k.vulnerability_id=v.vulnerability_id)`.
- `vulnEPSSScoreExpr`: `MAX(cve.epss_score) FROM cve_database` → `COALESCE((SELECT score FROM cve_epss e WHERE e.vulnerability_id=v.vulnerability_id),0)`.
- `vulnEPSSPercentileExpr`: 동일하게 `cve_epss.percentile`.
- `EnrichVulnerabilities`: EPSS/KEV를 cve_database 컬럼/행 대신 signal 테이블에서 join.
- `SyncEPSSPriorityColumns`(이중저장 동기화)는 **제거** — 컬럼이 사라지므로 불필요.
- 어드바이저리 통계/freshness 쿼리의 `source != 'epss'` / `NOT IN ('cisa-kev','epss')` 필터 제거(이제 advisory 테이블에 신호 행이 없음).
- 위험점수 `vulnRiskScoreExpr = cvss*5 + epss*30 + (KEV?20) + criticality`는 표현식 동일, 하위 expr만 signal 테이블로 교체 → **점수 불변**(동치성 테스트로 강제).

## 5. 병렬성·리소스 최적화

- **Ingest**: plane별 독립(advisory/KEV/EPSS/IOC) → bounded worker pool로 병렬 upsert. EPSS는 대량(수십만 CVE) → `COPY`/배치, 스트리밍 파싱으로 바운디드 메모리.
- **Match**: 스캔당 RematchCVEs/RematchCPE/MatchExposureCatalog는 독립 → fan-out 병렬(스캔 단위 워커). signal enrich는 join이므로 매칭과 분리된 단일 패스.
- 인덱스: `cve_epss(score DESC)` priority 정렬, `cve_kev(vulnerability_id)` PK 룩업 — 서브쿼리 O(1).

## 6. 마이그레이션 단계 (비파괴→백필→컷오버→정리)

1. **072**: `cve_kev`/`cve_epss` 생성(비파괴).
2. **백필**: `INSERT INTO cve_kev SELECT ... FROM cve_database WHERE source='cisa-kev'`; `INSERT INTO cve_epss SELECT vulnerability_id, MAX(epss_score), MAX(epss_percentile) FROM cve_database WHERE epss_score>0 OR epss_percentile>0 GROUP BY vulnerability_id`.
3. **컷오버(Go)**: signal expr/enrich/ingest를 새 테이블로 교체.
4. **073**: `DELETE FROM cve_database WHERE source IN ('cisa-kev','epss')`; `ALTER ... DROP COLUMN epss_score, epss_percentile`; `ADD CONSTRAINT source CHECK`. (Go 컷오버 머지 후 별도 마이그레이션으로 분리해 롤백 안전.)

## 7. 테스트 전략·엣지케이스

- **동치성**(핵심): 추출 전후 `vulnRiskScoreExpr`/exploited/epss 값이 동일 데이터셋에서 일치.
- KEV/EPSS ingest가 새 테이블에 적재되고 advisory 테이블엔 신호 행이 안 생김.
- freshness: advisory freshness가 신호 행 제거 후에도 정확.
- 엣지: 같은 CVE에 osv+nvd 어드바이저리 2행 + 1 KEV + 1 EPSS → 위험점수 단일.
- 빈 EPSS/KEV(미수집) → COALESCE 0 / EXISTS false.

## 8. 트레이드오프·기각 대안

| 결정 | 선택 | 기각 | 이유 |
|---|---|---|---|
| advisory 테이블명 | `cve_database` 유지 | `advisories` 개명(deepseek) | 수십 쿼리 churn 대비 이득 미흡 |
| EPSS 저장 | `cve_epss` 단일행/CVE | cve_database 컬럼 유지 | 이중저장·SyncEPSSPriorityColumns 제거, advisory에 신호 누출 차단 |
| 컷오버 분리 | Go 머지 후 DROP을 별 마이그레이션 | 한 번에 DROP | 컬럼 의존 코드 잔존 시 롤백 안전 |
| source 제약 | CHECK 추가 | 자유 텍스트 | 신호가 advisory 평면에 재유입 방지 |
