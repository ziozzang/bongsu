<!-- Trinity (jikji) verifier-gated design — panel: codex, glm-coding, kimi, deepseek-pro, claude-opus | verifier: deepseek-v4-pro:cloud (ACCEPT round 1) | synthesizer: claude-opus. Full intent spec below. -->


# Bongsu 보안 인텔리전스 백본 — 최종 설계 명세

> **목표·범위**: Bongsu의 secdb 데이터 평면(advisory/signal/ioc, SBOM, 의존성 그래프, VEX, exposure catalog, 자산 그래프)을 **jikji 바이너리만 사용하는 지능 백본**으로 구동하고, **MCP stdio 기반 동적 툴 인젝션**을 통해 상관·트리아지·교정·자연어질의 같은 인텔리전스 시나리오를 **모듈식·확장가능**하게 구현한다. 단일 Go 프로세스 + 단일 Postgres 유지, 모든 동작 감사, 인텔리전스 실패 시 기존 매칭 파이프라인에 zero impact.

---

## 1. 데이터모델 / 타입 / 스키마

### 1.1 Go 핵심 타입

```go
// ── Plane (확장축 ①) ─────────────────────────────────────
package secdbsource

type Plane string // "advisory" | "signal" | "ioc"

// SecuritySource 인터페이스
type SecuritySource interface {
    Plane() Plane
    Name() string                    // "osv" | "nvd" | "trivy" | "kev" | "epss" | "exposure-catalog"
    Attribution() SourceAttribution  // license, url, freshness_ttl
    Freshness(ctx context.Context, q DBQuerier) (time.Time, error)
    Upsert(ctx context.Context, tx *sql.Tx, batch SourceBatch) (UpsertResult, error)
}

type Registry struct {
    mu      sync.RWMutex
    sources map[string]SecuritySource
}
func (r *Registry) Register(s SecuritySource)
func (r *Registry) ByPlane(p Plane) []SecuritySource

// ── LLMProvider (확장축 ②) ───────────────────────────────
package intel

type LLMProvider interface {
    ChatComplete(ctx context.Context, req ChatRequest) (ChatResponse, error)
    Endpoint() string
    Health(ctx context.Context) error
}
// 기존 llm.Client를 JikjiProvider로 래핑: baseURL="[PROOF_IPV4_1]:1385/v1"

// ── ToolRegistry (확장축 ③) ────────────────────────────────
package intel

type ToolSpec struct {
    Name        string
    Description string
    InputSchema json.RawMessage   // JSON Schema (MCP tools/call 호환)
    MinScope    rbac.Scope        // 최소 권한
    Handler     func(ctx context.Context, args json.RawMessage, p Principal) (json.RawMessage, error)
}

type ToolRegistry struct {
    mu    sync.RWMutex
    tools map[string]ToolSpec
}
func (r *ToolRegistry) Register(spec ToolSpec) error
func (r *ToolRegistry) Resolve(names []string, p Principal) ([]ToolSpec, error) // 스코프 필터링

// ── ScenarioRegistry (확장축 ④) ───────────────────────────
type ScenarioSpec struct {
    Name          string
    Description   string
    RequiredTools []string
    BuildPrompt   func(req RunRequest) (string, error)
    OutputSchema  json.RawMessage
    MaxSteps      int
    Timeout       time.Duration
    MinScope      rbac.Scope // 시나리오 최소 권한
}

// ── IntelligenceRunner ────────────────────────────────────
type RunRequest struct {
    ScenarioName string
    Goal         string
    PromptParams map[string]any
    Principal    Principal
    Timeout      time.Duration
    MaxSteps     int
}
type RunResult struct {
    RunID  uuid.UUID
    Status string // "completed" | "failed" | "timeout" | "cancelled"
    Steps  []ToolCallRecord
    Output json.RawMessage
    Cost   TokenUsage
}
```

### 1.2 DB 스키마 변경 (비파괴 추가)

```sql
-- ── 인텔리전스 런 영속 ───────────────────────────────────
CREATE TABLE intel_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario        text NOT NULL,
    goal            text NOT NULL,
    principal_id    text NOT NULL,
    principal_scope jsonb NOT NULL DEFAULT '{}',  -- 호출 시점 RBAC 스냅샷
    status          text NOT NULL DEFAULT 'pending',
    -- pending|running|completed|failed|timeout|cancelled
    tools_injected  text[] NOT NULL DEFAULT '{}',
    output          jsonb,
    error           text,
    token_usage     jsonb,
    started_at      timestamptz NOT NULL DEFAULT now(),
    ended_at        timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_intel_runs_scenario_status ON intel_runs(scenario, status);
CREATE INDEX idx_intel_runs_principal_time ON intel_runs(principal_id, started_at DESC);

-- ── 툴 호출 감사 (모든 호출 100% 기록) ─────────────────────
CREATE TABLE intel_tool_calls (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          uuid NOT NULL REFERENCES intel_runs(id) ON DELETE CASCADE,
    tool_name       text NOT NULL,
    input_args      jsonb NOT NULL,
    output_result   jsonb,
    output_truncated bool DEFAULT false,
    duration_ms     int,
    error           text,
    called_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_intel_tool_calls_run ON intel_tool_calls(run_id, called_at);

-- ── 툴 레지스트리 카탈로그 ────────────────────────────────
CREATE TABLE intel_tool_registry (
    name          text PRIMARY KEY,
    description   text NOT NULL,
    input_schema  jsonb NOT NULL,
    min_scope     jsonb NOT NULL DEFAULT '{}',
    version       text NOT NULL,
    enabled       bool NOT NULL DEFAULT true,
    registered_at timestamptz NOT NULL DEFAULT now()
);

-- ── 시나리오 레지스트리 카탈로그 ──────────────────────────
CREATE TABLE intel_scenario_registry (
    name           text PRIMARY KEY,
    description    text NOT NULL,
    required_tools text[] NOT NULL,
    output_schema  jsonb NOT NULL,
    min_scope      jsonb NOT NULL DEFAULT '{}',
    version        text NOT NULL,
    enabled        bool NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);

-- ── 기존 테이블 비파괴 수정 ────────────────────────────────
-- securitySourceRegistryMetadata.category → plane 승격
ALTER TABLE securitySourceRegistryMetadata
    ADD COLUMN IF NOT EXISTS plane text NOT NULL DEFAULT 'advisory';
CREATE INDEX IF NOT EXISTS idx_secsrc_plane ON securitySourceRegistryMetadata(plane);

-- 데이터 마이그레이션은 애플리케이션 init()에서 수행
-- advisory: osv, nvd, trivy
-- signal: cve_kev, cve_epss
-- ioc: exposure_catalog_*
```

**[결정 근거]**: glm-coding의 스키마를 기반으로 deepseek-pro의 step_index를 seq로 대체. kimi의 완전 재설계(`security_source_registry` 신규 테이블)는 기존 테이블과 중복되므로 기각. 기존 `securitySourceRegistryMetadata`에 컬럼 추가로 충분.

### 1.3 기존 테이블 (변경 없음)

- `cve_database`, `cve_affected_packages` (advisory)
- `cve_kev`, `cve_epss` (signal, read 경로 컷오버 완료)
- `exposure_catalog_*` (ioc)
- `scan_sboms` (SBOM)
- `package_dependencies` (의존성 그래프, `DependentsOf` 전이적)
- VEX 입출력은 기존 CycloneDX 경로 유지

---

## 2. 제어흐름 · 해석 순서 · 경계

### 2.1 IntelligenceRunner.Run 제어흐름

```
API /api/intel/runs POST
  → RBAC 검증 (Principal 스코프 확인)
  → RunRequest 생성
  → IntelligenceRunner.Run(ctx, req):
      1. pool <- struct{}{} (bounded worker 획득, timeout race)
      2. Store.CreateRun → intel_runs(status='running')
      3. scenarios.Get(req.ScenarioName) → ScenarioSpec
      4. tools.Resolve(spec.RequiredTools, principal) → 스코프 필터링된 ToolSpec[]
      5. prompt = spec.BuildPrompt(req)
      6. exec.CommandContext(ctx, jikjictlPath, "run", goal,
              "--prompt", prompt,
              "--tools-from", "bongsu-mcp-serve --run-id <runID>",
              "--max-steps", N,
              "--output", "jsonl")
      7. stdout JSONL 파싱 → ToolCallRecord 축적
      8. 각 JSONL 이벤트:
          - tool_call: MCP 서버가 policy+audit 래퍼 경유 → tool.Handler 실행
          - tool_result: intel_tool_calls INSERT (non-blocking)
          - assistant_output: 축적
      9. ctx timeout/cancel → SIGTERM → status='timeout'/'cancelled'
      10. 종료 후 output 검증(spec.OutputSchema) → status='completed'/'failed'
      11. Store.FinishRun → intel_runs UPDATE
      12. pool -> struct{}{} (반납)
```

### 2.2 MCP 툴 서버 (Bongsu 내장, stdio)

```go
// mcp_server.go: MCP stdio 프로토콜 구현
// jikjictl이 tools/list → 등록된 ToolSpec[] JSON Schema 반환
// jikjictl이 tools/call → policy.Check(scope) → audit.Record → handler 실행

func (s *MCPServer) handleToolCall(req MCPRequest) MCPResponse {
    spec, ok := s.tools.Get(req.Params.Name)
    if !ok { return MCPError("unknown_tool") }
    if !policy.Check(s.principal, spec.MinScope) {
        return MCPError("forbidden")  // 권한 상승 차단
    }
    start := time.Now()
    result, err := spec.Handler(s.ctx, req.Params.Arguments, s.principal)
    s.store.RecordToolCall(req.RunID, spec.Name, req.Params.Arguments,
        result, err, time.Since(start)) // 감사 (non-blocking, outbox)
    return MCPResponse{Result: truncate(result)} // well-known limit
}
```

**[결정 근거]**: glm-coding/kimi 접근 채택 — Bongsu가 MCP stdio 자식 프로세스로 뜨는 구조. deepseek-pro의 HTTP MCP는 추가 네트워크 홉 불필요. jikji가 `jikjictl --tools-from <cmd>`를 지원한다는 [가정] 근거.

### 2.3 기존 runScanMatch와의 경계

`runScanMatch`(report.go) 파이프라인은 **intel의 존재를 모름**. intel은 완료된 데이터를 read-only로만 조회. 런 실패·백본 다운이 매칭 파이프라인에 zero impact.

---

## 3. 권한 · 능력 · 정합성 모델

### 3.1 RBAC 스코프 전파

```go
type Principal struct {
    ID    string
    Scope rbac.Scope // {hosts: [], packages: [], envs: [], planes: []}
}
```

런 시작 시 `principal_scope`를 `intel_runs`에 스냅샷 저장. 주입된 모든 툴의 Handler는 Principal.Scope를 강제 적용:
- `query_vulns(filter)`: filter.hosts ∈ scope.hosts 강제 (SQL WHERE 주입)
- `asset_graph(host)`: host ∈ scope.hosts 검증
- `sbom_at(scan)`: scan 소유자 검증

### 3.2 read-only 보장

툴 핸들러는 `db.ReadOnlyQuerier` 인터페이스만 주입받음 (SELECT만 가능). 인텔리전스 런이 DB 상태를 변경하는 유일한 경로 = `intel_runs`/`intel_tool_calls` INSERT (감사 목적).

### 3.3 aipolicy 흡수

기존 `internal/server/aipolicy`의 규칙을 `tool/policy.go` + `scenario/registry.go`의 `MinScope`로 흡수. 시나리오별 필요 최소 권한을 `ScenarioSpec.RequiredTools` → `ToolSpec.MinScope` 교차셋으로 산정.

### 3.4 VEX 처리 (쓰기 경계)

```go
// vex_mark 툴만 쓰기 허용, 런 완료 후 별도 apply 단계
type VEXApplyResult struct {
    RunID         uuid.UUID
    AppliedAt     time.Time
    VEXStatements []CycloneDXVEX
}
// 런 중에는 result JSON만 저장, 승인 후 apply
```

**[결정 근거]**: kimi의 별도 apply 단계 채택. 런 중 직접 DB 쓰기는 비결정성 위험. VEX는 런 완료 후 승인된 결과만 `vex_statements` 테이블에 apply.

---

## 4. 동시성 · 트랜잭션 · 실패 시맨틱

### 4.1 동시성 제어

| 레벨 | 메커니즘 | 값 |
|------|----------|----|
| 런 동시성 | bounded worker pool (`chan struct{}`) | maxConcurrentRuns=8 |
| 툴 호출 동시성 | jikjictl 내부 단계 직렬 | jikji 관할 |
| DB 쓰기 경합 | 없음 (intel은 INSERT만) | - |
| 메모이제이션 | `query_cache` (LRU, TTL=5m) | 동일 런 내 동일 툴+입력 |

### 4.2 트랜잭션 경계

| 연산 | TX 범위 | 격리 |
|------|---------|------|
| intel_runs 생성 | 단일 INSERT | READ COMMITTED |
| intel_tool_calls 기록 | 개별 INSERT (auto-commit, non-blocking) | READ COMMITTED |
| intel_runs 종료 업데이트 | 단일 UPDATE | READ COMMITTED |
| 툴 내부 데이터 조회 | ReadOnly 트랜잭션 | REPEATABLE READ [가정] |

### 4.3 아웃박스 — 툴 호출 감사

```go
// buffered channel + 단일 writer goroutine
auditCh := make(chan *AuditEvent, 1024)
go func() {
    for e := range auditCh {
        db.InsertIntelToolCall(e) // batch INSERT
    }
}()
// channel full 시 drop(카운터 증가, intel_runs.error에 기록)
```

**[결정 근거]**: glm-coding의 buffered channel 패턴 채택. kimi/deepseek-pro는 별도 언급 없음. 툴 응답 지연 방지가 우선.

### 4.4 실패·타임아웃 시맨틱

| 실패 모드 | 감지 | 복구 |
|-----------|------|------|
| jikji 서버 다운 | provider.Health() 사전 체크 | status='failed', graceful degrade |
| 런 타임아웃 | ctx.WithTimeout → SIGTERM | status='timeout', 부분 결과 보존 |
| 툴 핸들러 panic | recover() → error 반환 | 해당 툴 호출 error 기록, 런 계속 |
| MCP 서버 크래시 | jikjictl exit code != 0 | status='failed', 부분 파싱 시도 |
| DB 연결 끊김 | 툴 쿼리 에러 | 툴 error 반환, 런 계속 |
| 비밀값 노출 | 툴 출력에 `~/env` 패턴 | regex scrub 후 감사 |

**graceful degrade**: provider.Health() 실패 시 인텔리전스 기능 전체 비활성화, API 503 반환, 기존 스캔/매칭 정상.

---

## 5. 호환 깨짐 + 단계별 마이그레이션

### 5.1 비파괴 추가 (기본 원칙)

- 신규 테이블 4개 CREATE TABLE — 기존 테이블 변경 없음
- `securitySourceRegistryMetadata` 컬럼 추가(ADD COLUMN, 기본값 'advisory')
- 기존 `internal/server/llm` 인터페이스 유지, 내부 provider를 JikjiProvider로 교체

### 5.2 단계별 마이그레이션

**Phase 1 — 패키지 생성 + 스키마** (비파괴):
1. `internal/server/secdb/source/` 패키지 생성, `SecuritySource` 인터페이스 정의
2. `internal/server/intel/` 패키지 생성, `LLMProvider`, `ToolRegistry`, `ScenarioRegistry` 골격
3. DB 마이그레이션: 4개 테이블 + securitySourceRegistryMetadata 컬럼 추가
4. 기존 llm.Client를 `LLMProvider` 인터페이스로 래핑 (JikjiProvider)

**Phase 2 — SecuritySource 정렬** (기능 동일, 리팩터):
5. osv/nvd/trivy/kev/epss/exposure 각각을 SecuritySource 구현체로 추출
6. `secdb.Manager`가 Registry를 통해 source를 관리하도록 변경
7. `securitySourceRegistryMetadata.category` → `plane` 데이터 마이그레이션

**Phase 3 — 툴 + MCP 서버**:
8. 6개 기본 툴 구현(query_vulns, asset_graph, dependents_of, advisory_for, exposure_lookup, sbom_at)
9. MCP stdio 서버 구현, 툴 등록
10. policy.go + audit.go 래퍼 구현
11. 단위 테스트: 툴 권한경계, 결과 truncate, 감사 기록

**Phase 4 — IntelligenceRunner**:
12. `IntelligenceRunner.Run` 구현, jikjictl exec, JSONL 파싱
13. bounded pool, timeout, cancel, graceful degrade
14. /api/intel/runs POST·GET 핸들러

**Phase 5 — 시나리오 5개 + 기존 AI 흡수**:
15. 5개 시나리오 구현(correlate, triage, campaign, remediate, nl_query)
16. 기존 `vuln_analysis.go` + `aipolicy` 경로를 새 시나리오로 마이그레이션

**Phase 6 — 기존 AI 엔드포인트 제거** (파괴적):
17. `internal/server/llm` 직접 호출 경로 제거
18. `internal/server/aipolicy` 제거
19. `vuln_analysis.go` 제거

---

## 6. 테스트 전략 · 핵심 엣지케이스

### 6.1 테스트 레이어

| 레벨 | 대상 | 도구 |
|------|------|------|
| 단위 | ToolSpec.Handler (권한 필터링, 결과 truncate) | Go testing, fake DBQuerier |
| 단위 | ScenarioSpec.BuildPrompt (프롬프트 생성 결정성) | snapshot 테스트 |
| 단위 | MCP 서버 (tools/list, tools/call 프로토콜) | in-memory stdio pipe |
| 통합 | IntelligenceRunner.Run (jikji fake + 실제 DB) | testcontainers Postgres, mock 바이너리 |
| 시나리오 골든 | 5개 시나리오별 고정 입력→출력 스키마 검증 | golden file + JSON Schema |
| 권한 회귀 | Principal.Scope 벗어남 툴 호출 시 forbidden | 테이블 드리븐 |
| 동시성 | maxConcurrentRuns 초과 요청 백프레셔 | goroutine 100개 동시 Run |
| 실패 격리 | jikji 서버 다운 시 기존 매칭 정상 | 통합 테스트 |

### 6.2 핵심 엣지케이스

1. **권한 상승 시도**: Principal.Scope에 없는 host에 대한 `asset_graph` 호출 → 403 반환, 감사 기록
2. **툴 결과 대용량**: `dependents_of`가 10만 행 반환 → truncate(100행 + count), `output_truncated=true`
3. **비밀값 스크럽**: 툴 출력에 `~/env` 경로나 API 키 패턴 → regex scrub 후 감사
4. **런 중 취소**: 클라이언트 disconnect → ctx.Done → SIGTERM → 부분 결과 보존
5. **MCP 서버 크래시**: jikjictl exit code != 0 → 파싱 가능한 stdout까지 반환, status='failed'
6. **동일 런 내 동일 툴+입력**: 메모이제이션 캐시 히트 → 감사 1회 기록
7. **동시 런 풀 포화**: 9번째 요청 대기 → timeout 또는 429 백프레셔
8. **비결정성**: 동일 입력에 LLM 응답 달라짐 → 출력 스키마 검증만 (골든은 스키마+핵심 필드 존재)
9. **scenario 미등록 툴 요청**: RequiredTools에 없는 툴 → Registry.Resolve에서 거부
10. **read-only 위반 시도**: 툴 핸들러가 Write 쿼리 실행 → ReadOnlyQuerier 타입 제약으로 컴파일 타임 차단

---

## 7. 인텔리전스 시나리오 5개 (툴 + 오케스트레이션 + 출력 + 영속)

### (a) 교차소스 어드바이저리 상관/중복제거

- **주입 툴**: `advisory_for(cve)` → 다중 소스(osv/nvd/trivy) 메타데이터 반환
- **오케스트레이션**: prompt = "다음 CVE의 소스별 메타데이터를 비교하고 정합·신뢰도 판정하라". max_steps=5
- **출력 스키마**: `{cve, sources: [{name, cvss, severity, published, references}], canonical: {cvss, severity, confidence}, conflicts: [{field, values, resolution}]}`
- **영속**: `intel_runs.output`에 JSON

### (b) AI 트리아지

- **주입 툴**: `query_vulns(filter)`, `dependents_of(pkg)`, `advisory_for(cve)`, `sbom_at(scan)`
- **오케스트레이션**: prompt = "이 finding이 실제 도달 가능한지 의존성 그래프 + VEX + KEV 기반으로 판정하라". max_steps=10
- **출력 스키마**: `{finding_id, verdict: "false_positive"|"reachable"|"not_reachable", confidence: float, reasoning: string, evidence: [{tool, fact}]}`
- **영속**: `intel_runs.output`. 기존 `vuln_analysis.go` 경로 대체

### (c) 공급망 캠페인 상관

- **주입 툴**: `exposure_lookup(pkg,ver)`, `dependents_of(pkg)`, `query_vulns(filter)`
- **오케스트레이션**: prompt = "exposure catalog + 의존성 그래프 + KEV/EPSS로 침해 전파 범위를 추정하라". max_steps=15
- **출력 스키마**: `{campaign_id, affected_assets: [{host, path, blast_radius}], kev_boost: bool, epss_score: float, propagation_paths: [[pkg→pkg→...]]}`

### (d) 교정 계획

- **주입 툴**: `advisory_for(cve)`, `dependents_of(pkg)`, `query_vulns(filter)`
- **오케스트레이션**: prompt = "finding에 대해 fixed version, 업그레이드 경로, 영향받는 종속 패키지 목록을 생성하라". max_steps=8
- **출력 스키마**: `{finding_id, fixed_version, upgrade_path: [{pkg, current, target, breaking_changes: bool}], affected_dependents: [{pkg, version}], priority_score: float}`

### (e) 자연어 보안 질의

- **주입 툴**: `query_vulns(filter)`, `asset_graph(host)`, `dependents_of(pkg)`, `exposure_lookup(pkg,ver)`, `sbom_at(scan)`
- **오케스트레이션**: 자유 NL 질의 → 시나리오가 동적으로 툴 선택 프롬프트 구성. max_steps=12
- **출력 스키마**: `{question, answer: string, sources: [{tool, query, result_summary}], confidence: float}`

---

## 8. 명시적 트레이드오프 · 기각된 대안

### 8.1 채택 vs 기각

| 결정 | 채택 | 기각 대안 | 기각 근거 |
|------|------|-----------|-----------|
| **툴 인젝션** | MCP stdio (Bongsu 내장) | 별도 HTTP 툴 서버 | 네트워크 노출면 증가, 인증 추가 복잡, DB 연결풀 분리 |
| **jikji 연동** | jikjictl exec | jikji ACP server (Bongsu가 클라이언트) | Bongsu가 ACP 클라이언트 구현 필요, 복잡도 증가 |
| **DB 스키마** | 기존 테이블 + 컬럼 추가 | security_source_registry 완전 재설계 | 기존 테이블과 중복, 마이그레이션 과도 |
| **VEX 처리** | 별도 apply 단계 | 런 중 직접 DB 쓰기 | 비결정성 + 보안경계 위험 |
| **신선도 관리** | Freshness() 메서드 | freshness_policy JSONB | 기존 구현과 충돌, 과도한 유연성 [가정] |
| **패키지 구조** | glm-coding 구조 | kimi/deepseek-pro | glm-coding이 가장 명확한 의존 방향 |

### 8.2 보안 경계 검증

- **툴 인젝션 권한상승**: 툴 MinScope + Principal.Scope 교차검증 → MCP 서버가 모든 tools/call에서 강제. 우회 불가.
- **백본 의존 단일점**: jikji 서버 다운 시 graceful degrade(인텔리전스 비활성화, 매칭 정상). provider 다중화(litellm fallback) [가정 — 추후].
- **비결정성**: 출력 스키마 검증 + 감사 기록으로 추적 가능. 동일 질의 메모이제이션은 런 내에서만(TTL 짧음).
- **비밀값 노출**: 툴 핸들러에 비밀 전달 안 함. jikjictl 실행 시 `--env-file ~/env`로 주입하되 [가정], 툴 출력 scrub 필터 적용.
- **감사 누락**: buffered channel full 시 drop 카운터 증가 → `intel_runs.error`에 경고 기록. 감사 완전성 > 툴 응답 지연.

### 8.3 확장 절차 (새 소스·툴·시나리오 추가, 코어 변경 없음)

**새 secdb 소스**:
1. `secdb/source/`에 `SecuritySource` 구현체 추가
2. `init()`에서 `Registry.Register()` 호출
3. `securitySourceRegistryMetadata`에 행 INSERT (plane 설정)
4. 외부 동기화 스케줄러가 자동 감지

**새 툴**:
1. `intel/tool/`에 `ToolSpec` 정의 (Handler + InputSchema + MinScope)
2. `init()`에서 `ToolRegistry.Register()` 호출
3. `intel_tool_registry`에 행 INSERT
4. MCP 서버가 자동으로 tools/list에 노출

**새 시나리오**:
1. `intel/scenario/`에 `ScenarioSpec` 정의 (RequiredTools + BuildPrompt + OutputSchema)
2. `init()`에서 `ScenarioRegistry.Register()` 호출
3. `intel_scenario_registry`에 행 INSERT
4. `/api/intel/runs`에 scenario 이름으로 즉시 호출 가능

---

## 9. 패키지 구조

```
internal/server/
  secdb/
    source/              ← SecuritySource 인터페이스 + 레지스트리
      source.go
      osv.go nvd.go trivy.go kev.go epss.go exposure.go
  intel/                 ← 인텔리전스 백본
    runner.go            ← IntelligenceRunner (jikjictl exec, bounded pool)
    provider.go          ← LLMProvider 추상화 (jikji/litellm/ollama)
    mcp_server.go        ← Bongsu 내장 MCP stdio 툴 서버
    store.go             ← intel_runs, intel_tool_calls 영속
    api.go               ← /api/intel/* 핸들러
    tool/
      registry.go        ← ToolRegistry (플러그인 등록)
      policy.go          ← 툴 RBAC 강제 래퍼
      audit.go           ← 툴 호출 감사 래퍼
      query_vulns.go asset_graph.go dependents_of.go
      advisory_for.go exposure_lookup.go sbom_at.go
    scenario/
      registry.go        ← ScenarioRegistry (플러그인 등록)
      correlate.go       ← (a) 교차소스 상관/중복제거
      triage.go          ← (b) AI 트리아지
      campaign.go        ← (c) 공급망 캠페인 상관
      remediate.go       ← (d) 교정 계획
      nl_query.go        ← (e) 자연어 보안 질의
```

**의존 규칙**: `intel/* → db(읽기 전용 쿼리)` `intel/* → secdb/source(읽기)`. `db → intel` 역참조 절대 금지. `api → intel` 호출만 허용. `runScanMatch`는 intel을 모름.

---

## 10. [가정] 명시

1. jikji `:1385` 서버가 OpenAI `/v1/chat/completions` 호환
2. `jikjictl run --tools-from <cmd>` 또는 `tools mcp <cmd>`로 stdio MCP 툴 주입 지원
3. API 라우터가 chi/echo 기반 (`internal/server/api`)
4. Postgres ≥14 (gen_random_uuid 사용 가능)
5. `jikjictl`이 PATH에 존재하거나 설정 가능
6. Bongsu tenant isolation이 Postgres RLS 또는 쿼리 레벨 WHERE절로 구현
7. jikji 바이너리가 `tools mcp` 서브커맨드로 MCP 서버를 띄우고 `--tools-from` 인자 지원
8. 기존 `internal/server/db/vuln_analysis.go` 쿼리가 read-only이며 툴 포팅 가능
9. 비용/토큰 카운팅이 jikji 응답 JSONL에 포함

---

이상. 모든 확장이 `init()` 등록만으로 이루어지며, 코어(`IntelligenceRunner`, `MCP Server`, `ToolRegistry`) 변경 없이 새 소스·툴·시나리오가 추가되는 구조. 충돌하는 제안은 근거를 들어 하나로 결정하였으며, 양시론은 배제함.
