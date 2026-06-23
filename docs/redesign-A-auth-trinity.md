<!-- Design driven by Trinity (jikji) — multi-model design panel: codex, glm-coding, kimi, deepseek-pro, claude-opus. Round 1 flagged the union-escalation flaw; round 2 converged on the policy below. (The verifier ACCEPT step could not render because gpt-5.5 tripped an OpenAI cyber content-filter on the security text — a model refusal, not a design gap; the panel consensus was unanimous.) -->

# Phase A — 통합 인증/Principal/인가 평면 (재설계 명세)

## 1. 목표·범위
8개로 산재했던 자격증명 해석(`authenticateAdmin/Web/Agent/Install/Export`, `viewerSubjects`, `accessScope`, `exportScope`)을 **요청당 1회** 도는 단일 해석기 `resolvePrincipal`로 통합하고, 모든 인가가 하나의 `Principal`에서만 읽도록 한다. 호출부(~154곳)는 얇은 위임으로 유지한다.

## 2. 핵심 발견 — 기존 구현의 권한상승 결함
초기 구현(`principal.go` v1)은 8개 소스를 순회하며 `Scopes`와 `Subjects`를 **무조건 합집합(UNION)**했다. Trinity 패널(deepseek-pro, claude-opus 독립 동시 지적)이 이를 **신뢰도메인 혼합 권한상승**으로 판정:

- viewer 세션(`user:alice`) + 신뢰 리버스프록시 admin 헤더가 동시에 오면 `Admin=true` + `Subjects=[user:alice, group:eng]`로 합쳐져, 원래 viewer였던 alice가 admin과 eng 그룹 자산 접근을 동시에 획득.
- `accessScope`가 subject별 `GetAccessScope`를 `MergeAccessScopes`(OR)로 병합하므로, 서로 다른 신원의 단일호스트 스코프 둘이 합쳐져 **양쪽 호스트 모두 접근** 가능.

## 3. 확정 정책 — Strict First-Wins + 협소 능력 가산
패널 라운드2 만장일치(codex/glm/kimi/deepseek/opus):

> **UNION 시맨틱 완전 폐기.** 신원(identity)은 first-wins로 정확히 하나만 선택, 능력은 협소하게만 가산.

### 3.1 신원 소스(first-wins, 합집합 금지)
우선순위: `bootstrap > token > session > trusted > oidc > viewer-key`.
- 이 6개 중 **최고 우선순위로 매칭된 단 하나**가 `Kind/ID/Admin/Scopes/Subjects`를 독점 결정.
- 나머지 신원 소스가 매칭되어도 능력·subject를 **절대 합치지 않는다**.
- 둘 이상의 신원이 매칭되면 `MultiIdentity=true`로 표시하고 감사 로그에 `auth multi-identity` 기록(권한상승은 안 하되 자격증명 혼동/스푸핑 탐지용).

### 3.2 능력 토큰(가산, 협소)
- `agent`(공유 `X-API-Key`가 agentKey/bootstrap와 일치) → `ScopeAgent`만.
- `install`(전용 `X-Install-Token`) → `ScopeInstall`만.
- 이들은 **각자 고유 시크릿 보유로 독립 증명**되며 Admin·RBAC subject를 절대 싣지 않으므로, 선택된 신원에 가산해도 데이터 접근을 넓힐 수 없다. 신원이 없으면 `Kind`를 능력 종류로 명명.

### 3.3 파생
- `ScopeViewer || len(Subjects)>0` → `ScopeExport` 자동 부여.
- `has()`는 `Admin`이면 모든 scope를 함의(편의). install/agent까지 함의되지만, 이들 엔드포인트는 admin이 당연히 접근 가능하므로 의도된 동작.

## 4. 채택된 데이터모델
```go
type Principal struct {
    Kind     string
    ID       string
    Admin    bool
    Scopes   map[Scope]bool
    Subjects []string
    Presented     []SourceMatch // 감사: 탐지된 모든 소스(선택 안 된 것 포함)
    MultiIdentity bool          // 신원 2개 이상 매칭 시 true
}
type SourceMatch struct { Kind, ID string; Admin bool; Scopes []Scope; Subjects []string; Selected bool }
```
`resolvePrincipal`은 8소스를 `[]SourceMatch`로 수집 → `buildPrincipal`이 Pass1(신원 first-wins)·Pass2(능력 가산)로 조립.

## 5. 동시성·정합성
- 해석은 요청당 1회 `principalCacheMiddleware`로 메모이즈(컨텍스트값 + mutex).
- 토큰/세션 폐기 즉시성: DB 토큰 스토어는 해시맵 캐시이며 revoke 시 evict(별도 구현). 요청 단위 메모이즈는 단일 요청 수명 내에서만 유효하므로 폐기 지연은 최대 1요청.

## 6. 호환 깨짐·마이그레이션
- 破壊적: UNION 동작에 의존하던 "다중 신원으로 권한 누적" 흐름은 제거. 정상 단일-신원 요청은 영향 없음.
- 호출부 시그니처 불변(authenticate* 얇은 위임) → 154개 호출지 수정 불필요.

## 7. 테스트 전략·엣지케이스
- `TestResolvePrincipalEnvSources`: 소스별 단독 동작(bootstrap/agent/viewer-key/install/anonymous/빈키) + 가산 능력이 신원을 바꾸지 않음.
- `TestResolvePrincipalFirstWinsNoEscalation`: (a) trusted viewer가 하위 viewer-key를 이기고 subject 미병합 + MultiIdentity 플래그, (b) bootstrap admin이 하위 trusted를 이기되 하위 subject 미흡수.
- 핵심 엣지: 동일 헤더(X-API-Key)에 들어오는 bootstrap/DB토큰/viewer-key/agent 충돌, 빈 키가 빈 agentKey에 오매칭 금지(상수시간 비교 + 빈값 가드).

## 8. 트레이드오프·기각 대안
- **(기각) UNION 합집합**: 권한상승·감사 모호로 폐기.
- **(기각) 다중 자격증명 즉시 401 거부**(codex 강경안): 정상적인 "세션 쿠키 + API 키" 동시 제시까지 깨뜨릴 위험 → 채택 안 함. 대신 first-wins로 안전하게 무시 + 감사 플래그.
- **(기각) 동일-신원 enrichment**(codex/glm/kimi 제안: 같은 user의 group subject만 보강): 안전하지만 복잡도 증가. v1은 순수 first-wins(가장 보수적)로 가고, 필요 시 추가 가능한 확장으로 남김.
- **채택**: first-wins 신원 + 협소 능력 가산 + 감사 플래그 = 권한상승 제거, 정상 흐름 무중단, 결정적 테스트 가능.
