<!-- Phase B design. NOTE: the jikji Trinity design coordinator (used successfully for Phase A and Phase C) repeatedly hung on this brief — one panel provider stalled across three attempts and never returned a round-1 proposal, so this spec was authored directly from the same grounded brief and validated by real-PostgreSQL integration tests + a codex adversarial pass instead of the verifier-gated panel. -->

# Phase B — 이벤트 기반 ingest→match→notify 파이프라인 (설계 + 구현 명세)

## 1. 목표·범위
ingest→match→notify를 신뢰성 있게 만든다. 핵심 결함: **알림 이벤트 유실**(fire-and-forget, 트랜잭션 아웃박스·재시도 없음 → 크래시/웹훅 실패 시 영구 유실)과 **매칭의 요청 동기 실행**. 단일 Postgres·단일 프로세스(다중 인스턴스 미래 안전성 고려), 모든 변경 감사.

## 2. 확정 설계 — 트랜잭션 아웃박스 + at-least-once 디스패처

### 2.1 event_outbox (migration 066)
`id, event_type, payload JSONB, status(pending|processing|done|dead), attempts, max_attempts, next_attempt_at, locked_by, locked_at, last_error, dedup_key, created_at, updated_at`.
- 부분 인덱스 `idx_event_outbox_due (next_attempt_at) WHERE status='pending'` — 클레임 경로.
- 부분 유니크 `uq_event_outbox_dedup (dedup_key) WHERE dedup_key<>'' AND status IN ('pending','processing')` — 동일 트리거 폭주를 단일 라이브 이벤트로 코얼레싱.

### 2.2 DB API (db/outbox.go)
- `EnqueueEventTx(ctx, tx, type, payload, dedupKey)` — **인입 작업과 동일 트랜잭션**으로 이벤트 영속화(이벤트와 원인이 함께 커밋/롤백). `EnqueueEvent` 독립형. dedupKey 충돌 시 `ON CONFLICT DO NOTHING`으로 코얼레싱(삽입 여부 반환).
- `ClaimDueOutboxEvents(workerID, limit)` — `status='pending' AND next_attempt_at<=now()`을 `FOR UPDATE SKIP LOCKED`로 클레임, `status='processing'`, `attempts++`. 동시/미래 다중 디스패처가 서로 막지 않고 분리 집합 클레임.
- `CompleteOutboxEvent` / `RetryOutboxEvent(attempts,max,cause)`(지수 백오프 2s~1h, max 도달 시 dead) / `ReclaimStuckOutboxEvents(timeout)`(크래시 워커가 남긴 processing 회수).

### 2.3 디스패처 (api/outbox_dispatcher.go)
- `OutboxDispatcher`: 핸들러 레지스트리(event_type→handler), 폴링 루프(`Run(ctx)`), 매 틱마다 stuck 회수 후 due 드레인. `BONGSU_OUTBOX_*` 환경변수로 폴링 주기/배치/stuck TTL 조정.
- `notification.event` 핸들러 → `ruleNotifier.evaluateAndDispatch`. 핸들러가 error 반환 시 outbox 재시도, 성공 시 done.
- 알 수 없는 event_type은 즉시 dead-letter(핸들러 제거 배포가 무한 루프 안 되도록).
- main.go에서 `go server.StartOutboxDispatcher(bgCtx)`로 기동.

### 2.4 알림 신뢰성 (notifier_engine.go, report.go)
- report 핸들러: 응답 전에 `EnqueueEvent("notification.event", {Event, Data})`로 **durable 인큐**(기존 fire-and-forget goroutine 제거). trend 스냅샷만 best-effort goroutine 유지.
- `dispatch`가 전송 성공/실패를 bool 반환, `evaluateAndDispatch`가 실패 규칙 수를 error로 집계 → 디스패처가 재시도 판단.
- **JSON 라운드트립 안전성**: 이벤트 data가 outbox JSONB로 직렬화·역직렬화되며 `map[string]int→map[string]float64`, `int→float64`로 변함. `matchesConditions`의 타입 단언을 `notifCountMap`/`notifInt`로 교체해 severity/risk 필터가 라운드트립 후에도 정확히 적용.

## 3. 시맨틱·트레이드오프
- **at-least-once**: 유실 방지 우선, 중복 가능. notification_log가 per-rule 상태 기록. (정확히-한-번은 단일 Postgres·단일 프로세스에서 과설계로 판단해 기각.)
- 미스컨피그(예: webhook url 없음)는 재시도 무의미 → 이벤트 wedge 방지 위해 성공 처리하고 로그로만 노출.
- dedup_key 코얼레싱으로 동일 호스트 재매칭 폭주 흡수.
- **동시성**: `FOR UPDATE SKIP LOCKED`로 다중 워커/미래 다중 인스턴스 안전. scan_requests 클레임(이미 race-safe)과 동일 패턴.

## 4. 구현 상태
- **구현·검증 완료(B.1, B.2)**: event_outbox + DB API + 디스패처 + 알림 durable 라우팅 + JSON-safe 조건매칭. 실제 Postgres 통합테스트(enqueue/claim exactly-once-while-processing, dedup 코얼레싱, retry→dead-letter, stuck 회수) + 단위테스트(백오프, JSON 라운드트립 조건매칭) 전부 통과. codex 적대 리뷰 통과.
- **후속(B.3, staged)**: 매칭(RematchCVEs/CPE)을 `scan.rematch` outbox 이벤트로 비동기화하여 에이전트 요청에서 분리; 신규 CVE DB 인입 시 영향 호스트 재매칭 이벤트 enqueue. 인입 트랜잭션과 enqueue를 EnqueueEventTx로 원자 결합. (요청 지연·스캔 상태머신 변경을 수반하므로 별도 증분으로 분리.)

## 5. 테스트 전략
- 통합(real PG): 커밋 후 크래시 시 이벤트 보존, 디스패처 재시작 시 미처리 재개(=stuck 회수), 웹훅 5xx 재시도→dead, 동시 워커 비중복 클레임, dedup 코얼레싱.
- 단위: 지수 백오프 단조·상한, JSON 라운드트립 조건매칭(필터가 유실/과잉 안 됨).
