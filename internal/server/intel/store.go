package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

// Store persists intel runs and audits every tool call. Run/finish writes are
// synchronous (the run lifecycle depends on them); tool-call audit writes go
// through a buffered channel drained by a single writer goroutine, so a slow DB
// never stalls a tool response. When the channel is full an audit is dropped and
// a per-run counter is incremented (the run records how many audits it lost) —
// the design favors a fast tool path with visible loss over blocking.
type Store struct {
	db      *db.DB
	auditCh chan auditEvent
	wg      sync.WaitGroup
	dropped sync.Map // runID -> *int64
	closed  chan struct{}
	once    sync.Once
}

type auditEvent struct {
	runID      string
	seq        int
	tool       string
	args       []byte
	result     []byte
	truncated  bool
	durationMS int
	errMsg     string
}

// NewStore builds a store with an audit buffer of the given size (default 1024)
// and starts the writer goroutine.
func NewStore(database *db.DB, bufferSize int) *Store {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	s := &Store{
		db:      database,
		auditCh: make(chan auditEvent, bufferSize),
		closed:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.auditWriter()
	return s
}

// RunRecord is the persisted shape of a run at creation.
type RunRecord struct {
	Scenario       string
	Goal           string
	PrincipalID    string
	PrincipalScope any
	ToolsInjected  []string
	SessionID      string
}

// CreateRun inserts a new run in status 'running' and returns its id.
func (s *Store) CreateRun(ctx context.Context, r RunRecord) (string, error) {
	scope := marshalJSONObject(r.PrincipalScope)
	var id string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO intel_runs (scenario, goal, principal_id, principal_scope, status, tools_injected, session_id)
		 VALUES ($1,$2,$3,$4,'running',$5,$6) RETURNING id`,
		r.Scenario, r.Goal, r.PrincipalID, scope, pqTextArray(r.ToolsInjected), r.SessionID).Scan(&id)
	return id, err
}

// SetRunValidation records whether the run's output conformed to its scenario
// OutputSchema (structured-termination result).
func (s *Store) SetRunValidation(ctx context.Context, runID string, valid bool, validationErr string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE intel_runs SET output_valid=$2, output_validation_error=$3 WHERE id=$1`,
		runID, valid, validationErr)
}

// SetRunPipelineID stamps a run with its pipeline correlation id so the stages of
// one pipeline execution can be queried together (they no longer share a session).
func (s *Store) SetRunPipelineID(ctx context.Context, runID, pipelineRunID string) {
	if runID == "" || pipelineRunID == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE intel_runs SET pipeline_run_id=$2 WHERE id=$1`, runID, pipelineRunID)
}

// SetRunSession records the backbone session id resolved during the run (jikji
// generates one when none was supplied), so follow-up runs can reference it.
func (s *Store) SetRunSession(ctx context.Context, runID, sessionID string) {
	if sessionID == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE intel_runs SET session_id=$2 WHERE id=$1`, runID, sessionID)
}

// FinishRun records the terminal status, output, token usage and any dropped
// audits for a run.
func (s *Store) FinishRun(ctx context.Context, runID, status string, output any, usage any, errMsg string) error {
	var dropped int64
	if v, ok := s.dropped.Load(runID); ok {
		dropped = atomic.LoadInt64(v.(*int64))
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE intel_runs SET status=$2, output=$3, token_usage=$4, error=$5, dropped_audits=$6, ended_at=now()
		 WHERE id=$1`,
		runID, status, marshalJSONOrNull(output), marshalJSONObject(usage), errMsg, dropped)
	s.dropped.Delete(runID)
	return err
}

// LoadRunScope reads the RBAC scope snapshot a run was created with. The
// intel-mcp subprocess uses it to serve tools under exactly the scope the API
// caller had, so the agent can never exceed it.
func (s *Store) LoadRunScope(ctx context.Context, runID string) (*Scope, error) {
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT principal_scope FROM intel_runs WHERE id=$1`, runID).Scan(&raw); err != nil {
		return nil, err
	}
	var sc Scope
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &sc)
	}
	return &sc, nil
}

// RunView is the persisted run as read back for the API.
type RunView struct {
	ID         string          `json:"id"`
	Scenario   string          `json:"scenario"`
	Status     string          `json:"status"`
	Output     json.RawMessage `json:"output,omitempty"`
	TokenUsage json.RawMessage `json:"token_usage,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// GetRun reads a persisted run.
func (s *Store) GetRun(ctx context.Context, runID string) (RunView, error) {
	var v RunView
	var output, usage []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id::text, scenario, status, COALESCE(output,'null'::jsonb), COALESCE(token_usage,'{}'::jsonb), error
		   FROM intel_runs WHERE id=$1`, runID).
		Scan(&v.ID, &v.Scenario, &v.Status, &output, &usage, &v.Error)
	if err != nil {
		return RunView{}, err
	}
	v.Output = output
	v.TokenUsage = usage
	return v, nil
}

// VerificationRecord is the aggregate row at creation (before voters run).
type VerificationRecord struct {
	PrincipalID     string
	Params          map[string]any
	RequestedVoters int
	MinSuccess      int
	Lenses          []Lens
}

// CreateVerification inserts the aggregate row in status 'running' and returns
// its id, so voter runs can be linked to it as they complete.
func (s *Store) CreateVerification(ctx context.Context, r VerificationRecord) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO intel_verifications (principal_id, params, requested_voters, min_success, lenses, status)
		 VALUES ($1,$2,$3,$4,$5,'running') RETURNING id`,
		r.PrincipalID, marshalJSONObject(r.Params), r.RequestedVoters, r.MinSuccess, marshalJSONOrEmptyArray(r.Lenses)).Scan(&id)
	return id, err
}

// BackfillVoterRun links a completed voter run to its verification (best-effort;
// a failure here does not affect the verdict). runID is an intel_runs UUID.
func (s *Store) BackfillVoterRun(ctx context.Context, runID string, verID int64, index int, lens string) {
	if runID == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE intel_runs SET verification_id=$2, voter_index=$3, voter_lens=$4 WHERE id=$1`,
		runID, verID, index, lens)
}

// VerificationAggregate is the tally written when all voters finish.
type VerificationAggregate struct {
	Status       string
	Verdict      string
	Valid        bool
	Confidence   float64
	Succeeded    int
	Failed       int
	ValidVotes   int
	RefutedVotes int
	Votes        []VerificationVote
}

// UpdateVerification records the final tally and verdict for a verification.
func (s *Store) UpdateVerification(ctx context.Context, id int64, a VerificationAggregate) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE intel_verifications SET status=$2, verdict=$3, valid=$4, confidence=$5,
		   succeeded_voters=$6, failed_voters=$7, valid_votes=$8, refuted_votes=$9,
		   votes=$10, finished_at=now()
		 WHERE id=$1`,
		id, a.Status, a.Verdict, a.Valid, a.Confidence,
		a.Succeeded, a.Failed, a.ValidVotes, a.RefutedVotes, marshalJSONOrEmptyArray(a.Votes))
	return err
}

// UpsertFindingReport persists a report keyed UNIQUE by dedup_key: a new key
// inserts, an existing key updates to the latest report and bumps
// seen_count/last_seen (first_seen is preserved). Atomic via ON CONFLICT.
func (s *Store) UpsertFindingReport(ctx context.Context, in FindingReportInput) (*FindingReport, error) {
	report := in.Report
	if len(report) == 0 {
		report = []byte("{}")
	}
	var runID any
	if in.RunID != "" {
		runID = in.RunID
	}
	var fr FindingReport
	var cvss sql.NullFloat64
	var run sql.NullString
	err := s.db.QueryRowContext(ctx, `
INSERT INTO intel_finding_reports (dedup_key, finding, summary, severity, cvss, report, run_id, principal_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (dedup_key) DO UPDATE SET
	finding=EXCLUDED.finding, summary=EXCLUDED.summary, severity=EXCLUDED.severity,
	cvss=EXCLUDED.cvss, report=EXCLUDED.report, run_id=EXCLUDED.run_id,
	principal_id=EXCLUDED.principal_id, last_seen=now(),
	seen_count=intel_finding_reports.seen_count+1, updated_at=now()
RETURNING id, dedup_key, finding, summary, severity, cvss, report, run_id, principal_id, first_seen, last_seen, seen_count`,
		in.DedupKey, in.Finding, in.Summary, in.Severity, nullableFloat(in.CVSS), report, runID, in.PrincipalID).
		Scan(&fr.ID, &fr.DedupKey, &fr.Finding, &fr.Summary, &fr.Severity, &cvss, &fr.Report, &run, &fr.PrincipalID, &fr.FirstSeen, &fr.LastSeen, &fr.SeenCount)
	if err != nil {
		return nil, err
	}
	if cvss.Valid {
		fr.CVSS = &cvss.Float64
	}
	fr.RunID = run.String
	return &fr, nil
}

// ListFindingReports returns persisted reports, newest activity first, with
// optional severity/finding filters and pagination.
func (s *Store) ListFindingReports(ctx context.Context, f FindingReportFilter) (FindingReportList, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	out := FindingReportList{Limit: limit, Offset: offset}
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM intel_finding_reports WHERE ($1='' OR severity=$1) AND ($2='' OR finding ILIKE '%'||$2||'%')`,
		f.Severity, f.Finding).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, dedup_key, finding, summary, severity, cvss, report, run_id, principal_id, first_seen, last_seen, seen_count
FROM intel_finding_reports
WHERE ($1='' OR severity=$1) AND ($2='' OR finding ILIKE '%'||$2||'%')
ORDER BY last_seen DESC, id DESC
LIMIT $3 OFFSET $4`, f.Severity, f.Finding, limit, offset)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		fr, err := scanFindingReport(rows)
		if err != nil {
			return out, err
		}
		out.Reports = append(out.Reports, fr)
	}
	return out, rows.Err()
}

// GetFindingReportByDedupKey reads a single report by its normalized dedup key.
func (s *Store) GetFindingReportByDedupKey(ctx context.Context, dedupKey string) (FindingReport, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, dedup_key, finding, summary, severity, cvss, report, run_id, principal_id, first_seen, last_seen, seen_count
FROM intel_finding_reports WHERE dedup_key=$1`, dedupKey)
	return scanFindingReport(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFindingReport(r rowScanner) (FindingReport, error) {
	var fr FindingReport
	var cvss sql.NullFloat64
	var run sql.NullString
	if err := r.Scan(&fr.ID, &fr.DedupKey, &fr.Finding, &fr.Summary, &fr.Severity, &cvss, &fr.Report,
		&run, &fr.PrincipalID, &fr.FirstSeen, &fr.LastSeen, &fr.SeenCount); err != nil {
		return FindingReport{}, err
	}
	if cvss.Valid {
		fr.CVSS = &cvss.Float64
	}
	fr.RunID = run.String
	return fr, nil
}

func nullableFloat(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}

// RecordToolCall queues a tool-call audit (non-blocking). On a full buffer the
// audit is dropped and the run's drop counter is incremented.
func (s *Store) RecordToolCall(runID string, seq int, tool string, args, result []byte, truncated bool, duration time.Duration, errMsg string) {
	ev := auditEvent{
		runID: runID, seq: seq, tool: tool, args: args, result: result,
		truncated: truncated, durationMS: int(duration.Milliseconds()), errMsg: errMsg,
	}
	select {
	case s.auditCh <- ev:
	default:
		ctr, _ := s.dropped.LoadOrStore(runID, new(int64))
		atomic.AddInt64(ctr.(*int64), 1)
	}
}

func (s *Store) auditWriter() {
	defer s.wg.Done()
	for ev := range s.auditCh {
		args := ev.args
		if len(args) == 0 {
			args = []byte("{}")
		}
		_, _ = s.db.ExecContext(context.Background(),
			`INSERT INTO intel_tool_calls (run_id, seq, tool_name, input_args, output_result, output_truncated, duration_ms, error)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			ev.runID, ev.seq, ev.tool, args, nullableJSON(ev.result), ev.truncated, ev.durationMS, ev.errMsg)
	}
}

// Close stops the writer goroutine after draining queued audits.
func (s *Store) Close() {
	s.once.Do(func() {
		close(s.auditCh)
		s.wg.Wait()
	})
}

func marshalJSONObject(v any) []byte {
	if v == nil {
		return []byte("{}")
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return []byte("{}")
	}
	return raw
}

func marshalJSONOrEmptyArray(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 || string(raw) == "null" {
		return []byte("[]")
	}
	return raw
}

func marshalJSONOrNull(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil || string(raw) == "null" {
		return nil
	}
	return raw
}

func nullableJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func pqTextArray(items []string) any {
	// Build a Postgres text[] literal. lib/pq accepts a string literal of the
	// form {a,b}; values are quoted to survive commas/spaces.
	if len(items) == 0 {
		return "{}"
	}
	out := make([]byte, 0, 16)
	out = append(out, '{')
	for i, it := range items {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '"')
		for _, c := range []byte(it) {
			if c == '"' || c == '\\' {
				out = append(out, '\\')
			}
			out = append(out, c)
		}
		out = append(out, '"')
	}
	out = append(out, '}')
	return string(out)
}

// compile-time assertion that db.DB exposes the database/sql querier methods.
var _ interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
} = (*db.DB)(nil)
