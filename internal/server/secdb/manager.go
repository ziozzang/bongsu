package secdb

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	command       string
	interval      time.Duration
	mu            sync.RWMutex
	running       bool
	lastSync      time.Time
	lastAttempt   time.Time
	nextSync      time.Time
	lastStatus    string
	lastError     string
	lastOutput    string
	updateHook    func(string)
	failureHook   func(string, error)
	syncOnStart   bool
	lastSyncHint  time.Time
	failureStreak int
}

func NewManager(command string, interval time.Duration) *Manager {
	return &Manager{command: command, interval: interval, lastStatus: "never"}
}

func (m *Manager) Start(ctx context.Context) {
	if m.command == "" {
		return
	}
	m.mu.RLock()
	syncOnStart := m.syncOnStart
	m.mu.RUnlock()
	if syncOnStart {
		if err := m.UpdateNowWithReason(ctx, "security-db startup sync"); err != nil {
			log.Printf("security-db startup sync failed: %v", err)
		}
	}
	if m.interval <= 0 {
		return
	}
	log.Printf("security-db periodic sync enabled (interval: %s)", m.interval)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	m.scheduleNextPeriodicSync(time.Now())
	for {
		next := m.nextSyncTime()
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := m.UpdateNowWithReason(ctx, "security-db periodic sync"); err != nil {
				log.Printf("security-db sync failed: %v", err)
				m.scheduleRetrySync(time.Now())
			} else {
				m.scheduleNextPeriodicSync(time.Now())
			}
		}
	}
}

func (m *Manager) scheduleNextPeriodicSync(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	base := now
	if !m.lastSync.IsZero() {
		base = m.lastSync
	} else if !m.lastSyncHint.IsZero() {
		base = m.lastSyncHint
	}
	next := base.Add(m.interval)
	if next.Before(now) {
		next = now
	}
	m.nextSync = next
}

// scheduleRetrySync backs off exponentially after a failed sync instead of
// waiting a full interval with a stale security DB: base*2^(streak-1) capped
// at the retry max and at the regular interval.
func (m *Manager) scheduleRetrySync(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	base := retryBaseDelay()
	maxDelay := retryMaxDelay()
	if m.interval > 0 && maxDelay > m.interval {
		maxDelay = m.interval
	}
	delay := base
	for i := 1; i < m.failureStreak && delay < maxDelay; i++ {
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	m.nextSync = now.Add(delay)
	log.Printf("security-db sync retry in %s (consecutive failures: %d)", delay.Round(time.Second), m.failureStreak)
}

func retryBaseDelay() time.Duration {
	minutes := envMinutes("BONGSU_SECURITY_DB_RETRY_BASE_MINUTES", 5)
	return time.Duration(minutes) * time.Minute
}

func retryMaxDelay() time.Duration {
	minutes := envMinutes("BONGSU_SECURITY_DB_RETRY_MAX_MINUTES", 60)
	return time.Duration(minutes) * time.Minute
}

func envMinutes(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func (m *Manager) nextSyncTime() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nextSync
}

func (m *Manager) SetLastSyncHint(lastSync time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSyncHint = lastSync
}

func (m *Manager) SetUpdateHook(hook func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateHook = hook
}

func (m *Manager) SetFailureHook(hook func(string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureHook = hook
}

func (m *Manager) SetSyncOnStart(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncOnStart = enabled
}

func (m *Manager) UpdateNow(ctx context.Context) error {
	return m.UpdateNowWithReason(ctx, "security-db sync")
}

func (m *Manager) UpdateNowWithReason(ctx context.Context, reason string) error {
	if m.command == "" {
		err := fmt.Errorf("security-db sync command is not configured")
		m.notifyFailure(reason, err)
		return err
	}
	m.mu.Lock()
	if m.running {
		hook := m.failureHook
		m.mu.Unlock()
		err := fmt.Errorf("security-db sync already running")
		if hook != nil {
			hook(reason, err)
		}
		return err
	}
	m.running = true
	m.lastAttempt = time.Now()
	m.lastStatus = "running"
	m.lastError = ""
	m.lastOutput = ""
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	syncCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(syncCtx, "sh", "-c", m.command)
	out, err := cmd.CombinedOutput()
	output := trimCommandOutput(string(out), maxSyncOutputBytes())
	if err != nil {
		syncErr := fmt.Errorf("%w", err)
		if output != "" {
			syncErr = fmt.Errorf("%w: %s", err, output)
		}
		m.mu.Lock()
		m.lastStatus = "failed"
		m.lastError = syncErr.Error()
		m.lastOutput = output
		m.failureStreak++
		hook := m.failureHook
		m.mu.Unlock()
		if hook != nil {
			hook(reason, syncErr)
		}
		return err
	}
	m.mu.Lock()
	m.lastStatus = "ok"
	m.lastOutput = output
	m.lastSync = time.Now()
	m.failureStreak = 0
	hook := m.updateHook
	m.mu.Unlock()
	if hook != nil {
		hook(reason)
	}
	return nil
}

func (m *Manager) notifyFailure(reason string, err error) {
	m.mu.RLock()
	hook := m.failureHook
	m.mu.RUnlock()
	if hook != nil {
		hook(reason, err)
	}
}

func (m *Manager) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"configured":           m.command != "",
		"running":              m.running,
		"last_sync":            m.lastSync,
		"last_attempt":         m.lastAttempt,
		"next_sync":            m.nextSync,
		"status":               m.lastStatus,
		"last_error":           m.lastError,
		"last_output":          m.lastOutput,
		"consecutive_failures": m.failureStreak,
		"interval":             m.interval.String(),
	}
}

func (m *Manager) PublicStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"configured":   m.command != "",
		"running":      m.running,
		"last_sync":    m.lastSync,
		"last_attempt": m.lastAttempt,
		"next_sync":    m.nextSync,
		"status":       m.lastStatus,
		"interval":     m.interval.String(),
	}
}

func maxSyncOutputBytes() int {
	raw := strings.TrimSpace(os.Getenv("BONGSU_SECURITY_DB_SYNC_OUTPUT_MAX_BYTES"))
	if raw == "" {
		return 8192
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 8192
	}
	return n
}

func trimCommandOutput(output string, limit int) string {
	output = strings.TrimSpace(output)
	if limit <= 0 || len(output) <= limit {
		return output
	}
	return output[len(output)-limit:]
}
