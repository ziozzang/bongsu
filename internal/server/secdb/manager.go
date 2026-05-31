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
	command    string
	interval   time.Duration
	mu         sync.RWMutex
	running    bool
	lastSync   time.Time
	lastStatus string
	lastError  string
	lastOutput string
	updateHook func(string)
}

func NewManager(command string, interval time.Duration) *Manager {
	return &Manager{command: command, interval: interval, lastStatus: "never"}
}

func (m *Manager) Start(ctx context.Context) {
	if m.command == "" || m.interval <= 0 {
		return
	}
	log.Printf("security-db periodic sync enabled (interval: %s)", m.interval)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.UpdateNowWithReason(ctx, "security-db periodic sync"); err != nil {
				log.Printf("security-db sync failed: %v", err)
			}
		}
	}
}

func (m *Manager) SetUpdateHook(hook func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateHook = hook
}

func (m *Manager) UpdateNow(ctx context.Context) error {
	return m.UpdateNowWithReason(ctx, "security-db sync")
}

func (m *Manager) UpdateNowWithReason(ctx context.Context, reason string) error {
	if m.command == "" {
		return fmt.Errorf("security-db sync command is not configured")
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("security-db sync already running")
	}
	m.running = true
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
		m.mu.Lock()
		m.lastStatus = "failed"
		m.lastError = commandErrorMessage(err, output)
		m.lastOutput = output
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.lastStatus = "ok"
	m.lastOutput = output
	m.lastSync = time.Now()
	hook := m.updateHook
	m.mu.Unlock()
	if hook != nil {
		hook(reason)
	}
	return nil
}

func (m *Manager) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"configured":  m.command != "",
		"running":     m.running,
		"last_sync":   m.lastSync,
		"status":      m.lastStatus,
		"last_error":  m.lastError,
		"last_output": m.lastOutput,
		"interval":    m.interval.String(),
	}
}

func (m *Manager) PublicStatus() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"configured": m.command != "",
		"running":    m.running,
		"last_sync":  m.lastSync,
		"status":     m.lastStatus,
		"interval":   m.interval.String(),
	}
}

func commandErrorMessage(err error, output string) string {
	if output == "" {
		return err.Error()
	}
	return err.Error() + ": " + output
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
