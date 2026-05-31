package secdb

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
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
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	syncCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	cmd := exec.CommandContext(syncCtx, "sh", "-c", m.command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		m.mu.Lock()
		m.lastStatus = "failed"
		m.lastError = err.Error()
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.lastStatus = "ok"
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
		"configured": m.command != "",
		"running":    m.running,
		"last_sync":  m.lastSync,
		"status":     m.lastStatus,
		"last_error": m.lastError,
		"interval":   m.interval.String(),
	}
}
