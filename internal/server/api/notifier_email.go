package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/server/db"
)

type smtpConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// "starttls" (default, port 587), "tls" (implicit, port 465), "none" (plain, lab use)
	Encryption string
}

func smtpConfigFromEnv() (*smtpConfig, error) {
	host := strings.TrimSpace(os.Getenv("BONGSU_SMTP_HOST"))
	if host == "" {
		return nil, fmt.Errorf("BONGSU_SMTP_HOST is not configured")
	}
	from := strings.TrimSpace(os.Getenv("BONGSU_SMTP_FROM"))
	if from == "" {
		return nil, fmt.Errorf("BONGSU_SMTP_FROM is not configured")
	}
	enc := strings.ToLower(strings.TrimSpace(os.Getenv("BONGSU_SMTP_ENCRYPTION")))
	switch enc {
	case "":
		enc = "starttls"
	case "starttls", "tls", "none":
	default:
		return nil, fmt.Errorf("BONGSU_SMTP_ENCRYPTION must be starttls, tls, or none")
	}
	defPort := 587
	if enc == "tls" {
		defPort = 465
	}
	return &smtpConfig{
		Host:       host,
		Port:       envInt("BONGSU_SMTP_PORT", defPort),
		Username:   strings.TrimSpace(os.Getenv("BONGSU_SMTP_USERNAME")),
		Password:   os.Getenv("BONGSU_SMTP_PASSWORD"),
		From:       from,
		Encryption: enc,
	}, nil
}

func emailRecipients(cfg map[string]string) []string {
	var out []string
	for _, part := range strings.Split(cfg["to"], ",") {
		addr := strings.TrimSpace(part)
		if addr != "" && strings.Contains(addr, "@") {
			out = append(out, addr)
		}
	}
	return out
}

// sendEmail delivers the notification payload over SMTP using the rule's
// channel_config ({"to": "a@x,b@y", "subject_prefix"?: "..."}) and the
// server-wide BONGSU_SMTP_* environment configuration.
func (n *ruleNotifier) sendEmail(ctx context.Context, rule *db.NotificationRule, event string, payload map[string]any) (string, string, int) {
	smtpCfg, err := smtpConfigFromEnv()
	if err != nil {
		log.Printf("notification rule %s email: %v", rule.ID, err)
		return "failed", err.Error(), 1
	}
	cfg := map[string]string{}
	if len(rule.ChannelConfig) > 0 {
		_ = json.Unmarshal(rule.ChannelConfig, &cfg)
	}
	recipients := emailRecipients(cfg)
	if len(recipients) == 0 {
		return "failed", "no valid recipients in channel_config.to", 1
	}

	subjectPrefix := strings.TrimSpace(cfg["subject_prefix"])
	if subjectPrefix == "" {
		subjectPrefix = "[Bongsu]"
	}
	subject := fmt.Sprintf("%s %s — %s", subjectPrefix, event, rule.Name)
	body := formatNotificationEmailBody(rule, event, payload)
	msg := buildEmailMessage(smtpCfg.From, recipients, subject, body)

	attempts := notificationRetryAttemptsFromEnv()
	delay := notificationRetryDelayFromEnv()
	var lastErr string
	for attempt := 1; attempt <= attempts; attempt++ {
		err := deliverSMTP(ctx, smtpCfg, recipients, msg)
		if err == nil {
			return "sent", "", attempt
		}
		lastErr = err.Error()
		log.Printf("notification rule %s email attempt %d/%d: %v", rule.ID, attempt, attempts, err)
		if attempt < attempts {
			sleepWithContext(ctx, delay)
		}
	}
	return "failed", lastErr, attempts
}

func formatNotificationEmailBody(rule *db.NotificationRule, event string, payload map[string]any) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Bongsu notification\n\n")
	fmt.Fprintf(&b, "Event:      %s\n", event)
	fmt.Fprintf(&b, "Rule:       %s\n", rule.Name)
	if ts, ok := payload["timestamp"].(string); ok {
		fmt.Fprintf(&b, "Timestamp:  %s\n", ts)
	}
	if data, ok := payload["data"].(map[string]any); ok {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("\nDetails:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %-24s %v\n", k+":", data[k])
		}
	}
	b.WriteString("\n-- bongsu-notification\n")
	return b.String()
}

func buildEmailMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return []byte(b.String())
}

func deliverSMTP(ctx context.Context, cfg *smtpConfig, recipients []string, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	timeout := time.Duration(envInt("BONGSU_SMTP_TIMEOUT_SECONDS", 30)) * time.Second

	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if cfg.Encryption == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: cfg.Host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer client.Close()

	if cfg.Encryption == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp server does not support AUTH")
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		w.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close: %w", err)
	}
	return client.Quit()
}
