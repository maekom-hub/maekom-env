package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
)

const (
	EventSecretUpdated    = "secret.updated"
	EventSecretExpiring7d = "secret.expiring_7d"
	EventSecretExpiring1d = "secret.expiring_1d"
	EventWebhookTest      = "webhook.test"
)

// Event represents a secret lifecycle notification payload.
// By security design, plaintext secret values are never included.
type Event struct {
	Project     string    `json:"project"`
	Environment string    `json:"environment"`
	Key         string    `json:"key"`
	Event       string    `json:"event"`
	Timestamp   time.Time `json:"timestamp"`
}

// Notifier dispatches notifications for configured webhooks.
type Notifier interface {
	Send(ctx context.Context, webhook db.Webhook, event Event) error
}

// SMTPConfig holds SMTP settings loaded from environment variables.
type SMTPConfig struct {
	Host string
	Port string
	User string
	Pass string
	From string
}

// LoadSMTPConfigFromEnv reads SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and SMTP_FROM.
func LoadSMTPConfigFromEnv() SMTPConfig {
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	return SMTPConfig{
		Host: os.Getenv("SMTP_HOST"),
		Port: port,
		User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"),
		From: os.Getenv("SMTP_FROM"),
	}
}

// Dispatcher handles asynchronous webhook delivery and hourly secret expiration checks.
type Dispatcher struct {
	db         *db.DB
	httpClient *http.Client
	smtp       SMTPConfig
	sendMail   func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewDispatcher creates a Dispatcher backed by the database and environment SMTP configuration.
func NewDispatcher(database *db.DB) *Dispatcher {
	return &Dispatcher{
		db: database,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		smtp:     LoadSMTPConfigFromEnv(),
		sendMail: smtp.SendMail,
	}
}

// NotifySecretUpdatedAsync dispatches a secret.updated event asynchronously in a goroutine
// to all enabled webhooks matching the project and environment.
func (d *Dispatcher) NotifySecretUpdatedAsync(projectID, projectName, envID, envName, key string) {
	if d == nil || d.db == nil {
		return
	}

	ev := Event{
		Project:     projectName,
		Environment: envName,
		Key:         key,
		Event:       EventSecretUpdated,
		Timestamp:   time.Now().UTC(),
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		d.dispatchToEnv(ctx, projectID, envID, ev)
	}()
}

// StartExpiryScheduler runs a background ticker every hour to notify on secrets
// expiring within D-7 and D-1 without duplicate notifications.
func (d *Dispatcher) StartExpiryScheduler(ctx context.Context) {
	if d == nil || d.db == nil {
		return
	}

	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := d.CheckExpiringSecrets(ctx, now.UTC()); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("notifier: expiry check failed: %v", err)
				}
			}
		}
	}()
}

// CheckExpiringSecrets inspects secrets expiring within 7 days and dispatches D-7 or D-1 alerts once each.
func (d *Dispatcher) CheckExpiringSecrets(ctx context.Context, now time.Time) error {
	items, err := d.db.ListExpiringSecrets(ctx, now)
	if err != nil {
		return err
	}

	for _, item := range items {
		remaining := item.ExpiresAt.Sub(now)
		switch {
		case remaining <= 24*time.Hour && !item.Notified1d:
			ev := Event{
				Project:     item.ProjectName,
				Environment: item.EnvironmentName,
				Key:         item.Key,
				Event:       EventSecretExpiring1d,
				Timestamp:   now.UTC(),
			}
			d.dispatchToEnv(ctx, item.ProjectID, item.EnvID, ev)
			if err := d.db.MarkSecretNotified(ctx, item.SecretID, true, true); err != nil {
				return err
			}

		case remaining > 24*time.Hour && remaining <= 7*24*time.Hour && !item.Notified7d:
			ev := Event{
				Project:     item.ProjectName,
				Environment: item.EnvironmentName,
				Key:         item.Key,
				Event:       EventSecretExpiring7d,
				Timestamp:   now.UTC(),
			}
			d.dispatchToEnv(ctx, item.ProjectID, item.EnvID, ev)
			if err := d.db.MarkSecretNotified(ctx, item.SecretID, true, item.Notified1d); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Dispatcher) dispatchToEnv(ctx context.Context, projectID, envID string, ev Event) {
	webhooks, err := d.db.ListActiveWebhooksForEnv(ctx, projectID, envID)
	if err != nil {
		log.Printf("notifier: list active webhooks failed: %v", err)
		return
	}

	for _, wh := range webhooks {
		if !matchesEvent(wh.Events, ev.Event) {
			continue
		}
		if err := d.Send(ctx, wh, ev); err != nil {
			log.Printf("notifier: webhook %s (%s) delivery failed: %v", wh.ID, wh.Type, err)
		}
	}
}

// Send formats and delivers an Event to a single webhook target.
func (d *Dispatcher) Send(ctx context.Context, webhook db.Webhook, event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	switch webhook.Type {
	case db.WebhookDiscord:
		return d.sendDiscord(ctx, webhook, event)
	case db.WebhookSlack:
		return d.sendSlack(ctx, webhook, event)
	case db.WebhookEmail:
		return d.sendEmail(webhook, event)
	case db.WebhookCustom:
		return d.sendCustom(ctx, webhook, event)
	default:
		return fmt.Errorf("notifier: unsupported webhook type %q", webhook.Type)
	}
}

func (d *Dispatcher) sendDiscord(ctx context.Context, webhook db.Webhook, ev Event) error {
	color := 0x3B82F6 // blue
	if ev.Event == EventSecretExpiring7d {
		color = 0xF59E0B // amber
	} else if ev.Event == EventSecretExpiring1d {
		color = 0xEF4444 // red
	}

	payload := map[string]any{
		"username": "maekom-env",
		"embeds": []map[string]any{
			{
				"title":     fmt.Sprintf("[%s] %s", ev.Event, ev.Key),
				"color":     color,
				"timestamp": ev.Timestamp.UTC().Format(time.RFC3339),
				"fields": []map[string]any{
					{"name": "Project", "value": ev.Project, "inline": true},
					{"name": "Environment", "value": ev.Environment, "inline": true},
					{"name": "Key", "value": ev.Key, "inline": true},
					{"name": "Event", "value": ev.Event, "inline": true},
				},
			},
		},
	}

	return d.postJSON(ctx, webhook.TargetURL, payload, "")
}

func (d *Dispatcher) sendSlack(ctx context.Context, webhook db.Webhook, ev Event) error {
	payload := map[string]any{
		"text": fmt.Sprintf("[%s] %s (%s/%s)", ev.Event, ev.Key, ev.Project, ev.Environment),
		"blocks": []map[string]any{
			{
				"type": "header",
				"text": map[string]any{
					"type": "plain_text",
					"text": fmt.Sprintf("maekom-env: %s", ev.Event),
				},
			},
			{
				"type": "section",
				"fields": []map[string]any{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Project:*\n%s", ev.Project)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Environment:*\n%s", ev.Environment)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Key:*\n`%s`", ev.Key)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Timestamp:*\n%s", ev.Timestamp.UTC().Format(time.RFC3339))},
				},
			},
		},
	}

	return d.postJSON(ctx, webhook.TargetURL, payload, "")
}

func (d *Dispatcher) sendCustom(ctx context.Context, webhook db.Webhook, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("notifier: marshal custom payload: %w", err)
	}

	sig := "sha256=" + crypto.SignWebhook(webhook.SecretKey, body)
	return d.postRawJSON(ctx, webhook.TargetURL, body, sig)
}

func (d *Dispatcher) sendEmail(webhook db.Webhook, ev Event) error {
	if d.smtp.Host == "" || d.smtp.From == "" {
		return errors.New("notifier: SMTP_HOST and SMTP_FROM must be configured for email webhooks")
	}

	recipient := strings.TrimPrefix(strings.TrimSpace(webhook.TargetURL), "mailto:")
	if recipient == "" {
		return errors.New("notifier: email webhook target_url is empty")
	}

	recipients := strings.Split(recipient, ",")
	for i := range recipients {
		recipients[i] = strings.TrimSpace(recipients[i])
	}

	subject := fmt.Sprintf("[maekom-env] %s: %s (%s/%s)", ev.Event, ev.Key, ev.Project, ev.Environment)
	body := fmt.Sprintf(
		"Project: %s\r\nEnvironment: %s\r\nKey: %s\r\nEvent: %s\r\nTimestamp: %s\r\n",
		ev.Project,
		ev.Environment,
		ev.Key,
		ev.Event,
		ev.Timestamp.UTC().Format(time.RFC3339),
	)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		d.smtp.From,
		strings.Join(recipients, ", "),
		subject,
		body,
	))

	var auth smtp.Auth
	if d.smtp.User != "" {
		auth = smtp.PlainAuth("", d.smtp.User, d.smtp.Pass, d.smtp.Host)
	}

	addr := net.JoinHostPort(d.smtp.Host, d.smtp.Port)
	return d.sendMail(addr, auth, d.smtp.From, recipients, msg)
}

func (d *Dispatcher) postJSON(ctx context.Context, targetURL string, payload any, signature string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notifier: marshal payload: %w", err)
	}
	return d.postRawJSON(ctx, targetURL, body, signature)
}

func (d *Dispatcher) postRawJSON(ctx context.Context, targetURL string, body []byte, signature string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notifier: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "maekom-env/1.0")
	if signature != "" {
		req.Header.Set("X-Maekom-Signature", signature)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("notifier: post webhook: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notifier: webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func matchesEvent(configured, eventName string) bool {
	trimmed := strings.TrimSpace(configured)
	if trimmed == "" || trimmed == "*" {
		return true
	}
	for _, part := range strings.Split(trimmed, ",") {
		if strings.TrimSpace(part) == eventName {
			return true
		}
	}
	return false
}
