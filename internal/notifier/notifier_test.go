package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maekom-hub/maekom-env/internal/crypto"
	"github.com/maekom-hub/maekom-env/internal/db"
)

func TestSendCustomDiscordSlackAndEmail(t *testing.T) {
	ctx := context.Background()
	d := NewDispatcher(nil)

	t.Run("custom webhook HMAC signature and strict payload", func(t *testing.T) {
		var (
			gotSig  string
			gotBody []byte
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSig = r.Header.Get("X-Maekom-Signature")
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		wh := db.Webhook{
			Type:      db.WebhookCustom,
			TargetURL: srv.URL,
			SecretKey: "whsec_12345",
			Enabled:   true,
		}
		ev := Event{
			Project:     "billing",
			Environment: "prod",
			Key:         "STRIPE_KEY",
			Event:       EventSecretUpdated,
			Timestamp:   time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		}

		if err := d.Send(ctx, wh, ev); err != nil {
			t.Fatalf("Send custom failed: %v", err)
		}

		if !crypto.VerifyWebhookSignature("whsec_12345", gotBody, gotSig) {
			t.Fatalf("invalid X-Maekom-Signature: %q", gotSig)
		}

		var decoded map[string]any
		if err := json.Unmarshal(gotBody, &decoded); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if len(decoded) != 5 {
			t.Fatalf("expected exactly 5 fields in webhook payload, got %d: %v", len(decoded), decoded)
		}
		for _, field := range []string{"project", "environment", "key", "event", "timestamp"} {
			if _, ok := decoded[field]; !ok {
				t.Fatalf("missing field %q in payload", field)
			}
		}
	})

	t.Run("discord webhook card", func(t *testing.T) {
		var gotBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		wh := db.Webhook{Type: db.WebhookDiscord, TargetURL: srv.URL, Enabled: true}
		ev := Event{Project: "app", Environment: "staging", Key: "API_TOKEN", Event: EventSecretUpdated}
		if err := d.Send(ctx, wh, ev); err != nil {
			t.Fatalf("Send discord failed: %v", err)
		}
		if !strings.Contains(string(gotBody), `"embeds"`) || !strings.Contains(string(gotBody), "API_TOKEN") {
			t.Fatalf("unexpected discord payload: %s", string(gotBody))
		}
	})

	t.Run("slack webhook blocks", func(t *testing.T) {
		var gotBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		wh := db.Webhook{Type: db.WebhookSlack, TargetURL: srv.URL, Enabled: true}
		ev := Event{Project: "app", Environment: "dev", Key: "DB_PASS", Event: EventSecretUpdated}
		if err := d.Send(ctx, wh, ev); err != nil {
			t.Fatalf("Send slack failed: %v", err)
		}
		if !strings.Contains(string(gotBody), `"blocks"`) || !strings.Contains(string(gotBody), "DB_PASS") {
			t.Fatalf("unexpected slack payload: %s", string(gotBody))
		}
	})

	t.Run("email smtp delivery", func(t *testing.T) {
		var (
			gotAddr string
			gotTo   []string
			gotMsg  string
		)
		dEmail := NewDispatcher(nil)
		dEmail.smtp = SMTPConfig{
			Host: "smtp.example.com",
			Port: "587",
			User: "mailer",
			Pass: "secret",
			From: "noreply@maekom.dev",
		}
		dEmail.sendMail = func(addr string, _ smtp.Auth, _ string, to []string, msg []byte) error {
			gotAddr = addr
			gotTo = to
			gotMsg = string(msg)
			return nil
		}

		wh := db.Webhook{Type: db.WebhookEmail, TargetURL: "mailto:ops@example.com", Enabled: true}
		ev := Event{Project: "core", Environment: "prod", Key: "JWT_SECRET", Event: EventSecretExpiring1d}
		if err := dEmail.Send(ctx, wh, ev); err != nil {
			t.Fatalf("Send email failed: %v", err)
		}
		if gotAddr != "smtp.example.com:587" {
			t.Fatalf("got addr %q, want smtp.example.com:587", gotAddr)
		}
		if len(gotTo) != 1 || gotTo[0] != "ops@example.com" {
			t.Fatalf("unexpected recipients: %v", gotTo)
		}
		if !strings.Contains(gotMsg, "JWT_SECRET") || !strings.Contains(gotMsg, EventSecretExpiring1d) {
			t.Fatalf("unexpected email body: %s", gotMsg)
		}
	})
}

func TestCheckExpiringSecretsDeduplication(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(ctx, filepath.Join(t.TempDir(), "expiry.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = store.Close() }()

	proj, err := store.CreateProject(ctx, "payments", "")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := store.CreateEnvironment(ctx, proj.ID, "prod")
	if err != nil {
		t.Fatalf("create env: %v", err)
	}

	var (
		mu     sync.Mutex
		events []Event
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if _, err := store.CreateWebhook(ctx, proj.ID, &env.ID, db.WebhookCustom, srv.URL, "sec", "*", true); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	cipher, err := crypto.NewCipherFromMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	ct, nonce, err := cipher.EncryptString("super-secret-value")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	baseTime := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	expiresAt := baseTime.Add(5 * 24 * time.Hour) // 5 days from baseTime -> D-7 window
	if _, err := store.UpsertSecret(ctx, env.ID, "API_KEY", ct, nonce, &expiresAt); err != nil {
		t.Fatalf("upsert secret: %v", err)
	}

	dispatcher := NewDispatcher(store)

	// First check at baseTime (5 days left): should trigger D-7 once.
	if err := dispatcher.CheckExpiringSecrets(ctx, baseTime); err != nil {
		t.Fatalf("first check failed: %v", err)
	}
	// Second check 1 hour later: still >24h left, must NOT duplicate D-7.
	if err := dispatcher.CheckExpiringSecrets(ctx, baseTime.Add(1*time.Hour)); err != nil {
		t.Fatalf("second check failed: %v", err)
	}

	// Third check when 12 hours left: should trigger D-1 once.
	dayMinus1 := expiresAt.Add(-12 * time.Hour)
	if err := dispatcher.CheckExpiringSecrets(ctx, dayMinus1); err != nil {
		t.Fatalf("third check failed: %v", err)
	}
	// Fourth check 1 hour later: must NOT duplicate D-1.
	if err := dispatcher.CheckExpiringSecrets(ctx, dayMinus1.Add(1*time.Hour)); err != nil {
		t.Fatalf("fourth check failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("expected 2 total events (D-7 and D-1), got %d: %+v", len(events), events)
	}
	if events[0].Event != EventSecretExpiring7d || events[1].Event != EventSecretExpiring1d {
		t.Fatalf("unexpected event sequence: %+v", events)
	}
}
