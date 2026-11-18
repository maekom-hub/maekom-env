package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLILoginRunPullPush(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".maekom", "config.json")
	t.Setenv("MAEKOM_CONFIG", cfgPath)

	var importedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mkv_test_token" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/auth/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"is_admin": false,
				"service_token": map[string]any{
					"id":         "tok_1",
					"project_id": "proj_1",
					"name":       "cli",
					"scope":      "write",
				},
			})
		case "GET /api/projects/proj_1/environments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"environments": []map[string]any{
					{"id": "env_prod", "project_id": "proj_1", "name": "prod"},
				},
			})
		case "GET /api/projects/proj_1/environments/env_prod/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{
					{"key": "API_KEY", "value": "secret_123"},
					{"key": "APP_MODE", "value": "production"},
				},
			})
		case "GET /api/projects/proj_1/environments/env_prod/secrets/export":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("API_KEY=secret_123\nAPP_MODE=production\n"))
		case "POST /api/projects/proj_1/environments/env_prod/secrets/import":
			b, _ := io.ReadAll(r.Body)
			importedBody = string(b)
			_ = json.NewEncoder(w).Encode(map[string]any{"imported": 2})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 1. mkv login
	var out, errOut bytes.Buffer
	code := run([]string{"login", "--url", srv.URL, "--token", "mkv_test_token"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("login failed (%d): %s", code, errOut.String())
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected config mode 0600, got %o", info.Mode().Perm())
	}

	// 2. mkv run (injects env in memory, creates no .env file)
	out.Reset()
	errOut.Reset()
	workDir := filepath.Join(tmpDir, "work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	t.Chdir(workDir)

	code = run([]string{"run", "-e", "prod", "--", "sh", "-c", `printf "%s:%s" "$API_KEY" "$APP_MODE"`}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("run failed (%d): %s", code, errOut.String())
	}
	if out.String() != "secret_123:production" {
		t.Fatalf("unexpected child output: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, ".env")); !os.IsNotExist(err) {
		t.Fatal("mkv run must not create .env file on disk")
	}

	// 3. mkv pull
	out.Reset()
	errOut.Reset()
	pulledPath := filepath.Join(workDir, ".env.pulled")
	code = run([]string{"pull", "-e", "prod", "-o", pulledPath}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("pull failed (%d): %s", code, errOut.String())
	}
	pulledBytes, err := os.ReadFile(pulledPath)
	if err != nil {
		t.Fatalf("read pulled .env: %v", err)
	}
	if !strings.Contains(string(pulledBytes), "API_KEY=secret_123") {
		t.Fatalf("unexpected pulled content: %s", string(pulledBytes))
	}

	// 4. mkv push
	out.Reset()
	errOut.Reset()
	code = run([]string{"push", "-e", "prod", pulledPath}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("push failed (%d): %s", code, errOut.String())
	}
	if !strings.Contains(importedBody, "API_KEY=secret_123") {
		t.Fatalf("expected pushed body to contain API_KEY, got %q", importedBody)
	}
}
