package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "v0.1.0"

// Config holds the CLI connection settings stored in ~/.maekom/config.json.
type Config struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type authMeResponse struct {
	IsAdmin      bool `json:"is_admin"`
	ServiceToken *struct {
		ID        string  `json:"id"`
		ProjectID string  `json:"project_id"`
		EnvID     *string `json:"env_id"`
		Name      string  `json:"name"`
		Scope     string  `json:"scope"`
	} `json:"service_token"`
}

type envItem struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
}

type secretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 1
	}

	switch args[0] {
	case "login":
		if err := cmdLogin(args[1:], stdout); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	case "run":
		code, err := cmdRun(args[1:], stdin, stdout, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
		}
		return code
	case "pull":
		if err := cmdPull(args[1:], stdout); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	case "push":
		if err := cmdPush(args[1:], stdout); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "mkv (maekom-env CLI) %s\n", version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mkv - maekom-env lightweight secret manager CLI")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mkv login --url <server-url> --token <service-token>")
	fmt.Fprintln(w, "  mkv run [-e <env>] -- <command...>")
	fmt.Fprintln(w, "  mkv pull [-e <env>] [-o .env]")
	fmt.Fprintln(w, "  mkv push [-e <env>] [.env]")
	fmt.Fprintln(w, "  mkv version")
}

func cmdLogin(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	serverURL := fs.String("url", "", "maekom-env server URL (e.g. http://localhost:8080)")
	token := fs.String("token", "", "service token (mkv_...)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	u := strings.TrimRight(strings.TrimSpace(*serverURL), "/")
	t := strings.TrimSpace(*token)
	if u == "" || t == "" {
		return errors.New("both --url and --token are required")
	}

	cfgPath, err := configFilePath()
	if err != nil {
		return err
	}
	if err := saveConfig(cfgPath, Config{URL: u, Token: t}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "saved credentials to %s\n", cfgPath)
	return nil
}

func cmdRun(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	envArg := fs.String("e", "", "environment name or ID")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return 1, errors.New("usage: mkv run [-e <env>] -- <command...>")
	}

	cfg, err := loadDefaultConfig()
	if err != nil {
		return 1, err
	}

	client := newAPIClient(cfg)
	projectID, envID, err := client.resolveTarget(*envArg)
	if err != nil {
		return 1, err
	}

	secrets, err := client.fetchSecrets(projectID, envID)
	if err != nil {
		return 1, err
	}

	// Merge secrets into current process environment in memory; never write .env to disk.
	mergedEnv := mergeEnv(os.Environ(), secrets)

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = mergedEnv

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start command: %w", err)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	doneCh := make(chan struct{})

	go func() {
		for {
			select {
			case sig := <-sigCh:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-doneCh:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	signal.Stop(sigCh)
	close(doneCh)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, waitErr
	}
	return 0, nil
}

func cmdPull(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	envArg := fs.String("e", "", "environment name or ID")
	outPath := fs.String("o", ".env", "output file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadDefaultConfig()
	if err != nil {
		return err
	}

	client := newAPIClient(cfg)
	projectID, envID, err := client.resolveTarget(*envArg)
	if err != nil {
		return err
	}

	body, err := client.exportDotEnv(projectID, envID)
	if err != nil {
		return err
	}

	if err := os.WriteFile(*outPath, body, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *outPath, err)
	}

	fmt.Fprintf(stdout, "pulled secrets to %s\n", *outPath)
	return nil
}

func cmdPush(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	envArg := fs.String("e", "", "environment name or ID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	inPath := ".env"
	if fs.NArg() > 0 {
		inPath = fs.Arg(0)
	}

	content, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", inPath, err)
	}

	cfg, err := loadDefaultConfig()
	if err != nil {
		return err
	}

	client := newAPIClient(cfg)
	projectID, envID, err := client.resolveTarget(*envArg)
	if err != nil {
		return err
	}

	imported, err := client.importDotEnv(projectID, envID, content)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "pushed %d secret(s) from %s\n", imported, inPath)
	return nil
}

func configFilePath() (string, error) {
	if override := os.Getenv("MAEKOM_CONFIG"); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".maekom", "config.json"), nil
}

func saveConfig(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func loadDefaultConfig() (Config, error) {
	path, err := configFilePath()
	if err != nil {
		return Config{}, err
	}
	return loadConfig(path)
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("not logged in (%s not found); run 'mkv login --url ... --token ...'", path)
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.URL == "" || cfg.Token == "" {
		return Config{}, errors.New("invalid config: missing url or token")
	}
	return cfg, nil
}

func mergeEnv(base []string, secrets []secretItem) []string {
	envMap := make(map[string]string, len(base)+len(secrets))
	order := make([]string, 0, len(base)+len(secrets))

	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, exists := envMap[k]; !exists {
			order = append(order, k)
		}
		envMap[k] = v
	}

	for _, sec := range secrets {
		if _, exists := envMap[sec.Key]; !exists {
			order = append(order, sec.Key)
		}
		envMap[sec.Key] = sec.Value
	}

	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+envMap[k])
	}
	return out
}

type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(cfg Config) *apiClient {
	return &apiClient{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		token:   cfg.Token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *apiClient) do(method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errPayload struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &errPayload) == nil && errPayload.Error != "" {
			return nil, resp.StatusCode, fmt.Errorf("server returned %d: %s", resp.StatusCode, errPayload.Error)
		}
		return nil, resp.StatusCode, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return respBytes, resp.StatusCode, nil
}

func (c *apiClient) resolveTarget(envArg string) (projectID, envID string, err error) {
	meBytes, _, err := c.do(http.MethodGet, "/api/auth/me", nil, "")
	if err != nil {
		return "", "", fmt.Errorf("authenticate: %w", err)
	}
	var me authMeResponse
	if err := json.Unmarshal(meBytes, &me); err != nil {
		return "", "", fmt.Errorf("decode /api/auth/me: %w", err)
	}
	if me.ServiceToken == nil {
		return "", "", errors.New("service token authentication required (use mkv_... token)")
	}
	projectID = me.ServiceToken.ProjectID

	if envArg == "" {
		if me.ServiceToken.EnvID != nil && *me.ServiceToken.EnvID != "" {
			return projectID, *me.ServiceToken.EnvID, nil
		}
	}

	envsBytes, _, err := c.do(http.MethodGet, "/api/projects/"+projectID+"/environments", nil, "")
	if err != nil {
		return "", "", fmt.Errorf("list environments: %w", err)
	}
	var envResp struct {
		Environments []envItem `json:"environments"`
	}
	if err := json.Unmarshal(envsBytes, &envResp); err != nil {
		return "", "", fmt.Errorf("decode environments: %w", err)
	}

	if envArg == "" {
		if len(envResp.Environments) == 1 {
			return projectID, envResp.Environments[0].ID, nil
		}
		return "", "", errors.New("environment is required; pass -e <env>")
	}

	for _, env := range envResp.Environments {
		if env.ID == envArg || strings.EqualFold(env.Name, envArg) {
			return projectID, env.ID, nil
		}
	}
	return "", "", fmt.Errorf("environment %q not found in project", envArg)
}

func (c *apiClient) fetchSecrets(projectID, envID string) ([]secretItem, error) {
	b, _, err := c.do(http.MethodGet, "/api/projects/"+projectID+"/environments/"+envID+"/secrets", nil, "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Secrets []secretItem `json:"secrets"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, fmt.Errorf("decode secrets: %w", err)
	}
	return resp.Secrets, nil
}

func (c *apiClient) exportDotEnv(projectID, envID string) ([]byte, error) {
	b, _, err := c.do(http.MethodGet, "/api/projects/"+projectID+"/environments/"+envID+"/secrets/export", nil, "")
	return b, err
}

func (c *apiClient) importDotEnv(projectID, envID string, content []byte) (int, error) {
	b, _, err := c.do(
		http.MethodPost,
		"/api/projects/"+projectID+"/environments/"+envID+"/secrets/import",
		bytes.NewReader(content),
		"text/plain",
	)
	if err != nil {
		return 0, err
	}
	var resp struct {
		Imported int `json:"imported"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return 0, fmt.Errorf("decode import response: %w", err)
	}
	return resp.Imported, nil
}
