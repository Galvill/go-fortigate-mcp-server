package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) LookupEnv {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func load(t *testing.T, args []string, env map[string]string) (*Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return f.Load(envMap(env))
}

func mustLoad(t *testing.T, args []string, env map[string]string) *Config {
	t.Helper()
	cfg, err := load(t, args, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func device(t *testing.T, cfg *Config, name string) Device {
	t.Helper()
	for _, d := range cfg.Devices {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("device %q not found in %v", name, cfg.Devices)
	return Device{}
}

func TestSingleDeviceFromEnv(t *testing.T) {
	cfg := mustLoad(t, nil, map[string]string{
		"FORTIGATE_HOST":      "10.0.0.1:8443",
		"FORTIGATE_API_TOKEN": "tok",
	})
	want := Device{
		Name:    "default",
		Host:    "https://10.0.0.1:8443",
		Token:   "tok",
		VDOM:    "root",
		Timeout: 30 * time.Second,
	}
	if len(cfg.Devices) != 1 || cfg.Devices[0] != want {
		t.Errorf("devices = %#v, want [%#v]", cfg.Devices, want)
	}
}

func TestSingleDeviceOptions(t *testing.T) {
	tokenFile := writeFile(t, "token", "  file-tok\n")
	cfg := mustLoad(t, nil, map[string]string{
		"FORTIGATE_NAME":                 "lab",
		"FORTIGATE_HOST":                 "https://fw.lab/",
		"FORTIGATE_API_TOKEN_FILE":       tokenFile,
		"FORTIGATE_VDOM":                 "cust-a",
		"FORTIGATE_INSECURE_SKIP_VERIFY": "true",
		"FORTIGATE_TIMEOUT":              "5s",
		"FORTIGATE_READ_ONLY":            "1",
	})
	d := device(t, cfg, "lab")
	if d.Host != "https://fw.lab" || d.Token.Reveal() != "file-tok" || d.VDOM != "cust-a" ||
		!d.InsecureSkipVerify || d.Timeout != 5*time.Second || !d.ReadOnly {
		t.Errorf("device = %#v", d)
	}
}

func TestMultiDeviceFromEnv(t *testing.T) {
	cfg := mustLoad(t, nil, map[string]string{
		"FORTIGATE_DEVICES":            "hq, branch-1",
		"FORTIGATE_HQ_HOST":            "fw-hq",
		"FORTIGATE_HQ_API_TOKEN":       "hq-tok",
		"FORTIGATE_BRANCH_1_HOST":      "10.20.0.1",
		"FORTIGATE_BRANCH_1_API_TOKEN": "b1-tok",
		"FORTIGATE_BRANCH_1_VDOM":      "customer-a",
	})
	if len(cfg.Devices) != 2 || cfg.Devices[0].Name != "branch-1" || cfg.Devices[1].Name != "hq" {
		t.Fatalf("devices not sorted by name: %v", cfg.Devices)
	}
	if d := device(t, cfg, "branch-1"); d.VDOM != "customer-a" || d.Token.Reveal() != "b1-tok" {
		t.Errorf("branch-1 = %#v", d)
	}
}

func TestFileWithEnvOverrides(t *testing.T) {
	tokenFile := writeFile(t, "b1", "b1-tok")
	path := writeFile(t, "config.yaml", fmt.Sprintf(`
default_device: hq
devices:
  hq:
    host: https://fw-hq.example.com
    token_env: FGT_HQ_TOKEN
    timeout: 10s
  branch-1:
    host: 10.20.0.1
    token_file: %s
    read_only: true
`, tokenFile))
	cfg := mustLoad(t, []string{"-config", path}, map[string]string{
		"FGT_HQ_TOKEN":      "hq-tok",
		"FORTIGATE_HQ_VDOM": "from-env",
		// Env token replaces the file's token_file.
		"FORTIGATE_BRANCH_1_API_TOKEN": "env-tok",
	})
	if cfg.DefaultDevice != "hq" {
		t.Errorf("default device = %q", cfg.DefaultDevice)
	}
	hq := device(t, cfg, "hq")
	if hq.Token.Reveal() != "hq-tok" || hq.VDOM != "from-env" || hq.Timeout != 10*time.Second {
		t.Errorf("hq = %#v", hq)
	}
	b1 := device(t, cfg, "branch-1")
	if b1.Token.Reveal() != "env-tok" || !b1.ReadOnly {
		t.Errorf("branch-1 = %#v", b1)
	}
}

func TestConfigFileFromEnv(t *testing.T) {
	path := writeFile(t, "c.yaml", "devices:\n  hq:\n    host: fw\n    token_env: T\n")
	cfg := mustLoad(t, nil, map[string]string{"FORTIGATE_MCP_CONFIG": path, "T": "x"})
	if cfg.Server.ConfigFile != path || len(cfg.Devices) != 1 {
		t.Errorf("cfg = %#v", cfg)
	}
}

func TestErrors(t *testing.T) {
	base := map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		file    string
		wantErr string
	}{
		{name: "no devices", env: map[string]string{}, wantErr: "no FortiGate devices"},
		{name: "token without host", env: map[string]string{"FORTIGATE_API_TOKEN": "t"}, wantErr: "FORTIGATE_HOST is not"},
		{name: "no token", env: map[string]string{"FORTIGATE_HOST": "fw"}, wantErr: "no API token"},
		{name: "both token sources", env: with(map[string]string{"FORTIGATE_API_TOKEN_FILE": "/x"}), wantErr: "only one of"},
		{name: "missing token file", env: map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN_FILE": "/nonexistent"}, wantErr: "token file"},
		{name: "http host", env: with(map[string]string{"FORTIGATE_HOST": "http://fw"}), wantErr: "only https"},
		{name: "host with path", env: with(map[string]string{"FORTIGATE_HOST": "https://fw/api"}), wantErr: "want https://host"},
		{name: "bad port", env: with(map[string]string{"FORTIGATE_HOST": "fw:99999"}), wantErr: "bad port"},
		{name: "bad bool", env: with(map[string]string{"FORTIGATE_READ_ONLY": "maybe"}), wantErr: "invalid boolean"},
		{name: "bad timeout", env: with(map[string]string{"FORTIGATE_TIMEOUT": "soon"}), wantErr: "TIMEOUT"},
		{name: "zero timeout", env: with(map[string]string{"FORTIGATE_TIMEOUT": "0s"}), wantErr: "positive"},
		{name: "insecure with ca", env: with(map[string]string{"FORTIGATE_INSECURE_SKIP_VERIFY": "true", "FORTIGATE_CA_CERT": "/ca.pem"}), wantErr: "not both"},
		{name: "bad device name", env: map[string]string{"FORTIGATE_DEVICES": "HQ"}, wantErr: "invalid device name"},
		{name: "reserved name", env: map[string]string{"FORTIGATE_DEVICES": "mcp"}, wantErr: "reserved"},
		{name: "prefix collision", env: map[string]string{"FORTIGATE_DEVICES": "a-b,a_b"}, wantErr: "same environment prefix"},
		{name: "bad log level", args: []string{"-log-level", "loud"}, env: base, wantErr: "invalid log level"},
		{name: "bad log format", env: with(map[string]string{"FORTIGATE_MCP_LOG_FORMAT": "xml"}), wantErr: "invalid log format"},
		{name: "literal token in file", file: "devices:\n  hq:\n    host: fw\n    token: abc\n", wantErr: "literal token"},
		{name: "unknown field in file", file: "devices:\n  hq:\n    hots: fw\n", wantErr: "hots"},
		{name: "token_env unset", file: "devices:\n  hq:\n    host: fw\n    token_env: NOPE\n", wantErr: "NOPE is not set"},
		{name: "unknown default", file: "default_device: nope\ndevices:\n  hq:\n    host: fw\n    token_env: T\n", env: map[string]string{"T": "x"}, wantErr: "default_device"},
		{name: "missing config file", args: []string{"-config", "/nonexistent.yaml"}, wantErr: "reading config file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if tt.file != "" {
				args = append(args, "-config", writeFile(t, "c.yaml", tt.file))
			}
			_, err := load(t, args, tt.env)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestServerSettingPrecedence(t *testing.T) {
	env := map[string]string{
		"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t",
		"FORTIGATE_MCP_LOG_LEVEL": "warn",
	}
	if cfg := mustLoad(t, nil, env); cfg.Server.LogLevel != slog.LevelWarn {
		t.Errorf("env: level = %v, want warn", cfg.Server.LogLevel)
	}
	if cfg := mustLoad(t, []string{"-log-level", "debug"}, env); cfg.Server.LogLevel != slog.LevelDebug {
		t.Errorf("flag: level = %v, want debug", cfg.Server.LogLevel)
	}
	delete(env, "FORTIGATE_MCP_LOG_LEVEL")
	if cfg := mustLoad(t, nil, env); cfg.Server.LogLevel != slog.LevelInfo || cfg.Server.LogFormat != "text" {
		t.Errorf("default: %+v", cfg.Server)
	}
}

func TestToolsetAndLimitSettings(t *testing.T) {
	env := map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t"}
	cfg := mustLoad(t, nil, env)
	if cfg.Server.Toolsets != nil || cfg.Server.ReadOnly || cfg.Server.MaxResultBytes != DefaultMaxResultBytes {
		t.Errorf("defaults: %+v", cfg.Server)
	}

	env["FORTIGATE_MCP_TOOLSETS"] = "system, policy"
	env["FORTIGATE_MCP_READ_ONLY"] = "true"
	cfg = mustLoad(t, []string{"-max-result-bytes", "50000"}, env)
	if strings.Join(cfg.Server.Toolsets, ",") != "system,policy" || !cfg.Server.ReadOnly || cfg.Server.MaxResultBytes != 50000 {
		t.Errorf("env/flags: %+v", cfg.Server)
	}

	// A bare boolean flag works and overrides env.
	env["FORTIGATE_MCP_READ_ONLY"] = "false"
	if cfg = mustLoad(t, []string{"-read-only"}, env); !cfg.Server.ReadOnly {
		t.Error("-read-only flag ignored")
	}

	for _, bad := range []map[string]string{
		{"FORTIGATE_MCP_TOOLSETS": " , "},
		{"FORTIGATE_MCP_READ_ONLY": "maybe"},
		{"FORTIGATE_MCP_MAX_RESULT_BYTES": "10"},
		{"FORTIGATE_MCP_MAX_RESULT_BYTES": "lots"},
	} {
		e := map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t"}
		for k, v := range bad {
			e[k] = v
		}
		if _, err := load(t, nil, e); err == nil {
			t.Errorf("%v: expected error", bad)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"10.0.0.1":                  "https://10.0.0.1",
		"fw.example.com:8443":       "https://fw.example.com:8443",
		"https://fw.example.com/":   "https://fw.example.com",
		"[2001:db8::1]:443":         "https://[2001:db8::1]:443",
		" https://fw.example.com  ": "https://fw.example.com",
	}
	for in, want := range tests {
		got, err := normalizeHost(in)
		if err != nil || got != want {
			t.Errorf("normalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestSecretNeverPrints(t *testing.T) {
	d := Device{Name: "hq", Token: "super-secret"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "token", d.Token, "device", d)
	js, _ := json.Marshal(d)
	for _, out := range []string{
		fmt.Sprintf("%v %+v %#v %s", d, d, d, d.Token),
		string(js),
		buf.String(),
	} {
		if strings.Contains(out, "super-secret") {
			t.Errorf("secret leaked: %s", out)
		}
	}
	if d.Token.Reveal() != "super-secret" {
		t.Error("Reveal lost the value")
	}
}

func TestAuditAndBackupSettings(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t",
		"FORTIGATE_MCP_AUDIT_LOG": "/var/log/fgt-audit.jsonl", "FORTIGATE_MCP_BACKUP_DIR": dir,
	}
	cfg := mustLoad(t, []string{"-audit-bodies"}, env)
	if cfg.Server.AuditLog != "/var/log/fgt-audit.jsonl" || !cfg.Server.AuditBodies || cfg.Server.BackupDir != dir {
		t.Errorf("server = %+v", cfg.Server)
	}

	env["FORTIGATE_MCP_BACKUP_DIR"] = "/nonexistent-dir"
	if _, err := load(t, nil, env); err == nil || !strings.Contains(err.Error(), "backup-dir") {
		t.Errorf("missing backup dir: err = %v", err)
	}
	env["FORTIGATE_MCP_BACKUP_DIR"] = writeFile(t, "file", "x")
	if _, err := load(t, nil, env); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("file as backup dir: err = %v", err)
	}
}
