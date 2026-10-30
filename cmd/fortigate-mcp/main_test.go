package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestVersionFlag(t *testing.T) {
	var stderr bytes.Buffer
	if err := run([]string{"-version"}, env(nil), &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(stderr.String()); got != version {
		t.Errorf("version output = %q, want %q", got, version)
	}
}

func TestStartupErrors(t *testing.T) {
	device := map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t"}
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr string
	}{
		{"bad log level", []string{"-log-level", "loud"}, device, "invalid log level"},
		{"bad log format", []string{"-log-format", "xml"}, device, "invalid log format"},
		{"unknown flag", []string{"-nope"}, device, "not defined"},
		{"no devices", nil, nil, "no FortiGate devices"},
		{"unknown toolset", []string{"-toolsets", "system,nope"}, device, "unknown toolset"},
		{"bad CA file", nil, map[string]string{"FORTIGATE_HOST": "fw", "FORTIGATE_API_TOKEN": "t", "FORTIGATE_CA_CERT": "/nonexistent.pem"}, "CA certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args, env(tt.env), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestResolveVersion(t *testing.T) {
	build := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: v}}, true
		}
	}
	noInfo := func() (*debug.BuildInfo, bool) { return nil, false }
	for _, tc := range []struct {
		name, ldflags string
		info          func() (*debug.BuildInfo, bool)
		want          string
	}{
		{"release build keeps ldflags version", "0.1.0", build("v0.2.0"), "0.1.0"},
		{"go install uses module version", "dev", build("v0.1.0"), "0.1.0"},
		{"pseudo-version from a commit", "dev", build("v0.1.1-0.20261030081000-5ffbe37aaaaa"), "0.1.1-0.20261030081000-5ffbe37aaaaa"},
		{"local build without VCS info", "dev", build("(devel)"), "dev"},
		{"no build info", "dev", noInfo, "dev"},
	} {
		if got := resolveVersion(tc.ldflags, tc.info); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
