package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var stderr bytes.Buffer
	if err := run([]string{"-version"}, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(stderr.String()); got != version {
		t.Errorf("version output = %q, want %q", got, version)
	}
}

func TestInvalidFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"bad log level", []string{"-log-level", "loud"}},
		{"bad log format", []string{"-log-format", "xml"}},
		{"unknown flag", []string{"-nope"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := run(tt.args, &bytes.Buffer{}); err == nil {
				t.Error("expected error")
			}
		})
	}
}
