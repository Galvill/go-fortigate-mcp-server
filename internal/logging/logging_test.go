package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := New(&buf, slog.LevelInfo, format)
			if err != nil {
				t.Fatal(err)
			}
			logger.Info("msg",
				"api_token", "tok-123",
				slog.Group("req", "Authorization", "Bearer tok-456", "path", "firewall/policy"),
				"psksecret", "psk-789",
				"device", "hq",
			)
			out := buf.String()
			for _, secret := range []string{"tok-123", "tok-456", "psk-789"} {
				if strings.Contains(out, secret) {
					t.Errorf("output leaks %q: %s", secret, out)
				}
			}
			for _, keep := range []string{"firewall/policy", "hq", Redacted} {
				if !strings.Contains(out, keep) {
					t.Errorf("output missing %q: %s", keep, out)
				}
			}
		})
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, slog.LevelInfo, "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("expected error for unknown level")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	for _, k := range []string{"psksecret", "password", "passwd", "private-key", "md5-key", "pre-shared-key", "key", "api_key", "X-FortiGate-Token", "passphrase", "sae-password"} {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range []string{"name", "mkey", "keylife", "srcaddr", "q_origin_key", "policyid", "comments"} {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestAtLeast(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, slog.LevelDebug, "text")
	if err != nil {
		t.Fatal(err)
	}
	quiet := AtLeast(l, slog.LevelWarn).With("lib", "sdk")
	quiet.Info("hidden")
	quiet.Warn("shown", "token", "s3cret")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") || !strings.Contains(out, "lib=sdk") || strings.Contains(out, "s3cret") {
		t.Errorf("output = %q", out)
	}
}
