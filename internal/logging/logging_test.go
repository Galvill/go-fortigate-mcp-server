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
