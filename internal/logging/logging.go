// Package logging builds the server's slog logger, with redaction of
// secret-looking attributes.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Redacted replaces the value of any attribute whose key looks sensitive.
const Redacted = "[REDACTED]"

// sensitiveKeys are matched case-insensitively as substrings of attribute
// keys, so "api_token", "X-FortiGate-Token" and "psksecret" are all caught.
var sensitiveKeys = []string{
	"token",
	"password",
	"passwd",
	"secret",
	"private-key",
	"private_key",
	"privatekey",
	"authorization",
}

// IsSensitiveKey reports whether a key (attribute, header or FortiOS field
// name) should never have its value logged or returned.
func IsSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// ParseLevel parses a level name: debug, info, warn or error.
func ParseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("invalid log level %q (want debug, info, warn or error)", s)
	}
	return lvl, nil
}

// New returns a logger writing to w in the given format ("text" or "json").
func New(w io.Writer, level slog.Level, format string) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: redact}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q (want text or json)", format)
	}
}

func redact(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindGroup && IsSensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	return a
}
