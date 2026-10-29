// Package audit writes a JSON-lines record of every request that changes a
// FortiGate.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/logging"
)

// Info describes the tool call a request belongs to. Tools attach it to the
// request context; fields set after attaching (ConfirmedHostname) are seen
// by later records.
type Info struct {
	Tool              string
	SessionID         string
	RemoteAddr        string
	Identity          string
	ConfirmedHostname string
}

// RemoteAddrHeader carries the client's address from the HTTP transport to
// tool handlers. The HTTP server always overwrites it, so clients can't set it.
const RemoteAddrHeader = "X-Fortigate-Mcp-Remote-Addr"

type ctxKey struct{}

// WithInfo returns a context carrying info.
func WithInfo(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

// FromContext returns the Info attached to ctx, if any.
func FromContext(ctx context.Context) *Info {
	info, _ := ctx.Value(ctxKey{}).(*Info)
	return info
}

// Record is one audit log line.
type Record struct {
	Time              time.Time       `json:"ts"`
	Tool              string          `json:"tool,omitempty"`
	SessionID         string          `json:"session_id,omitempty"`
	RemoteAddr        string          `json:"remote_addr,omitempty"`
	Identity          string          `json:"identity,omitempty"`
	Device            string          `json:"device"`
	VDOM              string          `json:"vdom,omitempty"`
	Method            string          `json:"method"`
	Path              string          `json:"path"`
	Mkey              string          `json:"mkey,omitempty"`
	BodySHA256        string          `json:"request_body_sha256,omitempty"`
	Body              json.RawMessage `json:"request_body,omitempty"`
	Result            string          `json:"result"`
	Error             string          `json:"error,omitempty"`
	HTTPStatus        int             `json:"http_status,omitempty"`
	Revision          string          `json:"revision,omitempty"`
	DurationMS        int64           `json:"duration_ms"`
	ConfirmedHostname string          `json:"confirmed_hostname,omitempty"`
}

// Logger writes audit records. It is safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	bodies bool
	logger *slog.Logger
	now    func() time.Time
}

// New returns a Logger writing to w. With bodies, request bodies are
// included with secrets redacted; otherwise only their SHA-256 is.
// Write failures are reported to logger.
func New(w io.Writer, bodies bool, logger *slog.Logger) *Logger {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Logger{w: w, bodies: bodies, logger: logger, now: time.Now}
}

// Observe records a FortiOS write. It matches fortios.Options.Observer.
func (l *Logger) Observe(ctx context.Context, c fortios.Call) {
	rec := Record{
		Time:       l.now().UTC(),
		Device:     c.Device,
		VDOM:       c.VDOM,
		Method:     c.Method,
		Path:       c.Path,
		Mkey:       c.Mkey,
		Result:     "ok",
		HTTPStatus: c.HTTPStatus,
		Revision:   c.Revision,
		DurationMS: c.Duration.Milliseconds(),
	}
	if c.Err != nil {
		rec.Result, rec.Error = "error", c.Err.Error()
	}
	if info := FromContext(ctx); info != nil {
		rec.Tool, rec.SessionID, rec.RemoteAddr, rec.Identity = info.Tool, info.SessionID, info.RemoteAddr, info.Identity
		rec.ConfirmedHostname = info.ConfirmedHostname
	}
	if len(c.Body) > 0 {
		sum := sha256.Sum256(c.Body)
		rec.BodySHA256 = hex.EncodeToString(sum[:])
		if l.bodies {
			rec.Body = redactBody(c.Body)
		}
	}

	line, err := json.Marshal(rec)
	if err != nil {
		l.logger.Error("audit: encoding record", "err", err)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		l.logger.Error("audit: writing record", "err", err, "device", c.Device, "path", c.Path)
	}
}

func redactBody(body []byte) json.RawMessage {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return json.RawMessage(`"<unparseable body>"`)
	}
	out, err := json.Marshal(logging.Redact(v))
	if err != nil {
		return nil
	}
	return out
}
