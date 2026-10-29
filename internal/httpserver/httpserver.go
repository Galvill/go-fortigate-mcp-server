// Package httpserver serves the MCP server over streamable HTTP.
//
// It does not authenticate clients: that belongs to whatever sits in front
// of it (see SPEC §9). It does reject browser requests from origins that
// aren't allowed, which guards against DNS rebinding and cross-site requests.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/config"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	shutdownTimeout   = 10 * time.Second
	// sessionTimeout closes stateful sessions that have been idle this long.
	sessionTimeout = 30 * time.Minute
)

// Options configures the HTTP server.
type Options struct {
	Config config.HTTP
	Server *mcp.Server
	Logger *slog.Logger
	// Devices is reported by /readyz.
	Devices []string
}

// Handler returns the HTTP handler: the MCP endpoint at Config.Path, plus
// /healthz and /readyz.
func Handler(opts Options) http.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return opts.Server }, &mcp.StreamableHTTPOptions{
		Stateless:      opts.Config.Stateless,
		Logger:         logger,
		SessionTimeout: sessionTimeout,
	})

	mux := http.NewServeMux()
	mux.Handle(opts.Config.Path, guard(opts.Config, logger, mcpHandler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"status": "ready", "devices": opts.Devices})
	})
	return mux
}

// guard applies the Origin check and body limit, and passes the client
// address to tool handlers for the audit log.
func guard(cfg config.HTTP, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && !slices.Contains(cfg.AllowedOrigins, strings.ToLower(origin)) {
			logger.Warn("rejected request from disallowed origin", "origin", origin, "remote_addr", r.RemoteAddr)
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if r.ContentLength > cfg.MaxBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)
		r.Header.Set(audit.RemoteAddrHeader, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Serve listens on Config.Addr and serves until ctx is canceled, then shuts
// down gracefully.
func Serve(ctx context.Context, opts Options) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.Config.Addr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	return ServeListener(ctx, ln, opts)
}

// ServeListener is Serve on an existing listener, which it closes.
func ServeListener(ctx context.Context, ln net.Listener, opts Options) error {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if !isLoopback(ln.Addr()) {
		logger.Warn("listening on a non-loopback address: this server does not authenticate MCP clients, "+
			"so anyone who can reach it can use every configured FortiGate; put an authenticating proxy in front or restrict network access",
			"addr", ln.Addr().String())
	}

	srv := &http.Server{
		Handler:           Handler(opts),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	tls := opts.Config.TLSCert != ""
	errc := make(chan error, 1)
	go func() {
		if tls {
			errc <- srv.ServeTLS(ln, opts.Config.TLSCert, opts.Config.TLSKey)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	scheme := "http"
	if tls {
		scheme = "https"
	}
	logger.Info("serving MCP over HTTP", "url", scheme+"://"+ln.Addr().String()+opts.Config.Path, "stateless", opts.Config.Stateless)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down HTTP server")
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		// Long-lived streams may outlast the timeout; drop them.
		_ = srv.Close()
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}
