// Command fortigate-mcp is an MCP server for managing FortiGate firewalls.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/httpserver"
	"github.com/galvill/go-fortigate-mcp-server/internal/logging"
	"github.com/galvill/go-fortigate-mcp-server/internal/metrics"
	"github.com/galvill/go-fortigate-mcp-server/internal/server"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// version is set at build time via -ldflags "-X main.version=...". Builds
// without it, such as go install, use the module version Go records (see
// resolveVersion). It must stay a constant for -X to apply.
var version = "dev"

// resolveVersion returns v unless it is the "dev" default, in which case it
// returns the main module's version from the build info, without the "v"
// prefix to match release builds. Local builds without VCS info stay "dev".
func resolveVersion(v string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if v != "dev" {
		return v
	}
	if info, ok := readBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return v
}

func main() {
	version = resolveVersion(version, debug.ReadBuildInfo)
	if err := run(os.Args[1:], os.LookupEnv, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "fortigate-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, lookupEnv config.LookupEnv, stderr io.Writer) error {
	fs := flag.NewFlagSet("fortigate-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	flags := config.BindFlags(fs)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		_, err := fmt.Fprintln(stderr, version)
		return err
	}

	cfg, err := flags.Load(lookupEnv)
	if err != nil {
		return err
	}

	// Logs always go to stderr: stdout carries the stdio MCP transport.
	logger, err := logging.New(stderr, cfg.Server.LogLevel, cfg.Server.LogFormat)
	if err != nil {
		return err
	}

	auditOut := stderr
	if cfg.Server.AuditLog != "" {
		f, err := os.OpenFile(cfg.Server.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("opening audit log: %w", err)
		}
		defer func() { _ = f.Close() }()
		auditOut = f
	}
	auditLog := audit.New(auditOut, cfg.Server.AuditBodies, logger)

	devOpts := devices.Options{Logger: logger, Observer: auditLog.Observe}
	var m *metrics.Metrics
	var middleware []mcp.Middleware
	if cfg.Server.HTTP.Metrics {
		m = metrics.New()
		devOpts.OnRequest = m.OnRequest
		middleware = append(middleware, m.Middleware)
	}
	inv, err := devices.New(cfg, devOpts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := server.New(server.Options{
		Version:   version,
		Logger:    logger,
		Inventory: inv,
		Tools: tools.Options{
			Toolsets:       cfg.Server.Toolsets,
			ReadOnly:       cfg.Server.ReadOnly,
			MaxResultBytes: cfg.Server.MaxResultBytes,
			BackupDir:      cfg.Server.BackupDir,
			IdentityHeader: cfg.Server.HTTP.IdentityHeader,
		},
		Middleware: middleware,
	})
	if err != nil {
		return err
	}
	logger.Info("starting", "version", version, "transport", cfg.Server.Transport,
		"devices", inv.Names(), "default_device", inv.Default(), "read_only", cfg.Server.ReadOnly)
	if cfg.Server.Transport == "http" {
		opts := httpserver.Options{Config: cfg.Server.HTTP, Server: s, Logger: logger, Devices: inv.Names()}
		if m != nil {
			opts.Metrics = m.Handler()
		}
		return httpserver.Serve(ctx, opts)
	}
	if err := s.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
