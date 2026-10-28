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
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/logging"
	"github.com/galvill/go-fortigate-mcp-server/internal/server"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
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

	inv, err := devices.New(cfg, devices.Options{Logger: logger, Observer: auditLog.Observe})
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
		},
	})
	if err != nil {
		return err
	}
	logger.Info("starting", "version", version, "transport", "stdio",
		"devices", inv.Names(), "default_device", inv.Default(), "read_only", cfg.Server.ReadOnly)
	if err := s.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
