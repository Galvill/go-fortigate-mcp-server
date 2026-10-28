// Package server builds the MCP server and registers its tools.
package server

import (
	"context"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Name is the MCP implementation name reported to clients.
const Name = "fortigate-mcp"

// Options configures the MCP server.
type Options struct {
	Version string
	Logger  *slog.Logger
}

// New returns an MCP server with all tools registered.
func New(opts Options) *mcp.Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	s := mcp.NewServer(&mcp.Implementation{
		Name:    Name,
		Title:   "FortiGate MCP Server",
		Version: opts.Version,
	}, &mcp.ServerOptions{
		Logger: logger,
	})

	registerPing(s, opts.Version)
	return s
}

// PingInput is the input for the ping tool.
type PingInput struct{}

// PingOutput is the output of the ping tool.
type PingOutput struct {
	Message string `json:"message" jsonschema:"always \"pong\""`
	Version string `json:"version" jsonschema:"version of the MCP server"`
}

func registerPing(s *mcp.Server, version string) {
	openWorld := false
	mcp.AddTool(s, &mcp.Tool{
		Name:        "ping",
		Description: "Check that the FortiGate MCP server is running. Does not contact any FortiGate.",
		Annotations: &mcp.ToolAnnotations{
			Title:          "Ping",
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  &openWorld,
		},
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ PingInput) (*mcp.CallToolResult, PingOutput, error) {
		return nil, PingOutput{Message: "pong", Version: version}, nil
	})
}
