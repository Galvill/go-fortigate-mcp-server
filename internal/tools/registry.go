// Package tools holds the framework shared by every toolset: registration,
// device resolution, list conventions, redaction and result size limits.
// Toolsets live in subpackages and register themselves through a Registry.
package tools

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
)

// Toolset names.
const (
	System  = "system"
	Policy  = "policy"
	Objects = "objects"
	Network = "network"
	VPN     = "vpn"
	Admin   = "admin"
	Generic = "generic"
)

// Toolsets lists every toolset name.
var Toolsets = []string{System, Policy, Objects, Network, VPN, Admin, Generic}

// Options configures a Registry.
type Options struct {
	// Toolsets to enable; nil enables all.
	Toolsets []string
	// ReadOnly skips registration of mutating tools.
	ReadOnly bool
	// MaxResultBytes caps the serialized size of tool results.
	MaxResultBytes int
	// BackupDir, if set, is where fgt_config_backup may save files.
	BackupDir string
}

// Registry registers tools on an MCP server, honoring the enabled toolsets
// and read-only mode.
type Registry struct {
	server    *mcp.Server
	inv       *devices.Inventory
	enabled   map[string]bool
	readOnly  bool
	maxBytes  int
	backupDir string
}

// NewRegistry validates the options and returns a registry.
func NewRegistry(s *mcp.Server, inv *devices.Inventory, opts Options) (*Registry, error) {
	r := &Registry{server: s, inv: inv, readOnly: opts.ReadOnly, maxBytes: opts.MaxResultBytes, backupDir: opts.BackupDir}
	if opts.Toolsets != nil {
		r.enabled = map[string]bool{}
		for _, ts := range opts.Toolsets {
			if !slices.Contains(Toolsets, ts) {
				return nil, fmt.Errorf("unknown toolset %q (available: %s)", ts, strings.Join(Toolsets, ", "))
			}
			r.enabled[ts] = true
		}
	}
	return r, nil
}

// BackupDir returns the directory for saved backups, or "" if disabled.
func (r *Registry) BackupDir() string { return r.backupDir }

// MaxResultBytes returns the result size limit.
func (r *Registry) MaxResultBytes() int { return r.maxBytes }

// Inventory returns the device inventory.
func (r *Registry) Inventory() *devices.Inventory { return r.inv }

func (r *Registry) isEnabled(toolset string) bool {
	return r.enabled == nil || r.enabled[toolset]
}

// AddRead registers a tool that only reads from devices. It is annotated
// read-only and idempotent.
func AddRead[In, Out any](r *Registry, toolset string, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	if !r.isEnabled(toolset) {
		return
	}
	if t.Annotations == nil {
		t.Annotations = &mcp.ToolAnnotations{}
	}
	t.Annotations.ReadOnlyHint = true
	t.Annotations.IdempotentHint = true
	mcp.AddTool(r.server, t, h)
}

// WriteKind classifies a mutating tool for its MCP annotations.
type WriteKind int

// Write kinds.
const (
	// Create adds something new: not idempotent, not destructive.
	Create WriteKind = iota
	// Update overwrites existing state: idempotent, destructive.
	Update
	// Delete removes something: idempotent, destructive.
	Delete
	// Action triggers an operation such as a reboot: not idempotent, destructive.
	Action
)

// AddWrite registers a tool that changes devices. It is skipped in
// read-only mode. Calls are tagged with the tool name and session so the
// audit log can attribute the requests they make.
func AddWrite[In, Out any](r *Registry, toolset string, kind WriteKind, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	if !r.isEnabled(toolset) || r.readOnly {
		return
	}
	destructive := kind != Create
	if t.Annotations == nil {
		t.Annotations = &mcp.ToolAnnotations{}
	}
	t.Annotations.ReadOnlyHint = false
	t.Annotations.DestructiveHint = &destructive
	t.Annotations.IdempotentHint = kind == Update || kind == Delete
	name := t.Name
	mcp.AddTool(r.server, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		info := &audit.Info{Tool: name}
		if req != nil && req.Session != nil {
			info.SessionID = req.Session.ID()
		}
		return h(audit.WithInfo(ctx, info), req, in)
	})
}
