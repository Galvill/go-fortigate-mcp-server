// Package network provides interface, routing and SD-WAN tools.
package network

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Register adds the network toolset.
func Register(r *tools.Registry) {
	for _, t := range []tools.Table{interfaces, staticRoutes} {
		tools.RegisterTableReads(r, t)
		tools.RegisterTableWrites(r, t)
	}

	tools.AddRead(r, tools.Network, &mcp.Tool{
		Name:        "fgt_sdwan_status",
		Description: "Get SD-WAN health: health-check results (latency, jitter, packet loss, SLA state) per member, and member link status.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, SDWANStatusOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, SDWANStatusOutput{}, err
		}
		health, err := r.Monitor(ctx, tgt, "virtual-wan/health-check", nil)
		if err != nil {
			return nil, SDWANStatusOutput{}, err
		}
		members, err := r.Monitor(ctx, tgt, "virtual-wan/members", nil)
		if err != nil {
			return nil, SDWANStatusOutput{}, err
		}
		return nil, SDWANStatusOutput{Scope: health.Scope, HealthChecks: health.Results, Members: members.Results}, nil
	})

	tools.RegisterSingletonRead(r, tools.Network, "fgt_sdwan_config_get",
		"Get the SD-WAN configuration: members, zones, health checks and rules.", "system/sdwan")
	tools.RegisterSingletonWrite(r, tools.Network, "fgt_sdwan_config_update",
		"Change the SD-WAN configuration. Top-level fields given replace their current values entirely: to change one member, health check or rule, "+
			"read the configuration with fgt_sdwan_config_get, edit the list, and send the whole list. Main fields: status, zone, members, health-check, service.",
		"system/sdwan")
}

var interfaces = tools.Table{
	Toolset: tools.Network,
	Prefix:  "fgt_interface",
	Noun:    "interface configuration",
	Path:    "system/interface",
	About:   "Interfaces are global; each entry's vdom field says which VDOM it belongs to. For live link state and counters use fgt_interface_status.",
	Fields: `Main fields: vdom (required on create), type (vlan, loopback, aggregate, tunnel, ...), interface (parent of a VLAN), vlanid, ip ("10.1.1.1 255.255.255.0"), ` +
		`allowaccess ("ping https ssh"), role (lan, wan, dmz, undefined), alias, status (up, down), description. Physical ports cannot be created or deleted.`,
}

var staticRoutes = tools.Table{
	Toolset:    tools.Network,
	Prefix:     "fgt_static_route",
	Noun:       "IPv4 static route",
	Path:       "router/static",
	NumericKey: true,
	About:      "Entries are keyed by seq-num. For the active routing table use fgt_route_table.",
	Fields:     `Main fields: dst ("10.20.0.0 255.255.0.0"), gateway, device (outgoing interface), distance, priority, status, blackhole, comment.`,
}

// SDWANStatusOutput is the result of fgt_sdwan_status.
type SDWANStatusOutput struct {
	tools.Scope
	HealthChecks any `json:"health_checks"`
	Members      any `json:"members"`
}
