// Package vpn provides IPsec and SSL-VPN tools.
package vpn

import (
	"context"
	"errors"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// errNoSSLVPN explains a 404 from SSL-VPN endpoints.
var errNoSSLVPN = errors.New("SSL-VPN is not available on this device; FortiOS 7.6.3 and later removed SSL-VPN tunnel mode, and some models no longer include SSL-VPN at all")

// Register adds the vpn toolset.
func Register(r *tools.Registry) {
	tools.AddRead(r, tools.VPN, &mcp.Tool{
		Name:        "fgt_ipsec_status",
		Description: "Get IPsec tunnel status: each tunnel's remote gateway, uptime, traffic counters, and its phase 2 selectors with up/down state.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, "vpn/ipsec", nil)
		return nil, out, err
	})
	for _, t := range []tools.Table{phase1, phase2} {
		tools.RegisterTableReads(r, t)
		tools.RegisterTableWrites(r, t)
	}
	registerTunnelActions(r)

	tools.AddRead(r, tools.VPN, &mcp.Tool{
		Name:        "fgt_sslvpn_sessions",
		Description: "List connected SSL-VPN users with their source IP, assigned tunnel IP and login time.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, "vpn/ssl", nil)
		return nil, out, sslvpnError(err)
	})
	tools.AddRead(r, tools.VPN, &mcp.Tool{
		Name:        "fgt_sslvpn_settings_get",
		Description: "Get SSL-VPN settings: listening interfaces and port, tunnel IP pools, authentication rules.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ItemOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, tools.ItemOutput{}, err
		}
		out, err := r.GetCMDBSingleton(ctx, tgt, "vpn.ssl/settings")
		return nil, out, sslvpnError(err)
	})
	tools.AddWrite(r, tools.VPN, tools.Update, &mcp.Tool{
		Name:        "fgt_sslvpn_settings_update",
		Description: "Change SSL-VPN settings. Main fields: status, source-interface, port, tunnel-ip-pools, source-address, authentication-rule (replaces the whole list).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.SingletonUpdateInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		if len(in.Fields) == 0 {
			return nil, tools.WriteOutput{}, errors.New("fields must not be empty")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		resp, err := tgt.Device.Client.CMDBUpdate(ctx, "vpn.ssl/settings", "", in.Fields, tgt.Params())
		if err != nil {
			return nil, tools.WriteOutput{}, sslvpnError(err)
		}
		out := tools.WriteOutput{Scope: tools.Scope{Device: tgt.Device.Name, VDOM: tgt.VDOM}, Revision: resp.Revision}
		if item, err := r.GetCMDBSingleton(ctx, tgt, "vpn.ssl/settings"); err == nil {
			out.Item = item.Item
		}
		return nil, out, nil
	})
	tools.AddWrite(r, tools.VPN, tools.Action, &mcp.Tool{
		Name:        "fgt_sslvpn_disconnect",
		Description: "Disconnect an SSL-VPN user session. Get the index from fgt_sslvpn_sessions.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DisconnectInput) (*mcp.CallToolResult, tools.PostOutput, error) {
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.PostOutput{}, err
		}
		// TODO(M3): verify body field names against a FortiGate-VM.
		out, err := r.Post(ctx, tgt, "vpn/ssl/delete", map[string]any{"type": "subsession", "index": in.Index})
		return nil, out, sslvpnError(err)
	})
}

// DisconnectInput is the input of fgt_sslvpn_disconnect.
type DisconnectInput struct {
	tools.Target
	Index int `json:"index" jsonschema:"Session index from fgt_sslvpn_sessions."`
}

var phase1 = tools.Table{
	Toolset: tools.VPN,
	Prefix:  "fgt_ipsec_phase1",
	Noun:    "IPsec phase 1 (tunnel) configuration",
	Path:    "vpn.ipsec/phase1-interface",
	About:   "Pre-shared keys are never returned.",
	Fields: `Main fields: interface (outgoing), remote-gw, type (static, dynamic, ddns), ike-version (1, 2), peertype, psksecret (write-only), ` +
		`proposal ("aes256-sha256"), dhgrp ("14 20"), net-device, add-route, dpd, comments.`,
}

var phase2 = tools.Table{
	Toolset: tools.VPN,
	Prefix:  "fgt_ipsec_phase2",
	Noun:    "IPsec phase 2 (selector) configuration",
	Path:    "vpn.ipsec/phase2-interface",
	Fields:  `Main fields: phase1name (required), proposal, pfs, dhgrp, src-subnet and dst-subnet ("10.0.0.0 255.255.255.0"), keylifeseconds, auto-negotiate, comments.`,
}

// TunnelInput is the input of tunnel up/down tools.
type TunnelInput struct {
	tools.Target
	Phase1 string `json:"phase1" jsonschema:"Phase 1 (tunnel) name."`
	Phase2 string `json:"phase2,omitempty" jsonschema:"Phase 2 name. Omit for all phase 2 selectors of the tunnel."`
}

func registerTunnelActions(r *tools.Registry) {
	for _, dir := range []string{"up", "down"} {
		tools.AddWrite(r, tools.VPN, tools.Action, &mcp.Tool{
			Name:        "fgt_ipsec_tunnel_" + dir,
			Description: "Bring an IPsec tunnel " + dir + " (all phase 2 selectors, or one).",
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in TunnelInput) (*mcp.CallToolResult, tools.PostOutput, error) {
			if in.Phase1 == "" {
				return nil, tools.PostOutput{}, errors.New("phase1 is required")
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, tools.PostOutput{}, err
			}
			body := map[string]any{"p1name": in.Phase1}
			if in.Phase2 != "" {
				body["p2name"] = in.Phase2
			}
			// TODO(M3): verify body field names against a FortiGate-VM.
			out, err := r.Post(ctx, tgt, "vpn/ipsec/tunnel_"+dir, body)
			return nil, out, err
		})
	}
}

func sslvpnError(err error) error {
	var apiErr *fortios.APIError
	if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
		return errNoSSLVPN
	}
	return err
}
