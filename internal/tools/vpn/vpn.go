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
	tools.RegisterTableReads(r, tools.Table{
		Toolset: tools.VPN,
		Prefix:  "fgt_ipsec_phase1",
		Noun:    "IPsec phase 1 (tunnel) configuration",
		Path:    "vpn.ipsec/phase1-interface",
		About:   "Pre-shared keys are never returned.",
	})
	tools.RegisterTableReads(r, tools.Table{
		Toolset: tools.VPN,
		Prefix:  "fgt_ipsec_phase2",
		Noun:    "IPsec phase 2 (selector) configuration",
		Path:    "vpn.ipsec/phase2-interface",
	})

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
}

func sslvpnError(err error) error {
	var apiErr *fortios.APIError
	if errors.As(err, &apiErr) && apiErr.HTTPStatus == http.StatusNotFound {
		return errNoSSLVPN
	}
	return err
}
