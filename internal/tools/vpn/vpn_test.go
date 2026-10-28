package vpn_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/vpn"
)

func TestIPsec(t *testing.T) {
	env := toolstest.Connect(t, vpn.Register, tools.Options{})
	env.FW.Seed("root", "vpn.ipsec/phase1-interface", map[string]any{"name": "to-branch", "remote-gw": "203.0.113.1", "psksecret": "ENC xyz"})
	env.FW.SetMonitor("vpn/ipsec", []any{map[string]any{"name": "to-branch", "proxyid": []any{map[string]any{"status": "up"}}}})

	p1 := toolstest.Call[toolstest.Item](t, env, "fgt_ipsec_phase1_get", map[string]any{"name": "to-branch"})
	if p1.Item["remote-gw"] != "203.0.113.1" || p1.Item["psksecret"] != "[REDACTED]" {
		t.Errorf("phase1 = %+v", p1)
	}
	toolstest.Call[toolstest.Results](t, env, "fgt_ipsec_status", nil)
	toolstest.Call[toolstest.List](t, env, "fgt_ipsec_phase2_list", nil)
}

func TestSSLVPNUnavailable(t *testing.T) {
	env := toolstest.Connect(t, vpn.Register, tools.Options{})
	toolstest.ExpectError(t, env, "fgt_sslvpn_sessions", nil, "SSL-VPN is not available")

	env.FW.SetMonitor("vpn/ssl", []any{map[string]any{"user_name": "alice"}})
	out := toolstest.Call[toolstest.Results](t, env, "fgt_sslvpn_sessions", nil)
	if len(out.Results.([]any)) != 1 {
		t.Errorf("sessions = %v", out.Results)
	}
}
