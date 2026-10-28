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

func TestTunnelActions(t *testing.T) {
	env := toolstest.Connect(t, vpn.Register, tools.Options{})
	env.FW.SetMonitor("vpn/ipsec/tunnel_up", map[string]any{})
	env.FW.SetMonitor("vpn/ipsec/tunnel_down", map[string]any{})

	toolstest.Call[tools.PostOutput](t, env, "fgt_ipsec_tunnel_up", map[string]any{"phase1": "to-branch", "phase2": "p2"})
	toolstest.Call[tools.PostOutput](t, env, "fgt_ipsec_tunnel_down", map[string]any{"phase1": "to-branch"})
	reqs := env.FW.Requests()
	if reqs[0].Path != "monitor/vpn/ipsec/tunnel_up" || string(reqs[0].Body) != `{"p1name":"to-branch","p2name":"p2"}` {
		t.Errorf("up = %s %s", reqs[0].Path, reqs[0].Body)
	}
	if reqs[1].Path != "monitor/vpn/ipsec/tunnel_down" || string(reqs[1].Body) != `{"p1name":"to-branch"}` {
		t.Errorf("down = %s %s", reqs[1].Path, reqs[1].Body)
	}
	toolstest.ExpectError(t, env, "fgt_ipsec_tunnel_up", map[string]any{"phase1": ""}, "phase1 is required")
}

func TestPhase1Write(t *testing.T) {
	env := toolstest.Connect(t, vpn.Register, tools.Options{})
	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_ipsec_phase1_create", map[string]any{
		"name": "to-dc", "fields": map[string]any{"interface": "port1", "remote-gw": "198.51.100.1", "psksecret": "s3cret"},
	})
	if out.Item["psksecret"] != "[REDACTED]" || out.Item["remote-gw"] != "198.51.100.1" {
		t.Errorf("create = %+v", out)
	}
	if recs := env.Audit(t); len(recs) != 1 || recs[0].Body != nil {
		t.Errorf("audit must not include bodies by default: %+v", recs)
	}
}
