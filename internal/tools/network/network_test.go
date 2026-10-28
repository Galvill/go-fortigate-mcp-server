package network_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/network"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func TestNetworkReads(t *testing.T) {
	env := toolstest.Connect(t, network.Register, tools.Options{})
	env.FW.Seed("root", "system/interface", map[string]any{"name": "port1", "ip": "10.0.0.1 255.255.255.0", "vdom": "root"})
	env.FW.Seed("root", "router/static", map[string]any{"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "gateway": "10.0.0.254"})
	env.FW.SetSingleton("root", "system/sdwan", map[string]any{"status": "enable"})
	env.FW.SetMonitor("virtual-wan/health-check", map[string]any{"google": map[string]any{"port1": map[string]any{"status": "up"}}})
	env.FW.SetMonitor("virtual-wan/members", map[string]any{"port1": map[string]any{"link": "up"}})

	if it := toolstest.Call[toolstest.Item](t, env, "fgt_interface_get", map[string]any{"name": "port1"}); it.Item["ip"] != "10.0.0.1 255.255.255.0" {
		t.Errorf("interface = %+v", it)
	}
	if it := toolstest.Call[toolstest.Item](t, env, "fgt_static_route_get", map[string]any{"id": 1}); it.Item["gateway"] != "10.0.0.254" {
		t.Errorf("route = %+v", it)
	}
	if it := toolstest.Call[toolstest.Item](t, env, "fgt_sdwan_config_get", nil); it.Item["status"] != "enable" {
		t.Errorf("sdwan config = %+v", it)
	}
	st := toolstest.Call[network.SDWANStatusOutput](t, env, "fgt_sdwan_status", nil)
	if st.HealthChecks == nil || st.Members == nil {
		t.Errorf("sdwan status = %+v", st)
	}
}
