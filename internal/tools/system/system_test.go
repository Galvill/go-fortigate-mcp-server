package system_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/system"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

func connect(t *testing.T) *toolstest.Env {
	return toolstest.Connect(t, system.Register, tools.Options{})
}

func TestDeviceList(t *testing.T) {
	fgt := fakefgt.New(t)
	dead := config.Device{Name: "dead", Host: "https://127.0.0.1:1", Token: "t", VDOM: "root", Timeout: config.DefaultTimeout}
	inv, err := devices.New(&config.Config{Devices: []config.Device{dead, toolstest.Device(t, "lab", fgt)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	reg, err := tools.NewRegistry(s, inv, tools.Options{MaxResultBytes: config.DefaultMaxResultBytes})
	if err != nil {
		t.Fatal(err)
	}
	system.Register(reg)
	env := &toolstest.Env{Session: toolstest.ConnectServer(t, s)}

	out := toolstest.Call[system.DeviceListOutput](t, env, "fgt_device_list", nil)
	if out.DefaultDevice != "" || len(out.Devices) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if d := out.Devices[0]; d.Name != "dead" || d.Error == "" || d.Hostname != "" {
		t.Errorf("dead = %+v", d)
	}
	if d := out.Devices[1]; d.Name != "lab" || d.Hostname != fakefgt.DefaultHostname || d.Version != "7.4.4" || d.Serial != fakefgt.DefaultSerial || d.Error != "" {
		t.Errorf("lab = %+v", d)
	}
}

func TestSystemStatus(t *testing.T) {
	env := connect(t)
	out := toolstest.Call[system.StatusOutput](t, env, "fgt_system_status", map[string]any{"device": "fw2"})
	if out.Device != "fw2" || out.Hostname != fakefgt.DefaultHostname || out.Model != "FGVM64" || out.Version != "7.4.4" || out.Build != fakefgt.DefaultBuild {
		t.Errorf("status = %+v", out)
	}
}

func TestResourcesDropsHistory(t *testing.T) {
	env := connect(t)
	env.FW.SetMonitor("system/resource/usage", map[string]any{
		"cpu": []any{map[string]any{"current": 5, "historical": map[string]any{"1-min": []any{1, 2, 3}}}},
	})
	out := toolstest.Call[toolstest.Results](t, env, "fgt_system_resources", nil)
	cpu := out.Results.(map[string]any)["cpu"].([]any)[0].(map[string]any)
	if cpu["current"] != float64(5) || cpu["historical"] != nil {
		t.Errorf("cpu = %v", cpu)
	}
}

func TestMonitorQueries(t *testing.T) {
	env := connect(t)
	for _, p := range []string{"system/interface", "router/ipv6", "network/arp", "system/dhcp", "license/status", "firewall/session", "system/ha-peer", "system/ha-checksums"} {
		env.FW.SetMonitor(p, []any{})
	}

	toolstest.Call[toolstest.Results](t, env, "fgt_interface_status", map[string]any{"interface": "port1"})
	toolstest.Call[toolstest.Results](t, env, "fgt_route_table", map[string]any{"family": "ipv6"})
	toolstest.Call[toolstest.Results](t, env, "fgt_arp_table", nil)
	toolstest.Call[toolstest.Results](t, env, "fgt_dhcp_leases", nil)
	toolstest.Call[toolstest.Results](t, env, "fgt_license_status", nil)
	toolstest.Call[toolstest.Results](t, env, "fgt_session_list", map[string]any{"dstaddr": "8.8.8.8", "dstport": 443, "protocol": 6, "count": 20})
	toolstest.Call[system.HAOutput](t, env, "fgt_ha_status", nil)

	reqs := env.FW.Requests()
	got := map[string]string{}
	for _, r := range reqs {
		got[r.Path] = r.Query.Encode()
	}
	want := map[string][]string{
		"monitor/system/interface": {"interface_name=port1", "include_vlan=true"},
		"monitor/router/ipv6":      {"vdom=root"},
		"monitor/firewall/session": {"dstaddr=8.8.8.8", "dstport=443", "protocol=6", "count=20", "ip_version=ipv4"},
	}
	for path, parts := range want {
		q, ok := got[path]
		if !ok {
			t.Errorf("%s not called", path)
			continue
		}
		for _, p := range parts {
			if !strings.Contains(q, p) {
				t.Errorf("%s query %q missing %q", path, q, p)
			}
		}
	}
	if strings.Contains(got["monitor/firewall/session"], "srcaddr") {
		t.Error("unset filters must not be sent")
	}

	toolstest.ExpectError(t, env, "fgt_session_list", map[string]any{"count": 5}, "count must be")
	toolstest.ExpectError(t, env, "fgt_route_table", map[string]any{"family": "x"}, "family")
}

func TestLogSearch(t *testing.T) {
	env := connect(t)
	env.FW.SetLog("memory/event/system", []any{map[string]any{"msg": "admin login"}})
	out := toolstest.Call[toolstest.Results](t, env, "fgt_log_search", map[string]any{
		"source": "memory", "type": "event", "subtype": "system", "filter": []string{"user==admin"}, "rows": 10,
	})
	if len(out.Results.([]any)) != 1 {
		t.Errorf("results = %v", out.Results)
	}
	reqs := env.FW.Requests()
	q := reqs[len(reqs)-1].Query
	if q.Get("rows") != "10" || q.Get("filter") != "user==admin" {
		t.Errorf("query = %v", q)
	}

	toolstest.ExpectError(t, env, "fgt_log_search", map[string]any{"type": "traffic"}, "subtype is required")
	toolstest.ExpectError(t, env, "fgt_log_search", map[string]any{"type": "event", "subtype": "system", "source": "tape"}, "source must be")
	toolstest.ExpectError(t, env, "fgt_log_search", map[string]any{"type": "../x", "subtype": "y"}, "invalid log type")
	toolstest.ExpectError(t, env, "fgt_log_search", map[string]any{"type": "virus", "rows": 5000}, "rows must be")
}

func TestDeviceErrorIsToolError(t *testing.T) {
	env := connect(t)
	env.FW.FailNext("GET", "monitor/system/status", 401, 1)
	res, err := env.Session.CallTool(context.Background(), &mcp.CallToolParams{Name: "fgt_system_status", Arguments: map[string]any{}})
	if err != nil || !res.IsError {
		t.Fatalf("expected tool error, got %v %v", res, err)
	}
}
