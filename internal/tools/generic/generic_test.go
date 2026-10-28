package generic_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/generic"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func TestCMDBGet(t *testing.T) {
	env := toolstest.Connect(t, generic.Register, tools.Options{})
	env.FW.Seed("root", "user/local", map[string]any{"name": "alice", "passwd": "ENC x"}, map[string]any{"name": "bob"})
	env.FW.SetSingleton("root", "system/global", map[string]any{"hostname": "fw1"})

	list := toolstest.Call[toolstest.List](t, env, "fgt_cmdb_get", map[string]any{"path": "user/local", "limit": 1})
	if len(list.Items) != 1 || list.Items[0]["passwd"] != "[REDACTED]" || !list.Truncated {
		t.Errorf("list = %+v", list)
	}
	one := toolstest.Call[toolstest.List](t, env, "fgt_cmdb_get", map[string]any{"path": "user/local", "mkey": "bob"})
	if len(one.Items) != 1 || one.Items[0]["name"] != "bob" {
		t.Errorf("one = %+v", one)
	}
	single := toolstest.Call[toolstest.List](t, env, "fgt_cmdb_get", map[string]any{"path": "system/global"})
	if len(single.Items) != 1 || single.Items[0]["hostname"] != "fw1" {
		t.Errorf("singleton = %+v", single)
	}

	toolstest.ExpectError(t, env, "fgt_cmdb_get", map[string]any{"path": "../../monitor/system/status"}, "invalid API path")
	if n := len(env.FW.Requests()); n != 4 {
		t.Errorf("requests = %d, want 4 (invalid path must not reach the device)", n)
	}
}

func TestSchemaAndMonitor(t *testing.T) {
	env := toolstest.Connect(t, generic.Register, tools.Options{})
	out := toolstest.Call[toolstest.Results](t, env, "fgt_cmdb_schema", map[string]any{"path": "firewall/policy"})
	if out.Results.(map[string]any)["mkey"] != "policyid" {
		t.Errorf("schema = %v", out.Results)
	}
	if q := env.FW.Requests()[0].Query; q.Get("action") != "schema" {
		t.Errorf("schema query = %v", q)
	}

	env.FW.SetMonitor("router/bgp/neighbors", []any{map[string]any{"neighbor_ip": "10.0.0.2", "state": "Established"}})
	toolstest.Call[toolstest.Results](t, env, "fgt_monitor_get", map[string]any{"path": "router/bgp/neighbors", "params": map[string]string{"ip_version": "ipv4"}})
	if q := env.FW.Requests()[1].Query; q.Get("ip_version") != "ipv4" || q.Get("vdom") != "root" {
		t.Errorf("monitor query = %v", q)
	}

	toolstest.ExpectError(t, env, "fgt_monitor_get", map[string]any{"path": "system/status", "params": map[string]string{"vdom": "x"}}, "vdom argument")
	toolstest.ExpectError(t, env, "fgt_monitor_get", map[string]any{"path": "nope/missing"}, "HTTP 404")
}

func TestCMDBWrites(t *testing.T) {
	env := toolstest.Connect(t, generic.Register, tools.Options{})
	env.FW.SetSingleton("root", "system/dns", map[string]any{"primary": "8.8.8.8"})

	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_cmdb_create", map[string]any{"path": "user/local", "fields": map[string]any{"name": "carol", "type": "password"}})
	if out.Mkey != "carol" || out.Item["type"] != "password" {
		t.Errorf("create = %+v", out)
	}
	out = toolstest.Call[tools.WriteOutput](t, env, "fgt_cmdb_update", map[string]any{"path": "user/local", "mkey": "carol", "fields": map[string]any{"status": "disable"}})
	if out.Item["status"] != "disable" {
		t.Errorf("update = %+v", out)
	}
	out = toolstest.Call[tools.WriteOutput](t, env, "fgt_cmdb_update", map[string]any{"path": "system/dns", "fields": map[string]any{"primary": "1.1.1.1"}})
	if out.Item["primary"] != "1.1.1.1" {
		t.Errorf("singleton update = %+v", out)
	}
	toolstest.Call[tools.DeleteOutput](t, env, "fgt_cmdb_delete", map[string]any{"path": "user/local", "mkey": "carol"})

	toolstest.ExpectError(t, env, "fgt_cmdb_create", map[string]any{"path": "user/local", "mkey": "x", "fields": map[string]any{"name": "x"}}, "mkey is for updates")
	toolstest.ExpectError(t, env, "fgt_cmdb_delete", map[string]any{"path": "user/local", "mkey": ""}, "mkey is required")
	toolstest.ExpectError(t, env, "fgt_cmdb_create", map[string]any{"path": "../x", "fields": map[string]any{"a": 1}}, "invalid API path")
}

func TestMonitorPostConfirmation(t *testing.T) {
	env := toolstest.Connect(t, generic.Register, tools.Options{})
	env.FW.SetMonitor("user/firewall/deauth", map[string]any{})
	env.FW.SetMonitor("system/os/reboot", map[string]any{})

	out := toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_monitor_post", map[string]any{"path": "user/firewall/deauth", "body": map[string]any{"user_type": "fsso"}})
	if !out.Executed {
		t.Errorf("non-disruptive post = %+v", out)
	}

	// The generic tool must not be a way around confirmation.
	out = toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_monitor_post", map[string]any{"path": "system/os/reboot"})
	if out.Executed || out.Preview == nil {
		t.Errorf("reboot via monitor_post without confirm = %+v", out)
	}
	for _, r := range env.FW.Requests() {
		if r.Path == "monitor/system/os/reboot" {
			t.Fatal("reboot reached the device without confirmation")
		}
	}
	toolstest.ExpectError(t, env, "fgt_monitor_post", map[string]any{"path": "system//os/reboot"}, "invalid API path")
	toolstest.ExpectError(t, env, "fgt_monitor_post", map[string]any{"path": "system/os/../os/reboot"}, "invalid API path")

	out = toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_monitor_post", map[string]any{"path": "system/os/reboot", "confirm": "FGVM-FAKE"})
	if !out.Executed {
		t.Errorf("confirmed reboot = %+v", out)
	}
	recs := env.Audit(t)
	if last := recs[len(recs)-1]; last.Path != "monitor/system/os/reboot" || last.ConfirmedHostname != "FGVM-FAKE" || last.Tool != "fgt_monitor_post" {
		t.Errorf("audit = %+v", last)
	}
}
