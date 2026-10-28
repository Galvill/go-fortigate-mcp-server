package policy_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/policy"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func TestPolicyReads(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	env.FW.Seed("root", "firewall/policy",
		map[string]any{"policyid": 10, "name": "web", "action": "accept"},
		map[string]any{"policyid": 5, "name": "deny", "action": "deny"})

	list := toolstest.Call[toolstest.List](t, env, "fgt_policy_list", map[string]any{"filter": []string{"action==deny"}})
	if len(list.Items) != 1 || list.Items[0]["policyid"] != float64(5) {
		t.Errorf("list = %+v", list)
	}
	item := toolstest.Call[toolstest.Item](t, env, "fgt_policy_get", map[string]any{"id": 10})
	if item.Item["name"] != "web" {
		t.Errorf("get = %+v", item)
	}
}

func TestPolicyLookup(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	env.FW.SetMonitor("firewall/policy-lookup", map[string]any{"success": true, "policy_id": 10})

	out := toolstest.Call[toolstest.Results](t, env, "fgt_policy_lookup", map[string]any{
		"srcintf": "port1", "sourceip": "10.1.1.5", "dest": "8.8.8.8", "protocol": "TCP", "destport": 443,
	})
	if out.Results.(map[string]any)["policy_id"] != float64(10) {
		t.Errorf("results = %v", out.Results)
	}
	q := env.FW.Requests()[0].Query
	if q.Get("protocol") != "6" || q.Get("destport") != "443" || q.Get("sourceip") != "10.1.1.5" || q.Has("icmptype") {
		t.Errorf("query = %v", q)
	}

	toolstest.Call[toolstest.Results](t, env, "fgt_policy_lookup", map[string]any{
		"srcintf": "port1", "sourceip": "10.1.1.5", "dest": "10.2.2.2", "protocol": "icmp", "icmptype": 0, "icmpcode": 0,
	})
	q = env.FW.Requests()[1].Query
	if q.Get("protocol") != "1" || q.Get("icmptype") != "0" || q.Get("icmpcode") != "0" {
		t.Errorf("icmp query = %v", q)
	}

	toolstest.ExpectError(t, env, "fgt_policy_lookup", map[string]any{"srcintf": "port1", "sourceip": "1.1.1.1", "dest": "2.2.2.2", "protocol": "gre!"}, "protocol must be")
	toolstest.ExpectError(t, env, "fgt_policy_lookup", map[string]any{"srcintf": "", "sourceip": "1.1.1.1", "dest": "2.2.2.2", "protocol": "tcp"}, "required")
}

func TestHitCounts(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	env.FW.SetMonitor("firewall/policy", []any{map[string]any{"policyid": 3, "hit_count": 42}})
	toolstest.Call[toolstest.Results](t, env, "fgt_policy_hit_counts", map[string]any{"policyid": 3})
	if q := env.FW.Requests()[0].Query; q.Get("policyid") != "3" {
		t.Errorf("query = %v", q)
	}
}

func TestPolicyCreate(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	env.FW.Seed("root", "firewall/policy", map[string]any{"policyid": 1, "name": "first"})

	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_create", map[string]any{
		"name": "web", "srcintf": []string{"port1"}, "dstintf": []string{"port2"},
		"srcaddr": []string{"all"}, "dstaddr": []string{"web-servers"}, "service": []string{"HTTPS"},
		"action": "accept", "nat": true, "enabled": false, "av_profile": "default",
		"extra":  map[string]any{"inspection-mode": "flow", "schedule": "weekdays"},
		"before": 1,
	})
	if out.Mkey != "2" || out.Warning != "" {
		t.Fatalf("create = %+v", out)
	}
	entries := env.FW.Entries("root", "firewall/policy")
	if len(entries) != 2 || entries[0]["name"] != "web" {
		t.Fatalf("policy not moved before 1: %v", entries)
	}
	p := entries[0]
	want := map[string]any{"action": "accept", "nat": "enable", "status": "disable", "av-profile": "default", "inspection-mode": "flow", "schedule": "weekdays"}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}
	if src := p["srcaddr"].([]any)[0].(map[string]any)["name"]; src != "all" {
		t.Errorf("srcaddr = %v", p["srcaddr"])
	}
	if _, ok := p["ippool"]; ok {
		t.Error("unset ippool must not be sent")
	}

	toolstest.ExpectError(t, env, "fgt_policy_create", map[string]any{"srcintf": []string{"port1"}, "action": "accept"}, "are required")
	toolstest.ExpectError(t, env, "fgt_policy_create", map[string]any{
		"srcintf": []string{"a"}, "dstintf": []string{"b"}, "srcaddr": []string{"all"}, "dstaddr": []string{"all"},
		"service": []string{"ALL"}, "action": "accept", "before": 1, "after": 2,
	}, "not both")
}

func TestPolicyCreateDefaultsSchedule(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_create", map[string]any{
		"srcintf": []string{"a"}, "dstintf": []string{"b"}, "srcaddr6": []string{"all"}, "dstaddr6": []string{"all"},
		"service": []string{"ALL"}, "action": "deny",
	})
	if p := env.FW.Entries("root", "firewall/policy")[0]; p["schedule"] != "always" {
		t.Errorf("schedule = %v", p["schedule"])
	}
}

func TestPolicyUpdateMoveDelete(t *testing.T) {
	env := toolstest.Connect(t, policy.Register, tools.Options{})
	env.FW.Seed("root", "firewall/policy",
		map[string]any{"policyid": 1, "name": "a", "action": "accept"},
		map[string]any{"policyid": 2, "name": "b", "action": "accept"})

	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_update", map[string]any{"id": 1, "action": "deny", "comments": "blocked"})
	if out.Item["action"] != "deny" || out.Item["comments"] != "blocked" || out.Item["name"] != "a" {
		t.Errorf("update = %+v", out)
	}
	toolstest.ExpectError(t, env, "fgt_policy_update", map[string]any{"id": 1}, "at least one field")

	toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_move", map[string]any{"id": 1, "after": 2})
	if e := env.FW.Entries("root", "firewall/policy"); e[0]["name"] != "b" {
		t.Errorf("order = %v", e)
	}
	toolstest.ExpectError(t, env, "fgt_policy_move", map[string]any{"id": 1}, "before or after")

	toolstest.Call[tools.DeleteOutput](t, env, "fgt_policy_delete", map[string]any{"id": 2})
	if e := env.FW.Entries("root", "firewall/policy"); len(e) != 1 {
		t.Errorf("after delete = %v", e)
	}
}
