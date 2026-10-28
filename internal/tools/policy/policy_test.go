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
