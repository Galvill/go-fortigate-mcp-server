package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

var addressTable = tools.Table{
	Toolset: tools.Objects, Prefix: "fgt_address", Noun: "address",
	Path: "firewall/address", Path6: "firewall/address6",
}

var policyTable = tools.Table{
	Toolset: tools.Policy, Prefix: "fgt_policy", Noun: "policy",
	Path: "firewall/policy", NumericKey: true,
}

func connect(t *testing.T, opts tools.Options) *toolstest.Env {
	return toolstest.Connect(t, func(r *tools.Registry) {
		tools.RegisterTableReads(r, addressTable)
		tools.RegisterTableReads(r, policyTable)
		tools.RegisterSingletonRead(r, tools.Network, "fgt_sdwan_config_get", "sdwan", "system/sdwan")
	}, opts)
}

func TestListPaging(t *testing.T) {
	env := connect(t, tools.Options{})
	for i := range 5 {
		env.FW.Seed("root", "firewall/address", map[string]any{"name": fmt.Sprintf("a%d", i), "subnet": "10.0.0.0 255.0.0.0"})
	}

	out := toolstest.Call[toolstest.List](t, env, "fgt_address_list", map[string]any{"limit": 2, "offset": 1})
	if len(out.Items) != 2 || out.Items[0]["name"] != "a1" || out.Total != 5 || !out.Truncated || out.NextOffset != 3 {
		t.Errorf("page = %+v", out)
	}
	if out.Device != "fw" || out.VDOM != "root" {
		t.Errorf("scope = %s/%s", out.Device, out.VDOM)
	}

	out = toolstest.Call[toolstest.List](t, env, "fgt_address_list", map[string]any{"offset": 3})
	if len(out.Items) != 2 || out.Truncated || out.NextOffset != 0 {
		t.Errorf("last page = %+v", out)
	}

	out = toolstest.Call[toolstest.List](t, env, "fgt_address_list", map[string]any{"filter": []string{"name==a4"}, "fields": []string{"name"}})
	if len(out.Items) != 1 || out.Total != 1 || out.Items[0]["subnet"] != nil {
		t.Errorf("filtered = %+v", out)
	}

	empty := toolstest.Call[toolstest.List](t, env, "fgt_address_list", map[string]any{"family": "ipv6"})
	if len(empty.Items) != 0 || empty.Total != 0 || empty.Items == nil {
		t.Errorf("empty list = %+v", empty)
	}
}

func TestListValidation(t *testing.T) {
	env := connect(t, tools.Options{})
	toolstest.ExpectError(t, env, "fgt_address_list", map[string]any{"limit": 5000}, "limit must be between")
	toolstest.ExpectError(t, env, "fgt_address_list", map[string]any{"offset": -1}, "offset")
	toolstest.ExpectError(t, env, "fgt_address_list", map[string]any{"family": "ipx"}, "family must be")
	toolstest.ExpectError(t, env, "fgt_address_list", map[string]any{"device": "nope"}, `unknown device "nope"`)
	toolstest.ExpectError(t, env, "fgt_address_list", map[string]any{"bogus": 1}, "bogus")
}

func TestListSizeLimit(t *testing.T) {
	env := connect(t, tools.Options{MaxResultBytes: 4096})
	for i := range 50 {
		env.FW.Seed("root", "firewall/address", map[string]any{"name": fmt.Sprintf("addr-%02d", i), "comment": strings.Repeat("x", 100)})
	}
	out := toolstest.Call[toolstest.List](t, env, "fgt_address_list", nil)
	if len(out.Items) == 0 || len(out.Items) >= 50 || !out.Truncated || out.NextOffset != len(out.Items) {
		t.Errorf("size-limited: %d items, truncated=%v, next=%d", len(out.Items), out.Truncated, out.NextOffset)
	}
}

func TestGet(t *testing.T) {
	env := connect(t, tools.Options{})
	env.FW.Seed("root", "firewall/address6", map[string]any{"name": "v6", "ip6": "2001:db8::/32"})
	env.FW.Seed("root", "firewall/policy", map[string]any{"policyid": 7, "name": "p7"})
	env.FW2.Seed("cust", "firewall/policy", map[string]any{"policyid": 7, "name": "other"})

	item := toolstest.Call[toolstest.Item](t, env, "fgt_address_get", map[string]any{"name": "v6", "family": "ipv6"})
	if item.Item["ip6"] != "2001:db8::/32" {
		t.Errorf("address6 = %+v", item)
	}
	item = toolstest.Call[toolstest.Item](t, env, "fgt_policy_get", map[string]any{"id": 7})
	if item.Item["name"] != "p7" {
		t.Errorf("policy = %+v", item)
	}
	item = toolstest.Call[toolstest.Item](t, env, "fgt_policy_get", map[string]any{"id": 7, "device": "fw2", "vdom": "cust"})
	if item.Item["name"] != "other" || item.Device != "fw2" || item.VDOM != "cust" {
		t.Errorf("fw2 policy = %+v", item)
	}

	toolstest.ExpectError(t, env, "fgt_policy_get", map[string]any{"id": 99}, "not found")
	toolstest.ExpectError(t, env, "fgt_address_get", map[string]any{}, "name")
}

func TestRedaction(t *testing.T) {
	env := connect(t, tools.Options{})
	env.FW.Seed("root", "firewall/address", map[string]any{
		"name": "a", "q_origin_key": "a",
		"nested":   []any{map[string]any{"psksecret": "ENC abc", "name": "x"}},
		"password": "ENC secret", "comment": "",
	})
	out := toolstest.Call[toolstest.List](t, env, "fgt_address_list", nil)
	it := out.Items[0]
	if it["password"] != "[REDACTED]" || it["q_origin_key"] != "a" {
		t.Errorf("item = %v", it)
	}
	nested := it["nested"].([]any)[0].(map[string]any)
	if nested["psksecret"] != "[REDACTED]" || nested["name"] != "x" {
		t.Errorf("nested = %v", nested)
	}
}

func TestSingleton(t *testing.T) {
	env := connect(t, tools.Options{})
	env.FW.SetSingleton("root", "system/sdwan", map[string]any{"status": "enable"})
	item := toolstest.Call[toolstest.Item](t, env, "fgt_sdwan_config_get", nil)
	if item.Item["status"] != "enable" {
		t.Errorf("sdwan = %+v", item)
	}
}

func TestToolsetFiltering(t *testing.T) {
	env := connect(t, tools.Options{Toolsets: []string{tools.Policy}})
	res, err := env.Session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if !tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint {
			t.Errorf("%s: read tools must be annotated read-only and idempotent", tool.Name)
		}
	}
	if strings.Join(names, ",") != "fgt_policy_get,fgt_policy_list" {
		t.Errorf("tools = %v", names)
	}
}

func TestUnknownToolset(t *testing.T) {
	if _, err := tools.NewRegistry(nil, nil, tools.Options{Toolsets: []string{"nope"}}); err == nil {
		t.Error("expected error")
	}
}
