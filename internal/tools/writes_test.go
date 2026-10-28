package tools_test

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

var groupTable = tools.Table{
	Toolset: tools.Objects, Prefix: "fgt_addrgrp", Noun: "group",
	Path: "firewall/addrgrp", Path6: "firewall/addrgrp6",
}

var serviceTable = tools.Table{
	Toolset: tools.Objects, Prefix: "fgt_service", Noun: "service", Path: "firewall.service/custom",
}

func connectWrites(t *testing.T, opts tools.Options) *toolstest.Env {
	return toolstest.Connect(t, func(r *tools.Registry) {
		for _, tbl := range []tools.Table{addressTable, policyTable, groupTable, serviceTable} {
			tools.RegisterTableReads(r, tbl)
			tools.RegisterTableWrites(r, tbl)
		}
		tools.RegisterMemberTools(r, groupTable)
		tools.RegisterSingletonWrite(r, tools.Network, "fgt_sdwan_config_update", "sdwan", "system/sdwan")
		tools.AddWrite(r, tools.Admin, tools.Action, &mcp.Tool{Name: "test_reboot", Description: "reboot"},
			func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
				tools.Target
				tools.Confirmation
			}) (*mcp.CallToolResult, tools.DisruptiveOutput, error) {
				tgt, err := r.ResolveWrite(in.Target)
				if err != nil {
					return nil, tools.DisruptiveOutput{}, err
				}
				out, err := r.RunDisruptive(ctx, tgt, in.Confirmation, "system/os/reboot", map[string]any{}, "reboot the device", "Downtime.", nil)
				return nil, out, err
			})
	}, opts)
}

func TestTableCRUDByName(t *testing.T) {
	env := connectWrites(t, tools.Options{})

	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_address_create", map[string]any{
		"name": "web1", "fields": map[string]any{"subnet": "10.0.0.1 255.255.255.255", "comment": "web"},
	})
	if out.Mkey != "web1" || out.Item["subnet"] != "10.0.0.1 255.255.255.255" || out.Revision == "" {
		t.Errorf("create = %+v", out)
	}

	out = toolstest.Call[tools.WriteOutput](t, env, "fgt_address_update", map[string]any{"name": "web1", "fields": map[string]any{"comment": "changed"}})
	if out.Item["comment"] != "changed" || out.Item["subnet"] != "10.0.0.1 255.255.255.255" {
		t.Errorf("update = %+v", out)
	}

	out = toolstest.Call[tools.WriteOutput](t, env, "fgt_address_update", map[string]any{"name": "web1", "fields": map[string]any{"name": "web-1"}})
	if out.Mkey != "web-1" || out.Item["name"] != "web-1" {
		t.Errorf("rename = %+v", out)
	}

	del := toolstest.Call[tools.DeleteOutput](t, env, "fgt_address_delete", map[string]any{"name": "web-1"})
	if del.Deleted != "web-1" || len(env.FW.Entries("root", "firewall/address")) != 0 {
		t.Errorf("delete = %+v", del)
	}

	toolstest.Call[tools.WriteOutput](t, env, "fgt_address_create", map[string]any{"name": "v6", "family": "ipv6", "fields": map[string]any{"ip6": "2001:db8::/64"}})
	if len(env.FW.Entries("root", "firewall/address6")) != 1 {
		t.Error("ipv6 create went to the wrong table")
	}

	toolstest.ExpectError(t, env, "fgt_address_update", map[string]any{"name": "nope", "fields": map[string]any{"comment": "x"}}, "HTTP 404")
	toolstest.ExpectError(t, env, "fgt_address_update", map[string]any{"name": "v6", "fields": map[string]any{}}, "fields must not be empty")
}

func TestTableCRUDByID(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_create", map[string]any{"fields": map[string]any{"name": "p", "action": "accept"}})
	if out.Mkey != "1" || out.Item["action"] != "accept" {
		t.Errorf("create = %+v", out)
	}
	out = toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_update", map[string]any{"id": 1, "fields": map[string]any{"action": "deny"}})
	if out.Item["action"] != "deny" {
		t.Errorf("update = %+v", out)
	}
	toolstest.Call[tools.DeleteOutput](t, env, "fgt_policy_delete", map[string]any{"id": 1})
	toolstest.ExpectError(t, env, "fgt_policy_create", map[string]any{"fields": map[string]any{}}, "fields must not be empty")
}

func TestMembers(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	env.FW.Seed("root", "firewall/addrgrp", map[string]any{"name": "g", "member": []any{map[string]any{"name": "a"}}})

	out := toolstest.Call[tools.MembersOutput](t, env, "fgt_addrgrp_add_members", map[string]any{"name": "g", "members": []string{"b", "a"}})
	if got := members(env); len(got) != 2 || got[0] != "a" || got[1] != "b" || len(out.Unchanged) != 1 || out.Unchanged[0] != "a" {
		t.Errorf("after add: members = %v, unchanged = %v", got, out.Unchanged)
	}
	toolstest.Call[tools.MembersOutput](t, env, "fgt_addrgrp_remove_members", map[string]any{"name": "g", "members": []string{"a"}})
	if got := members(env); len(got) != 1 || got[0] != "b" {
		t.Errorf("after remove: members = %v", got)
	}

	writes := len(env.Audit(t))
	out = toolstest.Call[tools.MembersOutput](t, env, "fgt_addrgrp_remove_members", map[string]any{"name": "g", "members": []string{"zzz"}})
	if len(out.Unchanged) != 1 || len(env.Audit(t)) != writes {
		t.Errorf("no-op remove should not write: %+v", out)
	}
	toolstest.ExpectError(t, env, "fgt_addrgrp_add_members", map[string]any{"name": "g", "members": []string{}}, "members must not be empty")
}

func members(env *toolstest.Env) []string {
	var out []string
	for _, m := range env.FW.Entries("root", "firewall/addrgrp")[0]["member"].([]any) {
		out = append(out, m.(map[string]any)["name"].(string))
	}
	return out
}

func TestSingletonWrite(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	env.FW.SetSingleton("root", "system/sdwan", map[string]any{"status": "disable", "load-balance-mode": "source-ip-based"})
	out := toolstest.Call[tools.WriteOutput](t, env, "fgt_sdwan_config_update", map[string]any{"fields": map[string]any{"status": "enable"}})
	if out.Item["status"] != "enable" || out.Item["load-balance-mode"] != "source-ip-based" {
		t.Errorf("sdwan = %+v", out)
	}
}

func TestReadOnly(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	toolstest.ExpectError(t, env, "fgt_address_create", map[string]any{"device": "fw2", "name": "x"}, `device "fw2" is configured read-only`)
	if n := len(env.FW2.Requests()); n != 0 {
		t.Errorf("read-only device received %d requests", n)
	}

	ro := connectWrites(t, tools.Options{ReadOnly: true})
	res, err := ro.Session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("read-only mode registered %s", tool.Name)
		}
	}
}

func TestWriteAnnotations(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	res, err := env.Session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]bool{ // destructive, idempotent
		"fgt_address_create": {false, false},
		"fgt_address_update": {true, true},
		"fgt_address_delete": {true, true},
		"test_reboot":        {true, false},
	}
	for _, tool := range res.Tools {
		w, ok := want[tool.Name]
		if !ok {
			continue
		}
		a := tool.Annotations
		if a.ReadOnlyHint || a.DestructiveHint == nil || *a.DestructiveHint != w[0] || a.IdempotentHint != w[1] {
			t.Errorf("%s annotations = %+v", tool.Name, a)
		}
	}
}

func TestAuditRecords(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	toolstest.Call[tools.WriteOutput](t, env, "fgt_address_create", map[string]any{"name": "a", "fields": map[string]any{"subnet": "10.0.0.0/8"}})
	toolstest.CallError(t, env, "fgt_address_delete", map[string]any{"name": "missing"})

	recs := env.Audit(t)
	if len(recs) != 2 {
		t.Fatalf("records = %+v", recs)
	}
	if r := recs[0]; r.Tool != "fgt_address_create" || r.Device != "fw" || r.VDOM != "root" || r.Method != "POST" ||
		r.Path != "cmdb/firewall/address" || r.Result != "ok" || r.BodySHA256 == "" {
		t.Errorf("create record = %+v", r)
	}
	if r := recs[1]; r.Tool != "fgt_address_delete" || r.Result != "error" || r.HTTPStatus != 404 || r.Mkey != "missing" {
		t.Errorf("delete record = %+v", r)
	}
}

func TestConfirmation(t *testing.T) {
	env := connectWrites(t, tools.Options{})
	env.FW.SetMonitor("system/os/reboot", map[string]any{})
	rebootCalls := func() int {
		n := 0
		for _, r := range env.FW.Requests() {
			if r.Path == "monitor/system/os/reboot" {
				n++
			}
		}
		return n
	}

	out := toolstest.Call[tools.DisruptiveOutput](t, env, "test_reboot", nil)
	if out.Executed || out.Preview == nil || out.Preview.Hostname != "FGVM-FAKE" || out.Preview.Serial == "" || rebootCalls() != 0 {
		t.Errorf("no confirm: %+v", out)
	}

	out = toolstest.Call[tools.DisruptiveOutput](t, env, "test_reboot", map[string]any{"confirm": "fw-branch"})
	if out.Executed || out.Preview.Mismatch != "fw-branch" || rebootCalls() != 0 {
		t.Errorf("mismatch: %+v", out)
	}

	out = toolstest.Call[tools.DisruptiveOutput](t, env, "test_reboot", map[string]any{"confirm": " fgvm-fake "})
	if !out.Executed || rebootCalls() != 1 {
		t.Errorf("confirmed: %+v", out)
	}
	recs := env.Audit(t)
	if len(recs) != 1 || recs[0].ConfirmedHostname != "FGVM-FAKE" || recs[0].Tool != "test_reboot" {
		t.Errorf("audit = %+v", recs)
	}
}

func TestDisruptivePath(t *testing.T) {
	for _, p := range []string{"system/os/reboot", "system/os/shutdown", "system/config/restore", "system/firmware/upgrade", "firewall/session/clear_all", "system/os/anything", "firewall/session6/clear_all"} {
		if _, _, ok := tools.DisruptivePath(p); !ok {
			t.Errorf("%s should be disruptive", p)
		}
	}
	for _, p := range []string{"user/firewall/deauth", "system/dhcp/revoke", "firewall/session/close", "vpn/ipsec/tunnel_up"} {
		if _, _, ok := tools.DisruptivePath(p); ok {
			t.Errorf("%s should not be disruptive", p)
		}
	}
}
