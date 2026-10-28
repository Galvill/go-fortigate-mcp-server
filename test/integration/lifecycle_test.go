//go:build integration

// Package integration runs the server against a real FortiGate (a lab VM).
// It creates objects prefixed mcp-test- and removes them afterwards. The
// test policy is created disabled, so it never affects traffic.
//
//	FORTIGATE_HOST=https://10.0.0.1 FORTIGATE_API_TOKEN=... \
//	FORTIGATE_INSECURE_SKIP_VERIFY=true \
//	FORTIGATE_TEST_SRCINTF=port1 FORTIGATE_TEST_DSTINTF=port2 \
//	go test -tags integration -v ./test/integration/
package integration

import (
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/server"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/system"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func connect(t *testing.T) (*toolstest.Env, *bytes.Buffer) {
	t.Helper()
	if _, ok := os.LookupEnv("FORTIGATE_HOST"); !ok {
		t.Skip("FORTIGATE_HOST not set")
	}
	fs := flag.NewFlagSet("integration", flag.ContinueOnError)
	cfg, err := config.BindFlags(fs).Load(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	var auditBuf bytes.Buffer
	inv, err := devices.New(cfg, devices.Options{Observer: audit.New(&auditBuf, false, nil).Observe})
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(server.Options{Version: "integration", Inventory: inv, Tools: tools.Options{MaxResultBytes: cfg.Server.MaxResultBytes}})
	if err != nil {
		t.Fatal(err)
	}
	return &toolstest.Env{Session: toolstest.ConnectServer(t, s)}, &auditBuf
}

func TestStatus(t *testing.T) {
	env, _ := connect(t)
	out := toolstest.Call[system.StatusOutput](t, env, "fgt_system_status", nil)
	t.Logf("connected to %s (%s) FortiOS %s build %d", out.Hostname, out.Model, out.Version, out.Build)
	if out.Hostname == "" || out.Version == "" {
		t.Errorf("status = %+v", out)
	}
}

// TestObjectPolicyLifecycle is the M3 acceptance test: address -> group ->
// policy -> move -> delete all, with audit records.
func TestObjectPolicyLifecycle(t *testing.T) {
	env, auditBuf := connect(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000)
	addr, grp := "mcp-test-addr-"+suffix, "mcp-test-grp-"+suffix

	toolstest.Call[tools.WriteOutput](t, env, "fgt_address_create", map[string]any{
		"name": addr, "fields": map[string]any{"subnet": "192.0.2.10 255.255.255.255", "comment": "fortigate-mcp integration test"},
	})
	t.Cleanup(func() { toolstest.CallMaybe(t, env, "fgt_address_delete", map[string]any{"name": addr}) })

	toolstest.Call[tools.WriteOutput](t, env, "fgt_addrgrp_create", map[string]any{
		"name": grp, "fields": map[string]any{"member": []map[string]string{{"name": addr}}},
	})
	t.Cleanup(func() { toolstest.CallMaybe(t, env, "fgt_addrgrp_delete", map[string]any{"name": grp}) })

	pol := toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_create", map[string]any{
		"name":    "mcp-test-" + suffix,
		"srcintf": []string{cmp.Or(os.Getenv("FORTIGATE_TEST_SRCINTF"), "port1")},
		"dstintf": []string{cmp.Or(os.Getenv("FORTIGATE_TEST_DSTINTF"), "port2")},
		"srcaddr": []string{grp}, "dstaddr": []string{"all"}, "service": []string{"ALL"},
		"action": "deny", "enabled": false, "comments": "fortigate-mcp integration test",
	})
	if pol.Mkey == "" || pol.Item == nil {
		t.Fatalf("policy create = %+v", pol)
	}
	t.Cleanup(func() { toolstest.CallMaybe(t, env, "fgt_policy_delete", map[string]any{"id": json.Number(pol.Mkey)}) })

	first := toolstest.Call[toolstest.List](t, env, "fgt_policy_list", map[string]any{"limit": 1, "fields": []string{"policyid"}})
	if len(first.Items) == 1 {
		toolstest.Call[tools.WriteOutput](t, env, "fgt_policy_move", map[string]any{"id": json.Number(pol.Mkey), "before": first.Items[0]["policyid"]})
		top := toolstest.Call[toolstest.List](t, env, "fgt_policy_list", map[string]any{"limit": 1, "fields": []string{"policyid"}})
		if fmt.Sprint(top.Items[0]["policyid"]) != pol.Mkey {
			t.Errorf("policy %s not at top after move: %v", pol.Mkey, top.Items)
		}
	}

	usage := toolstest.Call[toolstest.Results](t, env, "fgt_object_usage", map[string]any{"path": "firewall/addrgrp", "name": grp})
	t.Logf("object usage of %s: %v", grp, usage.Results)

	toolstest.Call[tools.DeleteOutput](t, env, "fgt_policy_delete", map[string]any{"id": json.Number(pol.Mkey)})
	toolstest.Call[tools.DeleteOutput](t, env, "fgt_addrgrp_delete", map[string]any{"name": grp})
	toolstest.Call[tools.DeleteOutput](t, env, "fgt_address_delete", map[string]any{"name": addr})

	var recorded []string
	for _, line := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Result != "ok" {
			t.Errorf("audit record not ok: %+v", r)
		}
		recorded = append(recorded, r.Tool)
	}
	t.Logf("audit: %v", recorded)
	if len(recorded) < 6 {
		t.Errorf("expected at least 6 audit records, got %d", len(recorded))
	}
}
