// Package conformance checks the server against the official TypeScript MCP
// SDK client (client.mjs), which is stricter than the Go SDK about schemas.
//
// It needs Node.js and the pinned SDK, so it runs only when asked:
//
//	make conformance
//
// or: (cd test/conformance && npm ci) && MCP_CONFORMANCE=1 go test ./test/conformance/
package conformance

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/httpserver"
	"github.com/galvill/go-fortigate-mcp-server/internal/server"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

type report struct {
	Counts struct {
		Tools, ToolCalls, ToolErrors, Prompts, Resources, ResourceTemplates int
	}
	Failures   []string
	ToolErrors map[string]string
}

func TestTypeScriptSDKClient(t *testing.T) {
	if os.Getenv("MCP_CONFORMANCE") == "" {
		t.Skip("set MCP_CONFORMANCE=1 after npm ci in test/conformance (or run make conformance)")
	}
	if _, err := os.Stat("node_modules/@modelcontextprotocol/sdk"); err != nil {
		t.Fatalf("TypeScript SDK not installed; run npm ci in test/conformance: %v", err)
	}

	fgt := fakefgt.New(t)
	seed(fgt)
	inv, err := devices.New(&config.Config{Devices: []config.Device{toolstest.Device(t, "fw", fgt)}}, devices.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(server.Options{Version: "test", Inventory: inv, Tools: tools.Options{
		MaxResultBytes: config.DefaultMaxResultBytes, BackupDir: t.TempDir(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(httpserver.Handler(httpserver.Options{
		Config: config.HTTP{Path: "/mcp", MaxBodyBytes: config.DefaultMaxBodyBytes}, Server: s, Devices: inv.Names(),
	}))
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "client.mjs", ts.URL+"/mcp")
	cmd.Stderr = os.Stderr
	out, runErr := cmd.Output()

	var r report
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("client output is not a report (%v, run error %v):\n%s", err, runErr, out)
	}
	t.Logf("TypeScript SDK client: %+v", r.Counts)
	// Tools that return an error have no structured output to validate.
	for name, msg := range r.ToolErrors {
		t.Errorf("%s returned an error, so its output was not validated; seed the endpoint it needs: %s", name, msg)
	}
	for _, f := range r.Failures {
		t.Error(f)
	}
	if runErr != nil && len(r.Failures) == 0 {
		t.Fatalf("client failed: %v", runErr)
	}
	// Guard against a vacuous pass, e.g. if the tool or call selection breaks.
	if r.Counts.Tools < 100 || r.Counts.ToolCalls < 30 || r.Counts.Prompts < 3 || r.Counts.Resources < 3 || r.Counts.ResourceTemplates < 3 {
		t.Errorf("client exercised too little of the server: %+v", r.Counts)
	}
}

// seed gives the monitor endpoints and singleton tables that the no-argument
// read tools use realistic responses, so their structured output reaches the
// SDK's outputSchema validation instead of failing with a 404.
func seed(fgt *fakefgt.Server) {
	for path, results := range map[string]any{
		"system/ha-checksums":           []any{map[string]any{"serial_no": "FGVM00FAKE000001", "is_root_primary": 1}},
		"system/ha-peer":                []any{map[string]any{"serial_no": "FGVM00FAKE000001", "hostname": "fw", "priority": 128, "role": "primary"}},
		"system/resource/usage":         map[string]any{"cpu": []any{map[string]any{"current": 3}}, "mem": []any{map[string]any{"current": 41}}},
		"license/status":                map[string]any{"forticare": map[string]any{"status": "registered"}},
		"system/firmware":               map[string]any{"current": map[string]any{"version": "v7.4.4", "build": 2662}, "available": []any{}},
		"system/available-certificates": []any{map[string]any{"name": "Fortinet_Factory", "type": "local-cer"}},
		"system/config-revision":        []any{map[string]any{"id": 1, "comment": "initial"}},
		"system/interface":              map[string]any{"port1": map[string]any{"name": "port1", "link": true, "speed": 1000, "ip": "10.0.0.1"}},
		"system/dhcp":                   []any{map[string]any{"ip": "10.0.0.50", "mac": "00:11:22:33:44:55", "interface": "port2"}},
		"network/arp":                   []any{map[string]any{"ip": "10.0.0.2", "mac": "00:11:22:33:44:66", "interface": "port1"}},
		"router/ipv4":                   []any{map[string]any{"ip_mask": "0.0.0.0/0", "gateway": "10.0.0.254", "interface": "port1", "type": "static"}},
		"firewall/session":              map[string]any{"details": []any{map[string]any{"proto": "tcp", "saddr": "10.0.0.50", "daddr": "192.0.2.10", "dport": 443}}, "total": 1},
		"firewall/policy":               []any{map[string]any{"policyid": 1, "hit_count": 42, "bytes": 1024}},
		"vpn/ipsec":                     []any{map[string]any{"name": "to-branch", "proxyid": []any{map[string]any{"status": "up"}}}},
		"virtual-wan/health-check":      map[string]any{"google": map[string]any{"port1": map[string]any{"status": "up", "latency": 4.2}}},
		"virtual-wan/members":           map[string]any{"port1": map[string]any{"link": "up"}},
		"vpn/ssl":                       []any{map[string]any{"user_name": "alice"}},
	} {
		fgt.SetMonitor(path, results)
	}
	fgt.SetDownload("system/config/backup", []byte("#config-version=FGVM64-7.4.4\nconfig system global\n    set hostname \"fw\"\nend\n"))
	fgt.SetSingleton("root", "system/sdwan", map[string]any{"status": "enable", "load-balance-mode": "source-ip-based"})
	fgt.SetSingleton("root", "vpn.ssl/settings", map[string]any{"status": "enable", "port": 10443})
}
