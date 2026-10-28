package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

var update = flag.Bool("update", false, "rewrite golden files")

func connect(t *testing.T, opts tools.Options) *mcp.ClientSession {
	t.Helper()
	inv, err := devices.New(&config.Config{Devices: []config.Device{toolstest.Device(t, "fw", fakefgt.New(t))}}, devices.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.MaxResultBytes == 0 {
		opts.MaxResultBytes = config.DefaultMaxResultBytes
	}
	s, err := New(Options{Version: "test", Inventory: inv, Tools: opts})
	if err != nil {
		t.Fatal(err)
	}
	return toolstest.ConnectServer(t, s)
}

func listTools(t *testing.T, cs *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

func TestServerInfo(t *testing.T) {
	cs := connect(t, tools.Options{})
	res := cs.InitializeResult()
	if res.ServerInfo.Name != Name || res.ServerInfo.Version != "test" || res.Instructions == "" {
		t.Errorf("initialize result = %+v", res)
	}
}

func TestPing(t *testing.T) {
	cs := connect(t, tools.Options{})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"})
	if err != nil || res.IsError {
		t.Fatalf("ping: %v %v", res, err)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out PingOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if want := (PingOutput{Message: "pong", Version: "test"}); out != want {
		t.Errorf("ping output = %+v, want %+v", out, want)
	}
}

func TestToolConventions(t *testing.T) {
	for _, tool := range listTools(t, connect(t, tools.Options{})) {
		if tool.Description == "" {
			t.Errorf("%s: no description", tool.Name)
		}
		if tool.Annotations == nil {
			t.Errorf("%s: no annotations", tool.Name)
		} else if !tool.Annotations.ReadOnlyHint && tool.Annotations.DestructiveHint == nil {
			t.Errorf("%s: write tools must set destructiveHint", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s: no output schema", tool.Name)
		}
		if len(tool.Name) > 64 {
			t.Errorf("%s: name longer than 64 characters", tool.Name)
		}
	}
}

func TestToolsetSelection(t *testing.T) {
	all := listTools(t, connect(t, tools.Options{}))
	some := listTools(t, connect(t, tools.Options{Toolsets: []string{tools.VPN}}))
	if len(some) >= len(all) {
		t.Errorf("vpn only: %d tools, all: %d", len(some), len(all))
	}
	for _, tool := range some {
		if tool.Name != "ping" && !strings.HasPrefix(tool.Name, "fgt_ipsec_") && !strings.HasPrefix(tool.Name, "fgt_sslvpn_") {
			t.Errorf("unexpected tool with vpn toolset: %s", tool.Name)
		}
	}
	if _, err := New(Options{Tools: tools.Options{Toolsets: []string{"nope"}}}); err == nil {
		t.Error("unknown toolset: expected error")
	}
}

func TestReadOnlyMode(t *testing.T) {
	all := listTools(t, connect(t, tools.Options{}))
	ro := listTools(t, connect(t, tools.Options{ReadOnly: true}))
	if len(ro) == 0 || len(ro) >= len(all) {
		t.Fatalf("read-only: %d tools, all: %d", len(ro), len(all))
	}
	for _, tool := range ro {
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("read-only mode registered write tool %s", tool.Name)
		}
	}
}

func TestDisruptiveToolsTakeConfirm(t *testing.T) {
	byName := map[string]*mcp.Tool{}
	for _, tool := range listTools(t, connect(t, tools.Options{})) {
		byName[tool.Name] = tool
	}
	for _, name := range []string{"fgt_reboot", "fgt_shutdown", "fgt_config_restore", "fgt_firmware_upgrade", "fgt_session_clear", "fgt_monitor_post"} {
		tool, ok := byName[name]
		if !ok {
			t.Errorf("%s not registered", name)
			continue
		}
		schema, _ := json.Marshal(tool.InputSchema)
		if !strings.Contains(string(schema), `"confirm"`) {
			t.Errorf("%s has no confirm parameter", name)
		}
	}
}

// TestToolSchemasGolden snapshots every tool's name, description, schemas and
// annotations. Tool names and schemas are the server's API: review diffs.
// Regenerate with: go test ./internal/server -run Golden -update
func TestToolSchemasGolden(t *testing.T) {
	got, err := json.MarshalIndent(listTools(t, connect(t, tools.Options{})), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "tools.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("tool schemas changed; review and run: go test ./internal/server -run Golden -update")
	}
}
