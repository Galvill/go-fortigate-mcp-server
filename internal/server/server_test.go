package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// Prompts must only name tools that exist, and render their arguments.
func TestPromptsReferenceExistingTools(t *testing.T) {
	cs := connect(t, tools.Options{})
	ctx := context.Background()
	existing := map[string]bool{}
	for _, tool := range listTools(t, cs) {
		existing[tool.Name] = true
	}
	list, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Prompts) != 3 {
		t.Errorf("prompts = %d, want 3", len(list.Prompts))
	}
	toolName := regexp.MustCompile(`fgt_[a-z0-9_]+`)
	for _, p := range list.Prompts {
		args := map[string]string{"device": "hq", "vdom": "dmz"}
		for _, a := range p.Arguments {
			if a.Required {
				args[a.Name] = "ARG-" + a.Name
			}
		}
		res, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		text := res.Messages[0].Content.(*mcp.TextContent).Text
		for name := range args {
			if !strings.Contains(text, args[name]) {
				t.Errorf("%s: argument %s not rendered", p.Name, name)
			}
		}
		if strings.Contains(text, "%!") {
			t.Errorf("%s: formatting error in %q", p.Name, text)
		}
		for _, name := range toolName.FindAllString(text, -1) {
			if !existing[name] {
				t.Errorf("%s names unknown tool %s", p.Name, name)
			}
		}
		if req := slices.IndexFunc(p.Arguments, func(a *mcp.PromptArgument) bool { return a.Required }); req >= 0 {
			delete(args, p.Arguments[req].Name)
			if _, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: p.Name, Arguments: args}); err == nil {
				t.Errorf("%s: missing required argument accepted", p.Name)
			}
		}
	}
}

func TestResourcesRegistered(t *testing.T) {
	cs := connect(t, tools.Options{BackupDir: t.TempDir()})
	templates, err := cs.ListResourceTemplates(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates.ResourceTemplates) != 3 {
		t.Errorf("templates = %d, want 3 with a backup dir", len(templates.ResourceTemplates))
	}
}
