// Package toolstest connects an MCP client to tools backed by fake FortiGates.
package toolstest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

// Env is a client session over tools backed by two fake FortiGates:
// "fw" (the default device) and "fw2".
type Env struct {
	FW, FW2 *fakefgt.Server
	Session *mcp.ClientSession
}

// Connect registers tools with register and connects a client to them.
func Connect(t *testing.T, register func(*tools.Registry), opts tools.Options) *Env {
	t.Helper()
	env := &Env{FW: fakefgt.New(t), FW2: fakefgt.New(t)}
	inv, err := devices.New(&config.Config{
		DefaultDevice: "fw",
		Devices: []config.Device{
			Device(t, "fw", env.FW),
			Device(t, "fw2", env.FW2),
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.MaxResultBytes == 0 {
		opts.MaxResultBytes = config.DefaultMaxResultBytes
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	reg, err := tools.NewRegistry(s, inv, opts)
	if err != nil {
		t.Fatal(err)
	}
	register(reg)
	env.Session = ConnectServer(t, s)
	return env
}

// Device returns a config entry for a fake FortiGate.
func Device(t *testing.T, name string, fgt *fakefgt.Server) config.Device {
	t.Helper()
	return config.Device{
		Name:    name,
		Host:    fgt.URL,
		Token:   config.Secret(fgt.Token),
		VDOM:    "root",
		CACert:  fgt.WriteCACert(t),
		Timeout: config.DefaultTimeout,
	}
}

// ConnectServer connects an in-memory client to s.
func ConnectServer(t *testing.T, s *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func (e *Env) call(t *testing.T, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	res, err := e.Session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// Call calls a tool that must succeed and decodes its structured output.
func Call[Out any](t *testing.T, e *Env, name string, args map[string]any) Out {
	t.Helper()
	res := e.call(t, name, args)
	if res.IsError {
		t.Fatalf("%s returned error: %s", name, text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out Out
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: decoding output %s: %v", name, b, err)
	}
	return out
}

// CallError calls a tool that must fail and returns the error text.
func CallError(t *testing.T, e *Env, name string, args map[string]any) string {
	t.Helper()
	res := e.call(t, name, args)
	if !res.IsError {
		t.Fatalf("%s: expected error, got %s", name, text(res))
	}
	return text(res)
}

// ExpectError calls a tool that must fail with an error containing want.
func ExpectError(t *testing.T, e *Env, name string, args map[string]any, want string) {
	t.Helper()
	if got := CallError(t, e, name, args); !strings.Contains(got, want) {
		t.Errorf("%s: error %q does not contain %q", name, got, want)
	}
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Generic output shapes for decoding in tests.
type (
	List struct {
		Device     string           `json:"device"`
		VDOM       string           `json:"vdom"`
		Items      []map[string]any `json:"items"`
		Total      int              `json:"total"`
		Truncated  bool             `json:"truncated"`
		NextOffset int              `json:"next_offset"`
	}
	Item struct {
		Device string         `json:"device"`
		VDOM   string         `json:"vdom"`
		Item   map[string]any `json:"item"`
	}
	Results struct {
		Device    string `json:"device"`
		VDOM      string `json:"vdom"`
		Results   any    `json:"results"`
		Truncated bool   `json:"truncated"`
	}
)
