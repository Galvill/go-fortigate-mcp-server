package httpserver_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/httpserver"
	"github.com/galvill/go-fortigate-mcp-server/internal/metrics"
	"github.com/galvill/go-fortigate-mcp-server/internal/server"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

// syncBuffer is a bytes.Buffer safe for concurrent writers and readers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) records(t *testing.T) []audit.Record {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var recs []audit.Record
	for line := range strings.SplitSeq(strings.TrimSpace(s.b.String()), "\n") {
		if line == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	return recs
}

type fixture struct {
	fw, fw2 *fakefgt.Server
	audit   *syncBuffer
	cfg     config.HTTP
}

func newFixture(t *testing.T, stateless bool) *fixture {
	t.Helper()
	return &fixture{
		fw:    fakefgt.New(t),
		fw2:   fakefgt.New(t),
		audit: &syncBuffer{},
		cfg: config.HTTP{
			Path:           "/mcp",
			Stateless:      stateless,
			AllowedOrigins: []string{"https://console.example.com"},
			IdentityHeader: "X-Forwarded-User",
			MaxBodyBytes:   64 << 10,
		},
	}
}

// replica starts one server instance backed by the fixture's devices.
func (f *fixture) replica(t *testing.T) *httptest.Server {
	t.Helper()
	inv, err := devices.New(&config.Config{
		DefaultDevice: "fw",
		Devices:       []config.Device{toolstest.Device(t, "fw", f.fw), toolstest.Device(t, "fw2", f.fw2)},
	}, devices.Options{Observer: audit.New(f.audit, false, nil).Observe})
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(server.Options{Version: "test", Inventory: inv, Tools: tools.Options{
		MaxResultBytes: config.DefaultMaxResultBytes, IdentityHeader: f.cfg.IdentityHeader,
	}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(httpserver.Handler(httpserver.Options{Config: f.cfg, Server: s, Devices: inv.Names()}))
	t.Cleanup(ts.Close)
	return ts
}

// reply is an HTTP response with its JSON-RPC message (from a JSON or SSE
// body) decoded when the status is 200.
type reply struct {
	StatusCode int
	Header     http.Header
	Message    map[string]any
}

// post sends one JSON-RPC message.
func post(t *testing.T, url string, msg string, header http.Header) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	r := reply{StatusCode: resp.StatusCode, Header: resp.Header}
	if resp.StatusCode != http.StatusOK {
		return r
	}
	data := body
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				data = []byte(d)
			}
		}
	}
	if err := json.Unmarshal(data, &r.Message); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
	return r
}

func toolCall(name string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	return string(b)
}

func structured(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok || result["isError"] == true {
		t.Fatalf("tool call failed: %v", resp)
	}
	return result["structuredContent"].(map[string]any)
}

// A stateless server answers a tool call without initialization or a
// session ID, and one instance serves every configured device.
func TestStatelessWithoutSession(t *testing.T) {
	f := newFixture(t, true)
	ts := f.replica(t)

	for _, dev := range []string{"fw", "fw2"} {
		resp := post(t, ts.URL+"/mcp", toolCall("fgt_system_status", map[string]any{"device": dev}), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: HTTP %d", dev, resp.StatusCode)
		}
		if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
			t.Errorf("stateless response set a session ID %q", id)
		}
		if got := structured(t, resp.Message)["device"]; got != dev {
			t.Errorf("device = %v, want %s", got, dev)
		}
	}
	if len(f.fw.Requests()) == 0 || len(f.fw2.Requests()) == 0 {
		t.Error("both devices should have been queried")
	}
}

func TestOriginCheck(t *testing.T) {
	f := newFixture(t, true)
	ts := f.replica(t)
	call := toolCall("fgt_system_status", nil)

	for _, origin := range []string{"https://evil.example", "null", "https://console.example.com.evil.example"} {
		resp := post(t, ts.URL+"/mcp", call, http.Header{"Origin": {origin}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: HTTP %d, want 403", origin, resp.StatusCode)
		}
	}
	if n := len(f.fw.Requests()); n != 0 {
		t.Errorf("rejected requests reached the device %d times", n)
	}

	resp := post(t, ts.URL+"/mcp", call, http.Header{"Origin": {"https://Console.Example.com"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed origin: HTTP %d", resp.StatusCode)
	}
	// Non-browser clients send no Origin and are allowed.
	if resp := post(t, ts.URL+"/mcp", call, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("no origin: HTTP %d", resp.StatusCode)
	}
}

func TestBodyLimit(t *testing.T) {
	f := newFixture(t, true)
	ts := f.replica(t)
	big := toolCall("fgt_address_create", map[string]any{"name": "x", "fields": map[string]any{"comment": strings.Repeat("a", 100<<10)}})
	resp := post(t, ts.URL+"/mcp", big, nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("HTTP %d, want 413", resp.StatusCode)
	}
	if len(f.fw.Requests()) != 0 {
		t.Error("oversized request reached the device")
	}
}

func TestHealth(t *testing.T) {
	ts := newFixture(t, false).replica(t)
	for path, want := range map[string]string{"/healthz": `"ok"`, "/readyz": `["fw","fw2"]`} {
		resp, err := http.Get(ts.URL + path) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Errorf("%s: HTTP %d %s", path, resp.StatusCode, body)
		}
	}
}

// headerTransport adds headers to every request, like an authenticating proxy.
type headerTransport struct {
	header http.Header
	// hosts, if set, are used round-robin for successive requests.
	hosts []string
	n     atomic.Int64
	base  http.RoundTripper
}

func (h *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.header {
		r.Header[k] = v
	}
	if len(h.hosts) > 0 {
		r.URL.Host = h.hosts[int(h.n.Add(1))%len(h.hosts)]
	}
	return h.base.RoundTrip(r)
}

func connect(t *testing.T, endpoint string, rt *headerTransport) *mcp.ClientSession {
	t.Helper()
	rt.base = http.DefaultTransport
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &http.Client{Transport: rt}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: %v", name, res.Content)
	}
	return res
}

// Stateful sessions record the session ID, client address and the identity
// header from the proxy in audit records.
func TestStatefulAuditAttribution(t *testing.T) {
	f := newFixture(t, false)
	ts := f.replica(t)
	cs := connect(t, ts.URL+"/mcp", &headerTransport{header: http.Header{
		"X-Forwarded-User": {"alice@example.com"},
		// A client can't forge the address the server records.
		http.CanonicalHeaderKey(audit.RemoteAddrHeader): {"203.0.113.66:1"},
	}})
	if cs.ID() == "" {
		t.Fatal("stateful session has no ID")
	}
	callTool(t, cs, "fgt_address_create", map[string]any{"name": "web", "fields": map[string]any{"subnet": "192.0.2.1 255.255.255.255"}})

	recs := f.audit.records(t)
	if len(recs) != 1 {
		t.Fatalf("audit records = %+v", recs)
	}
	r := recs[0]
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if r.SessionID != cs.ID() || r.Identity != "alice@example.com" || host != "127.0.0.1" || r.Tool != "fgt_address_create" {
		t.Errorf("audit record = %+v", r)
	}
}

// Two stateless replicas behind a round-robin balancer serve one client
// without session affinity (the M4 acceptance criterion).
func TestStatelessReplicas(t *testing.T) {
	f := newFixture(t, true)
	a, b := f.replica(t), f.replica(t)
	rt := &headerTransport{hosts: []string{strings.TrimPrefix(a.URL, "http://"), strings.TrimPrefix(b.URL, "http://")}}
	cs := connect(t, a.URL+"/mcp", rt)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) < 100 {
		t.Errorf("tools = %d", len(tools.Tools))
	}
	for i := range 4 {
		dev := []string{"fw", "fw2"}[i%2]
		res := callTool(t, cs, "fgt_system_status", map[string]any{"device": dev})
		if got := res.StructuredContent.(map[string]any)["device"]; got != dev {
			t.Errorf("call %d: device = %v, want %s", i, got, dev)
		}
	}
	callTool(t, cs, "fgt_address_create", map[string]any{"name": "web", "fields": map[string]any{"subnet": "192.0.2.1 255.255.255.255"}})
	callTool(t, cs, "fgt_address_get", map[string]any{"name": "web"})
	if rt.n.Load() < 6 {
		t.Errorf("only %d requests went through the balancer", rt.n.Load())
	}
}

func TestServeShutdown(t *testing.T) {
	f := newFixture(t, false)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- httpserver.ServeListener(ctx, ln, httpserver.Options{Config: f.cfg, Server: mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)})
	}()

	url := "http://" + ln.Addr().String() + "/healthz"
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url) //nolint:noctx // test
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	f := newFixture(t, true)
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	get := func(h http.Handler) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
		return rec.Code
	}
	if code := get(httpserver.Handler(httpserver.Options{Config: f.cfg, Server: s})); code != http.StatusNotFound {
		t.Errorf("metrics disabled: HTTP %d, want 404", code)
	}
	m := metrics.New()
	if code := get(httpserver.Handler(httpserver.Options{Config: f.cfg, Server: s, Metrics: m.Handler()})); code != http.StatusOK {
		t.Errorf("metrics enabled: HTTP %d", code)
	}
}
