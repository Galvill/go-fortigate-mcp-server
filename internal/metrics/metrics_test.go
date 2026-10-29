package metrics_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/metrics"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestToolAndAPIMetrics(t *testing.T) {
	m := metrics.New()
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "good"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		return nil, struct{}{}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "bad"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		return nil, struct{}{}, errors.New("boom")
	})
	s.AddReceivingMiddleware(m.Middleware)
	cs := toolstest.ConnectServer(t, s)
	for _, name := range []string{"good", "good", "bad"} {
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{}}); err != nil {
			t.Fatal(err)
		}
	}
	m.OnRequest(context.Background(), fortios.Call{Device: "hq", Method: http.MethodGet, Path: "cmdb/firewall/policy/3", HTTPStatus: 200, Duration: 40 * time.Millisecond})
	m.OnRequest(context.Background(), fortios.Call{Device: "hq", Method: http.MethodPost, Path: "monitor/system/os/reboot", Duration: time.Second})

	out := scrape(t, m)
	for _, want := range []string{
		`fortigate_mcp_tool_calls_total{result="ok",tool="good"} 2`,
		`fortigate_mcp_tool_calls_total{result="error",tool="bad"} 1`,
		`fortigate_mcp_tool_call_duration_seconds_count{tool="good"} 2`,
		`fortigate_mcp_fortios_requests_total{api="cmdb",code="200",device="hq",method="GET"} 1`,
		`fortigate_mcp_fortios_requests_total{api="monitor",code="0",device="hq",method="POST"} 1`,
		`fortigate_mcp_fortios_request_duration_seconds_count{api="cmdb",device="hq"} 1`,
		`go_goroutines`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}
