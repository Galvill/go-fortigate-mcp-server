// Package metrics collects Prometheus metrics for tool calls and FortiOS
// API requests.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
)

const namespace = "fortigate_mcp"

// Metrics holds the collectors. Its own registry keeps them separate from
// any global state.
type Metrics struct {
	reg          *prometheus.Registry
	toolCalls    *prometheus.CounterVec
	toolDuration *prometheus.HistogramVec
	apiRequests  *prometheus.CounterVec
	apiDuration  *prometheus.HistogramVec
}

// New creates the collectors, including Go runtime and process metrics.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		toolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "tool_calls_total",
			Help: "MCP tool calls by tool and result (ok, error).",
		}, []string{"tool", "result"}),
		toolDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "tool_call_duration_seconds",
			Help:    "MCP tool call latency by tool.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"tool"}),
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "fortios_requests_total",
			Help: "FortiOS REST API requests by device, method, API (cmdb, monitor, log) and HTTP status (0 when no response was received).",
		}, []string{"device", "method", "api", "code"}),
		apiDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "fortios_request_duration_seconds",
			Help:    "FortiOS REST API latency by device and API, including retries.",
			Buckets: []float64{0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"device", "api"}),
	}
	m.reg.MustRegister(m.toolCalls, m.toolDuration, m.apiRequests, m.apiDuration,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the metrics in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Middleware records tools/call outcomes and latency.
func (m *Metrics) Middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		call, ok := req.(*mcp.CallToolRequest)
		if !ok || call.Params == nil {
			return next(ctx, method, req)
		}
		start := time.Now()
		res, err := next(ctx, method, req)
		result := "ok"
		if r, ok := res.(*mcp.CallToolResult); err != nil || (ok && r.IsError) {
			result = "error"
		}
		m.toolCalls.WithLabelValues(call.Params.Name, result).Inc()
		m.toolDuration.WithLabelValues(call.Params.Name).Observe(time.Since(start).Seconds())
		return res, err
	}
}

// OnRequest records a FortiOS API request; pass it as fortios.Options.OnRequest.
func (m *Metrics) OnRequest(_ context.Context, c fortios.Call) {
	api, _, _ := strings.Cut(c.Path, "/")
	m.apiRequests.WithLabelValues(c.Device, c.Method, api, strconv.Itoa(c.HTTPStatus)).Inc()
	m.apiDuration.WithLabelValues(c.Device, api).Observe(c.Duration.Seconds())
}
