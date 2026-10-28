package fortios_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

func newClient(t *testing.T, fgt *fakefgt.Server, mod ...func(*fortios.Options)) *fortios.Client {
	t.Helper()
	opts := fortios.Options{
		Name:         "test",
		BaseURL:      fgt.URL,
		Token:        fgt.Token,
		VDOM:         "root",
		CACertFile:   fgt.WriteCACert(t),
		RetryBackoff: time.Millisecond,
	}
	for _, m := range mod {
		m(&opts)
	}
	c, err := fortios.New(opts)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

type policy struct {
	PolicyID int    `json:"policyid"`
	Name     string `json:"name"`
	Action   string `json:"action"`
}

func policyIDs(t *testing.T, c *fortios.Client) []int {
	t.Helper()
	resp, err := c.CMDBGet(context.Background(), "firewall/policy", "", nil)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	var ps []policy
	if err := resp.Decode(&ps); err != nil {
		t.Fatal(err)
	}
	ids := make([]int, len(ps))
	for i, p := range ps {
		ids[i] = p.PolicyID
	}
	return ids
}

// TestPolicyLifecycle is the M1 acceptance test: create, list, update, move
// and delete a policy through the client against the fake FortiGate.
func TestPolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)

	var created []string
	for _, name := range []string{"allow-web", "allow-dns", "deny-all"} {
		resp, err := c.CMDBCreate(ctx, "firewall/policy", map[string]any{
			"name": name, "action": "accept",
			"srcintf": []map[string]string{{"name": "port1"}},
		}, nil)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if !resp.RevisionChanged || resp.Mkey == "" {
			t.Errorf("create %s: response = %+v", name, resp)
		}
		created = append(created, string(resp.Mkey))
	}
	if want := []string{"1", "2", "3"}; !slices.Equal(created, want) {
		t.Fatalf("created mkeys = %v, want %v", created, want)
	}

	if _, err := c.CMDBUpdate(ctx, "firewall/policy", "3", map[string]any{"action": "deny"}, nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	resp, err := c.CMDBGet(ctx, "firewall/policy", "3", nil)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var got []policy
	if err := resp.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (policy{3, "deny-all", "deny"}) {
		t.Errorf("after update = %+v", got)
	}

	if _, err := c.CMDBMove(ctx, "firewall/policy", "3", fortios.Before, "1", nil); err != nil {
		t.Fatalf("move: %v", err)
	}
	if ids := policyIDs(t, c); !slices.Equal(ids, []int{3, 1, 2}) {
		t.Errorf("order after move before = %v, want [3 1 2]", ids)
	}
	if _, err := c.CMDBMove(ctx, "firewall/policy", "3", fortios.After, "2", nil); err != nil {
		t.Fatalf("move: %v", err)
	}
	if ids := policyIDs(t, c); !slices.Equal(ids, []int{1, 2, 3}) {
		t.Errorf("order after move after = %v, want [1 2 3]", ids)
	}

	if _, err := c.CMDBDelete(ctx, "firewall/policy", "2", nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ids := policyIDs(t, c); !slices.Equal(ids, []int{1, 3}) {
		t.Errorf("after delete = %v, want [1 3]", ids)
	}
	if _, err := c.CMDBGet(ctx, "firewall/policy", "2", nil); !fortios.IsNotFound(err) {
		t.Errorf("get deleted: err = %v, want not found", err)
	}
}

func TestNewErrors(t *testing.T) {
	fgt := fakefgt.New(t)
	tests := map[string]fortios.Options{
		"http url":    {BaseURL: "http://fw", Token: "t"},
		"bad url":     {BaseURL: "::", Token: "t"},
		"empty token": {BaseURL: fgt.URL},
		"missing ca":  {BaseURL: fgt.URL, Token: "t", CACertFile: "/nonexistent.pem"},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := fortios.New(opts); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestTLSVerification(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)

	noCA := newClient(t, fgt, func(o *fortios.Options) { o.CACertFile = "" })
	if _, err := noCA.Status(ctx); err == nil {
		t.Error("expected TLS verification failure without CA")
	}
	insecure := newClient(t, fgt, func(o *fortios.Options) { o.CACertFile = ""; o.InsecureSkipVerify = true })
	if _, err := insecure.Status(ctx); err != nil {
		t.Errorf("insecure client: %v", err)
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)

	var apiErr *fortios.APIError

	bad := newClient(t, fgt, func(o *fortios.Options) { o.Token = "wrong" })
	_, err := bad.Status(ctx)
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusUnauthorized || !strings.Contains(err.Error(), "trusted hosts") {
		t.Errorf("bad token: err = %v", err)
	}

	_, err = c.CMDBGet(ctx, "firewall/address", "nope", nil)
	if !fortios.IsNotFound(err) || !errors.As(err, &apiErr) || apiErr.Code != -3 {
		t.Errorf("not found: err = %v", err)
	}

	fgt.Seed("root", "firewall/address", map[string]any{"name": "web"})
	_, err = c.CMDBCreate(ctx, "firewall/address", map[string]any{"name": "web"}, nil)
	if !errors.As(err, &apiErr) || apiErr.Code != -5 || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate: err = %v", err)
	}

	if _, err := c.CMDBDelete(ctx, "firewall/address", "", nil); err == nil {
		t.Error("delete without mkey: expected error")
	}
	if _, err := c.CMDBMove(ctx, "firewall/policy", "1", "sideways", "2", nil); err == nil {
		t.Error("invalid move position: expected error")
	}
}

func TestPathValidation(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)
	for _, p := range []string{"", "../etc", "firewall/../system", "firewall/policy?x=1", "/firewall/policy", "Firewall/policy", "https://evil/x", "firewall//policy"} {
		if _, err := c.CMDBGet(ctx, p, "", nil); err == nil {
			t.Errorf("path %q: expected error", p)
		}
	}
	if len(fgt.Requests()) != 0 {
		t.Errorf("invalid paths reached the device: %v", fgt.Requests())
	}
	for _, p := range []string{"firewall/policy", "firewall.service/custom", "vpn.ipsec/phase1-interface"} {
		if err := fortios.ValidatePath(p); err != nil {
			t.Errorf("path %q: %v", p, err)
		}
	}
}

func TestMkeyEscaping(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)
	name := "web/1 srv?#"
	if _, err := c.CMDBCreate(ctx, "firewall/address", map[string]any{"name": name}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CMDBGet(ctx, "firewall/address", name, nil); err != nil {
		t.Fatalf("get escaped mkey: %v", err)
	}
	reqs := fgt.Requests()
	if got := reqs[len(reqs)-1].Path; got != "cmdb/firewall/address/web%2F1%20srv%3F%23" {
		t.Errorf("escaped path = %q", got)
	}
}

func TestQueryParams(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt, func(o *fortios.Options) { o.VDOM = "cust-a" })
	fgt.Seed("cust-a", "firewall/address", map[string]any{"name": "web1", "subnet": "10.0.0.1 255.255.255.255"},
		map[string]any{"name": "web2", "subnet": "10.0.0.2 255.255.255.255"},
		map[string]any{"name": "db1", "subnet": "10.0.1.1 255.255.255.255"})

	resp, err := c.CMDBGet(ctx, "firewall/address", "", &fortios.Params{
		Filter: []string{"name=@web"}, Format: []string{"name"}, Start: 1, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := resp.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["name"] != "web2" || got[0]["subnet"] != nil || resp.MatchedCount != 2 {
		t.Errorf("results = %v, matched = %d", got, resp.MatchedCount)
	}
	q := fgt.Requests()[0].Query
	if q.Get("vdom") != "cust-a" || q.Get("filter") != "name=@web" || q.Get("format") != "name" || q.Get("start") != "1" || q.Get("count") != "1" {
		t.Errorf("query = %v", q)
	}

	if _, err := c.CMDBGet(ctx, "firewall/address", "", &fortios.Params{VDOM: "root"}); err != nil {
		t.Fatal(err)
	}
	if q := fgt.Requests()[1].Query; q.Get("vdom") != "root" {
		t.Errorf("vdom override: query = %v", q)
	}
}

func TestListAll(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)
	for range 7 {
		fgt.Seed("root", "firewall/policy", map[string]any{"action": "accept"})
	}

	items, more, err := c.ListAll(ctx, "firewall/policy", nil, 3, 100)
	if err != nil || len(items) != 7 || more {
		t.Errorf("all: len = %d, more = %v, err = %v", len(items), more, err)
	}
	items, more, err = c.ListAll(ctx, "firewall/policy", nil, 3, 5)
	if err != nil || len(items) != 5 || !more {
		t.Errorf("capped: len = %d, more = %v, err = %v", len(items), more, err)
	}
	items, more, err = c.ListAll(ctx, "firewall/policy", nil, 3, 7)
	if err != nil || len(items) != 7 || more {
		t.Errorf("exact cap: len = %d, more = %v, err = %v", len(items), more, err)
	}
}

func TestRetries(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)

	fgt.FailNext(http.MethodGet, "monitor/system/status", http.StatusServiceUnavailable, 2)
	if _, err := c.Status(ctx); err != nil {
		t.Errorf("GET should succeed on third attempt: %v", err)
	}

	fgt.FailNext(http.MethodGet, "monitor/system/status", http.StatusServiceUnavailable, 3)
	if _, err := c.Status(ctx); err == nil {
		t.Error("GET should fail after 3 attempts")
	}

	before := len(fgt.Requests())
	fgt.FailNext(http.MethodPost, "cmdb/firewall/address", http.StatusServiceUnavailable, 1)
	if _, err := c.CMDBCreate(ctx, "firewall/address", map[string]any{"name": "x"}, nil); err == nil {
		t.Error("POST should not be retried")
	}
	if n := len(fgt.Requests()) - before; n != 1 {
		t.Errorf("POST attempts = %d, want 1", n)
	}

	before = len(fgt.Requests())
	fgt.FailNext(http.MethodGet, "cmdb/firewall/address", http.StatusBadRequest, 1)
	if _, err := c.CMDBGet(ctx, "firewall/address", "", nil); err == nil {
		t.Error("400 should not be retried")
	}
	if n := len(fgt.Requests()) - before; n != 1 {
		t.Errorf("GET 400 attempts = %d, want 1", n)
	}
}

func TestContextCancel(t *testing.T) {
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Status(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": []any{}})
	}))
	defer srv.Close()

	c, err := fortios.New(fortios.Options{BaseURL: srv.URL, Token: "t", InsecureSkipVerify: true, MaxConcurrent: 2})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	for range 6 {
		go func() {
			_, err := c.CMDBGet(context.Background(), "firewall/address", "", nil)
			done <- err
		}()
	}
	for range 6 {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	if p := peak.Load(); p > 2 {
		t.Errorf("peak concurrency = %d, want <= 2", p)
	}
}

func TestVersionInfo(t *testing.T) {
	ctx := context.Background()
	fgt := fakefgt.New(t)
	c := newClient(t, fgt)

	// Info is learned from any response, without a dedicated status call.
	if _, err := c.CMDBGet(ctx, "firewall/address", "", nil); err != nil {
		t.Fatal(err)
	}
	info, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != (fortios.Version{Major: 7, Minor: 4, Patch: 4}) || info.Serial != fakefgt.DefaultSerial || info.Build != fakefgt.DefaultBuild {
		t.Errorf("info = %+v", info)
	}
	if n := len(fgt.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Hostname != fakefgt.DefaultHostname || st.Model != "FGVM64" || st.Version.String() != "7.4.4" {
		t.Errorf("status = %+v", st)
	}
}

func TestParseVersion(t *testing.T) {
	v, err := fortios.ParseVersion("v7.6.3")
	if err != nil || v != (fortios.Version{Major: 7, Minor: 6, Patch: 3}) {
		t.Fatalf("v = %v, err = %v", v, err)
	}
	checks := []struct {
		maj, min, patch int
		want            bool
	}{
		{7, 6, 3, true}, {7, 6, 4, false}, {7, 4, 9, true}, {8, 0, 0, false}, {6, 4, 15, true},
	}
	for _, c := range checks {
		if got := v.AtLeast(c.maj, c.min, c.patch); got != c.want {
			t.Errorf("%v.AtLeast(%d.%d.%d) = %v", v, c.maj, c.min, c.patch, got)
		}
	}
	for _, bad := range []string{"", "7.4", "v7.x.1", "7.4.4.1"} {
		if _, err := fortios.ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q): expected error", bad)
		}
	}
}
