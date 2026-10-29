package resources_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/resources"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

type env struct {
	fw, fw2 *fakefgt.Server
	session *mcp.ClientSession
}

func setup(t *testing.T, backupDir string, maxBytes int) *env {
	t.Helper()
	e := &env{fw: fakefgt.New(t), fw2: fakefgt.New(t)}
	fw2 := toolstest.Device(t, "fw_2", e.fw2)
	fw2.VDOM = "dmz"
	fw2.ReadOnly = true
	inv, err := devices.New(&config.Config{
		DefaultDevice: "fw",
		Devices:       []config.Device{toolstest.Device(t, "fw", e.fw), fw2},
	}, devices.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	resources.Register(s, resources.Options{Inventory: inv, BackupDir: backupDir, MaxBytes: maxBytes})
	e.session = toolstest.ConnectServer(t, s)
	return e
}

func (e *env) read(t *testing.T, uri string) *mcp.ResourceContents {
	t.Helper()
	res, err := e.session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("%s: contents = %v", uri, res.Contents)
	}
	return res.Contents[0]
}

func (e *env) readJSON(t *testing.T, uri string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(e.read(t, uri).Text), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) readError(t *testing.T, uri, want string) {
	t.Helper()
	_, err := e.session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want containing %q", uri, err, want)
	}
}

func TestListing(t *testing.T) {
	e := setup(t, "", 100_000)
	ctx := context.Background()
	list, err := e.session.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, r := range list.Resources {
		uris = append(uris, r.URI)
	}
	slices.Sort(uris)
	want := []string{"fortigate://devices", "fortigate://fw/root/policies", "fortigate://fw/status", "fortigate://fw_2/dmz/policies", "fortigate://fw_2/status"}
	if !slices.Equal(uris, want) {
		t.Errorf("resources = %v, want %v", uris, want)
	}
	templates, err := e.session.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates.ResourceTemplates) != 2 {
		t.Errorf("templates without backup dir = %d, want 2", len(templates.ResourceTemplates))
	}

	e.readError(t, "fortigate://fw/backup/latest", "not found")
}

func TestDevicesAndStatus(t *testing.T) {
	e := setup(t, "", 100_000)
	c := e.read(t, "fortigate://devices")
	if c.MIMEType != "application/json" || strings.Contains(c.Text, fakefgt.DefaultToken) {
		t.Errorf("devices = %+v", c)
	}
	var devs []map[string]any
	if err := json.Unmarshal([]byte(c.Text), &devs); err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0]["default"] != true || devs[1]["read_only"] != true || devs[1]["policies_uri"] != "fortigate://fw_2/dmz/policies" {
		t.Errorf("devices = %v", devs)
	}
	if n := len(e.fw.Requests()); n != 0 {
		t.Errorf("devices resource contacted a device %d times", n)
	}

	st := e.readJSON(t, "fortigate://fw_2/status")
	if st["device"] != "fw_2" || st["hostname"] != fakefgt.DefaultHostname || st["model"] != "FGVM64" {
		t.Errorf("status = %v", st)
	}
	e.readError(t, "fortigate://nope/status", "not found")
	e.readError(t, "fortigate://fw/whatever", "not found")
}

func TestPolicies(t *testing.T) {
	e := setup(t, "", 100_000)
	e.fw.Seed("dmz", "firewall/policy",
		map[string]any{"policyid": 7, "name": "web", "action": "accept", "srcintf": []any{map[string]any{"name": "port1"}},
			"srcaddr": []any{map[string]any{"name": "all"}}, "dstaddr6": []any{}, "comments": "", "uuid": "x"})
	out := e.readJSON(t, "fortigate://fw/dmz/policies")
	pols := out["policies"].([]any)
	if out["vdom"] != "dmz" || out["count"] != float64(1) || len(pols) != 1 {
		t.Fatalf("policies = %v", out)
	}
	p := pols[0].(map[string]any)
	if p["srcintf"].([]any)[0] != "port1" || p["policyid"] != float64(7) {
		t.Errorf("policy = %v", p)
	}
	for _, k := range []string{"dstaddr6", "comments", "uuid"} {
		if _, ok := p[k]; ok {
			t.Errorf("%s should be omitted: %v", k, p)
		}
	}
	if q := e.fw.Requests()[0].Query; q.Get("vdom") != "dmz" || !strings.Contains(q.Get("format"), "policyid") {
		t.Errorf("query = %v", q)
	}
}

func TestLatestBackup(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"fw_global_20260101T000000Z.conf":        "old",
		"fw_vdom-root_20260301T000000Z.conf":     "newest",
		"fw_global_20260201T000000Z.conf":        "middle",
		"fw_2_global_20260401T000000Z.conf":      "other device",
		"fw_global_20260501T000000Z.conf.tmp":    "not a backup",
		"notes.txt":                              "ignored",
		"fw_2_vdom-dmz_20250101T000000Z.conf":    "fw_2 only",
		"fw_global_20260301T000000Z.conf.backup": "ignored",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := setup(t, dir, 4096)
	c := e.read(t, "fortigate://fw/backup/latest")
	if c.Text != "newest" || c.MIMEType != "text/plain" || c.Meta["file"] != "fw_vdom-root_20260301T000000Z.conf" {
		t.Errorf("fw latest = %+v", c)
	}
	if c := e.read(t, "fortigate://fw_2/backup/latest"); c.Text != "other device" {
		t.Errorf("fw_2 latest = %q", c.Text)
	}

	if err := os.WriteFile(filepath.Join(dir, "fw_global_20270101T000000Z.conf"), []byte(strings.Repeat("x", 5000)), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := e.read(t, "fortigate://fw/backup/latest"); len(c.Text) > 4200 || !strings.Contains(c.Text, "truncated") {
		t.Errorf("large backup not truncated: %d bytes", len(c.Text))
	}

	empty := setup(t, t.TempDir(), 4096)
	empty.readError(t, "fortigate://fw/backup/latest", "no backup of fw")
}
