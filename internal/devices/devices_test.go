package devices

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

func dev(name, vdom string) config.Device {
	return config.Device{Name: name, Host: "https://" + name + ".example", Token: "t", VDOM: vdom}
}

func TestResolve(t *testing.T) {
	inv, err := New(&config.Config{Devices: []config.Device{dev("branch", "cust-a"), dev("hq", "root")}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Names(); strings.Join(got, ",") != "branch,hq" {
		t.Errorf("names = %v", got)
	}

	tgt, err := inv.Resolve("branch", "")
	if err != nil || tgt.Device.Name != "branch" || tgt.VDOM != "cust-a" || tgt.Params().VDOM != "cust-a" {
		t.Errorf("default vdom: %+v, %v", tgt, err)
	}
	tgt, err = inv.Resolve("hq", "other")
	if err != nil || tgt.VDOM != "other" {
		t.Errorf("vdom override: %+v, %v", tgt, err)
	}
	if _, err := inv.Resolve("", ""); err == nil || !strings.Contains(err.Error(), "branch, hq") {
		t.Errorf("no default with two devices: err = %v", err)
	}
	if _, err := inv.Resolve("nope", ""); err == nil || !strings.Contains(err.Error(), `unknown device "nope"`) {
		t.Errorf("unknown device: err = %v", err)
	}
}

func TestDefaultDevice(t *testing.T) {
	single, err := New(&config.Config{Devices: []config.Device{dev("only", "root")}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if tgt, err := single.Resolve("", ""); err != nil || tgt.Device.Name != "only" {
		t.Errorf("single device implicit default: %+v, %v", tgt, err)
	}

	multi, err := New(&config.Config{DefaultDevice: "hq", Devices: []config.Device{dev("branch", "root"), dev("hq", "root")}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if tgt, err := multi.Resolve("", ""); err != nil || tgt.Device.Name != "hq" {
		t.Errorf("explicit default: %+v, %v", tgt, err)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(&config.Config{}, Options{}); err == nil {
		t.Error("expected error for empty inventory")
	}
	bad := dev("hq", "root")
	bad.CACert = "/nonexistent.pem"
	if _, err := New(&config.Config{Devices: []config.Device{bad}}, Options{}); err == nil || !strings.Contains(err.Error(), `device "hq"`) {
		t.Errorf("bad CA: err = %v", err)
	}
}

func TestClientUsesDeviceSettings(t *testing.T) {
	fgt := fakefgt.New(t)
	inv, err := New(&config.Config{Devices: []config.Device{{
		Name: "lab", Host: fgt.URL, Token: config.Secret(fgt.Token), VDOM: "cust-a", CACert: fgt.WriteCACert(t),
	}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := inv.Resolve("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tgt.Device.Client.CMDBGet(context.Background(), "firewall/address", "", tgt.Params()); err != nil {
		t.Fatal(err)
	}
	if q := fgt.Requests()[0].Query; q.Get("vdom") != "cust-a" {
		t.Errorf("vdom = %q", q.Get("vdom"))
	}
}

func TestReadOnlyDeviceRefusesWrites(t *testing.T) {
	fgt := fakefgt.New(t)
	var observed int
	inv, err := New(&config.Config{Devices: []config.Device{{
		Name: "lab", Host: fgt.URL, Token: config.Secret(fgt.Token), VDOM: "root", CACert: fgt.WriteCACert(t), ReadOnly: true,
	}}}, Options{Observer: func(context.Context, fortios.Call) { observed++ }})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := inv.Get("lab")
	ctx := context.Background()
	if _, err := d.Client.CMDBCreate(ctx, "firewall/address", map[string]any{"name": "x"}, nil); !errors.Is(err, fortios.ErrReadOnly) {
		t.Errorf("create on read-only device: err = %v", err)
	}
	if _, err := d.Client.CMDBGet(ctx, "firewall/address", "", nil); err != nil {
		t.Errorf("read on read-only device: %v", err)
	}
	if len(fgt.Requests()) != 1 || observed != 0 {
		t.Errorf("requests = %d, observed = %d; the write must not reach the device", len(fgt.Requests()), observed)
	}
}

func TestObserverSeesWrites(t *testing.T) {
	fgt := fakefgt.New(t)
	var calls []fortios.Call
	inv, err := New(&config.Config{Devices: []config.Device{{
		Name: "lab", Host: fgt.URL, Token: config.Secret(fgt.Token), VDOM: "root", CACert: fgt.WriteCACert(t),
	}}}, Options{Observer: func(_ context.Context, c fortios.Call) { calls = append(calls, c) }})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := inv.Get("lab")
	ctx := context.Background()
	_, _ = d.Client.CMDBCreate(ctx, "firewall/address", map[string]any{"name": "x"}, nil)
	_, _ = d.Client.CMDBGet(ctx, "firewall/address", "x", nil)
	_, _ = d.Client.CMDBDelete(ctx, "firewall/address", "missing", nil)
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if c := calls[0]; c.Device != "lab" || c.Method != "POST" || c.Path != "cmdb/firewall/address" || c.VDOM != "root" ||
		c.HTTPStatus != 200 || c.Revision == "" || c.Err != nil || string(c.Body) != `{"name":"x"}` {
		t.Errorf("create call = %+v", c)
	}
	if c := calls[1]; c.Method != "DELETE" || c.Mkey != "missing" || c.HTTPStatus != 404 || c.Err == nil {
		t.Errorf("failed delete call = %+v", c)
	}
}
