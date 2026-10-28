package devices

import (
	"context"
	"strings"
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/test/fakefgt"
)

func dev(name, vdom string) config.Device {
	return config.Device{Name: name, Host: "https://" + name + ".example", Token: "t", VDOM: vdom}
}

func TestResolve(t *testing.T) {
	inv, err := New(&config.Config{Devices: []config.Device{dev("branch", "cust-a"), dev("hq", "root")}}, nil)
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
	single, err := New(&config.Config{Devices: []config.Device{dev("only", "root")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt, err := single.Resolve("", ""); err != nil || tgt.Device.Name != "only" {
		t.Errorf("single device implicit default: %+v, %v", tgt, err)
	}

	multi, err := New(&config.Config{DefaultDevice: "hq", Devices: []config.Device{dev("branch", "root"), dev("hq", "root")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tgt, err := multi.Resolve("", ""); err != nil || tgt.Device.Name != "hq" {
		t.Errorf("explicit default: %+v, %v", tgt, err)
	}
}

func TestNewErrors(t *testing.T) {
	if _, err := New(&config.Config{}, nil); err == nil {
		t.Error("expected error for empty inventory")
	}
	bad := dev("hq", "root")
	bad.CACert = "/nonexistent.pem"
	if _, err := New(&config.Config{Devices: []config.Device{bad}}, nil); err == nil || !strings.Contains(err.Error(), `device "hq"`) {
		t.Errorf("bad CA: err = %v", err)
	}
}

func TestClientUsesDeviceSettings(t *testing.T) {
	fgt := fakefgt.New(t)
	inv, err := New(&config.Config{Devices: []config.Device{{
		Name: "lab", Host: fgt.URL, Token: config.Secret(fgt.Token), VDOM: "cust-a", CACert: fgt.WriteCACert(t),
	}}}, nil)
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
