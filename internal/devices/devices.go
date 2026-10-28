// Package devices holds the FortiGate inventory and resolves which device
// and VDOM a tool call targets.
package devices

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/galvill/go-fortigate-mcp-server/internal/config"
	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
)

// Device is a configured FortiGate with its API client.
type Device struct {
	Name     string
	Host     string
	VDOM     string
	ReadOnly bool
	Client   *fortios.Client
}

// Target is a resolved device and VDOM for one call.
type Target struct {
	Device *Device
	VDOM   string
}

// Params returns fortios.Params scoped to the target's VDOM.
func (t Target) Params() *fortios.Params {
	return &fortios.Params{VDOM: t.VDOM}
}

// Inventory is the set of configured devices. It is immutable after creation.
type Inventory struct {
	devices       map[string]*Device
	names         []string
	defaultDevice string
}

// Options configures the clients New creates.
type Options struct {
	Logger *slog.Logger
	// Observer is called after every write request; see fortios.Options.Observer.
	Observer func(context.Context, fortios.Call)
}

// New builds an inventory and a client per device. It does not contact the devices.
func New(cfg *config.Config, opts Options) (*Inventory, error) {
	inv := &Inventory{devices: map[string]*Device{}, defaultDevice: cfg.DefaultDevice}
	for _, d := range cfg.Devices {
		client, err := fortios.New(fortios.Options{
			Name:               d.Name,
			BaseURL:            d.Host,
			Token:              d.Token.Reveal(),
			VDOM:               d.VDOM,
			CACertFile:         d.CACert,
			InsecureSkipVerify: d.InsecureSkipVerify,
			Timeout:            d.Timeout,
			Logger:             opts.Logger,
			ReadOnly:           d.ReadOnly,
			Observer:           opts.Observer,
		})
		if err != nil {
			return nil, fmt.Errorf("device %q: %w", d.Name, err)
		}
		inv.devices[d.Name] = &Device{
			Name:     d.Name,
			Host:     d.Host,
			VDOM:     d.VDOM,
			ReadOnly: d.ReadOnly,
			Client:   client,
		}
		inv.names = append(inv.names, d.Name)
	}
	if len(inv.names) == 0 {
		return nil, errors.New("no devices configured")
	}
	if inv.defaultDevice == "" && len(inv.names) == 1 {
		inv.defaultDevice = inv.names[0]
	}
	return inv, nil
}

// Names returns device names in sorted order.
func (inv *Inventory) Names() []string { return append([]string(nil), inv.names...) }

// Default returns the device used when a call names none, or "" if a name is required.
func (inv *Inventory) Default() string { return inv.defaultDevice }

// Get returns a device by name.
func (inv *Inventory) Get(name string) (*Device, bool) {
	d, ok := inv.devices[name]
	return d, ok
}

// Resolve picks the device and VDOM for a call. Empty name selects the
// default device; empty vdom selects the device's default VDOM.
func (inv *Inventory) Resolve(name, vdom string) (Target, error) {
	if name == "" {
		name = inv.defaultDevice
		if name == "" {
			return Target{}, fmt.Errorf("device is required; configured devices: %s", strings.Join(inv.names, ", "))
		}
	}
	d, ok := inv.devices[name]
	if !ok {
		return Target{}, fmt.Errorf("unknown device %q; configured devices: %s", name, strings.Join(inv.names, ", "))
	}
	if vdom == "" {
		vdom = d.VDOM
	}
	return Target{Device: d, VDOM: vdom}, nil
}
