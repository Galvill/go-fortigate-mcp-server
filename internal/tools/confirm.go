package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/galvill/go-fortigate-mcp-server/internal/audit"
	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
)

// Confirmation is embedded in inputs of disruptive tools (SPEC §7.1.1).
type Confirmation struct {
	Confirm string `json:"confirm,omitempty" jsonschema:"Hostname of the target FortiGate, to confirm this disruptive action. Call once without it to get a preview showing the hostname, then call again with confirm set to it. Take the hostname from the preview or the user, never guess it."`
}

// Preview describes a disruptive action that was not executed.
type Preview struct {
	Device    string         `json:"device"`
	Hostname  string         `json:"hostname"`
	Model     string         `json:"model,omitempty"`
	Serial    string         `json:"serial,omitempty"`
	Version   string         `json:"version,omitempty"`
	VDOM      string         `json:"vdom"`
	HAMode    string         `json:"ha_mode,omitempty" jsonschema:"standalone, a-p or a-a."`
	HAMembers int            `json:"ha_members,omitempty" jsonschema:"Cluster members, when in HA."`
	Action    string         `json:"action"`
	Impact    string         `json:"impact"`
	Details   map[string]any `json:"details,omitempty"`
	Mismatch  string         `json:"mismatch,omitempty" jsonschema:"The confirm value given, when it did not match the hostname."`
}

// DisruptiveOutput is the result of disruptive tools.
type DisruptiveOutput struct {
	Scope
	Executed bool     `json:"executed" jsonschema:"False when only a preview was returned."`
	Message  string   `json:"message"`
	Preview  *Preview `json:"preview,omitempty"`
	Result   any      `json:"result,omitempty" jsonschema:"The device's response, when executed."`
}

// Confirm checks a disruptive call's confirmation against the device's
// current hostname, fetched fresh. When it matches, it returns ok and records
// the hostname for the audit log. Otherwise it returns a preview to show.
func (r *Registry) Confirm(ctx context.Context, t devices.Target, c Confirmation, action, impact string, details map[string]any) (ok bool, _ DisruptiveOutput, _ error) {
	st, err := t.Device.Client.Status(ctx)
	if err != nil {
		return false, DisruptiveOutput{}, fmt.Errorf("reading device hostname for confirmation: %w", err)
	}
	if st.Hostname == "" {
		return false, DisruptiveOutput{}, fmt.Errorf("device %q reported no hostname, so the action cannot be confirmed", t.Device.Name)
	}
	given := strings.TrimSpace(c.Confirm)
	if given != "" && strings.EqualFold(given, st.Hostname) {
		if info := audit.FromContext(ctx); info != nil {
			info.ConfirmedHostname = st.Hostname
		}
		return true, DisruptiveOutput{}, nil
	}

	p := &Preview{
		Device:   t.Device.Name,
		Hostname: st.Hostname,
		Model:    st.Model,
		Serial:   st.Serial,
		Version:  st.Version.String(),
		VDOM:     t.VDOM,
		Action:   action,
		Impact:   impact,
		Details:  details,
	}
	r.addHA(ctx, t, p)
	out := DisruptiveOutput{Scope: scope(t), Preview: p}
	if given == "" {
		out.Message = fmt.Sprintf("Not executed. This will %s on %s (%s, serial %s). %s To proceed, call again with confirm: %q.",
			action, st.Hostname, t.Device.Name, st.Serial, impact, st.Hostname)
	} else {
		p.Mismatch = given
		out.Message = fmt.Sprintf("Not executed: confirm %q does not match the hostname of device %q, which is %q. Check that this is the FortiGate you mean before retrying.",
			given, t.Device.Name, st.Hostname)
	}
	return false, out, nil
}

// addHA adds HA mode and member count to a preview. Failures are ignored:
// the preview is still useful without them.
func (r *Registry) addHA(ctx context.Context, t devices.Target, p *Preview) {
	if resp, err := t.Device.Client.CMDBGet(ctx, "system/ha", "", t.Params()); err == nil {
		var ha struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(resp.Results, &ha) == nil {
			p.HAMode = ha.Mode
		}
	}
	if p.HAMode != "" && p.HAMode != "standalone" {
		if resp, err := t.Device.Client.MonitorGet(ctx, "system/ha-peer", t.Params()); err == nil {
			var peers []any
			if json.Unmarshal(resp.Results, &peers) == nil {
				p.HAMembers = len(peers)
			}
		}
	}
}

// disruptivePaths are monitor endpoints that need hostname confirmation,
// with a description of what they do.
var disruptivePaths = map[string][2]string{
	"system/os/reboot":           {"reboot the device", "It will be unreachable for several minutes."},
	"system/os/shutdown":         {"shut down the device", "It stays down until powered on locally."},
	"system/config/restore":      {"restore a configuration", "The current configuration is replaced and the device reboots."},
	"system/firmware/upgrade":    {"upgrade the firmware", "The device reboots into the new firmware."},
	"firewall/session/clear_all": {"clear all firewall sessions", "Every connection through the device is dropped."},
}

// DisruptivePath reports whether a monitor POST path needs hostname
// confirmation, and describes it.
func DisruptivePath(path string) (action, impact string, ok bool) {
	if d, ok := disruptivePaths[path]; ok {
		return d[0], d[1], true
	}
	switch {
	case strings.HasPrefix(path, "system/os/"):
		return "run " + path, "Operating system actions can take the device offline.", true
	case strings.HasPrefix(path, "system/firmware/"):
		return "run " + path, "Firmware actions can reboot the device.", true
	case strings.HasSuffix(path, "/clear_all"):
		return "run " + path, "This clears state on the device for all users.", true
	}
	return "", "", false
}

// RunDisruptive confirms a disruptive action and, once confirmed, POSTs
// body to the monitor endpoint at path.
func (r *Registry) RunDisruptive(ctx context.Context, t devices.Target, c Confirmation, path string, body any, action, impact string, details map[string]any) (DisruptiveOutput, error) {
	ok, out, err := r.Confirm(ctx, t, c, action, impact, details)
	if err != nil || !ok {
		return out, err
	}
	resp, err := t.Device.Client.MonitorPost(ctx, path, body, t.Params())
	if err != nil {
		return DisruptiveOutput{}, err
	}
	res, err := r.Results(t, resp)
	if err != nil {
		return DisruptiveOutput{}, err
	}
	return DisruptiveOutput{Scope: scope(t), Executed: true, Message: "Done: " + action + ".", Result: res.Results}, nil
}

// PostOutput is the result of monitor actions that need no confirmation.
type PostOutput struct {
	Scope
	Result any `json:"result,omitempty" jsonschema:"The device's response."`
}

// Post calls a monitor action endpoint that needs no confirmation.
func (r *Registry) Post(ctx context.Context, t devices.Target, path string, body any) (PostOutput, error) {
	resp, err := t.Device.Client.MonitorPost(ctx, path, body, t.Params())
	if err != nil {
		return PostOutput{}, err
	}
	res, err := r.Results(t, resp)
	if err != nil {
		return PostOutput{}, err
	}
	return PostOutput{Scope: scope(t), Result: res.Results}, nil
}
