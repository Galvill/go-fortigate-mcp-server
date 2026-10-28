// Package system provides monitoring and diagnostics tools.
package system

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// statusTimeout bounds each device's status call in fgt_device_list.
const statusTimeout = 10 * time.Second

// Register adds the system toolset.
func Register(r *tools.Registry) {
	registerDeviceList(r)

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_system_status",
		Description: "Get a FortiGate's hostname, model, serial number, FortiOS version and build.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, StatusOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, StatusOutput{}, err
		}
		st, err := tgt.Device.Client.Status(ctx)
		if err != nil {
			return nil, StatusOutput{}, err
		}
		return nil, StatusOutput{
			Scope:         tools.Scope{Device: tgt.Device.Name, VDOM: tgt.VDOM},
			Hostname:      st.Hostname,
			Model:         st.Model,
			ModelName:     st.ModelName,
			ModelNumber:   st.ModelNumber,
			Version:       st.Version.String(),
			Build:         st.Build,
			Serial:        st.Serial,
			LogDiskStatus: st.LogDiskStatus,
		}, nil
	})

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_system_resources",
		Description: "Get current CPU, memory, disk and session usage of a FortiGate.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, "system/resource/usage", url.Values{"interval": {"1-min"}})
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out.Results = dropKey(out.Results, "historical")
		return nil, out, nil
	})

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_interface_status",
		Description: "Get live interface state: link, speed, IP, and traffic and error counters. For interface configuration use fgt_interface_get.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in InterfaceStatusInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		q := url.Values{"include_vlan": {"true"}, "include_aggregate": {"true"}}
		if in.Interface != "" {
			q.Set("interface_name", in.Interface)
		}
		out, err := r.Monitor(ctx, tgt, "system/interface", q)
		return nil, out, err
	})

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_route_table",
		Description: "Get the active routing table (static, connected and dynamic routes) of a FortiGate.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in RouteTableInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		v6, err := in.IPv6()
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		path := "router/ipv4"
		if v6 {
			path = "router/ipv6"
		}
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, path, nil)
		return nil, out, err
	})

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_arp_table",
		Description: "Get the ARP table of a FortiGate.",
	}, monitorHandler(r, "network/arp", nil))

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_dhcp_leases",
		Description: "Get DHCP leases handed out by a FortiGate's DHCP servers.",
	}, monitorHandler(r, "system/dhcp", nil))

	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_license_status",
		Description: "Get license, support contract and FortiGuard subscription status of a FortiGate.",
	}, monitorHandler(r, "license/status", nil))

	registerSessions(r)
	registerHA(r)
	registerLogs(r)
}

// StatusOutput is the result of fgt_system_status.
type StatusOutput struct {
	tools.Scope
	Hostname      string `json:"hostname"`
	Model         string `json:"model"`
	ModelName     string `json:"model_name"`
	ModelNumber   string `json:"model_number"`
	Version       string `json:"version"`
	Build         int    `json:"build"`
	Serial        string `json:"serial"`
	LogDiskStatus string `json:"log_disk_status,omitempty"`
}

// InterfaceStatusInput is the input of fgt_interface_status.
type InterfaceStatusInput struct {
	tools.Target
	Interface string `json:"interface,omitempty" jsonschema:"Only this interface, e.g. port1. Omit for all."`
}

// RouteTableInput is the input of fgt_route_table.
type RouteTableInput struct {
	tools.Target
	tools.AddressFamily
}

func monitorHandler(r *tools.Registry, path string, q url.Values) mcp.ToolHandlerFor[tools.Target, tools.ResultsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, path, q)
		return nil, out, err
	}
}

// dropKey removes key from every object in v, recursively.
func dropKey(v any, key string) any {
	switch v := v.(type) {
	case map[string]any:
		delete(v, key)
		for k, val := range v {
			v[k] = dropKey(val, key)
		}
	case []any:
		for i := range v {
			v[i] = dropKey(v[i], key)
		}
	}
	return v
}

// DeviceListOutput is the result of fgt_device_list.
type DeviceListOutput struct {
	DefaultDevice string       `json:"default_device,omitempty" jsonschema:"Device used when a tool call omits device."`
	Devices       []DeviceInfo `json:"devices"`
}

// DeviceInfo describes one configured FortiGate.
type DeviceInfo struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	VDOM     string `json:"vdom" jsonschema:"Default VDOM."`
	ReadOnly bool   `json:"read_only"`
	Hostname string `json:"hostname,omitempty"`
	Model    string `json:"model,omitempty"`
	Version  string `json:"version,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Error    string `json:"error,omitempty" jsonschema:"Why the device could not be reached, if it could not."`
}

func registerDeviceList(r *tools.Registry) {
	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_device_list",
		Description: "List the FortiGates this server manages, with their default VDOM and, when reachable, hostname, model, FortiOS version and serial. Use the name as the device argument of other tools.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, DeviceListOutput, error) {
		inv := r.Inventory()
		names := inv.Names()
		out := DeviceListOutput{DefaultDevice: inv.Default(), Devices: make([]DeviceInfo, len(names))}
		var wg sync.WaitGroup
		for i, name := range names {
			d, _ := inv.Get(name)
			out.Devices[i] = DeviceInfo{Name: d.Name, Host: d.Host, VDOM: d.VDOM, ReadOnly: d.ReadOnly}
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(ctx, statusTimeout)
				defer cancel()
				st, err := d.Client.Status(ctx)
				if err != nil {
					out.Devices[i].Error = err.Error()
					return
				}
				out.Devices[i].Hostname = st.Hostname
				out.Devices[i].Model = st.Model
				out.Devices[i].Version = st.Version.String()
				out.Devices[i].Serial = st.Serial
			})
		}
		wg.Wait()
		return nil, out, nil
	})
}

// SessionListInput is the input of fgt_session_list.
type SessionListInput struct {
	tools.Target
	SrcAddr  string `json:"srcaddr,omitempty" jsonschema:"Source IP address."`
	DstAddr  string `json:"dstaddr,omitempty" jsonschema:"Destination IP address."`
	SrcPort  int    `json:"srcport,omitempty"`
	DstPort  int    `json:"dstport,omitempty"`
	Protocol int    `json:"protocol,omitempty" jsonschema:"IP protocol number: 6 TCP, 17 UDP, 1 ICMP."`
	PolicyID int    `json:"policyid,omitempty" jsonschema:"Only sessions matched by this policy."`
	SrcIntf  string `json:"srcintf,omitempty" jsonschema:"Incoming interface."`
	DstIntf  string `json:"dstintf,omitempty" jsonschema:"Outgoing interface."`
	IPv6     bool   `json:"ipv6,omitempty" jsonschema:"List IPv6 sessions instead of IPv4."`
	Count    int    `json:"count,omitempty" jsonschema:"Sessions to return, 20 to 1000 (default 50)."`
	Start    int    `json:"start,omitempty" jsonschema:"Sessions to skip, for paging."`
}

func registerSessions(r *tools.Registry) {
	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_session_list",
		Description: "List active firewall sessions, optionally filtered by addresses, ports, protocol, policy or interfaces. Use filters: busy firewalls have very many sessions.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SessionListInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		count := in.Count
		if count == 0 {
			count = 50
		}
		if count < 20 || count > 1000 {
			return nil, tools.ResultsOutput{}, fmt.Errorf("count must be between 20 and 1000")
		}
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		q := url.Values{
			"count":      {strconv.Itoa(count)},
			"start":      {strconv.Itoa(in.Start)},
			"ip_version": {map[bool]string{false: "ipv4", true: "ipv6"}[in.IPv6]},
		}
		for k, v := range map[string]string{"srcaddr": in.SrcAddr, "dstaddr": in.DstAddr, "srcintf": in.SrcIntf, "dstintf": in.DstIntf} {
			if v != "" {
				q.Set(k, v)
			}
		}
		for k, v := range map[string]int{"srcport": in.SrcPort, "dstport": in.DstPort, "protocol": in.Protocol, "policyid": in.PolicyID} {
			if v != 0 {
				q.Set(k, strconv.Itoa(v))
			}
		}
		out, err := r.Monitor(ctx, tgt, "firewall/session", q)
		return nil, out, err
	})
}

// HAOutput is the result of fgt_ha_status.
type HAOutput struct {
	tools.Scope
	Peers     any `json:"peers" jsonschema:"Cluster members with role, serial, hostname and priority. Empty for a standalone unit."`
	Checksums any `json:"checksums" jsonschema:"Configuration checksums per member; differing checksums mean the cluster is out of sync."`
}

func registerHA(r *tools.Registry) {
	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_ha_status",
		Description: "Get high-availability cluster status: members, roles and whether their configurations are in sync.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, HAOutput, error) {
		tgt, err := r.Resolve(in)
		if err != nil {
			return nil, HAOutput{}, err
		}
		peers, err := r.Monitor(ctx, tgt, "system/ha-peer", nil)
		if err != nil {
			return nil, HAOutput{}, err
		}
		sums, err := r.Monitor(ctx, tgt, "system/ha-checksums", nil)
		if err != nil {
			return nil, HAOutput{}, err
		}
		return nil, HAOutput{Scope: peers.Scope, Peers: peers.Results, Checksums: sums.Results}, nil
	})
}

// LogSearchInput is the input of fgt_log_search.
type LogSearchInput struct {
	tools.Target
	Source  string   `json:"source,omitempty" jsonschema:"Log storage: disk (default), memory, fortianalyzer or forticloud."`
	Type    string   `json:"type" jsonschema:"Log type: traffic, event, virus, webfilter, ips, app-ctrl, anomaly, dns, ssl, ..."`
	Subtype string   `json:"subtype,omitempty" jsonschema:"Log subtype. Traffic: forward, local, multicast, sniffer. Event: system, vpn, user, router, ha, ... Required for traffic and event."`
	Filter  []string `json:"filter,omitempty" jsonschema:"FortiOS log filters, e.g. srcip==10.0.0.5, action==deny, dstport==443."`
	Rows    int      `json:"rows,omitempty" jsonschema:"Entries to return, 1 to 1000 (default 100). Newest first."`
	Start   int      `json:"start,omitempty" jsonschema:"Entries to skip, for paging."`
}

var logSources = []string{"disk", "memory", "fortianalyzer", "forticloud"}

func registerLogs(r *tools.Registry) {
	tools.AddRead(r, tools.System, &mcp.Tool{
		Name:        "fgt_log_search",
		Description: "Search FortiGate logs (traffic, event, UTM) with filters. Results are newest first.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in LogSearchInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		source := in.Source
		if source == "" {
			source = "disk"
		}
		if !slices.Contains(logSources, source) {
			return nil, tools.ResultsOutput{}, fmt.Errorf("source must be one of %s", strings.Join(logSources, ", "))
		}
		if (in.Type == "traffic" || in.Type == "event") && in.Subtype == "" {
			return nil, tools.ResultsOutput{}, fmt.Errorf("subtype is required for %s logs", in.Type)
		}
		rows := in.Rows
		if rows == 0 {
			rows = 100
		}
		if rows < 1 || rows > 1000 {
			return nil, tools.ResultsOutput{}, fmt.Errorf("rows must be between 1 and 1000")
		}
		path := source + "/" + in.Type
		if in.Subtype != "" {
			path += "/" + in.Subtype
		}
		if err := fortios.ValidatePath(path); err != nil {
			return nil, tools.ResultsOutput{}, fmt.Errorf("invalid log type or subtype")
		}
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		params := tgt.Params()
		params.Filter = in.Filter
		params.Extra = url.Values{"rows": {strconv.Itoa(rows)}, "start": {strconv.Itoa(in.Start)}}
		resp, err := tgt.Device.Client.LogGet(ctx, path, params)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Results(tgt, resp)
		return nil, out, err
	})
}
