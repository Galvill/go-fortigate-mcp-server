// Package objects provides tools for address, service, VIP and IP pool objects.
package objects

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Tables are the object tables exposed by this toolset.
var Tables = []tools.Table{
	{
		Toolset: tools.Objects, Prefix: "fgt_address", Noun: "firewall address object", Path: "firewall/address", Path6: "firewall/address6",
		Fields: `Main fields: type (ipmask, iprange, fqdn, geography, wildcard), subnet ("10.0.0.0 255.255.255.0" or "10.0.0.0/24"), start-ip and end-ip (iprange), fqdn, country (geography), associated-interface, comment. IPv6: ip6 ("2001:db8::/64"), start-ip, end-ip, fqdn.`,
	},
	{
		Toolset: tools.Objects, Prefix: "fgt_addrgrp", Noun: "firewall address group", Path: "firewall/addrgrp", Path6: "firewall/addrgrp6",
		Fields: `Main fields: member (list of {"name": "<address>"}, at least one), comment. To change membership use fgt_addrgrp_add_members or fgt_addrgrp_remove_members.`,
	},
	{
		Toolset: tools.Objects, Prefix: "fgt_service", Noun: "custom firewall service", Path: "firewall.service/custom",
		Fields: `Main fields: protocol (TCP/UDP/SCTP, ICMP, ICMP6, IP), tcp-portrange and udp-portrange ("443", "8000-8080", "80:1024-65535" for dst:src), icmptype, protocol-number (IP), category, comment.`,
	},
	{
		Toolset: tools.Objects, Prefix: "fgt_servicegrp", Noun: "firewall service group", Path: "firewall.service/group",
		Fields: `Main fields: member (list of {"name": "<service>"}), comment. To change membership use fgt_servicegrp_add_members or fgt_servicegrp_remove_members.`,
	},
	{
		Toolset: tools.Objects, Prefix: "fgt_vip", Noun: "virtual IP (destination NAT)", Path: "firewall/vip", Path6: "firewall/vip6",
		Fields: `Main fields: extip (external IP), mappedip (list of {"range": "10.0.0.5"}), extintf (external interface or any), portforward (enable/disable), protocol (tcp, udp), extport, mappedport, comment.`,
	},
	{
		Toolset: tools.Objects, Prefix: "fgt_ippool", Noun: "IP pool (source NAT)", Path: "firewall/ippool", Path6: "firewall/ippool6",
		Fields: `Main fields: type (overload, one-to-one, fixed-port-range, port-block-allocation), startip, endip, comments.`,
	},
}

// groupTables have a member list edited by add/remove tools.
var groupTables = []string{"fgt_addrgrp", "fgt_servicegrp"}

// Register adds the objects toolset.
func Register(r *tools.Registry) {
	for _, t := range Tables {
		tools.RegisterTableReads(r, t)
		tools.RegisterTableWrites(r, t)
		if slices.Contains(groupTables, t.Prefix) {
			tools.RegisterMemberTools(r, t)
		}
	}

	tools.AddRead(r, tools.Objects, &mcp.Tool{
		Name:        "fgt_object_usage",
		Description: "Find where a CMDB object is referenced (policies, groups, routes, ...). Check this before deleting or renaming an object.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UsageInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		q, err := in.query()
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, "system/object/usage", q)
		return nil, out, err
	})
}

// UsageInput is the input of fgt_object_usage.
type UsageInput struct {
	tools.Target
	Path string `json:"path" jsonschema:"CMDB table of the object, e.g. firewall/address, firewall/addrgrp, firewall.service/custom."`
	Name string `json:"name" jsonschema:"Name (or ID) of the object."`
}

// query builds object usage parameters.
//
// TODO(M3): verify the endpoint and parameters against a FortiGate-VM.
func (in UsageInput) query() (url.Values, error) {
	if err := fortios.ValidatePath(in.Path); err != nil {
		return nil, err
	}
	category, table, ok := strings.Cut(in.Path, "/")
	if !ok || strings.Contains(table, "/") {
		return nil, fmt.Errorf("path must be <category>/<table>, e.g. firewall/address")
	}
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	return url.Values{"q_path": {category}, "q_name": {table}, "mkey": {in.Name}}, nil
}
