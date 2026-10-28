// Package objects provides tools for address, service, VIP and IP pool objects.
package objects

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Tables are the object tables exposed by this toolset.
var Tables = []tools.Table{
	{Toolset: tools.Objects, Prefix: "fgt_address", Noun: "firewall address object", Path: "firewall/address", Path6: "firewall/address6"},
	{Toolset: tools.Objects, Prefix: "fgt_addrgrp", Noun: "firewall address group", Path: "firewall/addrgrp", Path6: "firewall/addrgrp6"},
	{Toolset: tools.Objects, Prefix: "fgt_service", Noun: "custom firewall service", Path: "firewall.service/custom"},
	{Toolset: tools.Objects, Prefix: "fgt_servicegrp", Noun: "firewall service group", Path: "firewall.service/group"},
	{Toolset: tools.Objects, Prefix: "fgt_vip", Noun: "virtual IP (destination NAT)", Path: "firewall/vip", Path6: "firewall/vip6"},
	{Toolset: tools.Objects, Prefix: "fgt_ippool", Noun: "IP pool (source NAT)", Path: "firewall/ippool", Path6: "firewall/ippool6"},
}

// Register adds the objects toolset.
func Register(r *tools.Registry) {
	for _, t := range Tables {
		tools.RegisterTableReads(r, t)
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
