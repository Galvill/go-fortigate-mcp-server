// Package generic provides path-based tools that reach any CMDB or monitor
// endpoint not covered by a dedicated tool.
package generic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Register adds the generic toolset.
func Register(r *tools.Registry) {
	tools.AddRead(r, tools.Generic, &mcp.Tool{
		Name: "fgt_cmdb_get",
		Description: "Read any FortiOS configuration table (CMDB) by path, e.g. system/dns, user/local, firewall/schedule-recurring. " +
			"Omit mkey to list entries (filter, fields, limit and offset apply); give mkey to read one entry. " +
			"Single-object tables (e.g. system/global) return their object as the one item. Prefer a dedicated tool when one exists. " +
			"Use fgt_cmdb_schema to discover a table's fields.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CMDBGetInput) (*mcp.CallToolResult, tools.ListOutput, error) {
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ListOutput{}, err
		}
		if in.Mkey != "" {
			item, err := r.GetCMDB(ctx, tgt, in.Path, in.Mkey)
			if err != nil {
				return nil, tools.ListOutput{}, err
			}
			return nil, tools.ListOutput{Scope: item.Scope, Items: []map[string]any{item.Item}, Total: 1}, nil
		}
		out, err := r.ListCMDB(ctx, tgt, in.Path, in.Page)
		var decodeErr *json.UnmarshalTypeError
		if errors.As(err, &decodeErr) {
			// Not a list: a single-object table.
			item, err := r.GetCMDBSingleton(ctx, tgt, in.Path)
			if err != nil {
				return nil, tools.ListOutput{}, err
			}
			return nil, tools.ListOutput{Scope: item.Scope, Items: []map[string]any{item.Item}, Total: 1}, nil
		}
		return nil, out, err
	})

	tools.AddRead(r, tools.Generic, &mcp.Tool{
		Name:        "fgt_cmdb_schema",
		Description: "Get the schema of a CMDB table: its fields, their types, allowed values and defaults. Use before writing to an unfamiliar table.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SchemaInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		resp, err := tgt.Device.Client.CMDBSchema(ctx, in.Path, tgt.Params())
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Results(tgt, resp)
		return nil, out, err
	})

	tools.AddRead(r, tools.Generic, &mcp.Tool{
		Name: "fgt_monitor_get",
		Description: "Call any FortiOS monitor (status) endpoint by path, e.g. system/ha-statistics, router/bgp/neighbors, user/firewall, " +
			"wifi/client, switch-controller/managed-switch/status. Prefer a dedicated tool when one exists.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in MonitorGetInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		q := url.Values{}
		for k, v := range in.Params {
			if k == "vdom" {
				return nil, tools.ResultsOutput{}, fmt.Errorf("use the vdom argument instead of params.vdom")
			}
			q.Set(k, v)
		}
		out, err := r.Monitor(ctx, tgt, in.Path, q)
		return nil, out, err
	})
}

// CMDBGetInput is the input of fgt_cmdb_get.
type CMDBGetInput struct {
	tools.Target
	Path string `json:"path" jsonschema:"CMDB table path after /api/v2/cmdb/, e.g. system/dns or firewall.service/category."`
	Mkey string `json:"mkey,omitempty" jsonschema:"Name or ID of one entry. Omit to list."`
	tools.Page
}

// SchemaInput is the input of fgt_cmdb_schema.
type SchemaInput struct {
	tools.Target
	Path string `json:"path" jsonschema:"CMDB table path, e.g. firewall/policy."`
}

// MonitorGetInput is the input of fgt_monitor_get.
type MonitorGetInput struct {
	tools.Target
	Path   string            `json:"path" jsonschema:"Monitor endpoint path after /api/v2/monitor/, e.g. router/bgp/neighbors."`
	Params map[string]string `json:"params,omitempty" jsonschema:"Query parameters for the endpoint."`
}
