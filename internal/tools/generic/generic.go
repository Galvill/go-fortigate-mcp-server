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

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Register adds the generic toolset.
func Register(r *tools.Registry) {
	registerWrites(r)
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

// CMDBWriteInput is the input of fgt_cmdb_create and fgt_cmdb_update.
type CMDBWriteInput struct {
	tools.Target
	Path   string       `json:"path" jsonschema:"CMDB table path, e.g. user/local or system/dns."`
	Mkey   string       `json:"mkey,omitempty" jsonschema:"Update only: name or ID of the entry. Omit for single-object tables such as system/dns."`
	Fields tools.Fields `json:"fields" jsonschema:"Field values by FortiOS name (see fgt_cmdb_schema)."`
}

// CMDBDeleteInput is the input of fgt_cmdb_delete.
type CMDBDeleteInput struct {
	tools.Target
	Path string `json:"path" jsonschema:"CMDB table path."`
	Mkey string `json:"mkey" jsonschema:"Name or ID of the entry to delete."`
}

// MonitorPostInput is the input of fgt_monitor_post.
type MonitorPostInput struct {
	tools.Target
	tools.Confirmation
	Path   string            `json:"path" jsonschema:"Monitor endpoint path after /api/v2/monitor/, e.g. user/firewall/deauth."`
	Body   map[string]any    `json:"body,omitempty" jsonschema:"JSON body for the action."`
	Params map[string]string `json:"params,omitempty" jsonschema:"Query parameters."`
}

func registerWrites(r *tools.Registry) {
	tools.AddWrite(r, tools.Generic, tools.Create, &mcp.Tool{
		Name:        "fgt_cmdb_create",
		Description: "Create an entry in any CMDB table by path. Prefer a dedicated tool when one exists. Use fgt_cmdb_schema to discover fields.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CMDBWriteInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		if in.Mkey != "" {
			return nil, tools.WriteOutput{}, errors.New("mkey is for updates; put the new entry's name in fields")
		}
		if len(in.Fields) == 0 {
			return nil, tools.WriteOutput{}, errors.New("fields must not be empty")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		out, err := r.CreateCMDB(ctx, tgt, in.Path, in.Fields)
		return nil, out, err
	})

	tools.AddWrite(r, tools.Generic, tools.Update, &mcp.Tool{
		Name:        "fgt_cmdb_update",
		Description: "Change fields of an entry in any CMDB table by path, or of a single-object table (omit mkey). Prefer a dedicated tool when one exists.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CMDBWriteInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		if len(in.Fields) == 0 {
			return nil, tools.WriteOutput{}, errors.New("fields must not be empty")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		if in.Mkey != "" {
			out, err := r.UpdateCMDB(ctx, tgt, in.Path, in.Mkey, in.Fields)
			return nil, out, err
		}
		resp, err := tgt.Device.Client.CMDBUpdate(ctx, in.Path, "", in.Fields, tgt.Params())
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		out := tools.WriteOutput{Scope: tools.Scope{Device: tgt.Device.Name, VDOM: tgt.VDOM}, Revision: resp.Revision}
		if item, err := r.GetCMDBSingleton(ctx, tgt, in.Path); err == nil {
			out.Item = item.Item
		}
		return nil, out, nil
	})

	tools.AddWrite(r, tools.Generic, tools.Delete, &mcp.Tool{
		Name:        "fgt_cmdb_delete",
		Description: "Delete an entry from any CMDB table by path. Check references first with fgt_object_usage.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CMDBDeleteInput) (*mcp.CallToolResult, tools.DeleteOutput, error) {
		if in.Mkey == "" {
			return nil, tools.DeleteOutput{}, errors.New("mkey is required")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.DeleteOutput{}, err
		}
		out, err := r.DeleteCMDB(ctx, tgt, in.Path, in.Mkey)
		return nil, out, err
	})

	tools.AddWrite(r, tools.Generic, tools.Action, &mcp.Tool{
		Name: "fgt_monitor_post",
		Description: "Call any FortiOS monitor action endpoint by path with a JSON body, e.g. user/firewall/deauth or system/dhcp/revoke. " +
			"Prefer a dedicated tool when one exists. Disruptive endpoints (reboot, shutdown, restore, firmware, clearing all sessions) need hostname confirmation.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in MonitorPostInput) (*mcp.CallToolResult, tools.DisruptiveOutput, error) {
		if err := fortios.ValidatePath(in.Path); err != nil {
			return nil, tools.DisruptiveOutput{}, err
		}
		q := url.Values{}
		for k, v := range in.Params {
			if k == "vdom" {
				return nil, tools.DisruptiveOutput{}, errors.New("use the vdom argument instead of params.vdom")
			}
			q.Set(k, v)
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.DisruptiveOutput{}, err
		}
		if action, impact, disruptive := tools.DisruptivePath(in.Path); disruptive {
			ok, out, err := r.Confirm(ctx, tgt, in.Confirmation, action, impact, map[string]any{"path": in.Path})
			if err != nil || !ok {
				return nil, out, err
			}
		}
		params := tgt.Params()
		params.Extra = q
		var body any
		if in.Body != nil {
			body = in.Body
		}
		resp, err := tgt.Device.Client.MonitorPost(ctx, in.Path, body, params)
		if err != nil {
			return nil, tools.DisruptiveOutput{}, err
		}
		res, err := r.Results(tgt, resp)
		if err != nil {
			return nil, tools.DisruptiveOutput{}, err
		}
		return nil, tools.DisruptiveOutput{Scope: res.Scope, Executed: true, Message: "Done.", Result: res.Results}, nil
	})
}
