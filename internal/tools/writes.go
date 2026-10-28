package tools

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
)

// ResolveWrite picks the device and VDOM for a call that changes the device,
// rejecting devices configured read-only.
func (r *Registry) ResolveWrite(t Target) (devices.Target, error) {
	tgt, err := r.Resolve(t)
	if err != nil {
		return tgt, err
	}
	if tgt.Device.ReadOnly {
		return tgt, fmt.Errorf("device %q is configured read-only", tgt.Device.Name)
	}
	return tgt, nil
}

// WriteOutput is the result of create and update tools.
type WriteOutput struct {
	Scope
	Mkey     string         `json:"mkey" jsonschema:"Name or ID of the entry."`
	Revision string         `json:"revision,omitempty" jsonschema:"Configuration revision after the change."`
	Item     map[string]any `json:"item,omitempty" jsonschema:"The entry as stored on the device after the change."`
	Warning  string         `json:"warning,omitempty"`
}

// DeleteOutput is the result of delete tools.
type DeleteOutput struct {
	Scope
	Deleted  string `json:"deleted" jsonschema:"Name or ID of the deleted entry."`
	Revision string `json:"revision,omitempty"`
}

// CreateCMDB adds an entry and returns it as stored.
func (r *Registry) CreateCMDB(ctx context.Context, t devices.Target, path string, body map[string]any) (WriteOutput, error) {
	resp, err := t.Device.Client.CMDBCreate(ctx, path, body, t.Params())
	if err != nil {
		return WriteOutput{}, err
	}
	mkey := string(resp.Mkey)
	if mkey == "" {
		if name, ok := body["name"].(string); ok {
			mkey = name
		}
	}
	return r.written(ctx, t, path, mkey, resp), nil
}

// UpdateCMDB changes fields of an entry and returns it as stored.
func (r *Registry) UpdateCMDB(ctx context.Context, t devices.Target, path, mkey string, body map[string]any) (WriteOutput, error) {
	if mkey == "" {
		return WriteOutput{}, fmt.Errorf("an entry name or ID is required")
	}
	resp, err := t.Device.Client.CMDBUpdate(ctx, path, mkey, body, t.Params())
	if err != nil {
		return WriteOutput{}, err
	}
	// A rename changes the key the entry is stored under.
	if name, ok := body["name"].(string); ok && name != "" && resp.Mkey == "" {
		mkey = name
	}
	if resp.Mkey != "" {
		mkey = string(resp.Mkey)
	}
	return r.written(ctx, t, path, mkey, resp), nil
}

// DeleteCMDB removes an entry.
func (r *Registry) DeleteCMDB(ctx context.Context, t devices.Target, path, mkey string) (DeleteOutput, error) {
	resp, err := t.Device.Client.CMDBDelete(ctx, path, mkey, t.Params())
	if err != nil {
		return DeleteOutput{}, err
	}
	return DeleteOutput{Scope: scope(t), Deleted: mkey, Revision: resp.Revision}, nil
}

// MoveCMDB reorders an entry and returns it.
func (r *Registry) MoveCMDB(ctx context.Context, t devices.Target, path, mkey string, pos fortios.MovePosition, target string) (WriteOutput, error) {
	resp, err := t.Device.Client.CMDBMove(ctx, path, mkey, pos, target, t.Params())
	if err != nil {
		return WriteOutput{}, err
	}
	out := r.written(ctx, t, path, mkey, resp)
	out.Item = nil // Moving doesn't change the entry; keep the result small.
	return out, nil
}

// written re-reads an entry after a change. A failed re-read is reported as
// a warning: the change itself succeeded.
func (r *Registry) written(ctx context.Context, t devices.Target, path, mkey string, resp *fortios.Response) WriteOutput {
	out := WriteOutput{Scope: scope(t), Mkey: mkey, Revision: resp.Revision}
	if mkey == "" {
		return out
	}
	item, err := r.GetCMDB(ctx, t, path, mkey)
	if err != nil {
		out.Warning = "the change succeeded but re-reading the entry failed: " + err.Error()
		return out
	}
	out.Item = item.Item
	return out
}

// Fields is the free-form body of create and update tools.
type Fields map[string]any

// Inputs for table write tools.
type (
	CreateNameInput struct {
		Target
		Name   string `json:"name" jsonschema:"Name of the new entry."`
		Fields Fields `json:"fields,omitempty" jsonschema:"Field values as FortiOS expects them (see the tool description and fgt_cmdb_schema)."`
	}
	CreateNameFamilyInput struct {
		Target
		AddressFamily
		Name   string `json:"name" jsonschema:"Name of the new entry."`
		Fields Fields `json:"fields,omitempty" jsonschema:"Field values as FortiOS expects them (see the tool description and fgt_cmdb_schema)."`
	}
	CreateIDInput struct {
		Target
		Fields Fields `json:"fields" jsonschema:"Field values as FortiOS expects them (see the tool description and fgt_cmdb_schema). The ID is assigned by the device unless given."`
	}
	UpdateNameInput struct {
		Target
		Name   string `json:"name" jsonschema:"Name of the entry to change."`
		Fields Fields `json:"fields" jsonschema:"Fields to change; others keep their values. Set name to rename."`
	}
	UpdateNameFamilyInput struct {
		Target
		AddressFamily
		Name   string `json:"name" jsonschema:"Name of the entry to change."`
		Fields Fields `json:"fields" jsonschema:"Fields to change; others keep their values. Set name to rename."`
	}
	UpdateIDInput struct {
		Target
		ID     int    `json:"id" jsonschema:"Numeric ID of the entry to change."`
		Fields Fields `json:"fields" jsonschema:"Fields to change; others keep their values."`
	}
)

func withName(f Fields, name string) map[string]any {
	body := map[string]any{}
	for k, v := range f {
		body[k] = v
	}
	body["name"] = name
	return body
}

func nonEmpty(f Fields) error {
	if len(f) == 0 {
		return fmt.Errorf("fields must not be empty")
	}
	return nil
}

// RegisterTableWrites registers create, update and delete tools for a table.
func RegisterTableWrites(r *Registry, t Table) {
	noun := t.Noun
	help := ""
	if t.Fields != "" {
		help = " " + t.Fields
	}
	schemaHint := fmt.Sprintf(" Use fgt_cmdb_schema with path %s for all fields.", t.Path)
	create := &mcp.Tool{Name: t.Prefix + "_create", Description: "Create a " + noun + "." + help + schemaHint}
	update := &mcp.Tool{Name: t.Prefix + "_update", Description: "Change fields of a " + noun + "; fields not given keep their values." + help + schemaHint}
	del := &mcp.Tool{Name: t.Prefix + "_delete", Description: "Delete a " + noun + ". It must not be referenced by other objects; check with fgt_object_usage."}

	switch {
	case t.NumericKey:
		AddWrite(r, t.Toolset, Create, create, func(ctx context.Context, _ *mcp.CallToolRequest, in CreateIDInput) (*mcp.CallToolResult, WriteOutput, error) {
			if err := nonEmpty(in.Fields); err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.CreateCMDB(ctx, tgt, t.Path, in.Fields)
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Update, update, func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateIDInput) (*mcp.CallToolResult, WriteOutput, error) {
			if err := nonEmpty(in.Fields); err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.UpdateCMDB(ctx, tgt, t.Path, strconv.Itoa(in.ID), in.Fields)
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Delete, del, func(ctx context.Context, _ *mcp.CallToolRequest, in GetIDInput) (*mcp.CallToolResult, DeleteOutput, error) {
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, DeleteOutput{}, err
			}
			out, err := r.DeleteCMDB(ctx, tgt, t.Path, strconv.Itoa(in.ID))
			return nil, out, err
		})

	case t.Path6 == "":
		AddWrite(r, t.Toolset, Create, create, func(ctx context.Context, _ *mcp.CallToolRequest, in CreateNameInput) (*mcp.CallToolResult, WriteOutput, error) {
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.CreateCMDB(ctx, tgt, t.Path, withName(in.Fields, in.Name))
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Update, update, func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateNameInput) (*mcp.CallToolResult, WriteOutput, error) {
			if err := nonEmpty(in.Fields); err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.UpdateCMDB(ctx, tgt, t.Path, in.Name, in.Fields)
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Delete, del, func(ctx context.Context, _ *mcp.CallToolRequest, in GetNameInput) (*mcp.CallToolResult, DeleteOutput, error) {
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, DeleteOutput{}, err
			}
			out, err := r.DeleteCMDB(ctx, tgt, t.Path, in.Name)
			return nil, out, err
		})

	default:
		AddWrite(r, t.Toolset, Create, create, func(ctx context.Context, _ *mcp.CallToolRequest, in CreateNameFamilyInput) (*mcp.CallToolResult, WriteOutput, error) {
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.CreateCMDB(ctx, tgt, path, withName(in.Fields, in.Name))
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Update, update, func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateNameFamilyInput) (*mcp.CallToolResult, WriteOutput, error) {
			if err := nonEmpty(in.Fields); err != nil {
				return nil, WriteOutput{}, err
			}
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out, err := r.UpdateCMDB(ctx, tgt, path, in.Name, in.Fields)
			return nil, out, err
		})
		AddWrite(r, t.Toolset, Delete, del, func(ctx context.Context, _ *mcp.CallToolRequest, in GetNameFamilyInput) (*mcp.CallToolResult, DeleteOutput, error) {
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, DeleteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, DeleteOutput{}, err
			}
			out, err := r.DeleteCMDB(ctx, tgt, path, in.Name)
			return nil, out, err
		})
	}
}

// MembersInput is the input of group membership tools.
type MembersInput struct {
	Target
	AddressFamily
	Name    string   `json:"name" jsonschema:"Name of the group."`
	Members []string `json:"members" jsonschema:"Names of the members to add or remove."`
}

// MembersOutput is the result of group membership tools.
type MembersOutput struct {
	WriteOutput
	Unchanged []string `json:"unchanged,omitempty" jsonschema:"Requested members that were already present (add) or absent (remove)."`
}

// RegisterMemberTools registers add_members and remove_members tools for a
// group table whose members are in the "member" field. They read the group,
// change the list, and write it back.
func RegisterMemberTools(r *Registry, t Table) {
	register := func(op string, add bool) {
		AddWrite(r, t.Toolset, Update, &mcp.Tool{
			Name:        t.Prefix + "_" + op + "_members",
			Description: fmt.Sprintf("%s members %s a %s without resending the whole member list.", map[bool]string{true: "Add", false: "Remove"}[add], map[bool]string{true: "to", false: "from"}[add], t.Noun),
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in MembersInput) (*mcp.CallToolResult, MembersOutput, error) {
			if len(in.Members) == 0 {
				return nil, MembersOutput{}, fmt.Errorf("members must not be empty")
			}
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, MembersOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, MembersOutput{}, err
			}
			current, err := r.GetCMDB(ctx, tgt, path, in.Name)
			if err != nil {
				return nil, MembersOutput{}, err
			}
			members := memberNames(current.Item["member"])
			var unchanged []string
			for _, m := range in.Members {
				present := slices.Contains(members, m)
				switch {
				case add && !present:
					members = append(members, m)
				case !add && present:
					members = slices.DeleteFunc(members, func(x string) bool { return x == m })
				default:
					unchanged = append(unchanged, m)
				}
			}
			if len(unchanged) == len(in.Members) {
				return nil, MembersOutput{WriteOutput: WriteOutput{Scope: scope(tgt), Mkey: in.Name, Item: current.Item}, Unchanged: unchanged}, nil
			}
			list := make([]map[string]string, len(members))
			for i, m := range members {
				list[i] = map[string]string{"name": m}
			}
			out, err := r.UpdateCMDB(ctx, tgt, path, in.Name, map[string]any{"member": list})
			return nil, MembersOutput{WriteOutput: out, Unchanged: unchanged}, err
		})
	}
	register("add", true)
	register("remove", false)
}

func memberNames(v any) []string {
	list, _ := v.([]any)
	names := make([]string, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	return names
}

// SingletonUpdateInput is the input of single-object table update tools.
type SingletonUpdateInput struct {
	Target
	Fields Fields `json:"fields" jsonschema:"Fields to change; others keep their values."`
}

// RegisterSingletonWrite registers an update tool for a table holding one object.
func RegisterSingletonWrite(r *Registry, toolset, name, description, path string) {
	AddWrite(r, toolset, Update, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *mcp.CallToolRequest, in SingletonUpdateInput) (*mcp.CallToolResult, WriteOutput, error) {
			if err := nonEmpty(in.Fields); err != nil {
				return nil, WriteOutput{}, err
			}
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, WriteOutput{}, err
			}
			resp, err := tgt.Device.Client.CMDBUpdate(ctx, path, "", in.Fields, tgt.Params())
			if err != nil {
				return nil, WriteOutput{}, err
			}
			out := WriteOutput{Scope: scope(tgt), Revision: resp.Revision}
			if item, err := r.GetCMDBSingleton(ctx, tgt, path); err != nil {
				out.Warning = "the change succeeded but re-reading failed: " + err.Error()
			} else {
				out.Item = item.Item
			}
			return nil, out, nil
		})
}
