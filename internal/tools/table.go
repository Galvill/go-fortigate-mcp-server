package tools

import (
	"context"
	"fmt"
	"strconv"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Table describes a CMDB table exposed through list/get tools.
type Table struct {
	Toolset string
	// Prefix names the tools: Prefix+"_list", Prefix+"_get".
	Prefix string
	// Noun describes one entry, e.g. "firewall address object".
	Noun string
	Path string
	// Path6 is the IPv6 variant of the table, if any. It adds a family parameter.
	Path6 string
	// NumericKey means entries are keyed by an integer ID (e.g. policyid)
	// rather than a name.
	NumericKey bool
	// About is appended to the list tool's description.
	About string
}

// AddressFamily is embedded in inputs of tables with IPv4/IPv6 variants.
type AddressFamily struct {
	Family string `json:"family,omitempty" jsonschema:"Address family: ipv4 (default) or ipv6."`
}

// IPv6 reports whether the family is ipv6, rejecting unknown values.
func (f AddressFamily) IPv6() (bool, error) {
	switch f.Family {
	case "", "ipv4":
		return false, nil
	case "ipv6":
		return true, nil
	default:
		return false, fmt.Errorf("family must be ipv4 or ipv6, got %q", f.Family)
	}
}

func (t Table) path(f AddressFamily) (string, error) {
	v6, err := f.IPv6()
	if err != nil || !v6 {
		return t.Path, err
	}
	return t.Path6, nil
}

// Inputs for table tools. Separate types keep each tool's schema exact.
type (
	ListInput struct {
		Target
		Page
	}
	ListFamilyInput struct {
		Target
		AddressFamily
		Page
	}
	GetNameInput struct {
		Target
		Name string `json:"name" jsonschema:"Name of the entry."`
	}
	GetNameFamilyInput struct {
		Target
		AddressFamily
		Name string `json:"name" jsonschema:"Name of the entry."`
	}
	GetIDInput struct {
		Target
		ID int `json:"id" jsonschema:"Numeric ID of the entry."`
	}
)

// RegisterTableReads registers list and get tools for a table.
func RegisterTableReads(r *Registry, t Table) {
	listDesc := fmt.Sprintf("List %ss (CMDB %s). Supports filter, fields, limit and offset.", t.Noun, t.Path)
	if t.About != "" {
		listDesc += " " + t.About
	}
	getDesc := fmt.Sprintf("Get one %s by %s, with all its fields.", t.Noun, map[bool]string{true: "ID", false: "name"}[t.NumericKey])
	listTool := &mcp.Tool{Name: t.Prefix + "_list", Description: listDesc}
	getTool := &mcp.Tool{Name: t.Prefix + "_get", Description: getDesc}

	if t.Path6 == "" {
		AddRead(r, t.Toolset, listTool, func(ctx context.Context, _ *mcp.CallToolRequest, in ListInput) (*mcp.CallToolResult, ListOutput, error) {
			tgt, err := r.Resolve(in.Target)
			if err != nil {
				return nil, ListOutput{}, err
			}
			out, err := r.ListCMDB(ctx, tgt, t.Path, in.Page)
			return nil, out, err
		})
	} else {
		AddRead(r, t.Toolset, listTool, func(ctx context.Context, _ *mcp.CallToolRequest, in ListFamilyInput) (*mcp.CallToolResult, ListOutput, error) {
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, ListOutput{}, err
			}
			tgt, err := r.Resolve(in.Target)
			if err != nil {
				return nil, ListOutput{}, err
			}
			out, err := r.ListCMDB(ctx, tgt, path, in.Page)
			return nil, out, err
		})
	}

	switch {
	case t.NumericKey:
		AddRead(r, t.Toolset, getTool, func(ctx context.Context, _ *mcp.CallToolRequest, in GetIDInput) (*mcp.CallToolResult, ItemOutput, error) {
			tgt, err := r.Resolve(in.Target)
			if err != nil {
				return nil, ItemOutput{}, err
			}
			out, err := r.GetCMDB(ctx, tgt, t.Path, strconv.Itoa(in.ID))
			return nil, out, err
		})
	case t.Path6 == "":
		AddRead(r, t.Toolset, getTool, func(ctx context.Context, _ *mcp.CallToolRequest, in GetNameInput) (*mcp.CallToolResult, ItemOutput, error) {
			tgt, err := r.Resolve(in.Target)
			if err != nil {
				return nil, ItemOutput{}, err
			}
			out, err := r.GetCMDB(ctx, tgt, t.Path, in.Name)
			return nil, out, err
		})
	default:
		AddRead(r, t.Toolset, getTool, func(ctx context.Context, _ *mcp.CallToolRequest, in GetNameFamilyInput) (*mcp.CallToolResult, ItemOutput, error) {
			path, err := t.path(in.AddressFamily)
			if err != nil {
				return nil, ItemOutput{}, err
			}
			tgt, err := r.Resolve(in.Target)
			if err != nil {
				return nil, ItemOutput{}, err
			}
			out, err := r.GetCMDB(ctx, tgt, path, in.Name)
			return nil, out, err
		})
	}
}

// RegisterSingletonRead registers a get tool for a table holding one object.
func RegisterSingletonRead(r *Registry, toolset, name, description, path string) {
	AddRead(r, toolset, &mcp.Tool{Name: name, Description: description},
		func(ctx context.Context, _ *mcp.CallToolRequest, in Target) (*mcp.CallToolResult, ItemOutput, error) {
			tgt, err := r.Resolve(in)
			if err != nil {
				return nil, ItemOutput{}, err
			}
			out, err := r.GetCMDBSingleton(ctx, tgt, path)
			return nil, out, err
		})
}
