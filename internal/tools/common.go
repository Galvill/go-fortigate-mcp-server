package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/logging"
)

// Target is embedded in every device-scoped tool input.
type Target struct {
	Device string `json:"device,omitempty" jsonschema:"FortiGate to use, as named by fgt_device_list. Optional when a default device is configured."`
	VDOM   string `json:"vdom,omitempty" jsonschema:"VDOM to use. Defaults to the device's configured VDOM."`
}

// Scope is embedded in tool outputs to say where results came from.
type Scope struct {
	Device string `json:"device"`
	VDOM   string `json:"vdom"`
}

func scope(t devices.Target) Scope { return Scope{Device: t.Device.Name, VDOM: t.VDOM} }

// Resolve picks the device and VDOM for a call.
func (r *Registry) Resolve(t Target) (devices.Target, error) {
	return r.inv.Resolve(t.Device, t.VDOM)
}

// List defaults and bounds.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// Page is embedded in list tool inputs.
type Page struct {
	Filter []string `json:"filter,omitempty" jsonschema:"FortiOS filters. Separate filters are ANDed; commas inside one filter are ORed. Operators: == != =@ (contains) !@ (does not contain) < <= > >=. Examples: name=@web, action==deny"`
	Fields []string `json:"fields,omitempty" jsonschema:"Return only these fields of each entry. Use to keep results small."`
	Limit  int      `json:"limit,omitempty" jsonschema:"Maximum entries to return (default 100, max 1000)."`
	Offset int      `json:"offset,omitempty" jsonschema:"Number of matching entries to skip, for paging."`
}

// ListOutput is the result of list tools.
type ListOutput struct {
	Scope
	Items []map[string]any `json:"items"`
	// Total is the number of matching entries reported by the device, or -1 if unknown.
	Total      int  `json:"total" jsonschema:"Number of matching entries on the device, or -1 if the device did not report it."`
	Truncated  bool `json:"truncated" jsonschema:"True if more matching entries exist than were returned."`
	NextOffset int  `json:"next_offset,omitempty" jsonschema:"Offset to request the next page, when truncated."`
}

// ItemOutput is the result of get tools.
type ItemOutput struct {
	Scope
	Item map[string]any `json:"item"`
}

// ResultsOutput is the result of tools returning monitor data as-is.
type ResultsOutput struct {
	Scope
	Results   any  `json:"results" jsonschema:"Data returned by the FortiOS endpoint, as the device sent it."`
	Truncated bool `json:"truncated,omitempty" jsonschema:"True if the results were cut to fit the size limit."`
}

func (p Page) validate() (limit int, err error) {
	limit = p.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	if limit < 0 || limit > MaxLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", MaxLimit)
	}
	if p.Offset < 0 {
		return 0, fmt.Errorf("offset must not be negative")
	}
	return limit, nil
}

// ListCMDB lists entries of a CMDB table.
func (r *Registry) ListCMDB(ctx context.Context, t devices.Target, path string, p Page) (ListOutput, error) {
	limit, err := p.validate()
	if err != nil {
		return ListOutput{}, err
	}
	params := t.Params()
	params.Filter, params.Format, params.Start, params.Count = p.Filter, p.Fields, p.Offset, limit
	resp, err := t.Device.Client.CMDBGet(ctx, path, "", params)
	if err != nil {
		return ListOutput{}, err
	}
	var items []map[string]any
	if err := resp.Decode(&items); err != nil {
		return ListOutput{}, err
	}

	out := ListOutput{Scope: scope(t), Total: -1}
	if resp.MatchedCount > 0 || len(items) == 0 {
		out.Total = resp.MatchedCount
		out.Truncated = p.Offset+len(items) < resp.MatchedCount
	} else {
		// No count reported: a full page may mean more remain.
		out.Truncated = len(items) == limit
	}
	kept, cut := r.fitItems(items)
	out.Items = kept
	if cut {
		out.Truncated = true
	}
	if out.Truncated {
		out.NextOffset = p.Offset + len(kept)
	}
	return out, nil
}

// GetCMDB reads one entry of a CMDB table.
func (r *Registry) GetCMDB(ctx context.Context, t devices.Target, path, mkey string) (ItemOutput, error) {
	if mkey == "" {
		return ItemOutput{}, fmt.Errorf("an entry name or ID is required")
	}
	resp, err := t.Device.Client.CMDBGet(ctx, path, mkey, t.Params())
	if err != nil {
		return ItemOutput{}, err
	}
	var items []map[string]any
	if err := resp.Decode(&items); err != nil {
		return ItemOutput{}, err
	}
	if len(items) == 0 {
		return ItemOutput{}, fmt.Errorf("%s %q not found", path, mkey)
	}
	Redact(items[0])
	item, err := r.fitOne(items[0])
	if err != nil {
		return ItemOutput{}, err
	}
	return ItemOutput{Scope: scope(t), Item: item}, nil
}

// GetCMDBSingleton reads a table that holds one object, such as system/sdwan.
func (r *Registry) GetCMDBSingleton(ctx context.Context, t devices.Target, path string) (ItemOutput, error) {
	resp, err := t.Device.Client.CMDBGet(ctx, path, "", t.Params())
	if err != nil {
		return ItemOutput{}, err
	}
	var item map[string]any
	if err := resp.Decode(&item); err != nil {
		return ItemOutput{}, err
	}
	Redact(item)
	item, err = r.fitOne(item)
	if err != nil {
		return ItemOutput{}, err
	}
	return ItemOutput{Scope: scope(t), Item: item}, nil
}

// Monitor calls a monitor GET endpoint and returns its results redacted and
// cut to the size limit.
func (r *Registry) Monitor(ctx context.Context, t devices.Target, path string, query url.Values) (ResultsOutput, error) {
	params := t.Params()
	params.Extra = query
	resp, err := t.Device.Client.MonitorGet(ctx, path, params)
	if err != nil {
		return ResultsOutput{}, err
	}
	return r.Results(t, resp)
}

// Results decodes a response's results into a ResultsOutput.
func (r *Registry) Results(t devices.Target, resp *fortios.Response) (ResultsOutput, error) {
	var results any
	if len(resp.Results) > 0 {
		if err := json.Unmarshal(resp.Results, &results); err != nil {
			return ResultsOutput{}, fmt.Errorf("decoding results: %w", err)
		}
	}
	fitted, cut, err := r.fitAny(Redact(results))
	if err != nil {
		return ResultsOutput{}, err
	}
	return ResultsOutput{Scope: scope(t), Results: fitted, Truncated: cut}, nil
}

// Redact replaces, in place, the values of sensitive fields anywhere in v.
func Redact(v any) any { return logging.Redact(v) }

// overhead leaves room for the envelope around items in a result.
const overhead = 512

// fitItems redacts items and keeps as many as fit within the size limit.
func (r *Registry) fitItems(items []map[string]any) (kept []map[string]any, cut bool) {
	kept = make([]map[string]any, 0, len(items))
	size := overhead
	for _, it := range items {
		Redact(it)
		b, _ := json.Marshal(it)
		if size+len(b)+1 > r.maxBytes {
			return kept, true
		}
		size += len(b) + 1
		kept = append(kept, it)
	}
	return kept, false
}

func (r *Registry) fitOne(item map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(item)
	if len(b)+overhead > r.maxBytes {
		return nil, fmt.Errorf("result is %d bytes, over the %d byte limit; request fewer fields", len(b), r.maxBytes)
	}
	return item, nil
}

// fitAny cuts array results to the size limit. Non-array results that are
// too large are an error.
func (r *Registry) fitAny(v any) (_ any, cut bool, _ error) {
	b, _ := json.Marshal(v)
	if len(b)+overhead <= r.maxBytes {
		return v, false, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false, fmt.Errorf("result is %d bytes, over the %d byte limit; narrow the query", len(b), r.maxBytes)
	}
	kept := make([]any, 0, len(list))
	size := overhead
	for _, it := range list {
		eb, _ := json.Marshal(it)
		if size+len(eb)+1 > r.maxBytes {
			break
		}
		size += len(eb) + 1
		kept = append(kept, it)
	}
	return kept, true, nil
}
