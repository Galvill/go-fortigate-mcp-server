package fortios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// CMDBGet reads a CMDB table, or one entry when mkey is non-empty.
func (c *Client) CMDBGet(ctx context.Context, path, mkey string, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodGet, api: "cmdb", path: path, mkey: mkey, params: p})
}

// CMDBCreate adds an entry to a CMDB table.
func (c *Client) CMDBCreate(ctx context.Context, path string, body any, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodPost, api: "cmdb", path: path, params: p, body: body})
}

// CMDBUpdate changes fields of an entry, or of a singleton table such as
// system/global when mkey is empty.
func (c *Client) CMDBUpdate(ctx context.Context, path, mkey string, body any, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodPut, api: "cmdb", path: path, mkey: mkey, params: p, body: body})
}

// CMDBDelete removes an entry.
func (c *Client) CMDBDelete(ctx context.Context, path, mkey string, p *Params) (*Response, error) {
	if mkey == "" {
		return nil, errors.New("fortios: delete requires an mkey")
	}
	return c.do(ctx, request{method: http.MethodDelete, api: "cmdb", path: path, mkey: mkey, params: p})
}

// MovePosition says where CMDBMove places an entry relative to the target.
type MovePosition string

// Move positions.
const (
	Before MovePosition = "before"
	After  MovePosition = "after"
)

// CMDBMove reorders an entry in an ordered table such as firewall/policy.
func (c *Client) CMDBMove(ctx context.Context, path, mkey string, pos MovePosition, target string, p *Params) (*Response, error) {
	if mkey == "" || target == "" {
		return nil, errors.New("fortios: move requires an mkey and a target")
	}
	if pos != Before && pos != After {
		return nil, fmt.Errorf("fortios: invalid move position %q", pos)
	}
	params := withExtra(p, url.Values{"action": {"move"}, string(pos): {target}})
	return c.do(ctx, request{method: http.MethodPut, api: "cmdb", path: path, mkey: mkey, params: params})
}

// CMDBSchema returns the table schema (fields, types, enums).
func (c *Client) CMDBSchema(ctx context.Context, path string, p *Params) (*Response, error) {
	return c.CMDBGet(ctx, path, "", withExtra(p, url.Values{"action": {"schema"}}))
}

// MonitorGet calls a monitor endpoint.
func (c *Client) MonitorGet(ctx context.Context, path string, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodGet, api: "monitor", path: path, params: p})
}

// MonitorPost calls a monitor action endpoint.
func (c *Client) MonitorPost(ctx context.Context, path string, body any, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodPost, api: "monitor", path: path, params: p, body: body})
}

// LogGet reads log entries, e.g. path "disk/traffic/forward".
func (c *Client) LogGet(ctx context.Context, path string, p *Params) (*Response, error) {
	return c.do(ctx, request{method: http.MethodGet, api: "log", path: path, params: p})
}

// ListAll pages through a CMDB table, returning at most max entries. more
// reports whether entries remain beyond max.
func (c *Client) ListAll(ctx context.Context, path string, p *Params, pageSize, maxItems int) (items []json.RawMessage, more bool, _ error) {
	if pageSize <= 0 || maxItems <= 0 {
		return nil, false, errors.New("fortios: pageSize and max must be positive")
	}
	page := Params{}
	if p != nil {
		page = *p
	}
	for {
		page.Count = min(pageSize, maxItems-len(items))
		resp, err := c.CMDBGet(ctx, path, "", &page)
		if err != nil {
			return nil, false, err
		}
		var batch []json.RawMessage
		if err := resp.Decode(&batch); err != nil {
			return nil, false, err
		}
		items = append(items, batch...)
		if len(batch) < page.Count {
			return items, false, nil
		}
		if len(items) >= maxItems {
			// Probe one entry past the cap so callers can report truncation.
			probe := page
			probe.Start, probe.Count = page.Start+len(batch), 1
			resp, err := c.CMDBGet(ctx, path, "", &probe)
			if err != nil {
				return nil, false, err
			}
			var rest []json.RawMessage
			if err := resp.Decode(&rest); err != nil {
				return nil, false, err
			}
			return items, len(rest) > 0, nil
		}
		page.Start += len(batch)
	}
}

func withExtra(p *Params, extra url.Values) *Params {
	out := Params{}
	if p != nil {
		out = *p
	}
	merged := url.Values{}
	for k, vs := range out.Extra {
		merged[k] = vs
	}
	for k, vs := range extra {
		merged[k] = vs
	}
	out.Extra = merged
	return &out
}
