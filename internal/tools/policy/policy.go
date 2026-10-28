// Package policy provides firewall policy tools.
package policy

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/fortios"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

const path = "firewall/policy"

// Register adds the policy toolset.
func Register(r *tools.Registry) {
	registerWrites(r)
	tools.RegisterTableReads(r, tools.Table{
		Toolset:    tools.Policy,
		Prefix:     "fgt_policy",
		Noun:       "firewall policy",
		Path:       path,
		NumericKey: true,
		About:      "Entries are in evaluation order: the first match wins. Use fields (e.g. policyid, name, srcintf, dstintf, srcaddr, dstaddr, service, action, status) to keep results small.",
	})

	tools.AddRead(r, tools.Policy, &mcp.Tool{
		Name:        "fgt_policy_lookup",
		Description: "Find which firewall policy would match a given flow (source interface, source IP, destination, protocol and port). Use this to answer \"would this traffic be allowed?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in LookupInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		q, err := in.query()
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		out, err := r.Monitor(ctx, tgt, "firewall/policy-lookup", q)
		return nil, out, err
	})

	tools.AddRead(r, tools.Policy, &mcp.Tool{
		Name:        "fgt_policy_hit_counts",
		Description: "Get usage statistics per firewall policy: hit count, bytes, active sessions and when last used. Useful to find unused policies.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in HitCountInput) (*mcp.CallToolResult, tools.ResultsOutput, error) {
		tgt, err := r.Resolve(in.Target)
		if err != nil {
			return nil, tools.ResultsOutput{}, err
		}
		q := url.Values{}
		if in.PolicyID != 0 {
			q.Set("policyid", strconv.Itoa(in.PolicyID))
		}
		out, err := r.Monitor(ctx, tgt, "firewall/policy", q)
		return nil, out, err
	})
}

// LookupInput is the input of fgt_policy_lookup.
type LookupInput struct {
	tools.Target
	SrcIntf    string `json:"srcintf" jsonschema:"Interface the traffic arrives on, e.g. port1."`
	SourceIP   string `json:"sourceip" jsonschema:"Source IP address."`
	Dest       string `json:"dest" jsonschema:"Destination IP address or FQDN."`
	Protocol   string `json:"protocol" jsonschema:"tcp, udp, icmp, or an IP protocol number."`
	DestPort   int    `json:"destport,omitempty" jsonschema:"Destination port (TCP/UDP)."`
	SourcePort int    `json:"sourceport,omitempty" jsonschema:"Source port (TCP/UDP)."`
	ICMPType   *int   `json:"icmptype,omitempty" jsonschema:"ICMP type (ICMP only)."`
	ICMPCode   *int   `json:"icmpcode,omitempty" jsonschema:"ICMP code (ICMP only)."`
	IPv6       bool   `json:"ipv6,omitempty" jsonschema:"True if the addresses are IPv6."`
}

var protocolNumbers = map[string]int{"icmp": 1, "tcp": 6, "udp": 17, "icmp6": 58, "sctp": 132}

// query builds policy-lookup parameters.
//
// TODO(M3): verify parameter names and protocol encoding against a FortiGate-VM.
func (in LookupInput) query() (url.Values, error) {
	if in.SrcIntf == "" || in.SourceIP == "" || in.Dest == "" || in.Protocol == "" {
		return nil, fmt.Errorf("srcintf, sourceip, dest and protocol are required")
	}
	proto, ok := protocolNumbers[strings.ToLower(in.Protocol)]
	if !ok {
		n, err := strconv.Atoi(in.Protocol)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("protocol must be tcp, udp, icmp, sctp or a number 0-255, got %q", in.Protocol)
		}
		proto = n
	}
	q := url.Values{
		"srcintf":  {in.SrcIntf},
		"sourceip": {in.SourceIP},
		"dest":     {in.Dest},
		"protocol": {strconv.Itoa(proto)},
	}
	if in.DestPort != 0 {
		q.Set("destport", strconv.Itoa(in.DestPort))
	}
	if in.SourcePort != 0 {
		q.Set("sourceport", strconv.Itoa(in.SourcePort))
	}
	if in.ICMPType != nil {
		q.Set("icmptype", strconv.Itoa(*in.ICMPType))
	}
	if in.ICMPCode != nil {
		q.Set("icmpcode", strconv.Itoa(*in.ICMPCode))
	}
	if in.IPv6 {
		q.Set("ipv6", "true")
	}
	return q, nil
}

// HitCountInput is the input of fgt_policy_hit_counts.
type HitCountInput struct {
	tools.Target
	PolicyID int `json:"policyid,omitempty" jsonschema:"Only this policy. Omit for all."`
}

// Fields are the common firewall policy settings. Unset fields are not sent.
type Fields struct {
	Name             string         `json:"name,omitempty" jsonschema:"Policy name."`
	SrcIntf          []string       `json:"srcintf,omitempty" jsonschema:"Incoming interfaces or zones, e.g. [\"port1\"]. Use any for all."`
	DstIntf          []string       `json:"dstintf,omitempty" jsonschema:"Outgoing interfaces or zones."`
	SrcAddr          []string       `json:"srcaddr,omitempty" jsonschema:"IPv4 source address objects or groups. Use all for any."`
	DstAddr          []string       `json:"dstaddr,omitempty" jsonschema:"IPv4 destination address objects, groups or VIPs."`
	SrcAddr6         []string       `json:"srcaddr6,omitempty" jsonschema:"IPv6 source address objects or groups."`
	DstAddr6         []string       `json:"dstaddr6,omitempty" jsonschema:"IPv6 destination address objects or groups."`
	Service          []string       `json:"service,omitempty" jsonschema:"Service objects or groups, e.g. [\"HTTPS\"], or ALL."`
	Action           string         `json:"action,omitempty" jsonschema:"accept, deny or ipsec."`
	Schedule         string         `json:"schedule,omitempty" jsonschema:"Schedule name. Defaults to always on create."`
	NAT              *bool          `json:"nat,omitempty" jsonschema:"Source NAT to the outgoing interface address, or to IP pools when ippool is set."`
	IPPool           *bool          `json:"ippool,omitempty" jsonschema:"Use the IP pools in poolname for source NAT."`
	PoolName         []string       `json:"poolname,omitempty" jsonschema:"IP pools for source NAT."`
	Users            []string       `json:"users,omitempty" jsonschema:"Local or remote users the policy applies to."`
	Groups           []string       `json:"groups,omitempty" jsonschema:"User groups the policy applies to."`
	LogTraffic       string         `json:"logtraffic,omitempty" jsonschema:"all, utm or disable."`
	Enabled          *bool          `json:"enabled,omitempty" jsonschema:"Whether the policy is active."`
	Comments         string         `json:"comments,omitempty"`
	UTMStatus        *bool          `json:"utm_status,omitempty" jsonschema:"Enable security profiles."`
	AVProfile        string         `json:"av_profile,omitempty"`
	WebFilterProfile string         `json:"webfilter_profile,omitempty"`
	IPSSensor        string         `json:"ips_sensor,omitempty"`
	ApplicationList  string         `json:"application_list,omitempty"`
	SSLSSHProfile    string         `json:"ssl_ssh_profile,omitempty"`
	Extra            map[string]any `json:"extra,omitempty" jsonschema:"Any other policy fields, by FortiOS name (see fgt_cmdb_schema path firewall/policy). Typed fields take precedence."`
}

func names(list []string) []map[string]string {
	out := make([]map[string]string, len(list))
	for i, n := range list {
		out[i] = map[string]string{"name": n}
	}
	return out
}

func enable(b bool) string {
	if b {
		return "enable"
	}
	return "disable"
}

// body converts the fields to a FortiOS request body.
func (f Fields) body() map[string]any {
	b := map[string]any{}
	for k, v := range f.Extra {
		b[k] = v
	}
	for k, v := range map[string][]string{
		"srcintf": f.SrcIntf, "dstintf": f.DstIntf, "srcaddr": f.SrcAddr, "dstaddr": f.DstAddr,
		"srcaddr6": f.SrcAddr6, "dstaddr6": f.DstAddr6, "service": f.Service, "poolname": f.PoolName,
		"users": f.Users, "groups": f.Groups,
	} {
		if v != nil {
			b[k] = names(v)
		}
	}
	for k, v := range map[string]string{
		"name": f.Name, "action": f.Action, "schedule": f.Schedule, "logtraffic": f.LogTraffic, "comments": f.Comments,
		"av-profile": f.AVProfile, "webfilter-profile": f.WebFilterProfile, "ips-sensor": f.IPSSensor,
		"application-list": f.ApplicationList, "ssl-ssh-profile": f.SSLSSHProfile,
	} {
		if v != "" {
			b[k] = v
		}
	}
	for k, v := range map[string]*bool{"nat": f.NAT, "ippool": f.IPPool, "status": f.Enabled, "utm-status": f.UTMStatus} {
		if v != nil {
			b[k] = enable(*v)
		}
	}
	return b
}

// Position places a policy relative to another one.
type Position struct {
	Before *int `json:"before,omitempty" jsonschema:"Place the policy directly before the policy with this ID."`
	After  *int `json:"after,omitempty" jsonschema:"Place the policy directly after the policy with this ID."`
}

func (p Position) resolve() (fortios.MovePosition, string, bool, error) {
	switch {
	case p.Before != nil && p.After != nil:
		return "", "", false, fmt.Errorf("give before or after, not both")
	case p.Before != nil:
		return fortios.Before, strconv.Itoa(*p.Before), true, nil
	case p.After != nil:
		return fortios.After, strconv.Itoa(*p.After), true, nil
	}
	return "", "", false, nil
}

// CreateInput is the input of fgt_policy_create.
type CreateInput struct {
	tools.Target
	Fields
	Position
}

// UpdateInput is the input of fgt_policy_update.
type UpdateInput struct {
	tools.Target
	ID int `json:"id" jsonschema:"ID of the policy to change."`
	Fields
}

// MoveInput is the input of fgt_policy_move.
type MoveInput struct {
	tools.Target
	ID int `json:"id" jsonschema:"ID of the policy to move."`
	Position
}

func registerWrites(r *tools.Registry) {
	tools.AddWrite(r, tools.Policy, tools.Create, &mcp.Tool{
		Name: "fgt_policy_create",
		Description: "Create a firewall policy. New policies go to the end of the list, where earlier policies may shadow them; " +
			"use before or after to place it. Requires srcintf, dstintf, srcaddr or srcaddr6, dstaddr or dstaddr6, service and action.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CreateInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		f := in.Fields
		if len(f.SrcIntf) == 0 || len(f.DstIntf) == 0 || len(f.SrcAddr)+len(f.SrcAddr6) == 0 ||
			len(f.DstAddr)+len(f.DstAddr6) == 0 || len(f.Service) == 0 || f.Action == "" {
			return nil, tools.WriteOutput{}, fmt.Errorf("srcintf, dstintf, srcaddr (or srcaddr6), dstaddr (or dstaddr6), service and action are required")
		}
		pos, target, move, err := in.resolve()
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		body := f.body()
		if _, ok := body["schedule"]; !ok {
			body["schedule"] = "always"
		}
		out, err := r.CreateCMDB(ctx, tgt, path, body)
		if err != nil || !move {
			return nil, out, err
		}
		moved, err := r.MoveCMDB(ctx, tgt, path, out.Mkey, pos, target)
		if err != nil {
			out.Warning = fmt.Sprintf("policy %s was created at the end of the list, but moving it failed: %v", out.Mkey, err)
			return nil, out, nil
		}
		out.Revision = moved.Revision
		return nil, out, nil
	})

	tools.AddWrite(r, tools.Policy, tools.Update, &mcp.Tool{
		Name:        "fgt_policy_update",
		Description: "Change fields of a firewall policy. Only the fields given change; list fields (srcaddr, service, ...) replace the whole list.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		body := in.body()
		if len(body) == 0 {
			return nil, tools.WriteOutput{}, fmt.Errorf("give at least one field to change")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		out, err := r.UpdateCMDB(ctx, tgt, path, strconv.Itoa(in.ID), body)
		return nil, out, err
	})

	tools.AddWrite(r, tools.Policy, tools.Delete, &mcp.Tool{
		Name:        "fgt_policy_delete",
		Description: "Delete a firewall policy.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in tools.GetIDInput) (*mcp.CallToolResult, tools.DeleteOutput, error) {
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.DeleteOutput{}, err
		}
		out, err := r.DeleteCMDB(ctx, tgt, path, strconv.Itoa(in.ID))
		return nil, out, err
	})

	tools.AddWrite(r, tools.Policy, tools.Update, &mcp.Tool{
		Name:        "fgt_policy_move",
		Description: "Move a firewall policy before or after another one. Policies are evaluated top to bottom; the first match wins.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in MoveInput) (*mcp.CallToolResult, tools.WriteOutput, error) {
		pos, target, move, err := in.resolve()
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		if !move {
			return nil, tools.WriteOutput{}, fmt.Errorf("give before or after")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.WriteOutput{}, err
		}
		out, err := r.MoveCMDB(ctx, tgt, path, strconv.Itoa(in.ID), pos, target)
		return nil, out, err
	})
}
