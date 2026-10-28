// Package policy provides firewall policy tools.
package policy

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Register adds the policy toolset.
func Register(r *tools.Registry) {
	tools.RegisterTableReads(r, tools.Table{
		Toolset:    tools.Policy,
		Prefix:     "fgt_policy",
		Noun:       "firewall policy",
		Path:       "firewall/policy",
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
