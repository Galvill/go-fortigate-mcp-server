// Package admin provides administration and lifecycle tools.
package admin

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

// Register adds the admin toolset.
func Register(r *tools.Registry) {
	monitor := func(name, description, path string) {
		tools.AddRead(r, tools.Admin, &mcp.Tool{Name: name, Description: description},
			func(ctx context.Context, _ *mcp.CallToolRequest, in tools.Target) (*mcp.CallToolResult, tools.ResultsOutput, error) {
				tgt, err := r.Resolve(in)
				if err != nil {
					return nil, tools.ResultsOutput{}, err
				}
				out, err := r.Monitor(ctx, tgt, path, nil)
				return nil, out, err
			})
	}

	monitor("fgt_firmware_info",
		"Get the running firmware version and the firmware images available for upgrade from FortiGuard.",
		"system/firmware")
	monitor("fgt_config_revisions",
		"List saved configuration revisions with their IDs, time, admin and comment.",
		"system/config-revision")
	monitor("fgt_certificate_list",
		"List certificates available on the device (local, CA, remote), with subject, issuer and expiry.",
		"system/available-certificates")

	tools.RegisterTableReads(r, tools.Table{
		Toolset: tools.Admin,
		Prefix:  "fgt_admin",
		Noun:    "administrator account",
		Path:    "system/admin",
		About:   "Passwords are never returned.",
	})
}
