package admin_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/admin"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func TestAdminReads(t *testing.T) {
	env := toolstest.Connect(t, admin.Register, tools.Options{})
	env.FW.Seed("root", "system/admin", map[string]any{"name": "admin", "accprofile": "super_admin", "password": "ENC SH2abc"})
	env.FW.SetMonitor("system/firmware", map[string]any{"current": map[string]any{"version": "v7.4.4"}})
	env.FW.SetMonitor("system/config-revision", []any{})
	env.FW.SetMonitor("system/available-certificates", []any{})

	a := toolstest.Call[toolstest.Item](t, env, "fgt_admin_get", map[string]any{"name": "admin"})
	if a.Item["accprofile"] != "super_admin" || a.Item["password"] != "[REDACTED]" {
		t.Errorf("admin = %+v", a)
	}
	toolstest.Call[toolstest.Results](t, env, "fgt_firmware_info", nil)
	toolstest.Call[toolstest.Results](t, env, "fgt_config_revisions", nil)
	toolstest.Call[toolstest.Results](t, env, "fgt_certificate_list", nil)
}
