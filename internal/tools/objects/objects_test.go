package objects_test

import (
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/objects"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

func TestObjectTables(t *testing.T) {
	env := toolstest.Connect(t, objects.Register, tools.Options{})
	for _, tbl := range objects.Tables {
		env.FW.Seed("root", tbl.Path, map[string]any{"name": "v4-" + tbl.Prefix})
		if tbl.Path6 != "" {
			env.FW.Seed("root", tbl.Path6, map[string]any{"name": "v6-" + tbl.Prefix})
		}
	}
	for _, tbl := range objects.Tables {
		list := toolstest.Call[toolstest.List](t, env, tbl.Prefix+"_list", nil)
		if len(list.Items) != 1 || list.Items[0]["name"] != "v4-"+tbl.Prefix {
			t.Errorf("%s_list = %+v", tbl.Prefix, list)
		}
		toolstest.Call[toolstest.Item](t, env, tbl.Prefix+"_get", map[string]any{"name": "v4-" + tbl.Prefix})
		if tbl.Path6 != "" {
			item := toolstest.Call[toolstest.Item](t, env, tbl.Prefix+"_get", map[string]any{"name": "v6-" + tbl.Prefix, "family": "ipv6"})
			if item.Item["name"] != "v6-"+tbl.Prefix {
				t.Errorf("%s_get ipv6 = %+v", tbl.Prefix, item)
			}
		}
	}
}

func TestObjectUsage(t *testing.T) {
	env := toolstest.Connect(t, objects.Register, tools.Options{})
	env.FW.SetMonitor("system/object/usage", map[string]any{"currently_using": []any{}})
	toolstest.Call[toolstest.Results](t, env, "fgt_object_usage", map[string]any{"path": "firewall.service/custom", "name": "HTTPS"})
	q := env.FW.Requests()[0].Query
	if q.Get("q_path") != "firewall.service" || q.Get("q_name") != "custom" || q.Get("mkey") != "HTTPS" {
		t.Errorf("query = %v", q)
	}
	toolstest.ExpectError(t, env, "fgt_object_usage", map[string]any{"path": "firewall", "name": "x"}, "<category>/<table>")
	toolstest.ExpectError(t, env, "fgt_object_usage", map[string]any{"path": "../x/y", "name": "x"}, "invalid API path")
}
