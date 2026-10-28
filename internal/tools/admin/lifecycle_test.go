package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools/toolstest"
)

const sampleConfig = `#config-version=FGVM64-7.4.4
config system global
    set hostname "FGVM-FAKE"
end
config vdom
edit root
config firewall policy
    edit 1
        set name "web"
    next
end
config firewall address
    edit "all"
    next
end
next
end
`

func TestExtractSections(t *testing.T) {
	got, missing := extractSections(sampleConfig, []string{"firewall policy", "system global", "router bgp"})
	if !strings.Contains(got, "config firewall policy\n    edit 1") || !strings.Contains(got, `set hostname "FGVM-FAKE"`) || strings.Contains(got, "firewall address") {
		t.Errorf("sections = %q", got)
	}
	if len(missing) != 1 || missing[0] != "router bgp" {
		t.Errorf("missing = %v", missing)
	}
}

func TestBackupInline(t *testing.T) {
	env := toolstest.Connect(t, Register, tools.Options{})
	env.FW.SetDownload("system/config/backup", []byte(sampleConfig))

	out := toolstest.Call[BackupOutput](t, env, "fgt_config_backup", nil)
	if out.Config != sampleConfig || out.Size != len(sampleConfig) || out.SHA256 == "" || out.ConfigScope != "global" || out.Truncated {
		t.Errorf("backup = %+v", out)
	}
	if q := env.FW.Requests()[0].Query; q.Get("scope") != "global" {
		t.Errorf("query = %v", q)
	}

	part := toolstest.Call[BackupOutput](t, env, "fgt_config_backup", map[string]any{"sections": []string{"firewall policy"}, "scope": "vdom"})
	if !strings.HasPrefix(part.Config, "config firewall policy") || part.SHA256 != out.SHA256 || part.ConfigScope != "vdom" {
		t.Errorf("sections backup = %+v", part)
	}

	toolstest.ExpectError(t, env, "fgt_config_backup", map[string]any{"destination": "disk"}, "no backup directory")
	toolstest.ExpectError(t, env, "fgt_config_backup", map[string]any{"scope": "everything"}, "scope must be")
}

func TestBackupTruncated(t *testing.T) {
	env := toolstest.Connect(t, Register, tools.Options{MaxResultBytes: 4096})
	env.FW.SetDownload("system/config/backup", []byte(strings.Repeat("# filler line\n", 1000)))
	out := toolstest.Call[BackupOutput](t, env, "fgt_config_backup", nil)
	if !out.Truncated || len(out.Config) >= 4096 || out.Size != 14000 {
		t.Errorf("truncated backup: truncated=%v len=%d size=%d", out.Truncated, len(out.Config), out.Size)
	}
}

func TestBackupToDiskAndRestore(t *testing.T) {
	dir := t.TempDir()
	env := toolstest.Connect(t, Register, tools.Options{BackupDir: dir})
	env.FW.SetDownload("system/config/backup", []byte(sampleConfig))
	env.FW.SetMonitor("system/config/restore", map[string]any{"status": "success"})

	out := toolstest.Call[BackupOutput](t, env, "fgt_config_backup", map[string]any{"destination": "disk"})
	if out.File == "" || out.Config != "" || !strings.HasPrefix(out.File, "fw_global_") {
		t.Fatalf("disk backup = %+v", out)
	}
	path := filepath.Join(dir, out.File)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != sampleConfig {
		t.Fatalf("saved file: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("backup file mode = %v", info.Mode().Perm())
	}

	preview := toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_config_restore", map[string]any{"file": out.File})
	if preview.Executed || preview.Preview.Details["sha256"] != out.SHA256 {
		t.Errorf("restore preview = %+v", preview)
	}
	done := toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_config_restore", map[string]any{"file": out.File, "confirm": "FGVM-FAKE"})
	if !done.Executed {
		t.Errorf("restore = %+v", done)
	}
	reqs := env.FW.Requests()
	last := reqs[len(reqs)-1]
	if last.Path != "monitor/system/config/restore" || !strings.Contains(string(last.Body), `"source":"upload"`) {
		t.Errorf("restore request = %s %s", last.Path, last.Body)
	}

	for _, bad := range []string{"../etc/passwd", "/etc/passwd", ".hidden", ""} {
		toolstest.ExpectError(t, env, "fgt_config_restore", map[string]any{"file": bad, "confirm": "FGVM-FAKE"}, "file must be")
	}
	toolstest.ExpectError(t, env, "fgt_config_restore", map[string]any{"file": "missing.conf"}, "reading backup file")
}

func TestPowerAndFirmware(t *testing.T) {
	env := toolstest.Connect(t, Register, tools.Options{})
	for _, p := range []string{"system/os/reboot", "system/os/shutdown", "system/firmware/upgrade"} {
		env.FW.SetMonitor(p, map[string]any{})
	}
	for _, name := range []string{"fgt_reboot", "fgt_shutdown"} {
		if out := toolstest.Call[tools.DisruptiveOutput](t, env, name, nil); out.Executed {
			t.Errorf("%s executed without confirm", name)
		}
		if out := toolstest.Call[tools.DisruptiveOutput](t, env, name, map[string]any{"confirm": "FGVM-FAKE", "reason": "maintenance"}); !out.Executed {
			t.Errorf("%s not executed with confirm: %+v", name, out)
		}
	}
	up := toolstest.Call[tools.DisruptiveOutput](t, env, "fgt_firmware_upgrade", map[string]any{"image_id": "06004001FIMG0012345678"})
	if up.Executed || up.Preview.Details["image_id"] != "06004001FIMG0012345678" {
		t.Errorf("firmware preview = %+v", up)
	}
	toolstest.ExpectError(t, env, "fgt_firmware_upgrade", map[string]any{"image_id": ""}, "image_id is required")
	toolstest.ExpectError(t, env, "fgt_reboot", map[string]any{"device": "fw2", "confirm": "FGVM-FAKE"}, "read-only")

	for _, r := range env.FW.Requests() {
		if r.Path == "monitor/system/os/reboot" && !strings.Contains(string(r.Body), "maintenance") {
			t.Errorf("reboot body = %s", r.Body)
		}
	}
}

func TestRestoreCannotEscapeBackupDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.conf")
	if err := os.WriteFile(outside, []byte("config system global\nend\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.conf")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	env := toolstest.Connect(t, Register, tools.Options{BackupDir: dir})
	toolstest.ExpectError(t, env, "fgt_config_restore", map[string]any{"file": "link.conf"}, "reading backup file")
}
