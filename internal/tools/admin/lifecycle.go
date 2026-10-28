package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/galvill/go-fortigate-mcp-server/internal/devices"
	"github.com/galvill/go-fortigate-mcp-server/internal/tools"
)

var admins = tools.Table{
	Toolset: tools.Admin,
	Prefix:  "fgt_admin",
	Noun:    "administrator account",
	Path:    "system/admin",
	About:   "Passwords are never returned.",
	Fields: `Main fields: accprofile (e.g. super_admin, prof_admin), password (write-only), trusthost1..trusthost10 ("10.0.0.0 255.255.255.0"), ` +
		`vdom (list of {"name": "root"}), two-factor, email-to, comments.`,
}

// BackupInput is the input of fgt_config_backup.
type BackupInput struct {
	tools.Target
	Scope       string   `json:"scope,omitempty" jsonschema:"global (default): the whole device. vdom: only the VDOM given by the vdom argument."`
	Destination string   `json:"destination,omitempty" jsonschema:"inline (default): return the configuration text. disk: save the full file on the server (only when the server has a backup directory)."`
	Sections    []string `json:"sections,omitempty" jsonschema:"Inline only: return just these top-level sections, e.g. [\"firewall policy\", \"system interface\"]."`
}

// BackupOutput is the result of fgt_config_backup.
type BackupOutput struct {
	tools.Scope
	ConfigScope string   `json:"config_scope"`
	SHA256      string   `json:"sha256" jsonschema:"SHA-256 of the full configuration, even when only sections are returned."`
	Size        int      `json:"size" jsonschema:"Size of the full configuration in bytes."`
	File        string   `json:"file,omitempty" jsonschema:"Name of the saved file in the server's backup directory (disk destination)."`
	Config      string   `json:"config,omitempty" jsonschema:"Configuration text (inline destination)."`
	Missing     []string `json:"missing_sections,omitempty" jsonschema:"Requested sections not found in the configuration."`
	Truncated   bool     `json:"truncated,omitempty" jsonschema:"True if the text was cut to fit the size limit; request sections or use disk."`
}

func registerLifecycle(r *tools.Registry) {
	tools.RegisterTableWrites(r, admins)

	tools.AddRead(r, tools.Admin, &mcp.Tool{
		Name: "fgt_config_backup",
		Description: "Back up the device configuration. By default returns the text inline; use sections to return only parts " +
			"(e.g. firewall policy), or destination disk to save the full file on the server when a backup directory is configured.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BackupInput) (*mcp.CallToolResult, BackupOutput, error) {
		out, err := backup(ctx, r, in)
		return nil, out, err
	})

	tools.AddWrite(r, tools.Admin, tools.Action, &mcp.Tool{
		Name: "fgt_config_restore",
		Description: "Restore a configuration file saved by fgt_config_backup in the server's backup directory. " +
			"Replaces the running configuration and reboots the device. Needs hostname confirmation.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in RestoreInput) (*mcp.CallToolResult, tools.DisruptiveOutput, error) {
		out, err := restore(ctx, r, in)
		return nil, out, err
	})

	tools.AddWrite(r, tools.Admin, tools.Action, &mcp.Tool{
		Name:        "fgt_firmware_upgrade",
		Description: "Upgrade the firmware to an image from FortiGuard (see fgt_firmware_info for available images). The device reboots. Needs hostname confirmation.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UpgradeInput) (*mcp.CallToolResult, tools.DisruptiveOutput, error) {
		if in.ImageID == "" {
			return nil, tools.DisruptiveOutput{}, errors.New("image_id is required")
		}
		tgt, err := r.ResolveWrite(in.Target)
		if err != nil {
			return nil, tools.DisruptiveOutput{}, err
		}
		// TODO(M3): verify body field names against a FortiGate-VM.
		out, err := r.RunDisruptive(ctx, tgt, in.Confirmation, "system/firmware/upgrade",
			map[string]any{"source": "fortiguard", "filename": in.ImageID},
			"upgrade the firmware to image "+in.ImageID, "The device downloads the image and reboots into it; expect several minutes of downtime.",
			map[string]any{"image_id": in.ImageID})
		return nil, out, err
	})

	for _, op := range []struct{ name, path, action, impact string }{
		{"fgt_reboot", "system/os/reboot", "reboot the device", "It will be unreachable for several minutes."},
		{"fgt_shutdown", "system/os/shutdown", "shut down the device", "It stays down until someone powers it on locally."},
	} {
		tools.AddWrite(r, tools.Admin, tools.Action, &mcp.Tool{
			Name:        op.name,
			Description: strings.ToUpper(op.action[:1]) + op.action[1:] + ". " + op.impact + " Needs hostname confirmation.",
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in PowerInput) (*mcp.CallToolResult, tools.DisruptiveOutput, error) {
			tgt, err := r.ResolveWrite(in.Target)
			if err != nil {
				return nil, tools.DisruptiveOutput{}, err
			}
			reason := in.Reason
			if reason == "" {
				reason = "requested through fortigate-mcp"
			}
			out, err := r.RunDisruptive(ctx, tgt, in.Confirmation, op.path,
				map[string]any{"event_log_message": reason}, op.action, op.impact, nil)
			return nil, out, err
		})
	}
}

// RestoreInput is the input of fgt_config_restore.
type RestoreInput struct {
	tools.Target
	tools.Confirmation
	File  string `json:"file" jsonschema:"Name of a backup file in the server's backup directory, as returned by fgt_config_backup."`
	Scope string `json:"scope,omitempty" jsonschema:"global (default) or vdom. Must match how the file was backed up."`
}

// UpgradeInput is the input of fgt_firmware_upgrade.
type UpgradeInput struct {
	tools.Target
	tools.Confirmation
	ImageID string `json:"image_id" jsonschema:"ID of an available image from fgt_firmware_info."`
}

// PowerInput is the input of fgt_reboot and fgt_shutdown.
type PowerInput struct {
	tools.Target
	tools.Confirmation
	Reason string `json:"reason,omitempty" jsonschema:"Recorded in the device's event log."`
}

func configScope(s string) (string, error) {
	switch s {
	case "", "global":
		return "global", nil
	case "vdom":
		return "vdom", nil
	}
	return "", fmt.Errorf("scope must be global or vdom, got %q", s)
}

func backup(ctx context.Context, r *tools.Registry, in BackupInput) (BackupOutput, error) {
	scope, err := configScope(in.Scope)
	if err != nil {
		return BackupOutput{}, err
	}
	disk := false
	switch in.Destination {
	case "", "inline":
	case "disk":
		if r.BackupDir() == "" {
			return BackupOutput{}, errors.New("this server has no backup directory configured; use destination inline")
		}
		if len(in.Sections) > 0 {
			return BackupOutput{}, errors.New("sections apply to inline backups only")
		}
		disk = true
	default:
		return BackupOutput{}, fmt.Errorf("destination must be inline or disk, got %q", in.Destination)
	}
	tgt, err := r.Resolve(in.Target)
	if err != nil {
		return BackupOutput{}, err
	}

	// TODO(M3): verify on 7.6, which may require POST for backups.
	params := tgt.Params()
	params.Extra = url.Values{"scope": {scope}}
	resp, err := tgt.Device.Client.MonitorDownload(ctx, "system/config/backup", params)
	if err != nil {
		return BackupOutput{}, err
	}
	config := resp.Raw
	sum := sha256.Sum256(config)
	out := BackupOutput{
		Scope:       tools.Scope{Device: tgt.Device.Name, VDOM: tgt.VDOM},
		ConfigScope: scope,
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        len(config),
	}

	if disk {
		name, err := save(r.BackupDir(), tgt, scope, config)
		if err != nil {
			return BackupOutput{}, err
		}
		out.File = name
		return out, nil
	}

	text := string(config)
	if len(in.Sections) > 0 {
		text, out.Missing = extractSections(text, in.Sections)
	}
	if limit := r.MaxResultBytes() - 1024; len(text) > limit {
		text, out.Truncated = text[:limit], true
	}
	out.Config = text
	return out, nil
}

func save(dir string, t devices.Target, scope string, config []byte) (string, error) {
	label := "global"
	if scope == "vdom" {
		label = "vdom-" + t.VDOM
	}
	name := fmt.Sprintf("%s_%s_%s.conf", t.Device.Name, label, time.Now().UTC().Format("20060102T150405Z"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("saving backup: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("saving backup: %w", err)
	}
	if _, err := f.Write(config); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("saving backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("saving backup: %w", err)
	}
	return name, nil
}

// extractSections returns the "config <section>" ... "end" blocks for each
// requested section (at any nesting level, e.g. inside VDOM blocks), and
// the sections that were not found.
func extractSections(config string, sections []string) (string, []string) {
	lines := strings.Split(config, "\n")
	var b strings.Builder
	var missing []string
	for _, sec := range sections {
		header := "config " + strings.TrimSpace(sec)
		found := false
		for i := 0; i < len(lines); i++ {
			trimmed := strings.TrimLeft(lines[i], " \t")
			if strings.TrimRight(trimmed, " \r") != header {
				continue
			}
			found = true
			indent := lines[i][:len(lines[i])-len(trimmed)]
			j := i
			for ; j < len(lines); j++ {
				b.WriteString(lines[j])
				b.WriteByte('\n')
				if j > i && strings.TrimRight(lines[j], " \r") == indent+"end" {
					break
				}
			}
			i = j
		}
		if !found {
			missing = append(missing, sec)
		}
	}
	return b.String(), missing
}

func restore(ctx context.Context, r *tools.Registry, in RestoreInput) (tools.DisruptiveOutput, error) {
	if r.BackupDir() == "" {
		return tools.DisruptiveOutput{}, errors.New("this server has no backup directory configured, so there is nothing to restore from")
	}
	if in.File == "" || in.File != filepath.Base(in.File) || strings.HasPrefix(in.File, ".") {
		return tools.DisruptiveOutput{}, errors.New("file must be the name of a file in the backup directory, without a path")
	}
	scope, err := configScope(in.Scope)
	if err != nil {
		return tools.DisruptiveOutput{}, err
	}
	// os.Root confines access to the backup directory, symlinks included.
	root, err := os.OpenRoot(r.BackupDir())
	if err != nil {
		return tools.DisruptiveOutput{}, fmt.Errorf("reading backup file: %w", err)
	}
	defer func() { _ = root.Close() }()
	config, err := root.ReadFile(in.File)
	if err != nil {
		return tools.DisruptiveOutput{}, fmt.Errorf("reading backup file: %w", err)
	}
	tgt, err := r.ResolveWrite(in.Target)
	if err != nil {
		return tools.DisruptiveOutput{}, err
	}
	sum := sha256.Sum256(config)
	body := map[string]any{"source": "upload", "scope": scope, "file_content": base64.StdEncoding.EncodeToString(config)}
	if scope == "vdom" {
		body["vdom"] = tgt.VDOM
	}
	// TODO(M3): verify body field names against a FortiGate-VM.
	return r.RunDisruptive(ctx, tgt, in.Confirmation, "system/config/restore", body,
		"restore configuration "+in.File, "The running configuration is replaced and the device reboots.",
		map[string]any{"file": in.File, "sha256": hex.EncodeToString(sum[:]), "size": len(config), "scope": scope})
}
