// Package config loads server settings and the FortiGate device inventory
// from flags, environment variables and an optional YAML file.
//
// Precedence, highest first: flags, environment, config file, defaults.
package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/galvill/go-fortigate-mcp-server/internal/logging"
)

const (
	// DefaultVDOM is used when a device doesn't specify one.
	DefaultVDOM = "root"
	// DefaultTimeout is the per-request timeout when a device doesn't specify one.
	DefaultTimeout = 30 * time.Second
	// DefaultSingleDeviceName names the device defined by unprefixed FORTIGATE_* variables.
	DefaultSingleDeviceName = "default"
)

// Config is the fully resolved configuration.
type Config struct {
	Server Server
	// DefaultDevice is used when a tool call omits the device. Empty means a
	// device must be named unless exactly one is configured.
	DefaultDevice string
	// Devices is sorted by name.
	Devices []Device
}

// Server holds settings for the MCP server itself.
type Server struct {
	ConfigFile string
	LogLevel   slog.Level
	LogFormat  string
	// Toolsets lists enabled toolsets; nil means all.
	Toolsets []string
	// ReadOnly omits every mutating tool.
	ReadOnly bool
	// MaxResultBytes caps the size of a tool result.
	MaxResultBytes int
	// AuditLog is the audit log file path; empty means stderr.
	AuditLog string
	// AuditBodies includes redacted request bodies in audit records.
	AuditBodies bool
	// BackupDir, if set, is where fgt_config_backup may save files.
	BackupDir string
	// Transport is "stdio" or "http".
	Transport string
	// HTTP holds settings for the http transport.
	HTTP HTTP
}

// HTTP holds settings for the streamable HTTP transport.
type HTTP struct {
	Addr string
	// Path is the MCP endpoint path, starting with "/".
	Path      string
	Stateless bool
	// AllowedOrigins lists browser origins (scheme://host[:port]) allowed to
	// call the endpoint. Requests with any other Origin header are rejected.
	AllowedOrigins []string
	// IdentityHeader names a header set by an upstream proxy whose value is
	// recorded in audit records. It is never used for access decisions.
	IdentityHeader string
	// MaxBodyBytes caps the size of a request body.
	MaxBodyBytes int64
	// TLSCert and TLSKey enable TLS when both are set.
	TLSCert, TLSKey string
	// Metrics serves Prometheus metrics at /metrics.
	Metrics bool
}

// DefaultMaxBodyBytes is the default cap on an HTTP request body.
const DefaultMaxBodyBytes = 4 << 20

// DefaultMaxResultBytes is the default cap on a tool result's size.
const DefaultMaxResultBytes = 200_000

// minMaxResultBytes keeps the cap large enough for a single typical entry.
const minMaxResultBytes = 4_096

// Device is one FortiGate.
type Device struct {
	Name string
	// Host is a normalized base URL: https://host[:port], no path.
	Host               string
	Token              Secret
	VDOM               string
	CACert             string
	InsecureSkipVerify bool
	Timeout            time.Duration
	ReadOnly           bool
}

// Secret is a string that never prints, logs or marshals its value.
type Secret string

// Reveal returns the secret value. Call it only where the value is sent to a FortiGate.
func (s Secret) Reveal() string { return string(s) }

func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return logging.Redacted
}

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return strconv.Quote(s.String()) }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// MarshalText keeps JSON/YAML encoders from emitting the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// LookupEnv matches os.LookupEnv; tests pass a map-backed one.
type LookupEnv func(string) (string, bool)

type setting struct {
	flag, env, def, usage string
	// boolean settings are registered as flags that need no value (-read-only).
	boolean bool
}

var settings = []setting{
	{flag: "config", env: "FORTIGATE_MCP_CONFIG", usage: "path to YAML config file"},
	{flag: "log-level", env: "FORTIGATE_MCP_LOG_LEVEL", def: "info", usage: "log level: debug, info, warn, error"},
	{flag: "log-format", env: "FORTIGATE_MCP_LOG_FORMAT", def: "text", usage: "log format: text or json"},
	{flag: "toolsets", env: "FORTIGATE_MCP_TOOLSETS", def: "all", usage: "comma-separated toolsets to enable, or \"all\""},
	{flag: "read-only", env: "FORTIGATE_MCP_READ_ONLY", def: "false", usage: "omit all mutating tools", boolean: true},
	{flag: "max-result-bytes", env: "FORTIGATE_MCP_MAX_RESULT_BYTES", def: strconv.Itoa(DefaultMaxResultBytes), usage: "maximum size of a tool result in bytes"},
	{flag: "audit-log", env: "FORTIGATE_MCP_AUDIT_LOG", usage: "audit log file (JSON lines); default stderr"},
	{flag: "audit-bodies", env: "FORTIGATE_MCP_AUDIT_BODIES", def: "false", usage: "include request bodies, secrets redacted, in the audit log", boolean: true},
	{flag: "backup-dir", env: "FORTIGATE_MCP_BACKUP_DIR", usage: "directory where config backups may be saved; disabled if unset"},
	{flag: "transport", env: "FORTIGATE_MCP_TRANSPORT", def: "stdio", usage: "transport: stdio or http"},
	{flag: "http-addr", env: "FORTIGATE_MCP_HTTP_ADDR", def: "127.0.0.1:8080", usage: "http listen address"},
	{flag: "http-path", env: "FORTIGATE_MCP_HTTP_PATH", def: "/mcp", usage: "http endpoint path"},
	{flag: "stateless", env: "FORTIGATE_MCP_STATELESS", def: "false", usage: "stateless streamable HTTP (no sessions)", boolean: true},
	{flag: "allowed-origins", env: "FORTIGATE_MCP_ALLOWED_ORIGINS", usage: "comma-separated browser origins allowed to call the http endpoint; requests with other Origin headers are rejected"},
	{flag: "audit-identity-header", env: "FORTIGATE_MCP_AUDIT_IDENTITY_HEADER", usage: "header set by an upstream proxy (e.g. X-Forwarded-User) to record in audit logs; never used for access decisions"},
	{flag: "http-max-body-bytes", env: "FORTIGATE_MCP_HTTP_MAX_BODY_BYTES", def: strconv.Itoa(DefaultMaxBodyBytes), usage: "maximum http request body size in bytes"},
	{flag: "tls-cert", env: "FORTIGATE_MCP_TLS_CERT", usage: "TLS certificate file for the http transport (with -tls-key)"},
	{flag: "tls-key", env: "FORTIGATE_MCP_TLS_KEY", usage: "TLS key file for the http transport (with -tls-cert)"},
	{flag: "metrics", env: "FORTIGATE_MCP_METRICS", def: "false", usage: "serve Prometheus metrics at /metrics (http transport only)", boolean: true},
}

// Flags holds the server flags registered on a FlagSet.
type Flags struct {
	fs   *flag.FlagSet
	vals map[string]func() string
}

// BindFlags registers the server flags on fs.
func BindFlags(fs *flag.FlagSet) *Flags {
	f := &Flags{fs: fs, vals: make(map[string]func() string, len(settings))}
	for _, s := range settings {
		usage := fmt.Sprintf("%s (env %s)", s.usage, s.env)
		if s.boolean {
			def, _ := strconv.ParseBool(s.def)
			p := fs.Bool(s.flag, def, usage)
			f.vals[s.flag] = func() string { return strconv.FormatBool(*p) }
		} else {
			p := fs.String(s.flag, s.def, usage)
			f.vals[s.flag] = func() string { return *p }
		}
	}
	return f
}

// Load resolves the configuration. Call it after the FlagSet is parsed.
func (f *Flags) Load(lookupEnv LookupEnv) (*Config, error) {
	setByFlag := map[string]bool{}
	f.fs.Visit(func(fl *flag.Flag) { setByFlag[fl.Name] = true })

	value := func(name string) string {
		for _, s := range settings {
			if s.flag != name {
				continue
			}
			if setByFlag[name] {
				return f.vals[name]()
			}
			if v, ok := getenv(lookupEnv, s.env); ok {
				return v
			}
			return s.def
		}
		panic("unknown setting " + name)
	}

	cfg := &Config{}
	var err error
	cfg.Server.ConfigFile = value("config")
	cfg.Server.LogFormat = value("log-format")
	if cfg.Server.LogFormat != "text" && cfg.Server.LogFormat != "json" {
		return nil, fmt.Errorf("invalid log format %q (want text or json)", cfg.Server.LogFormat)
	}
	if cfg.Server.LogLevel, err = logging.ParseLevel(value("log-level")); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(value("toolsets")); v != "all" {
		for name := range strings.SplitSeq(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				cfg.Server.Toolsets = append(cfg.Server.Toolsets, name)
			}
		}
		if len(cfg.Server.Toolsets) == 0 {
			return nil, errors.New("toolsets: list at least one toolset, or \"all\"")
		}
	}
	if cfg.Server.ReadOnly, err = strconv.ParseBool(value("read-only")); err != nil {
		return nil, fmt.Errorf("read-only: invalid boolean %q", value("read-only"))
	}
	if cfg.Server.MaxResultBytes, err = strconv.Atoi(value("max-result-bytes")); err != nil || cfg.Server.MaxResultBytes < minMaxResultBytes {
		return nil, fmt.Errorf("max-result-bytes: want an integer >= %d, got %q", minMaxResultBytes, value("max-result-bytes"))
	}
	cfg.Server.AuditLog = value("audit-log")
	if cfg.Server.AuditBodies, err = strconv.ParseBool(value("audit-bodies")); err != nil {
		return nil, fmt.Errorf("audit-bodies: invalid boolean %q", value("audit-bodies"))
	}
	if cfg.Server.BackupDir = value("backup-dir"); cfg.Server.BackupDir != "" {
		if err := checkWritableDir(cfg.Server.BackupDir); err != nil {
			return nil, fmt.Errorf("backup-dir: %w", err)
		}
	}

	if err := loadHTTP(cfg, value); err != nil {
		return nil, err
	}

	var file *fileConfig
	if cfg.Server.ConfigFile != "" {
		if file, err = readFile(cfg.Server.ConfigFile); err != nil {
			return nil, err
		}
	}
	if err := loadDevices(cfg, file, lookupEnv); err != nil {
		return nil, err
	}
	return cfg, nil
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)

func loadHTTP(cfg *Config, value func(string) string) error {
	var err error
	switch cfg.Server.Transport = value("transport"); cfg.Server.Transport {
	case "stdio", "http":
	default:
		return fmt.Errorf("invalid transport %q (want stdio or http)", cfg.Server.Transport)
	}
	h := &cfg.Server.HTTP
	h.Addr = value("http-addr")
	if h.Path = value("http-path"); !strings.HasPrefix(h.Path, "/") || h.Path == "/" || strings.HasPrefix(h.Path, "/healthz") || strings.HasPrefix(h.Path, "/readyz") {
		return fmt.Errorf("http-path: want a path such as /mcp, got %q", h.Path)
	}
	if h.Stateless, err = strconv.ParseBool(value("stateless")); err != nil {
		return fmt.Errorf("stateless: invalid boolean %q", value("stateless"))
	}
	for o := range strings.SplitSeq(value("allowed-origins"), ",") {
		if o = strings.TrimSpace(o); o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return fmt.Errorf("allowed-origins: want scheme://host[:port], got %q", o)
		}
		h.AllowedOrigins = append(h.AllowedOrigins, u.Scheme+"://"+strings.ToLower(u.Host))
	}
	if h.IdentityHeader = strings.TrimSpace(value("audit-identity-header")); h.IdentityHeader != "" && !headerName.MatchString(h.IdentityHeader) {
		return fmt.Errorf("audit-identity-header: invalid header name %q", h.IdentityHeader)
	}
	if h.MaxBodyBytes, err = strconv.ParseInt(value("http-max-body-bytes"), 10, 64); err != nil || h.MaxBodyBytes < 1024 {
		return fmt.Errorf("http-max-body-bytes: want an integer >= 1024, got %q", value("http-max-body-bytes"))
	}
	if h.Metrics, err = strconv.ParseBool(value("metrics")); err != nil {
		return fmt.Errorf("metrics: invalid boolean %q", value("metrics"))
	}
	if h.Metrics && cfg.Server.Transport != "http" {
		return errors.New("metrics needs the http transport")
	}
	h.TLSCert, h.TLSKey = value("tls-cert"), value("tls-key")
	if (h.TLSCert == "") != (h.TLSKey == "") {
		return errors.New("tls-cert and tls-key must be set together")
	}
	return nil
}

// checkWritableDir verifies dir exists and files can be created in it.
func checkWritableDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".fortigate-mcp-check-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// getenv treats set-but-empty variables as unset.
func getenv(lookupEnv LookupEnv, key string) (string, bool) {
	v, ok := lookupEnv(key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

type fileConfig struct {
	DefaultDevice string                `yaml:"default_device"`
	Devices       map[string]fileDevice `yaml:"devices"`
}

type fileDevice struct {
	Host               string         `yaml:"host"`
	TokenEnv           string         `yaml:"token_env"`
	TokenFile          string         `yaml:"token_file"`
	VDOM               string         `yaml:"vdom"`
	CACert             string         `yaml:"ca_cert"`
	InsecureSkipVerify *bool          `yaml:"insecure_skip_verify"`
	Timeout            *time.Duration `yaml:"timeout"`
	ReadOnly           *bool          `yaml:"read_only"`

	// Present only to reject literal tokens with a clear message.
	Token    string `yaml:"token"`
	APIToken string `yaml:"api_token"`
}

func readFile(path string) (*fileConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied config
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	for name, d := range fc.Devices {
		if d.Token != "" || d.APIToken != "" {
			return nil, fmt.Errorf("config file %s: device %q has a literal token; use token_env or token_file", path, name)
		}
	}
	return &fc, nil
}

// draft accumulates a device's settings from each source before validation.
type draft struct {
	host      string
	token     Secret
	tokenFile string
	vdom      string
	caCert    string
	insecure  *bool
	timeout   *time.Duration
	readOnly  *bool
}

var deviceNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

func validateName(name string) error {
	if !deviceNameRE.MatchString(name) {
		return fmt.Errorf("invalid device name %q: use lowercase letters, digits, '-' and '_'", name)
	}
	if name == "mcp" {
		// FORTIGATE_MCP_* is the server settings namespace.
		return errors.New(`device name "mcp" is reserved`)
	}
	return nil
}

// envPrefix returns the per-device variable prefix, e.g. "branch-1" -> "FORTIGATE_BRANCH_1_".
func envPrefix(name string) string {
	return "FORTIGATE_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

func loadDevices(cfg *Config, file *fileConfig, lookupEnv LookupEnv) error {
	drafts := map[string]*draft{}

	if file != nil {
		cfg.DefaultDevice = file.DefaultDevice
		for name, fd := range file.Devices {
			if err := validateName(name); err != nil {
				return fmt.Errorf("config file: %w", err)
			}
			d := &draft{
				host:      fd.Host,
				tokenFile: fd.TokenFile,
				vdom:      fd.VDOM,
				caCert:    fd.CACert,
				insecure:  fd.InsecureSkipVerify,
				timeout:   fd.Timeout,
				readOnly:  fd.ReadOnly,
			}
			if fd.TokenEnv != "" {
				if fd.TokenFile != "" {
					return fmt.Errorf("config file: device %q sets both token_env and token_file", name)
				}
				v, ok := getenv(lookupEnv, fd.TokenEnv)
				if !ok {
					return fmt.Errorf("config file: device %q: token_env %s is not set", name, fd.TokenEnv)
				}
				d.token = Secret(v)
			}
			drafts[name] = d
		}
	}

	// Single device from unprefixed variables.
	single, ok := getenv(lookupEnv, "FORTIGATE_NAME")
	if !ok {
		single = DefaultSingleDeviceName
	} else if err := validateName(single); err != nil {
		return fmt.Errorf("FORTIGATE_NAME: %w", err)
	}
	if _, hostSet := getenv(lookupEnv, "FORTIGATE_HOST"); hostSet || drafts[single] != nil {
		if drafts[single] == nil {
			drafts[single] = &draft{}
		}
		if err := applyEnv(drafts[single], "FORTIGATE_", lookupEnv); err != nil {
			return err
		}
	} else {
		for _, f := range deviceEnvFields {
			if _, set := getenv(lookupEnv, "FORTIGATE_"+f); set {
				return fmt.Errorf("FORTIGATE_%s is set but FORTIGATE_HOST is not", f)
			}
		}
	}

	// Multiple devices: FORTIGATE_DEVICES lists names, FORTIGATE_<NAME>_* configure them.
	if list, ok := getenv(lookupEnv, "FORTIGATE_DEVICES"); ok {
		for name := range strings.SplitSeq(list, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if err := validateName(name); err != nil {
				return fmt.Errorf("FORTIGATE_DEVICES: %w", err)
			}
			if drafts[name] == nil {
				drafts[name] = &draft{}
			}
		}
	}

	names := make([]string, 0, len(drafts))
	for name := range drafts {
		names = append(names, name)
	}
	slices.Sort(names)

	prefixes := map[string]string{}
	for _, name := range names {
		p := envPrefix(name)
		if other, dup := prefixes[p]; dup {
			return fmt.Errorf("device names %q and %q map to the same environment prefix %s", other, name, p)
		}
		prefixes[p] = name
		if err := applyEnv(drafts[name], p, lookupEnv); err != nil {
			return err
		}
	}

	if len(names) == 0 {
		return errors.New("no FortiGate devices configured: set FORTIGATE_HOST and FORTIGATE_API_TOKEN, FORTIGATE_DEVICES, or a config file")
	}
	for _, name := range names {
		dev, err := finish(name, drafts[name])
		if err != nil {
			return fmt.Errorf("device %q: %w", name, err)
		}
		cfg.Devices = append(cfg.Devices, dev)
	}
	if cfg.DefaultDevice != "" && drafts[cfg.DefaultDevice] == nil {
		return fmt.Errorf("default_device %q is not a configured device", cfg.DefaultDevice)
	}
	return nil
}

// deviceEnvFields are the per-device variable suffixes.
var deviceEnvFields = []string{
	"HOST", "API_TOKEN", "API_TOKEN_FILE", "VDOM", "CA_CERT",
	"INSECURE_SKIP_VERIFY", "TIMEOUT", "READ_ONLY",
}

// applyEnv overlays variables with the given prefix onto d.
func applyEnv(d *draft, prefix string, lookupEnv LookupEnv) error {
	get := func(field string) (string, bool) { return getenv(lookupEnv, prefix+field) }

	if v, ok := get("HOST"); ok {
		d.host = v
	}
	tok, tokOK := get("API_TOKEN")
	tokFile, fileOK := get("API_TOKEN_FILE")
	switch {
	case tokOK && fileOK:
		return fmt.Errorf("set only one of %sAPI_TOKEN and %sAPI_TOKEN_FILE", prefix, prefix)
	case tokOK:
		d.token, d.tokenFile = Secret(tok), ""
	case fileOK:
		d.token, d.tokenFile = "", tokFile
	}
	if v, ok := get("VDOM"); ok {
		d.vdom = v
	}
	if v, ok := get("CA_CERT"); ok {
		d.caCert = v
	}
	for field, dst := range map[string]**bool{"INSECURE_SKIP_VERIFY": &d.insecure, "READ_ONLY": &d.readOnly} {
		if v, ok := get(field); ok {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("%s%s: invalid boolean %q", prefix, field, v)
			}
			*dst = &b
		}
	}
	if v, ok := get("TIMEOUT"); ok {
		t, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%sTIMEOUT: %w", prefix, err)
		}
		d.timeout = &t
	}
	return nil
}

func finish(name string, d *draft) (Device, error) {
	dev := Device{
		Name:     name,
		Token:    d.token,
		VDOM:     d.vdom,
		CACert:   d.caCert,
		Timeout:  DefaultTimeout,
		ReadOnly: d.readOnly != nil && *d.readOnly,
	}
	var err error
	if dev.Host, err = normalizeHost(d.host); err != nil {
		return Device{}, err
	}
	if d.tokenFile != "" {
		data, err := os.ReadFile(d.tokenFile)
		if err != nil {
			return Device{}, fmt.Errorf("reading token file: %w", err)
		}
		dev.Token = Secret(strings.TrimSpace(string(data)))
	}
	if dev.Token == "" {
		return Device{}, errors.New("no API token configured")
	}
	if dev.VDOM == "" {
		dev.VDOM = DefaultVDOM
	}
	if d.insecure != nil {
		dev.InsecureSkipVerify = *d.insecure
	}
	if dev.InsecureSkipVerify && dev.CACert != "" {
		return Device{}, errors.New("set either a CA certificate or insecure_skip_verify, not both")
	}
	if d.timeout != nil {
		if *d.timeout <= 0 {
			return Device{}, fmt.Errorf("timeout must be positive, got %s", *d.timeout)
		}
		dev.Timeout = *d.timeout
	}
	return dev, nil
}

// normalizeHost turns "10.0.0.1", "fw:8443" or "https://fw:8443/" into "https://host[:port]".
func normalizeHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("no host configured")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid host %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("invalid host %q: only https is supported", raw)
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", fmt.Errorf("invalid host %q: want https://host[:port]", raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid host %q: bad port", raw)
		}
	}
	return "https://" + u.Host, nil
}
