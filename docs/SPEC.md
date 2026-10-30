# go-fortigate-mcp-server — Specification

Status: implemented in v1.0.0 · 2026-10-30

## 1. Purpose

An MCP (Model Context Protocol) server, written in Go, that lets LLM clients
(Claude Code, Claude Desktop, other MCP hosts) inspect and manage one or more
FortiGate firewalls through the FortiOS REST API.

### Goals

- Manage **multiple standalone FortiGates** (and their VDOMs) from one server
  instance. A single device can be configured with environment variables alone.
- **Full read/write** access: policies, objects, network, VPN, admin and
  lifecycle operations.
- Three transport modes: **stdio**, **streamable HTTP (stateful)** and
  **streamable HTTP (stateless)**.
- **Hybrid tool surface**: curated, typed tools for common tasks plus generic
  passthrough tools that reach any CMDB or monitor endpoint.
- Support FortiOS **7.2, 7.4 and 7.6**.

### Non-goals (v1)

- FortiManager / FortiAnalyzer JSON-RPC APIs.
- SSH/CLI-based management (REST API only).
- A web UI.
- MCP client authentication. It is delegated to infrastructure in front of
  the server (§9).
- Workflow-level guardrails such as approval queues or change windows. Writes
  are executed directly. The FortiGate admin profile bound to the API token is
  the authority on what is permitted.

## 2. Architecture

```
 MCP client ──stdio / HTTP──▶ ┌────────────────────────────────────────┐
                              │ transport (stdio | streamable HTTP)    │
                              │ MCP server (modelcontextprotocol/go-sdk)│
                              │  ├ tools (toolsets)                    │
                              │  ├ resources                           │
                              │  └ prompts                             │
                              │ device resolver ── inventory           │
                              │ fortios client (REST, per device)      │
                              │ audit logger                           │
                              └───────────────┬────────────────────────┘
                                              │ HTTPS, Bearer API token
                                   FortiGate A, B, C … (VDOMs)
```

### Tech choices

| Concern | Choice |
|---|---|
| Language | Go 1.26+ (built with the latest stable toolchain, pinned via `toolchain` in go.mod) |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk` (typed handlers → JSON Schema generation, stdio + streamable HTTP incl. stateless) |
| HTTP client | `net/http`, a custom `Transport` per device for TLS settings |
| Config | YAML file + env vars + flags (`flag` stdlib or `spf13/pflag`; no heavy framework) |
| Logging | `log/slog`, JSON or text, **always to stderr** (stdout belongs to stdio transport) |
| Testing | `testing`, `httptest` fake FortiGate, golden fixtures; optional integration suite against a FortiGate-VM |
| Release | GoReleaser (linux/darwin/windows, amd64/arm64), distroless container image |

### Package layout

```
cmd/fortigate-mcp/          main: flags, config load, transport selection
internal/config/            config structs, file/env/flag merge, validation
internal/fortios/           REST client: auth, envelope decode, errors, pagination, VDOM
internal/fortios/types/     typed structs for curated objects (policy, address, …)
internal/devices/           inventory + resolver
internal/server/            MCP server construction, toolset registration, middleware
internal/tools/<toolset>/   one package per toolset: system, policy, objects, network, vpn, admin, generic
internal/resources/         MCP resources
internal/prompts/           MCP prompts
internal/audit/             structured audit log of mutating calls
test/fakefgt/               fake FortiGate HTTP server + fixtures
test/integration/           build-tagged tests against a real/VM FortiGate
```

## 3. Configuration

Precedence (highest wins): **flags → environment → config file → defaults**.

### 3.1 Single device via environment (simplest)

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `FORTIGATE_HOST` | yes | — | Base URL or host[:port], e.g. `https://10.0.0.1:8443` |
| `FORTIGATE_API_TOKEN` | yes* | — | REST API admin token |
| `FORTIGATE_API_TOKEN_FILE` | yes* | — | Alternative: read token from a file (Docker/K8s secrets) |
| `FORTIGATE_VDOM` | no | `root` | Default VDOM |
| `FORTIGATE_CA_CERT` | no | system roots | PEM file path for the device CA |
| `FORTIGATE_INSECURE_SKIP_VERIFY` | no | `false` | Disable TLS verification (lab use; logs a warning) |
| `FORTIGATE_TIMEOUT` | no | `30s` | Per-request timeout |
| `FORTIGATE_NAME` | no | `default` | Device name used in tool calls |

\* one of `_API_TOKEN` / `_API_TOKEN_FILE`.

### 3.2 Multiple devices via environment

```
FORTIGATE_DEVICES=hq,branch-1
FORTIGATE_HQ_HOST=https://fw-hq.example.com
FORTIGATE_HQ_API_TOKEN=...
FORTIGATE_BRANCH_1_HOST=https://10.20.0.1
FORTIGATE_BRANCH_1_API_TOKEN_FILE=/run/secrets/branch1
FORTIGATE_BRANCH_1_VDOM=customer-a
```

Device names are upper-cased with `-` → `_` to form the variable prefix. Every
single-device variable above has a per-device form.

Device names must be lowercase letters, digits, `-` and `_`. `mcp` is
reserved, because `FORTIGATE_MCP_*` holds server settings. Two names that map
to the same prefix (e.g. `a-b` and `a_b`) are rejected. Empty variables are
treated as unset. Hosts must be `https`; a bare `host[:port]` gets `https://`
prepended.

### 3.3 Config file (`--config` / `FORTIGATE_MCP_CONFIG`)

```yaml
default_device: hq
devices:
  hq:
    host: https://fw-hq.example.com
    token_env: FGT_HQ_TOKEN        # or token_file:, never a literal token
    vdom: root
    ca_cert: /etc/fortigate-mcp/hq-ca.pem
    timeout: 30s
    read_only: false               # per-device override
  branch-1:
    host: https://10.20.0.1
    token_file: /run/secrets/branch1
    insecure_skip_verify: true
```

Literal tokens in the file are rejected; use `token_env` or `token_file`.
Unknown keys are rejected. Devices from file and env are merged: for every
device, `FORTIGATE_<NAME>_*` variables override the file's fields one by one
(so the file can hold hosts while env supplies tokens). A token from env
replaces a file `token_file`, and vice versa.

### 3.4 Server settings

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--transport` | `FORTIGATE_MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `--http-addr` | `FORTIGATE_MCP_HTTP_ADDR` | `127.0.0.1:8080` | Listen address |
| `--http-path` | `FORTIGATE_MCP_HTTP_PATH` | `/mcp` | Endpoint path |
| `--stateless` | `FORTIGATE_MCP_STATELESS` | `false` | Stateless streamable HTTP (no sessions) |
| `--allowed-origins` | `FORTIGATE_MCP_ALLOWED_ORIGINS` | — | Comma list of browser origins (`scheme://host[:port]`) allowed to call the HTTP endpoint. Requests with any other `Origin` header get 403; requests without one are allowed. |
| `--http-max-body-bytes` | `FORTIGATE_MCP_HTTP_MAX_BODY_BYTES` | `4194304` | Maximum HTTP request body size |
| `--tls-cert`, `--tls-key` | `FORTIGATE_MCP_TLS_CERT`, `FORTIGATE_MCP_TLS_KEY` | — | Serve HTTPS directly (both or neither) |
| `--audit-identity-header` | `FORTIGATE_MCP_AUDIT_IDENTITY_HEADER` | — | Optional header set by an upstream proxy (e.g. `X-Forwarded-User`) to record in audit logs. Recorded only; never used for access decisions. |
| `--backup-dir` | `FORTIGATE_MCP_BACKUP_DIR` | — (disabled) | Optional directory for saving config backups to disk (§7.7) |
| `--toolsets` | `FORTIGATE_MCP_TOOLSETS` | `all` | Comma list: `system,policy,objects,network,vpn,admin,generic` |
| `--read-only` | `FORTIGATE_MCP_READ_ONLY` | `false` | Don't register mutating tools (optional kill switch) |
| `--max-result-bytes` | `FORTIGATE_MCP_MAX_RESULT_BYTES` | `200000` | Truncate tool output beyond this |
| `--audit-log` | `FORTIGATE_MCP_AUDIT_LOG` | stderr | Path for the JSON-lines audit log |
| `--audit-bodies` | `FORTIGATE_MCP_AUDIT_BODIES` | `false` | Include request bodies, secrets redacted, in audit records |
| `--log-level` | `FORTIGATE_MCP_LOG_LEVEL` | `info` | slog level |
| `--log-format` | `FORTIGATE_MCP_LOG_FORMAT` | `text` | `text` or `json` |
| `--config` | `FORTIGATE_MCP_CONFIG` | — | YAML config file (§3.3) |

Startup validation fails fast on: no devices, an unreadable token file, an
unwritable `--backup-dir` (when set), or an invalid URL. Binding HTTP to a
non-loopback address logs a warning that the server has no client
authentication of its own (§9).

## 4. FortiOS REST client (`internal/fortios`)

- Auth: `Authorization: Bearer <token>` header (never the `access_token` query
  param, so tokens stay out of logs and proxies).
- Endpoints:
  - CMDB: `/api/v2/cmdb/<path>[/<mkey>]` (GET/POST/PUT/DELETE)
  - Monitor: `/api/v2/monitor/<path>` (GET/POST)
  - Log: `/api/v2/log/<source>/<type>[/<subtype>]`
- Common query params: `vdom`, `filter` (repeatable), `format` (field
  selection), `start`, `count`, `datasource`, `with_meta`, `action`
  (`move`, `schema`, `default`), `before`/`after`.
- Response envelope decoded into
  `Response{Results json.RawMessage, Status, HTTPStatus, Error, Vdom, Path, Name, Mkey, Revision, Build, Version, Serial}`.
- Errors are mapped to a typed `*APIError{HTTPStatus, FortiError int, Message, Path}`.
  Known FortiOS error codes (e.g. -3 not found, -5 duplicate, -23 in use)
  are translated into human-readable hints for the LLM.
- mkeys are path-escaped (names can contain `/`, spaces, etc.).
- Paths for the generic tools are validated against
  `^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`. No `..`, query strings or
  absolute URLs are allowed.
- Pagination helper: `ListAll(ctx, path, opts)` with `start`/`count` and a
  hard cap.
- Version detection: `GET monitor/system/status` on first use, cached per
  device. Exposes `Version()` so tools can branch on version-specific
  differences (e.g. SSL-VPN availability in 7.6).
- Retries: idempotent GETs only, on 5xx/connection errors, with jittered
  backoff (max 2). Writes are never retried.
- Concurrency: per-device semaphore (default 4) so the server doesn't overrun
  the FortiGate's management plane.
- One `http.Client` per device (TLS config is per device).

## 5. Device resolution

Every device-scoped tool accepts two optional parameters:

- `device` (string): an inventory name. May be omitted when `default_device`
  is set. When exactly one device is configured, tools (and prompts) have no
  `device` parameter at all, so models aren't asked to choose; passing one is
  rejected as an unknown argument.
- `vdom` (string): overrides the device's default VDOM.

The resolver looks up `device` in the merged inventory. Devices and their
FortiGate tokens come only from server-side configuration (§3). Clients can
never supply a FortiGate host or token.

`fgt_device_list` returns inventory names, hosts, default VDOMs and (when
reachable) model/version/serial/hostname. Tokens are never returned.

## 6. Transports

| Mode | How | Notes |
|---|---|---|
| stdio | `mcp.StdioTransport` | Default. Logs to stderr only. |
| HTTP stateful | `mcp.NewStreamableHTTPHandler(..., &StreamableHTTPOptions{})` | Sessions via `Mcp-Session-Id`. Supports server→client notifications (progress, list changes). |
| HTTP stateless | same, `Stateless: true` | No session state. Each POST is self-contained, so it scales horizontally behind a load balancer. Server-initiated requests (elicitation, sampling) are unavailable, so **no tool depends on them**. |

HTTP extras: `/healthz` (liveness), `/readyz` (config loaded; lists device
names, without contacting devices), graceful shutdown on SIGINT/SIGTERM
(10 s, then open streams are dropped), a 10 s read-header timeout and 2 min
idle timeout (no write timeout, since tool calls and streams can be long),
stateful sessions closed after 30 min idle, a request size limit, and optional
TLS (`--tls-cert`/`--tls-key`) for setups without a reverse proxy.

The audit record's `remote_addr` is the TCP peer (the proxy, when there is
one); `identity` comes from `--audit-identity-header`. The SDK's per-session
log lines are shown only at debug level, since stateless mode creates a session
per request.

The server does **not** authenticate MCP clients in any transport. In HTTP
mode, authentication belongs to whatever sits in front of it (reverse proxy,
API gateway, service mesh, private network). See §9.

## 7. Tool surface

### 7.1 Conventions

- Names: `fgt_<area>_<verb>` (snake_case, ≤ 64 chars).
- All device-scoped tools take optional `device` and `vdom`.
- Input/output are Go structs, and JSON Schemas are generated by the SDK. Each
  struct field carries a `jsonschema` description written for an LLM reader.
- Outputs: structured content (typed) plus a compact text rendering. List tools
  support `filter` (FortiOS filter syntax, e.g. `name=@web`), `fields`
  (→ `format`), `limit` (default 100) and `offset`, and return
  `{items, total, truncated}`.
- Tool annotations: `readOnlyHint` on reads; `destructiveHint`/`idempotentHint`
  on writes, so MCP clients can apply their own confirmation UX.
- Mutating tools return the resulting object (re-fetched after the write) and
  the FortiOS `revision`.
- Every mutating call emits an audit record:
  `{ts, session_id, remote_addr, identity, device, vdom, tool, method, path, mkey, request_body_hash, result, http_status, revision, duration_ms}`.
  Bodies are hashed, not logged, by default. `--audit-bodies` logs them with
  secrets redacted.
- Toolsets can be enabled selectively (`--toolsets`) to keep the tool list small
  for clients that handle many tools poorly.

- Sensitive fields (passwords, PSKs, keys, passphrases) are replaced with
  `[REDACTED]` anywhere in read output, including nested objects.
- Tables with IPv4/IPv6 variants (addresses, groups, VIPs, IP pools) take a
  `family` parameter (`ipv4` default, `ipv6`) instead of separate tools.
  Numerically keyed tables (policies, static routes) take `id`; others `name`.
- Tool errors (device unreachable, FortiOS errors, invalid arguments) are
  returned as MCP tool results with `isError: true` and a readable message.

- Mutating tools are annotated by kind: create (not destructive, not
  idempotent), update and delete (destructive, idempotent), action
  (destructive, not idempotent). Under `--read-only` none are registered.
- Create and update tools for most tables take `name` (or `id`) plus a
  free-form `fields` object with FortiOS field names; descriptions list the
  main fields and point to `fgt_cmdb_schema`. Policies have typed fields
  (with `extra` for anything else) and optional `before`/`after` placement.
- Every request other than GET is audited by an observer in the FortiOS
  client, so the generic tools are audited too. A device configured
  `read_only` refuses writes in the client before any request is sent.

### 7.1.1 Hostname confirmation for disruptive operations

Operations that cause an outage (marked ⚠ below) take a `confirm` string
parameter. They only execute when it equals the target device's hostname.

| Tool | Why it's disruptive |
|---|---|
| `fgt_reboot`, `fgt_shutdown` | Device goes down |
| `fgt_config_restore` | Replaces config and reboots |
| `fgt_firmware_upgrade` | Reboots, may change behaviour |
| `fgt_session_clear` with `all: true` | Drops every session in the VDOM |
| `fgt_monitor_post` on the equivalent paths (`system/os/reboot`, `system/os/shutdown`, `system/config/restore`, `system/firmware/upgrade`, `firewall/session/clear_all`) | Same as above, so the generic tool can't bypass the check |

Behaviour:

1. The server fetches `monitor/system/status` for the resolved device and reads
   `hostname` (a fresh call, not the cached version info).
2. If `confirm` is missing or doesn't match, nothing is executed. The tool returns
   a non-error result with `executed: false` and a preview: device name,
   hostname, model, serial, FortiOS version, HA mode/role, target VDOM, the
   action and its expected impact (e.g. "reboot, ~3–5 min downtime"; for
   firmware: current → target version). The result tells the LLM to call again
   with `confirm: "<hostname>"`.
3. If it matches (case-insensitive, exact otherwise), the action runs and the
   audit record includes `confirmed_hostname`.

A mismatched `confirm` (e.g. `fw-branch-1` while targeting `fw-hq`) is called
out explicitly in the preview, since it usually means the wrong device was
picked. The `confirm` parameter description tells the LLM to get the hostname
from the user's request or a prior preview, not to guess it.

### 7.2 `system` — monitoring & diagnostics (read-only unless noted)

| Tool | FortiOS endpoint(s) |
|---|---|
| `fgt_device_list` | inventory + `monitor/system/status` |
| `fgt_system_status` | `monitor/system/status`, `monitor/system/firmware` |
| `fgt_system_resources` | `monitor/system/resource/usage` (CPU, mem, sessions, disk) |
| `fgt_interface_status` | `monitor/system/interface` (link, speed, counters) |
| `fgt_route_table` | `monitor/router/ipv4`, `monitor/router/ipv6` |
| `fgt_arp_table` | `monitor/network/arp` |
| `fgt_dhcp_leases` | `monitor/system/dhcp` |
| `fgt_session_list` | `monitor/firewall/session` (filters: src/dst/port/proto/policy) |
| `fgt_session_clear` ✎ ⚠ (`all: true`) | `monitor/firewall/session/close`, `.../clear_all` |
| `fgt_ha_status` | `monitor/system/ha-peer`, `monitor/system/ha-checksums` |
| `fgt_license_status` | `monitor/license/status` |
| `fgt_log_search` | `log/{disk,memory,fortianalyzer,forticloud}/{traffic,event,utm}/{subtype}` with filter, rows, time range |

### 7.3 `policy` — firewall policies

| Tool | Endpoint |
|---|---|
| `fgt_policy_list` | `cmdb/firewall/policy` |
| `fgt_policy_get` | `cmdb/firewall/policy/{id}` |
| `fgt_policy_create` ✎ | POST `cmdb/firewall/policy` |
| `fgt_policy_update` ✎ | PUT `cmdb/firewall/policy/{id}` (partial update) |
| `fgt_policy_delete` ✎ | DELETE `cmdb/firewall/policy/{id}` |
| `fgt_policy_move` ✎ | PUT `cmdb/firewall/policy/{id}?action=move&before|after=` |
| `fgt_policy_lookup` | `monitor/firewall/policy-lookup` ("which policy matches this flow?") |
| `fgt_policy_hit_counts` | `monitor/firewall/policy` (hits, bytes, last used) |

The policy input struct is typed (name, srcintf, dstintf, srcaddr, dstaddr,
service, action, schedule, nat, ippool/poolname, utm profiles, logtraffic,
comments, status) and has an `extra map[string]any` field for anything else.

### 7.4 `objects` — address/service objects, VIPs, pools

For each object type there are `list`, `get`, `create`, `update` and `delete`
tools. Group types also get `add_members` and `remove_members`, which do a
read-modify-write so the LLM doesn't have to resend full member lists.

| Type | Path | Tool prefix |
|---|---|---|
| Address (v4/v6 via `family`) | `firewall/address`, `firewall/address6` | `fgt_address_*` |
| Address group | `firewall/addrgrp`, `addrgrp6` | `fgt_addrgrp_*` |
| Custom service | `firewall.service/custom` | `fgt_service_*` |
| Service group | `firewall.service/group` | `fgt_servicegrp_*` |
| Virtual IP | `firewall/vip`, `vip6` | `fgt_vip_*` |
| IP pool | `firewall/ippool` | `fgt_ippool_*` |

Plus `fgt_object_usage` (where-used lookup before delete/rename).

### 7.5 `network` — interfaces, routing, SD-WAN

| Tool | Endpoint |
|---|---|
| `fgt_interface_list` / `_get` | `cmdb/system/interface` |
| `fgt_interface_create` ✎ | VLAN / loopback / aggregate creation |
| `fgt_interface_update` ✎ / `_delete` ✎ | `cmdb/system/interface/{name}` |
| `fgt_static_route_list` / `_create` ✎ / `_update` ✎ / `_delete` ✎ | `cmdb/router/static` |
| `fgt_sdwan_status` | `monitor/virtual-wan/health-check`, `monitor/virtual-wan/members` |
| `fgt_sdwan_config_get` | `cmdb/system/sdwan` |
| `fgt_sdwan_config_update` ✎ | `cmdb/system/sdwan` (members, zones, health-checks, rules) |

### 7.6 `vpn` — IPsec and SSL-VPN

| Tool | Endpoint |
|---|---|
| `fgt_ipsec_status` | `monitor/vpn/ipsec` (tunnels, phase2 selectors, bytes, uptime) |
| `fgt_ipsec_tunnel_up` ✎ / `_down` ✎ | `monitor/vpn/ipsec/tunnel_up`, `tunnel_down` |
| `fgt_ipsec_phase1_list/get/create/update/delete` | `cmdb/vpn.ipsec/phase1-interface` |
| `fgt_ipsec_phase2_list/get/create/update/delete` | `cmdb/vpn.ipsec/phase2-interface` |
| `fgt_sslvpn_sessions` | `monitor/vpn/ssl` |
| `fgt_sslvpn_disconnect` ✎ | `monitor/vpn/ssl/delete` |
| `fgt_sslvpn_settings_get` / `_update` ✎ | `cmdb/vpn.ssl/settings` |

SSL-VPN tools check the device's version/model and return a clear "not
supported on this device" error where SSL-VPN tunnel mode has been removed
(7.6.3+).

### 7.7 `admin` — admin & lifecycle

| Tool | Endpoint / behaviour |
|---|---|
| `fgt_config_backup` | `monitor/system/config/backup?scope=global|vdom`. Param `destination`: `inline` (default) returns the config text, optionally narrowed to `sections` (e.g. `firewall policy`) and subject to `--max-result-bytes`, with a sha256 of the full config. `disk` is available only when `--backup-dir` is set: it saves the full file and returns path, size and sha256. |
| `fgt_config_restore` ✎ ⚠ | `monitor/system/config/restore` (device reboots). Restores only files from `--backup-dir`, by bare file name; access is confined to that directory with `os.Root`. |
| `fgt_config_revisions` | `monitor/system/config-revision` |
| `fgt_firmware_info` | `monitor/system/firmware` (current + available upgrades) |
| `fgt_firmware_upgrade` ✎ ⚠ | `monitor/system/firmware/upgrade` (FortiGuard source) |
| `fgt_reboot` ✎ ⚠ / `fgt_shutdown` ✎ ⚠ | `monitor/system/os/reboot`, `.../shutdown` |
| `fgt_admin_list/get/create/update/delete` | `cmdb/system/admin` (password fields write-only, never returned) |
| `fgt_certificate_list` | `monitor/system/available-certificates` |

### 7.8 `generic` — escape hatch

| Tool | Behaviour |
|---|---|
| `fgt_cmdb_get` | GET any `cmdb/<path>[/<mkey>]` with filter/format/paging |
| `fgt_cmdb_schema` | GET `cmdb/<path>?action=schema` so the LLM can discover fields and enums |
| `fgt_cmdb_create` ✎ | POST |
| `fgt_cmdb_update` ✎ | PUT |
| `fgt_cmdb_delete` ✎ | DELETE |
| `fgt_monitor_get` | GET any `monitor/<path>` |
| `fgt_monitor_post` ✎ | POST any `monitor/<path>` (⚠ on disruptive paths, §7.1.1) |

✎ = mutating (omitted under `--read-only` or per-device `read_only: true`).
⚠ = requires hostname confirmation (§7.1.1).

Estimated total: about 85 tools with all toolsets on, hence `--toolsets`.

## 8. Resources & prompts

Resources (read-only context the client can attach):

- `fortigate://devices`: inventory (no secrets).
- `fortigate://{device}/status`: system status snapshot.
- `fortigate://{device}/{vdom}/policies`: compact policy table.
- `fortigate://{device}/backup/latest`: most recent backup file from `--backup-dir` (registered only when it is set).

Prompts:

- `troubleshoot_connectivity(src, dst, port, proto)`: policy lookup → routes →
  sessions → logs.
- `audit_policies(device, vdom)`: shadowed/unused/any-any policies and missing logging.
- `onboard_site_to_site_vpn(...)`: guided phase1/phase2/policies/routes.

## 9. Security

- **Authorization model:** each FortiGate in the inventory has its own API
  token, and that token's admin profile (plus per-device `read_only`) is the
  only per-device permission boundary. The MCP server has no per-client ACLs.
  Any client that can reach the server can use every configured device. To give
  different clients different access, run separate server instances with
  different inventories/tokens.
- The server's power equals the API token's admin profile. Docs recommend a
  dedicated REST API admin with a scoped profile, trusted hosts set to the MCP
  server's address, and per-VDOM restriction where possible.
- Secrets are never logged, never returned in tool output, and never accepted
  as literals in the config file. `slog` handlers run a redaction pass over
  known keys (`token`, `password`, `psksecret`, `private-key`, `passwd`).
- Sensitive FortiOS fields (`psksecret`, admin `password`, private keys) are
  stripped from read outputs and accepted on writes.
- **No client authentication:** the server trusts every request it receives.
  stdio is protected by being a local child process. In HTTP mode, operators
  must put an authenticating layer in front (e.g. OAuth2 proxy, API gateway,
  mTLS at an ingress, or a private network) and should keep the listener on
  loopback or an internal interface. The default bind is `127.0.0.1`. Docs
  include a reverse-proxy example.
- HTTP mode: any request with an `Origin` header not in `--allowed-origins`
  is rejected, which guards against DNS rebinding and cross-site requests from
  browsers (a rebound page's Origin matches its Host, so a same-origin check
  isn't enough). The SDK's localhost Host-header protection stays on. Request
  bodies are size-limited.
- FortiGate targets and tokens come only from server config, so clients can't
  point the server at arbitrary hosts. The FortiOS client follows no redirects.
- Generic tools: strict path validation, and only the `/api/v2/{cmdb,monitor,log}` prefixes.
- Prompt-injection awareness: values read from the device (comments, names,
  log lines) go back to the LLM as data. Tool descriptions say not to treat
  them as instructions. This is documented as a residual risk given full write
  access.

## 10. Observability

- slog structured logs (stderr), request IDs, per-tool latency.
- Audit log (JSON lines) for every mutating call.
- Optional `/metrics` (Prometheus) in HTTP mode: tool calls, errors and latency
  by tool/device; FortiOS API latency and status codes.

## 11. Testing strategy

- **Unit**: config merge/validation, path validation, envelope/error decoding,
  redaction, resolver (device/vdom defaulting).
- **Fake FortiGate** (`test/fakefgt`): an `httptest` server with an in-memory
  CMDB tree that implements GET/POST/PUT/DELETE, `action=move`, filters and
  paging, plus canned monitor responses recorded from 7.2/7.4/7.6.
- **Tool tests**: drive the MCP server via the SDK's in-memory transport and
  assert on structured outputs and FortiOS requests issued.
- **Golden schema tests**: snapshot every tool's input/output JSON Schema to
  catch accidental breaking changes.
- **Integration** (`//go:build integration`): against a FortiGate-VM (the
  permanent trial license is fine for most of the API surface), driven by
  `FORTIGATE_*` env vars. Each test creates objects with an `mcp-test-` prefix
  and cleans up after itself.
- CI: `go vet`, `staticcheck`, `golangci-lint`, `govulncheck`, race tests.

## 12. Open questions

1. Should `fgt_config_backup` support pushing to S3/Git, or only a local directory?
2. Should multi-step writes (e.g. VPN onboarding) be rolled back on partial failure? Options: best-effort compensating deletes, or config-revision restore.
3. FortiOS also exposes a per-session config *transaction* mechanism. It's worth evaluating for atomic multi-object changes in a later version.
