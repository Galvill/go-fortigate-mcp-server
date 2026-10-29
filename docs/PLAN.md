# go-fortigate-mcp-server — Implementation Plan

Companion to [SPEC.md](SPEC.md). Each milestone ends in a usable, tested state.

## M0 — Skeleton (½ day) — done

- [x] `go mod init github.com/galvill/go-fortigate-mcp-server`
- [x] Layout per SPEC §2; `cmd/fortigate-mcp/main.go` with flag parsing and slog setup (stderr)
- [x] Minimal MCP server over stdio with one `ping`-style tool, using `modelcontextprotocol/go-sdk`
- [x] Makefile / `task` targets: `build`, `test`, `lint`, `fmt`
- [x] CI (GitHub Actions): vet, golangci-lint, staticcheck, govulncheck, `go test -race`
- [x] `.golangci.yml`, `.gitignore`, README stub
- [x] LICENSE (MIT)

**Done when:** `claude mcp add fortigate -- ./fortigate-mcp` lists the ping tool.

## M1 — Config & FortiOS client (2–3 days) — done

- [x] `internal/config`: structs, YAML load, env (single + `FORTIGATE_DEVICES` multi), flags, precedence, validation, token_env/token_file, literal-token rejection
- [x] `internal/fortios`: client per device (TLS/CA/insecure, timeout, bearer auth), envelope decode, `APIError` + FortiOS error-code hints, mkey escaping, path validation, paging helper, GET retries, per-device semaphore, version detection
- [x] `internal/devices`: inventory resolver (`device`/`vdom` defaulting)
- [x] Redacting slog handler (`internal/logging`)
- [x] `test/fakefgt`: in-memory CMDB (filter/format/paging/move, -3/-5 errors) + canned monitor endpoints + failure injection. Envelopes are hand-written to the 7.4 format; recording real fixtures moves to M3 with the VM integration suite.
- [x] Unit tests for all of the above

**Done when:** a test can create, list, update, move and delete a policy against fakefgt through the client.

## M2 — Read-only tools (3–4 days) — built; VM acceptance pending

- [x] Tool registration framework (`internal/tools`): toolset registry, `--toolsets`, `--read-only`, common `device`/`vdom` params, list conventions (`filter`, `fields`, `limit`, `offset` → `{items,total,truncated}`), output truncation (`--max-result-bytes`), annotations
- [x] `system` toolset (all read tools in SPEC §7.2)
- [x] Read halves of `policy`, `objects` (incl. `fgt_object_usage`), `network`, `vpn`, `admin` (list/get/status/lookup/hit-counts)
- [x] `generic`: `fgt_cmdb_get`, `fgt_cmdb_schema`, `fgt_monitor_get`
- [x] Tool tests via the in-memory MCP transport + golden schema snapshots (`internal/server/testdata/tools.golden.json`)
- [x] Secret field redaction on all read output (moved up from M3)
- [ ] Acceptance run against a FortiGate-VM (needs a VM; see below)

**Done when:** "Would 10.1.1.5 → 8.8.8.8:443 be allowed on hq, and which policy matches?" works end-to-end against a real FortiGate-VM.

## M3 — Write tools + audit (3–4 days) — built; VM acceptance pending

- [x] `internal/audit` JSON-lines writer, fed by an observer in the FortiOS client so every non-GET request is recorded, tagged by `AddWrite` with tool and session
- [x] Policy create (typed fields, optional placement)/update/delete/move
- [x] Object CRUD for all types, plus group `add_members`/`remove_members` (read-modify-write)
- [x] Network writes (interfaces, static routes, SD-WAN)
- [x] VPN writes (phase1/phase2, tunnel up/down, SSL-VPN disconnect/settings, version gating)
- [x] Admin writes (admins, backup (inline by default, to disk when `--backup-dir` is set), restore, firmware upgrade, reboot/shutdown)
- [x] `fgt_session_clear`, generic `fgt_cmdb_create/update/delete`, `fgt_monitor_post`
- [x] Per-device `read_only` enforcement (in the FortiOS client, so no write can reach the device, plus a clear tool error)
- [x] Hostname confirmation (SPEC §7.1.1): shared wrapper for ⚠ tools, preview builder (status + HA + firmware target), path matcher for `fgt_monitor_post`, audit `confirmed_hostname`; tests for missing/mismatched/matching confirm and generic-tool bypass attempts

- [ ] Record monitor/CMDB fixtures from 7.2/7.4/7.6 VMs into `test/fakefgt` and validate the FortiOS error-code table (`internal/fortios/response.go`)
- [x] Integration suite (`test/integration`, `-tags integration`) for the acceptance flow below
- [ ] Run the integration suite on 7.2, 7.4 and 7.6 VMs
- [ ] Verify endpoints and parameters marked `TODO(M3)` or unverified: `fgt_policy_lookup` parameters and protocol encoding, `fgt_object_usage` (`monitor/system/object/usage`), `fgt_session_list` filters, `fgt_arp_table` (`monitor/network/arp`), request bodies of session close, tunnel up/down, SSL-VPN disconnect, firmware upgrade and config restore, whether 7.6 needs POST for config backup, and renaming entries via PUT

**Done when:** integration suite creates an address → group → policy → moves it → deletes all, with audit records, on 7.2, 7.4 and 7.6 VMs.

## M4 — HTTP transports (1–2 days) — done

- [x] `--transport http` with streamable HTTP handler, stateful and `--stateless`
- [x] Origin check (`--allowed-origins`), body limit, timeouts, graceful shutdown (no client authentication; see SPEC §9)
- [x] `--audit-identity-header` passthrough into audit records (plus `remote_addr`, which clients can't forge)
- [x] `/healthz`, `/readyz`, optional `--tls-cert/--tls-key`
- [x] Warning log when binding to a non-loopback address
- [x] Tests: stateless request without session id, Origin rejection, multiple devices served from one stateless instance, body limit, audit attribution, graceful shutdown
- [x] Acceptance: `TestStatelessReplicas` runs one client through a round-robin balancer across two stateless replicas

**Done when:** two server replicas in stateless mode behind a load balancer serve the same client across requests without session affinity.

## M5 — Resources, prompts, observability (1–2 days) — done

- [x] Resources from SPEC §8 (incl. resource templates for `{device}`)
- [x] Prompts: `troubleshoot_connectivity`, `audit_policies`, `onboard_site_to_site_vpn`
- [x] Optional Prometheus `/metrics` (`--metrics`, http transport only), plus debug-level tool-call logging

## M6 — Packaging & docs (1–2 days) — done (release workflow not yet run on a real tag)

- [x] GoReleaser (multi-OS/arch), SBOM, checksums, signed artifacts (cosign keyless; `.github/workflows/release.yml` on `v*` tags)
- [x] Distroless Dockerfile (nonroot, read-only FS), example `docker run` with env/secrets
- [x] README: quick start (single device via env), multi-device config, Claude Code / Claude Desktop setup snippets, HTTP deployment behind an authenticating reverse proxy (example config), FortiGate REST API admin setup (scoped profile, trusted hosts), tool catalog (generated from registry: `docs/TOOLS.md`, kept in sync by `TestToolCatalog`; nginx example in `docs/deploy/nginx.conf`)
- [x] `CHANGELOG.md`, versioning policy (tool names/schemas are API)

## Cross-cutting: FortiOS version matrix

| Area | Watch for |
|---|---|
| SSL-VPN | Tunnel mode removed in 7.6.3+, and some small models lose SSL-VPN entirely. Gate on version/model. |
| SD-WAN | `system/sdwan` field names drift between 7.2 and 7.4. Verify with `action=schema`. |
| Policy lookup | Parameter names differ slightly across versions. Normalise in the tool. |
| Monitor endpoints | Record fixtures per version and run tool tests against each fixture set. |

## Rough total

About 2.5–3.5 weeks for one engineer to reach v1.0. M2 alone (read-only + generic) is a useful early release (v0.1) to dogfood before writes land.

## Next decisions needed

See SPEC §12. None of the remaining questions block M0–M4.
