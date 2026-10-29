# go-fortigate-mcp-server

An [MCP](https://modelcontextprotocol.io) server, written in Go, for inspecting
and managing FortiGate firewalls through the FortiOS REST API.

- 105 tools for monitoring and managing policies, objects, network, VPN and
  admin, plus generic CMDB, monitor and log access ([catalog](docs/TOOLS.md)).
- Resources for device status and policy tables, and prompts for
  troubleshooting connectivity, auditing policies and onboarding a
  site-to-site VPN.
- Several FortiGates from one server, each with its own token and VDOM.
- Writes are audited. Reboot, shutdown, restore, firmware upgrade and
  clearing sessions need the device's hostname as confirmation. `-read-only`
  hides every write tool.
- Runs over stdio, or over streamable HTTP for shared deployments.

> **Status:** pre-1.0. Tested against a simulated FortiGate, not yet
> against real FortiOS 7.2/7.4/7.6 devices. See [docs/SPEC.md](docs/SPEC.md)
> for the design and [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Contents

- [Install](#install)
- [Prepare the FortiGate](#prepare-the-fortigate)
- [Quick start](#quick-start)
- [Several FortiGates](#several-fortigates)
- [Use with Claude Code and Claude Desktop](#use-with-claude-code-and-claude-desktop)
- [Safety](#safety)
- [Run over HTTP](#run-over-http)
- [Docker](#docker)
- [Logs, audit and metrics](#logs-audit-and-metrics)
- [Versioning](#versioning)
- [Development](#development)

## Install

**Release binaries** for Linux, macOS and Windows (amd64, arm64) are on the
[releases page](https://github.com/Galvill/go-fortigate-mcp-server/releases).

**Container image:** `ghcr.io/galvill/go-fortigate-mcp-server` (see [Docker](#docker)).

**From source** (Go 1.26+):

```sh
go install github.com/galvill/go-fortigate-mcp-server/cmd/fortigate-mcp@latest
```

### Verify a release

Each release has a `checksums.txt` covering every archive and SBOM, signed
with [Sigstore](https://www.sigstore.dev/) by the release workflow. With
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/Galvill/go-fortigate-mcp-server/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

Container images are signed the same way:

```sh
cosign verify ghcr.io/galvill/go-fortigate-mcp-server:<version> \
  --certificate-identity-regexp '^https://github\.com/Galvill/go-fortigate-mcp-server/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Prepare the FortiGate

The server can do exactly what its API token allows, so give it a dedicated
REST API admin with the smallest profile that covers your use, and restrict
it to the address the server connects from. On the FortiGate CLI:

```
config system accprofile
    edit "mcp-read"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
config system api-user
    edit "mcp"
        set accprofile "mcp-read"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.0.2.10 255.255.255.255
            next
        end
    next
end
execute api-user generate-key mcp
```

- Replace `192.0.2.10` with the server's address as the FortiGate sees it.
- The last command prints the token once; store it in a file readable only by
  the server's user.
- To allow changes, set the relevant groups (for example `fwgrp`, `netgrp`,
  `vpngrp`) to `read-write`. Backup, restore, reboot, firmware and admin
  management need `sysgrp read-write`.
- List several VDOMs in `set vdom` to manage them, or limit the user to one.
- Use the device's CA certificate (`FORTIGATE_CA_CERT`) rather than turning
  verification off.

## Quick start

One FortiGate, configured through environment variables:

```sh
export FORTIGATE_HOST=https://10.0.0.1:8443
export FORTIGATE_API_TOKEN_FILE=$HOME/.config/fortigate-mcp/token   # or FORTIGATE_API_TOKEN=...
export FORTIGATE_CA_CERT=/path/ca.pem   # or FORTIGATE_INSECURE_SKIP_VERIFY=true (lab only)
fortigate-mcp                            # serves MCP on stdin/stdout
```

Other per-device settings: `FORTIGATE_VDOM` (default `root`),
`FORTIGATE_TIMEOUT` (default `30s`), `FORTIGATE_NAME` (default `default`) and
`FORTIGATE_READ_ONLY`.

## Several FortiGates

Through the environment, name the devices and set each one's variables
(upper case, `-` becomes `_`):

```sh
export FORTIGATE_DEVICES=hq,branch-1
export FORTIGATE_HQ_HOST=https://fw-hq.example.com
export FORTIGATE_HQ_API_TOKEN_FILE=/run/secrets/hq
export FORTIGATE_BRANCH_1_HOST=https://10.20.0.1
export FORTIGATE_BRANCH_1_API_TOKEN_FILE=/run/secrets/branch1
export FORTIGATE_BRANCH_1_VDOM=customer-a
```

Or in a YAML file passed with `-config` (or `FORTIGATE_MCP_CONFIG`). Tokens
come from a file or an environment variable, never from the YAML itself:

```yaml
default_device: hq
devices:
  hq:
    host: https://fw-hq.example.com
    token_file: /run/secrets/hq
    ca_cert: /etc/fortigate-mcp/hq-ca.pem
  branch-1:
    host: https://10.20.0.1
    token_env: FGT_BRANCH1_TOKEN
    vdom: customer-a
    read_only: true
```

Environment variables override the file field by field, so the file can hold
hosts while the environment supplies tokens. Tools take an optional `device`
argument; `fgt_device_list` lists the configured devices. See
[SPEC §3](docs/SPEC.md#3-configuration) for every option, and run
`fortigate-mcp -h` for the server flags.

## Use with Claude Code and Claude Desktop

**Claude Code**, with the server as a local process:

```sh
claude mcp add fortigate \
  -e FORTIGATE_HOST=https://10.0.0.1 \
  -e FORTIGATE_API_TOKEN_FILE=$HOME/.config/fortigate-mcp/token \
  -- fortigate-mcp -read-only
```

Or connected to a shared HTTP deployment (see [Run over HTTP](#run-over-http)):

```sh
claude mcp add --transport http fortigate https://mcp.example.com/mcp \
  --header "Authorization: Bearer $FORTIGATE_MCP_TOKEN"
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "/usr/local/bin/fortigate-mcp",
      "args": ["-read-only"],
      "env": {
        "FORTIGATE_HOST": "https://10.0.0.1",
        "FORTIGATE_API_TOKEN_FILE": "/Users/me/.config/fortigate-mcp/token"
      }
    }
  }
}
```

Or with the container image:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--read-only",
        "-e", "FORTIGATE_HOST=https://10.0.0.1",
        "-e", "FORTIGATE_API_TOKEN_FILE=/run/secrets/fortigate_token",
        "-v", "/Users/me/.config/fortigate-mcp/token:/run/secrets/fortigate_token:ro",
        "ghcr.io/galvill/go-fortigate-mcp-server:0.1",
        "-read-only"
      ]
    }
  }
}
```

Drop `-read-only` once you want the model to make changes.

## Safety

- **Read-only:** `-read-only` (or `FORTIGATE_MCP_READ_ONLY=true`) removes every
  write tool. Per device, `read_only: true` or `FORTIGATE_<NAME>_READ_ONLY=true`
  refuses writes to that device.
- **Fewer tools:** `-toolsets system,policy` registers only those toolsets
  (system, policy, objects, network, vpn, admin, generic).
- **Confirmation:** reboot, shutdown, config restore, firmware upgrade,
  clearing sessions and `fgt_monitor_post` first return what they would do;
  the model must call again with the device's hostname as `confirm`.
- **Audit:** every write is logged (see [below](#logs-audit-and-metrics)).
- **Secrets** are never logged or returned in tool output, and are not
  accepted as literals in the config file.
- **Untrusted data:** names, comments and log lines from the device go back to
  the model as data, but a model with write access could still be misled by
  them. Prefer read-only access where it suffices.

The token's admin profile is the only per-device permission boundary: any
client that can reach the server can use every configured device. To give
different users different access, run separate instances with different
tokens. See [SPEC §9](docs/SPEC.md#9-security).

## Run over HTTP

```sh
fortigate-mcp -transport http             # http://127.0.0.1:8080/mcp, with sessions
fortigate-mcp -transport http -stateless  # no sessions; replicas need no affinity
```

The server does **not** authenticate MCP clients. Keep it on loopback or a
private network and put an authenticating reverse proxy in front; it warns at
startup when listening on any other address.

[docs/deploy/nginx.conf](docs/deploy/nginx.conf) is a complete nginx example:
TLS, a bearer token per client, and the client's name passed to the server in
`X-Forwarded-User`. Run the server behind it with:

```sh
fortigate-mcp -transport http -http-addr 127.0.0.1:8080 \
  -audit-identity-header X-Forwarded-User
```

The identity header is only recorded in the audit log, never used for access
decisions, so the proxy must overwrite whatever value the client sends (the
example does). Any other authenticating layer works too: an OAuth2 proxy, an
API gateway, or mTLS at an ingress.

Other HTTP settings:

| Flag | Default | Meaning |
|---|---|---|
| `-http-addr` | `127.0.0.1:8080` | Listen address |
| `-http-path` | `/mcp` | MCP endpoint |
| `-allowed-origins` | none | Browser origins allowed to call the endpoint. Requests with any other `Origin` header get 403; MCP clients outside browsers send none. |
| `-http-max-body-bytes` | `4194304` | Request body limit |
| `-tls-cert`, `-tls-key` | none | Serve HTTPS directly |
| `-metrics` | `false` | Serve Prometheus metrics at `/metrics` |

`/healthz` and `/readyz` serve health checks. Every flag also has an
environment variable, e.g. `FORTIGATE_MCP_HTTP_ADDR`.

## Docker

The image is distroless, runs as a non-root user, and works with a read-only
root filesystem. Pass the token as a mounted file:

```sh
docker run -i --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e FORTIGATE_HOST=https://10.0.0.1 \
  -e FORTIGATE_API_TOKEN_FILE=/run/secrets/fortigate_token \
  -v "$PWD/token:/run/secrets/fortigate_token:ro" \
  ghcr.io/galvill/go-fortigate-mcp-server:0.1
```

That serves stdio, for an MCP client that starts the container. To serve HTTP
instead, listen on all of the container's interfaces and publish the port on
loopback only, for a proxy on the same host:

```sh
docker run -d --name fortigate-mcp --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -e FORTIGATE_MCP_TRANSPORT=http \
  -e FORTIGATE_MCP_HTTP_ADDR=0.0.0.0:8080 \
  -e FORTIGATE_MCP_AUDIT_IDENTITY_HEADER=X-Forwarded-User \
  -e FORTIGATE_HOST=https://10.0.0.1 \
  -e FORTIGATE_API_TOKEN_FILE=/run/secrets/fortigate_token \
  -v "$PWD/token:/run/secrets/fortigate_token:ro" \
  ghcr.io/galvill/go-fortigate-mcp-server:0.1
```

The startup warning about a non-loopback address is expected here, since the
published port is what limits access. For `-backup-dir` or `-audit-log FILE`,
mount a writable volume, e.g. `-v fortigate-backups:/backups
-e FORTIGATE_MCP_BACKUP_DIR=/backups`. To build the image yourself:
`make docker`.

## Logs, audit and metrics

- **Logs** go to stderr. `-log-level` (`debug` logs every tool call) and
  `-log-format text|json` control them.
- **Audit log:** each request a write tool makes is one JSON line on stderr,
  or in `-audit-log FILE`, with the tool, session, client address, proxy
  identity, device, VDOM, method, path, result and duration.
  `-audit-bodies` adds the request body with secrets redacted.
- **Metrics** (`-metrics`, HTTP only): `fortigate_mcp_tool_calls_total` and
  `fortigate_mcp_tool_call_duration_seconds` by tool;
  `fortigate_mcp_fortios_requests_total` and
  `fortigate_mcp_fortios_request_duration_seconds` by device, API and status;
  plus Go runtime and process metrics. `/metrics` is served without
  authentication, so keep it off the proxy, as the nginx example does.

## Versioning

Releases follow [Semantic Versioning](https://semver.org/). The public API is
what clients and operators depend on:

- tool names, input and output schemas, and annotations;
- resource URIs and prompt names and arguments;
- flags, environment variables and config file keys;
- audit log fields and metric names.

From 1.0, removing or renaming any of these, adding a required tool argument,
or narrowing an accepted value needs a major version. Additions, such as new
tools, optional arguments or output fields, are minor versions. Tool
descriptions may be reworded in any release. Before 1.0, breaking changes
can land in minor versions and are listed under **⚠ BREAKING CHANGES** in
[CHANGELOG.md](CHANGELOG.md).

Tool schemas are snapshotted in
[internal/server/testdata/tools.golden.json](internal/server/testdata/tools.golden.json),
so every change to them shows up in review.

Versions and [CHANGELOG.md](CHANGELOG.md) are managed by
[Release Please](https://github.com/googleapis/release-please) from
[Conventional Commits](https://www.conventionalcommits.org/) on `main`:

| Commit | Release |
|---|---|
| `fix: ...` | patch |
| `feat: ...` | minor |
| `feat!: ...` or a `BREAKING CHANGE:` footer | major (minor before 1.0) |
| `docs:`, `test:`, `ci:`, `chore:`, `refactor:` | none, and not in the changelog |

Release Please keeps a release PR open with the next version and changelog.
Merging it tags the release, and the release workflow publishes the
binaries and images. To force a version, add a `Release-As: x.y.z` footer to
a commit.

## Development

```sh
make build     # bin/fortigate-mcp
make test      # go test -race ./...
make lint      # golangci-lint
make vuln      # govulncheck
make docs      # regenerate tools.golden.json and docs/TOOLS.md after tool changes
make docker    # build the container image from source
make snapshot  # local GoReleaser dry run (needs goreleaser and syft)
```

Integration tests run against a lab FortiGate-VM with
`go test -tags integration ./test/integration/`; the package comment in
[test/integration](test/integration/lifecycle_test.go) lists the variables
they need.

Commit messages follow Conventional Commits, since they drive releases (see [Versioning](#versioning)).

## License

[MIT](LICENSE)
