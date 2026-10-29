# go-fortigate-mcp-server

An [MCP](https://modelcontextprotocol.io) server, written in Go, for inspecting
and managing FortiGate firewalls through the FortiOS REST API.

> **Status:** early development (milestone M4). About 100 tools for
> monitoring and managing policies, objects, network, VPN and admin, plus
> generic CMDB and monitor access. Writes are audited; reboot, shutdown,
> restore, firmware upgrade and clearing all sessions need the device's
> hostname as confirmation. Runs over stdio or streamable HTTP. Not yet verified against real FortiGates. See [docs/SPEC.md](docs/SPEC.md) for the design and
> [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Build

Requires Go 1.26+.

```sh
make build        # bin/fortigate-mcp
make test         # go test -race ./...
make lint         # golangci-lint
make vuln         # govulncheck
```

## Configure

One FortiGate, via environment:

```sh
export FORTIGATE_HOST=https://10.0.0.1:8443
export FORTIGATE_API_TOKEN=...          # or FORTIGATE_API_TOKEN_FILE=/path
export FORTIGATE_CA_CERT=/path/ca.pem   # or FORTIGATE_INSECURE_SKIP_VERIFY=true (lab only)
```

Several FortiGates:

```sh
export FORTIGATE_DEVICES=hq,branch-1
export FORTIGATE_HQ_HOST=fw-hq.example.com FORTIGATE_HQ_API_TOKEN=...
export FORTIGATE_BRANCH_1_HOST=10.20.0.1 FORTIGATE_BRANCH_1_API_TOKEN=...
```

Or a YAML file passed with `-config`. See [SPEC §3](docs/SPEC.md#3-configuration)
for every option.

## Use with Claude Code

```sh
claude mcp add fortigate \
  -e FORTIGATE_HOST=https://10.0.0.1 -e FORTIGATE_API_TOKEN_FILE=/path/token \
  -- /path/to/bin/fortigate-mcp
```

Run with `-read-only` (or per device `read_only: true` / `FORTIGATE_<NAME>_READ_ONLY=true`)
to prevent changes. Writes are logged as JSON lines to stderr, or to `-audit-log FILE`.

Limit the tool list with `-toolsets system,policy` (toolsets: system, policy,
objects, network, vpn, admin, generic).

## Run over HTTP

```sh
fortigate-mcp -transport http                      # http://127.0.0.1:8080/mcp, with sessions
fortigate-mcp -transport http -stateless           # no sessions; replicas need no affinity
```

The server does **not** authenticate MCP clients. Keep it on loopback or a
private network, or put an authenticating reverse proxy in front. It warns at
startup when listening on any other address. If the proxy passes the user in a
header, `-audit-identity-header X-Forwarded-User` records it in the audit log
(it is never used for access decisions).

Requests carrying an `Origin` header are rejected unless the origin is listed
in `-allowed-origins` (MCP clients outside browsers send none). `/healthz` and
`/readyz` serve health checks; `-tls-cert`/`-tls-key` enable TLS without a
proxy.

Logs go to stderr. `-log-level` and `-log-format` (`text`/`json`) control them.

## License

[MIT](LICENSE)
