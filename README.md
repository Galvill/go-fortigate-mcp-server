# go-fortigate-mcp-server

An [MCP](https://modelcontextprotocol.io) server, written in Go, for inspecting
and managing FortiGate firewalls through the FortiOS REST API.

> **Status:** early development (milestone M1). The server loads its device
> inventory but still exposes only a `ping` tool. See [docs/SPEC.md](docs/SPEC.md) for the design and
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

Logs go to stderr. `-log-level` and `-log-format` (`text`/`json`) control them.

## License

[MIT](LICENSE)
