# go-fortigate-mcp-server

An [MCP](https://modelcontextprotocol.io) server, written in Go, for inspecting
and managing FortiGate firewalls through the FortiOS REST API.

> **Status:** early development (milestone M0). The server currently exposes
> only a `ping` tool. See [docs/SPEC.md](docs/SPEC.md) for the design and
> [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Build

Requires Go 1.26+.

```sh
make build        # bin/fortigate-mcp
make test         # go test -race ./...
make lint         # golangci-lint
make vuln         # govulncheck
```

## Use with Claude Code

```sh
claude mcp add fortigate -- /path/to/bin/fortigate-mcp
```

Logs go to stderr. `-log-level` and `-log-format` (`text`/`json`) control them.

## License

[MIT](LICENSE)
