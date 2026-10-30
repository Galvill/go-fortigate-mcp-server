# Changelog

## [0.2.0](https://github.com/Galvill/go-fortigate-mcp-server/compare/v0.1.1...v0.2.0) (2026-10-30)


### ⚠ BREAKING CHANGES

* drop the device argument from tools when only one FortiGate is configured ([#8](https://github.com/Galvill/go-fortigate-mcp-server/issues/8))

### Features

* drop the device argument from tools when only one FortiGate is configured ([#8](https://github.com/Galvill/go-fortigate-mcp-server/issues/8)) ([c7e402f](https://github.com/Galvill/go-fortigate-mcp-server/commit/c7e402fe81cbf713960c999c2b84c26ee61de478))

## [0.1.1](https://github.com/Galvill/go-fortigate-mcp-server/compare/v0.1.0...v0.1.1) (2026-10-30)


### Bug Fixes

* make every tool schema property an object for strict MCP clients ([#5](https://github.com/Galvill/go-fortigate-mcp-server/issues/5)) ([705400f](https://github.com/Galvill/go-fortigate-mcp-server/commit/705400f8803d94d13da2f1aab13005421c8156fe))
* report the module version for go install builds ([#4](https://github.com/Galvill/go-fortigate-mcp-server/issues/4)) ([1218a43](https://github.com/Galvill/go-fortigate-mcp-server/commit/1218a43de7b196d96a9150efb7e35106c5df0dad))

## 0.1.0 (2026-10-29)


### Features

* 105 tools across the system, policy, objects, network, vpn, admin and generic toolsets ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* config backup inline or to a backup directory, and restore from it ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* MCP server over stdio and streamable HTTP, stateful or stateless ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* Origin allowlist, body limit, optional TLS, health checks and Prometheus metrics for HTTP ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* prompts for troubleshooting connectivity, auditing policies and onboarding a site-to-site VPN ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* read-only modes, an audit log of every write, and hostname confirmation for disruptive actions ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* resources for the device inventory, device status, policy tables and the latest backup ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* several FortiGates per server, from environment variables or a YAML file ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
* signed release binaries with SBOMs, and a signed distroless image on ghcr.io ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))


### Continuous Integration

* manage versions and changelog with release-please ([2e2f0e3](https://github.com/Galvill/go-fortigate-mcp-server/commit/2e2f0e340a02b97dc6e75519b90a9670d90a4d58))
