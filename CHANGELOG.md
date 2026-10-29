# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) as described in
[Versioning](README.md#versioning).

To release, rename `Unreleased` to the new version and date, then tag it
(`git tag v0.1.0 && git push origin v0.1.0`). The release workflow uses that
section as the GitHub release notes and fails if it is missing.

## [Unreleased]

First release.

### Added

- MCP server over stdio and streamable HTTP (stateful, or `-stateless` for
  replicas without session affinity).
- 105 tools across seven toolsets: system, policy, objects, network, vpn,
  admin and generic (CMDB, monitor and log access by path). See
  [docs/TOOLS.md](docs/TOOLS.md).
- Several FortiGates per server, configured through environment variables or
  a YAML file, each with its own API token, CA, default VDOM and `read_only`
  flag.
- Safety: `-read-only` and per-device read-only mode; JSON-lines audit log of
  every write, attributed to the tool, session, client address and an optional
  proxy-supplied identity; the device hostname is required as confirmation for
  reboot, shutdown, restore, firmware upgrade, clearing sessions and generic
  monitor actions; secrets are redacted from logs and tool output.
- Config backup inline or to `-backup-dir`, and restore only from that
  directory.
- Resources: `fortigate://devices`, `fortigate://{device}/status`,
  `fortigate://{device}/{vdom}/policies` and
  `fortigate://{device}/backup/latest`.
- Prompts: `troubleshoot_connectivity`, `audit_policies` and
  `onboard_site_to_site_vpn`.
- HTTP: Origin allowlist, request body limit, optional TLS, `/healthz`,
  `/readyz` and optional Prometheus `/metrics`.
- Release binaries for Linux, macOS and Windows (amd64, arm64) with SBOMs and
  a Sigstore-signed checksum file; a signed distroless container image at
  `ghcr.io/galvill/go-fortigate-mcp-server`.
