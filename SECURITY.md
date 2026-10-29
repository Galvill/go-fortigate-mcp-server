# Security policy

## Supported versions

Security fixes go into the latest release. Before 1.0, only the latest minor
version is supported.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub's private vulnerability reporting](https://github.com/Galvill/go-fortigate-mcp-server/security/advisories/new),
not in public issues or pull requests. Include the version, how the server
was configured (transport, toolsets, read-only or not) and steps to
reproduce.

You should get a reply within a week. Once a fix is released, the advisory is
published with credit to the reporter unless you ask otherwise.

## Scope

In scope: the server itself, for example secrets leaking into logs or tool
output, writes that bypass read-only mode or hostname confirmation, path
traversal in the generic tools or the backup directory, and the release
artifacts and images.

Out of scope, as documented design decisions (see the README's
[Safety](README.md#safety) section and [SPEC §9](docs/SPEC.md#9-security)):
the HTTP transport not authenticating clients, any client being able to use
every configured device, and a model being misled by data read from a
FortiGate.
