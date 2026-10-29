# Contributing

Issues and pull requests are welcome. For anything larger than a small fix,
open an issue first to agree on the approach. Report security problems
privately, as described in [SECURITY.md](SECURITY.md).

## Development

Requires Go 1.26+.

```sh
make test   # go test -race ./...
make lint   # golangci-lint
make docs   # after changing tools: regenerate the schema snapshot and docs/TOOLS.md
```

Tool names and schemas are part of the public API (see
[Versioning](README.md#versioning)). The schema snapshot test fails when they
change; regenerate it with `make docs` and explain the change in the pull
request.

## Pull requests

- Pull requests are squash-merged, so the **pull request title** becomes the
  commit message on `main`. It must follow
  [Conventional Commits](https://www.conventionalcommits.org/), because
  [Release Please](https://github.com/googleapis/release-please) builds the
  version and changelog from it:
  - `feat: add fgt_ospf_neighbors tool` (minor release)
  - `fix(policy): keep policy order when moving` (patch release)
  - `feat!: rename fgt_address_get to fgt_address_show` (breaking change)
  - `docs:`, `test:`, `refactor:`, `ci:`, `chore:` (no release)
- CI (tests, lint, govulncheck, release config) must pass.
- Keep changes focused, and add tests: tool tests run against the fake
  FortiGate in `test/fakefgt`.
