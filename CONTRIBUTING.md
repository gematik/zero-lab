# Contributing

Thank you for your interest in zero-lab. This is a research and proof-of-concept project; contributions are welcome, but there is no commitment to review or merge them within a given time.

## Issues

Report bugs, questions and suggestions as [GitHub Issues](https://github.com/gematik/zero-lab/issues). For security vulnerabilities, follow the [Security Policy](./SECURITY.md).

## Pull Requests

Before you start, read the [documentation](./docs/README.md): zero-lab is security-critical,
and every change is held against its [principles](./docs/principles.md) and the design
rules they link to.

1. Fork the repository and create a branch from `main` ([git and releases](./docs/conventions/git-and-releases.md)).
2. Work inside the workspace you change, as described in its development guide: [Go](./go/docs/development.md) or [Rust](./rust/docs/development.md).
3. Run the checks of that workspace: `just check` in `rust/` and in `go/`, and `go test ./...` in every Go module you touched.
4. Start every new source file with the EUPL-1.2 license header used by the existing files, beginning with `Copyright (Change Date see Readme), gematik GmbH`.
5. Open a pull request against `main` with a short description of the change and its motivation.

By submitting a contribution, you agree that it is licensed under the [EUPL-1.2](./LICENSE).
