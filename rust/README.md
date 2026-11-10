# Rust workspace

Rust libraries for the gematik Telematikinfrastruktur, developed alongside the Go modules in
[`../go`](../go).

| Crate | Purpose |
| --- | --- |
| [`ti-types`](./ti-types) | Shared vocabulary types (`Env`, `Tier`), `no_std`, no dependencies |
| [`ti-pki`](./ti-pki) | X.509 certificate validation against the TI PKI (port of the archived `go/gempki`) |

Every crate is versioned independently by its own git tag `rust/<crate>/vX.Y.Z`. The
workspace `Cargo.toml` wires the crates together for local development. See the
[Development & Release Guide](./docs/development.md) for the versioning model, the `just`
recipes, tagging, and how to consume a crate from another project.

```console
cd rust
just tools    # once: install the pinned cargo tools
just check        # what every PR must pass
just check-full   # before a release: check plus every feature combination
```

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
