# Rust workspace

Rust libraries for the gematik Telematikinfrastruktur, developed alongside the Go modules in
[`../go`](../go).

| Crate | Purpose |
| --- | --- |
| [`ti-pki`](./ti-pki) | X.509 certificate validation against the TI PKI (port of `go/gempki`) |

Every crate is versioned independently by its own git tag `rust/<crate>/vX.Y.Z`. The
workspace `Cargo.toml` wires the crates together for local development. See the
[Development & Release Guide](./docs/development.md) for the versioning model, the `just`
recipes, tagging, and how to consume a crate from another project.

```console
cd rust
just tools    # once: install the pinned cargo tools
just check    # what every PR must pass
```

## License

Same licence and disclaimer as the repository: see the [root README](../README.md#license)
and [LICENSE](../LICENSE).
