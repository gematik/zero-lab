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

Copyright 2026 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations
under the License.

The [Additional Notes and Disclaimer from gematik GmbH](../README.md#additional-notes-and-disclaimer-from-gematik-gmbh)
in the root README apply here too.
