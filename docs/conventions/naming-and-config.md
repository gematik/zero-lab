# Naming and configuration

## Identifiers

- Each language's own idiom wins: Rust `snake_case` functions and `CamelCase` types, Go
  `MixedCaps` with initialisms in one case (`ID`, `URL`, `JWK`, `HTTPClient`, never `Id`,
  `Url`); the profiles add what their linters enforce.
- Names follow the specification they implement: gematik names (profiles, certificate
  types, OIDs) as the gemSpec writes them, one naming rule per layer
  ([decision-5](../../backlog/decisions/decision-5%20-%20PKI-naming-follows-gemSpec-one-rule-per-layer.md)).
- Tests are named after the requirement they prove
  ([testing](../design/testing.md#tests-name-the-requirement-they-prove)).

- A Go module and its Rust crate share a name, without the `ti-` prefix and a product
  client's `-client` suffix: `go/idpd` and `ti-idpd-client`, `go/tipki` and `ti-pki`,
  `go/pkcs12` and `ti-pkcs12`. So do what an operator sees of it: `idpd:` in YAML,
  `PEP_IDPD_*`, `/idpd-callback`. `go/brainpool` keeps its name, being wider than
  `ti-jwz`'s brainpool; `go/dpop`, `go/openid`, `go/oidf` have no crate yet.

## Environment variables

- Prefixed by the component that reads them: `ZERO_PDP_…`, `PEP_…`, `EPA_…`, `TI_…`,
  `TI_TEST_…` for test gates.
- A variable that holds a file or directory path ends in `_PATH` or `_DIR`
  (`PEP_SESSION_KEY_PATH`, `GEMATIK_API_TOOLS_DIR`).
- Secrets never travel as a variable's value: the variable names a file (`…_PATH`) and the
  command reads the secret from it. Secrets are not bootstrapped into or stored in the kv
  store either.
- One value stays a variable: the key of gematik's development federation
  (`PDP_OIDF_DEV_API_KEY`, `PEP_OIDF_DEV_API_KEY`). It opens a development environment,
  `*.dev.gematik.solutions`, and nothing else: it signs nothing, names no identity, guards
  no personal data and has no counterpart in test, reference or production. The transport
  sends it only over https to hosts below `.dev.gematik.solutions`, so a deployment
  outside that environment leaves it unset and never sees it.

## Helpers

- A helper is named after the `ti` command group it serves: `ti <group>` becomes
  `ti-<group>-helper`, crate and binary of the same name under `rust/helpers/<group>`;
  its protocol is `<group>/<n>` in `spec/ti-rpc`; its Go client is `go/tirpc/<group>`.
- Methods carry the names of the group's subcommands and the `--format json` schemas of
  `ti`, so a subprocess and a helper return the same shapes.
- `TI_<GROUP>_HELPER_PATH` overrides where a product finds the helper;
  `TI_<GROUP>_HELPER_SOCKET_PATH` names the Unix socket of a sidecar. A helper reads no
  other configuration than its flags and these variables: no profile, configuration
  directory, store, cache file or key file.

## Configuration

- Configuration is read at the edge: the command (or CLI) reads flags, environment and
  files, validates them and hands typed configuration to the libraries, which read
  nothing themselves ([architecture](../architecture.md#sans-io)).
- Environments are data, not behaviour: everything that differs between environments is
  a named field of the configuration, and an environment name only picks a preset.
  Library code never branches on the environment; the one decision code makes is the
  production tier, in one place, which rejects TEST-ONLY anchors and relaxed policies.
- Production refuses insecure configuration at start-up
  ([servers](../design/servers.md), rule 17).
