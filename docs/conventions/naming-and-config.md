# Naming and configuration

## Identifiers

- Each language's own idiom wins: Rust `snake_case` functions and `CamelCase` types, Go
  `MixedCaps` with initialisms in one case (`ID`, `URL`, `JWK`, `HTTPClient`, never `Id`,
  `Url`); the profiles add what their linters enforce.
- Names follow the specification they implement: gematik names (profiles, certificate
  types, OIDs) as the gemSpec writes them, one naming rule per layer
  ([decision-5](../../rust/docs/backlog/decisions/decision-5%20-%20PKI-naming-follows-gemSpec-one-rule-per-layer.md)).
- Tests are named after the requirement they prove
  ([testing](../design/testing.md#tests-name-the-requirement-they-prove)).

## Environment variables

- Prefixed by the component that reads them: `ZERO_PDP_…`, `PEP_…`, `EPA_…`, `TI_…`,
  `TI_TEST_…` for test gates.
- A variable that holds a file or directory path ends in `_PATH` or `_DIR`
  (`PEP_SESSION_KEY_PATH`, `GEMATIK_API_TOOLS_DIR`).
- Secrets never travel as a variable's value: the variable names a file (`…_PATH`) and the
  command reads the secret from it. Secrets are not bootstrapped into or stored in the kv
  store either.

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
