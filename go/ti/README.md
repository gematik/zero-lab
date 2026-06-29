# 🖥️ ti — Telematik CLI

A command-line tool for interacting with the German Telematikinfrastruktur (TI).

![ti CLI screencast](images/cli.gif)

## Installation

```bash
go install github.com/gematik/zero-lab/go/ti@latest
```

## Configuration

Connector commands require a `.kon` configuration file (JSON):

```json
{
  "url": "https://konnektor.example.com",
  "mandantId": "m1",
  "workplaceId": "w1",
  "clientSystemId": "cs1",
  "credentials": {
    "type": "basic",
    "username": "${KON_USER}",
    "password": "${KON_PASS}"
  }
}
```

Environment variables can be referenced with `${VAR_NAME}` syntax.

Select a connector with `-c`/`--connector-config`, the `TI_CONNECTOR_CONFIG` env var,
or `ti connector use <name>` to make the selection sticky. The name is resolved as:

1. Exact path
2. `<name>.kon` in current directory
3. `$XDG_CONFIG_HOME/telematik/connectors/<name>.kon`

When no flag, env var, or `use` selection is set, the default name is `default` (i.e. `default.kon`).

List available configs with `ti connector configs`. Tab-completion of `-c` and `use` values is supported when shell completion is installed.

### Credential types

| Type | Fields | Description |
|------|--------|-------------|
| `basic` | `username`, `password` | HTTP Basic Auth |
| `pkcs12` | `data`, `password` | Base64-encoded PKCS#12 for mTLS |

## Usage

### Connector commands

```bash
# List available connector configurations
ti connector configs

# Set the active connector (sticky for subsequent commands)
ti connector use prod

# Show Konnektor product information
ti connector get info

# List available SOAP services and endpoints
ti connector get services
ti connector get services --raw    # raw XML output

# List inserted cards (SMC-B, HBA, eGK, …)
ti connector get cards

# Show connector, card terminal, and card status
ti connector get status

# List certificates on a card
ti connector get certificates <card-handle>

# Show detailed certificate information
ti connector describe certificate <card-handle> <cert-ref>
# cert-ref: C.AUT, C.ENC, C.SIG, C.QES

# Verify a card PIN
ti connector verify pin <card-handle> <pin-type>
```

### ePA commands

```bash
# Pick an ePA environment (sticky for subsequent commands)
ti epa use test                    # one of: dev, test, ref (default), prod
ti epa env                         # shows current env + source

# List the 3 aggregators in the current env
ti epa providers
# (Reachability check for the whole env — IDP, eRezept, all ePA aggregators — lives at `ti probe <env>`.)

# Locate a record and show consent decisions. Lazy discovery:
# first call fans out across all 3 aggregators and caches KVNR→provider for 1h.
ti epa record X110411675

# Open VAU session(s) and cache the metadata
ti epa --auth-method p12 --p12-file smcb.p12 connect       # all 3 providers in parallel
ti epa --auth-method p12 --p12-file smcb.p12 connect 2     # just provider 2
ti epa session list                                        # cached entries
ti epa session close 2                                     # drop one provider's entry

# Run the localhost forwarding proxy (long-lived)
ti epa --auth-method p12 --p12-file smcb.p12 proxy --addr :8082
# then: curl http://localhost:8082/info

# Inspect the state cache (Redis-style KV with TTL)
ti epa cache list
ti epa cache get   <key>
ti epa cache clear           # all
ti epa cache clear <key>     # one
```

State is stored at `$XDG_CONFIG_HOME/telematik/cli-state.db` (SQLite). Entries
carry a TTL and are lazily expired on read. KVNR→provider mappings live for 1h;
session metadata lives for 15 min.

#### ePA auth methods

`record`, `providers`, `cache`, `env`, `use`, `session list/close` don't need
auth. Commands that hit VAU (`connect`, `proxy`) take an auth method via
`--auth-method connector|p12` (default `connector`, env `TI_EPA_AUTH_METHOD`):

| Flag | Default | Method |
|---|---|---|
| `-c`, `--connector-config` | (see connectors above) | connector |
| `--card` | first SMC-B on the connector | connector |
| `--p12-file` | (required) | p12 |
| `--p12-alias` | `alias` | p12 |
| `--p12-password` | `00` (env: `TI_EPA_P12_PASSWORD`) | p12 |

> Entitlement (VAU-bound calls that need Proof-of-PN / HCV) is intentionally
> deferred — real flows use either the VSDM PN service or a POPP token, neither
> of which is wired in this version. `/information` endpoints and the VAU
> handshake work fully; entitlement-bound calls will fail clearly until PN/POPP
> is added.

### PKCS#12 commands

```bash
# Inspect contents of a PKCS#12 file
ti pkcs12 inspect <file>

# Convert legacy BER-encoded PKCS#12 to modern DER format
ti pkcs12 convert <input> <output>

# Encode PKCS#12 file as connector credentials JSON (for .kon configs)
ti pkcs12 encode <file>
```

### Flags

| Flag | Scope | Description |
|------|-------|-------------|
| `-v`, `--verbose` | global | Enable debug logging |
| `-o`, `--output` | `ti connector ...` | Output format: `text` (default) or `json` |
| `-c`, `--connector-config` | connector leaf commands | Name or path of `.kon` config file (env: `TI_CONNECTOR_CONFIG`) |
| `--epa-env` | `ti epa ...` | ePA environment: `dev`, `test`, `ref` (default), `prod` (env: `TI_EPA_ENV`) |
| `--auth-method` | `ti epa session open / proxy` | `connector` (default) or `p12` (env: `TI_EPA_AUTH_METHOD`) |

## Testing

Most tests run offline. Two end-to-end auth tests require a real test identity
and skip by default; pass an env var to opt in:

```bash
TI_TEST_SMCB_P12=/path/to/test.p12      go test ./...    # p12 auth e2e
TI_TEST_KON_FILE=/path/to/test.kon      go test ./...    # connector auth e2e (live Konnektor)
```

Without these vars the tests `t.Skip` so CI stays green and no fixtures are
committed.

## License

EUROPEAN UNION PUBLIC LICENCE v. 1.2 — see [LICENSE](../../LICENSE).
