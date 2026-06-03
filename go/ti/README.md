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

## License

EUROPEAN UNION PUBLIC LICENCE v. 1.2 — see [LICENSE](../../LICENSE).
