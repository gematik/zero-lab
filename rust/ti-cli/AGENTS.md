# {bin} for scripts and agents

`{bin}` is the command-line tool for the gematik Telematikinfrastruktur (TI). Commands
are grouped by subsystem (`{bin} pki …`), and the conventions below hold for every one
of them. It never prompts. Every input is an argument, an environment variable, a file
or stdin.

## Calling it

- Ask for JSON: `--format json` (or `TI_FORMAT=json`). Each command writes one JSON
  document to stdout with `"schema": 1`. Within a schema version, fields are only ever
  added, so ignore unknown fields.
- `{bin} schema COMMAND` prints the JSON Schema of a command's output, e.g.
  `{bin} schema pki verify`. `{bin} schema` alone prints all of them, plus `error`.
- Without `--format json`, piped output is compact Markdown and terminal output is
  aligned text. Both are for reading, not for parsing.
- Diagnostics (`-v`, `-vv`) and warnings go to stderr, never to stdout.
- Times in JSON are RFC 3339 in UTC. Text and Markdown use the system time zone.
- `{bin} version` names the build: `--format json` gives `name`, `version`, `os` and
  `arch`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success; for a verification: valid |
| 1 | a verification ran and the result is not valid (the report is still on stdout) |
| 2 | wrong arguments, or the environment cannot be told |
| 3 | trust material or another remote resource unavailable, or failed verification |
| 4 | input unreadable or without the expected content |
| 5 | output could not be written |

On failure with `--format json`, stderr carries
`{"schema":1,"error":{"kind","message","hint"}}`. Branch on `kind` and the exit code,
never on `message`.

## Common options and environment

- `TI_FORMAT` sets the default format.
- `TI_ENV` sets the default environment: `auto`, `prod`, `ref`, `test` or `dev`.
- `TI_CACHE_DIR` sets the cache directory.
- The HTTP options and variables follow curl: `-x`/`HTTPS_PROXY`/`HTTP_PROXY`/
  `ALL_PROXY`, `--noproxy`/`NO_PROXY`, `--cacert`/`CURL_CA_BUNDLE`/`SSL_CERT_FILE`,
  `--capath`/`SSL_CERT_DIR`, `--connect-timeout`, `-m`, `--retry`, `-A`.
- `-k` skips TLS checks for downloads only. Do not use it unless asked to.
- Downloads are cached in `~/.cache/telematik/ti` (`%LOCALAPPDATA%\telematik\ti` on
  Windows). `--offline` makes no request and works from the cache.
- `{bin} cache clear` empties the cache.

## Subsystem pki: certificates and trust

```sh
{bin} --format json pki inspect card.pem          # what the TI reads from a certificate
{bin} --format json pki verify card.pem           # chain, profile, OCSP; exit 0/1
{bin} --format json pki verify card.pem --offline # no network, no OCSP
{bin} --format json pki profiles list
{bin} --format json pki profiles describe smb-aut
{bin} --format json pki roots list --env ref
{bin} --format json pki tsl show --env ref        # CAs under the roots that signed them
{bin} --format json pki tsl show --rejected       # CAs no verified root signed
{bin} --format json pki tsl show --ca SMCB-CA51   # filter by name, also --provider, --root
```

- `-` reads the certificate from stdin (PEM or DER). A PEM file may carry the chain,
  with the end entity first.
- Certificates come back as PEM in `pem` fields (`inspect`, and `verify`'s `chain`),
  ready to save or to pass on.
- Reading a verify report:
  - `valid` is the verdict. `errors` says why it is false.
  - `warnings` never change the verdict but deserve a look, e.g.
    `ocsp_responder_not_rfc6960`.
  - `revocation_checked: false` means revocation was not checked (`--offline`). A
    valid result then says nothing about revocation.
  - `chain[].revocation` holds the OCSP answer per certificate. The root has none.
  - `environment.detection` says how `--env auto` chose the environment. Pass `--env`
    when you already know it.
  - `trust.note` is set when the trust material is less than the full set, e.g.
    offline with nothing cached. Then pass the issuing CA with `--issuer`.
- The TSL is not authenticated. `tsl show` takes only certificates and provider names
  from it. What it reports about a CA comes from the CA's signed certificate, and a CA
  counts only if a verified root signed it.
