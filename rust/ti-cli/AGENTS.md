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
| 0 | success; for a verification: valid, or the PIN was accepted |
| 1 | a verification ran and the result is not valid, or the PIN was not accepted (the report is still on stdout) |
| 2 | wrong arguments, the environment cannot be told, or no usable connector configuration |
| 3 | trust material unavailable or failed verification, or the Konnektor did not answer or refused the call |
| 4 | input unreadable or without the expected content |
| 5 | output could not be written |

On failure with `--format json`, stderr carries
`{"schema":1,"error":{"kind","message","hint"}}`. Branch on `kind` and the exit code,
never on `message`.

## Common options and environment

- `TI_FORMAT` sets the default format.
- `TI_ENV` sets the default of `--env`: `auto`, `prod`, `ref`, `test` or `dev`. Every
  command that needs an environment takes `--env`. `pki verify` and `pki tsl verify`
  detect it with `auto` (their default); `pki roots list` and `pki tsl show` cannot, so
  `auto` from `TI_ENV` means `prod` there and `--env auto` is an error (exit 2,
  `environment_invalid`).
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
{bin} --format json pki verify tls.pem --fqdn epa-as-1.ref.epa4all.de
{bin} --format json pki verify --connect epa-as-1.ref.epa4all.de   # the server's chain; --fqdn is the host
{bin} --format json pki profiles list
{bin} --format json pki profiles describe smb-aut
{bin} --format json pki profiles describe smb-aut --env ref   # tsl.cas: CAs the TSL allows for its types
{bin} --format json pki roots list --env ref
{bin} --format json pki tsl show --env ref        # CAs under the roots that signed them
{bin} --format json pki tsl show --rejected       # CAs no verified root signed
{bin} --format json pki tsl show --ca SMCB-CA51   # filter by name, also --provider, --root
{bin} --format json pki tsl verify tsl.xml --previous old.xml   # exit 0 valid, 1 not
```

- Input is PEM, DER or PKCS#12 (`.p12`, `.pfx`); `-` reads stdin. A PEM file may carry
  the chain with the end entity first. In a PKCS#12 file, the certificate with its
  private key comes first and is the end entity for `verify`, and `inspect` marks it
  `"private_key": true`. The password is `00` (gematik's test cards) unless
  `--p12-password` gives another. A wrong password fails with exit 4 and the error kind
  `p12_password`. For PKCS#12 input, `inspect` also reports the container in `pkcs12`:
  encoding, MAC, encryption per part, and the keys with the certificate each belongs
  to.
- `{bin} pki pkcs12 convert IN OUT` re-encodes a PKCS#12 file as DER with PBES2 AES-256
  and an SHA-256 MAC, which OpenSSL 3 and the Go tools read without `-legacy`. OUT is
  written with mode 0600 and never replaced without `--force` (error kind
  `output_exists`).
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
- The TSL is verified whenever trust material is loaded; a list that fails is not used.
  `trust.tsl` names the list, its signer and the TSL signer CA; `trust.tsl_warnings`
  holds `no_ocsp_check` when the signer's OCSP status was not queried (offline, `--at`).
  `revocation.authorization` is `tsl_listed` for a responder the TSL lists for the
  issuing CA's TSP. `tsl show` takes only certificates and provider names from
  it (the provider only in JSON, for filtering); a CA counts only if a verified root
  signed it.
- `tsl verify` checks a TSL file: signature, signer under the embedded TSL signer CA,
  `NextUpdate` (`--grace`), the signer's OCSP status (not with `--offline` or `--at`),
  and with `--previous` the sequence. `result` is `valid` or `invalid`; an invalid one
  has `code` (gemSpec_PKI Tab_PKI_274, e.g. `xml_signature_error`), `rule`
  (`TSLSIG-nnn`) and `detail`, and the list fields are null. A valid one may carry
  `warnings` and `skipped` entries. `tier` is `prod` or `nonprod`: ref, test and dev
  share one TSL signer CA.

## Subsystem connector: the Konnektor

```sh
{bin} --format json connector configs                   # the .kon files; "selected" is the default
{bin} connector use praxis                              # select one for later commands
{bin} --format json connector -c praxis get info        # configuration and product
{bin} --format json connector get services              # "used": the versions this tool calls
{bin} --format json connector get cards
{bin} --format json connector get identities            # Telematik-IDs of HBAs and SMC-Bs
{bin} --format json connector get certificates CARD     # ECC and RSA, with PEM
{bin} --format json connector get status                # VPN and operating errors
{bin} --format json connector get expiration [CARD]
{bin} --format json connector describe card CARD
{bin} --format json connector describe certificate CARD C.AUT   # as pki inspect
{bin} --format json connector verify certificate CARD C.AUT     # or --file; exit 0/1
{bin} --format json connector verify pin CARD [PIN]             # exit 0/1
{bin} --format json connector change pin CARD [PIN]
{bin} --format json connector sign FILE --card CARD            # CAdES → FILE.p7s; .pdf (PDF/A) → PAdES
{bin} --format json connector verify signature FILE --signature FILE.p7s   # PAdES: the PDF alone; exit 0/1
{bin} --format json connector encrypt FILE --to CERT [--to-card CARD …]  # CMS → FILE.p7m
{bin} connector export certificate CARD C.ENC > enc.pem         # PEM on stdout; -o FILE, --der
{bin} connector export certificate CARD > all.pem               # every certificate, one bundle
{bin} --format json connector decrypt FILE.p7m --card CARD      # plaintext mode 0600
{bin} --format json connector comfort activate|status|deactivate HBA
```

- The configuration: `-c NAME|PATH` or `TI_CONNECTOR_CONFIG`, else the one
  `connector use` selected, else `default`. A name is looked up as `NAME` and
  `NAME.kon` in the current directory, then in `~/.config/telematik/connectors/`
  (`$XDG_CONFIG_HOME` if set). The files are shared with the Go `ti`.
- In a `.kon` file, `${NAME}` is expanded only in `credentials.username`, `.password`
  and `.data`, from the environment; `-v` names the variables, never their values.
- CARD is an ICCSN, a Telematik-ID (as in the card's C.AUT) or a card handle. Handles
  change when a card is re-inserted; prefer the ICCSN or the Telematik-ID.
- PIN is `PIN.CH`, `PIN.QES` or `PIN.SMC`; needed only for an HBA, which has two. PIN
  commands wait for the user at the card terminal: never run them unasked. A
  `REJECTED` result costs a try; `left_tries` says how many remain.
- SMC-KT, KVK and eGK are restricted on the Konnektor's SOAP API: calls about them fail
  with error kind `card_restricted`.
- Error kinds: `connector_config` (exit 2), `connector_unreachable`,
  `connector_fault` (the Konnektor's code and text are in the message),
  `connector_unsupported` (it offers no version of a service this tool speaks),
  `connector_failed`, `card_restricted` (exit 3), `pin_type` (exit 2).
- `--connector-timeout SECS` (default 10) bounds each call, `--card-timeout SECS`
  (default 300) calls that wait for the card terminal. `-v` prints one line per call,
  `-vv` the SOAP bodies; the `Authorization` header never appears.
- The service directory is cached like the trust material (`--no-cache` bypasses it,
  `cache clear` removes it). A proxy is used only when `-x` is given; proxy
  environment variables do not apply to the Konnektor.
- Signing and decrypting use the card: an HBA asks for PIN.QES at the card terminal
  for each signature (never run it unasked); an SMC-B's PIN must be verified before.
  Signatures are made with the ECC key unless `--crypt rsa`. PAdES needs PDF/A, and the
  Konnektor refuses an already signed PDF. Output files are never replaced without
  `--force` (error kind `output_exists`).
- `decrypt` needs the plaintext's media type as given to `encrypt` (`encrypt` reports
  it as `mime_type`); by default both take it from the file extension.
- Comfort signature: `comfort activate` asks for PIN.QES once and stores a new random
  user ID for that HBA; `sign` then uses it and needs no PIN until the session's count
  or time runs out. The ID lets anyone with the same context sign without a PIN: it is
  kept owner-only in the state directory (`~/.local/state/telematik/ti/comfort/`),
  masked in `-vv`, and removed by `comfort deactivate`. `--comfort-user-id` or
  `TI_COMFORT_USER_ID` supplies one instead.

## Subsystem probe: are the TI services reachable

```sh
{bin} probe ref                      # live table on a terminal; exit 0 none failed, 1 otherwise
{bin} --format json probe prod       # one document once all probes are done
```

- `ENV` is `prod`, `ref`, `test` or `dev` (also `pu`, `ru`, `tu`), positional or as
  `--env`; without either, `TI_ENV`. A positional `ENV` wins over `TI_ENV`; one that
  disagrees with an explicit `--env` is exit 2.
- Every probe runs in parallel with a 3 s limit per request; TLS is not verified (the
  question is reachability, and TI services use TI-internal CAs).
- Each service is checked with its protocol: `oidc` (the IDP's OpenID discovery, JSON
  or signed), `zeta` (RFC 9728 protected-resource metadata of ZETA-protected services
  such as PoPP, VSDM and DiPag), `erp` (the E-Rezept Fachdienst's VAU certificate), `epa` (the
  ePA Information Service's record status for an insurant ID of nobody, `X000000000`:
  `noHealthRecord`), `catalog`
  (the TI platform's service-discovery `catalog.json`), `http` (any answer).
- The catalog's `service_instances` are probed too (`source: "catalog"`).
- `status`: `ok` the expected answer, `warn` an answer but not the expected one, `fail`
  no answer; `detail` is `{kind} …` when ok (`oidc discovery`, `catalog, 6 instances`,
  `http 403`), otherwise the cause (`HTTP 404`, `issuer … differs`, `DNS lookup failed`,
  `timeout`, `connection refused`, `TLS error`). Hosts
  under `splitdns.ti-dienste.de` resolve only inside the TI.

