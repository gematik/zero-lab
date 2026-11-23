---
name: ti-cli
description: Use the `ti` command-line tool for the gematik Telematikinfrastruktur (TI) correctly from scripts and agents. Covers certificate inspection and verification against the TSL (`ti pki`), TSL and CA bundles for curl/openssl/Java, SMC-B identities and JWS signing (`ti identity`), IDP-Dienst authentication (`ti idpd`), FHIR-Directory/VZD tokens (`ti directory`), Konnektor operations such as cards, PINs, CAdES/PAdES signing and CMS encryption (`ti connector`, `.kon` files), TI service reachability (`ti probe`), and profiles/store/cache. Make sure to use this skill whenever the user mentions `ti`, ti-cli, Telematikinfrastruktur, gematik, TSL, SMC-B, HBA, eGK, Konnektor, .kon files, OCSP for TI certificates, C.HCI.AUT / C.FD.TLS-S style certificate types, VZD, IDP-Dienst, ePA clientAttest, or asks to verify, inspect, sign, or encrypt anything in the German health-care PKI, even if they do not name the tool.
---

# ti-cli

`ti` is a non-interactive CLI for the gematik TI. Every input is an argument, an
environment variable, a file or stdin; it never prompts. That makes it safe to script,
and it also means the caller (you) is responsible for not triggering things a human has
to be present for (card PINs, see below).

The installed binary carries its own authoritative guide for its version: run
`ti agent` (Markdown). If something in this skill disagrees with `ti agent` or
`ti <cmd> --help`, trust the binary. Check it exists first with `ti version`.

## The five rules that prevent most mistakes

1. **Ask for JSON and parse that, not text.** `ti --format json …` (or
   `export TI_FORMAT=json`) prints one document with `"schema": 1` on stdout. Fields are
   only ever added within a schema version, so ignore unknown ones. Text and Markdown
   output are for reading.
2. **Branch on exit code and error `kind`, never on `message`.** In JSON mode a failure
   puts `{"schema":1,"error":{"kind","message","hint"}}` on stderr. The `hint` often
   names the fix.
3. **Never run PIN commands unasked.** `connector verify pin`, `change pin`, signing with
   an HBA (PIN.QES) and `comfort activate` wait for a person at the card terminal, and a
   `REJECTED` PIN costs one of a limited number of tries. Only run them when the user
   explicitly asks, and say what will happen first.
4. **Don't use `-k`** (skips TLS checks for downloads) unless the user asks. Trust
   material is verified cryptographically either way, but `-k` still weakens the
   transport and sets `insecure_transport` in the report.
5. **Pass `--env` when you know the environment** (`prod`, `ref`, `test`, `dev`). `auto`
   works for `pki verify`/`pki tsl verify` only; elsewhere it is exit 2
   (`environment_invalid`).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success; verification valid; PIN accepted |
| 1 | verification ran and the result is *not valid* (report still on stdout), or PIN not accepted |
| 2 | wrong arguments, environment cannot be told, or no usable connector configuration |
| 3 | trust material unavailable/failed verification, or the Konnektor/IDP/directory did not answer or refused |
| 4 | input unreadable or without the expected content (e.g. wrong PKCS#12 password) |
| 5 | output could not be written |

Exit 1 is a *result*, not a crash: read the JSON report for `errors`.

## Snippet: a robust call pattern

```sh
out=$(ti --format json pki verify card.pem --env ref 2>err.json)
rc=$?
case $rc in
  0) echo "valid" ;;
  1) jq -r '.errors[]' <<<"$out" ;;                 # verified, but not valid
  3) jq -r '.error.kind + ": " + .error.hint' err.json ;;   # trust material / network
  *) jq -r '.error.kind + ": " + .error.message' err.json ;;
esac
```

## Which subsystem do I need?

| The user wants to… | Command family | Reference |
| --- | --- | --- |
| look at / validate a certificate, check a TLS server's chain, build a CA bundle or truststore, check a TSL | `ti pki …` | [references/pki.md](references/pki.md) |
| read an SMC-B's AUT identity, make an ES256/BP256R1 JWS (ePA clientAttest, entitlement) | `ti identity …` | [references/identity-idpd-directory.md](references/identity-idpd-directory.md) |
| get an authorization code from the IDP-Dienst; get a VZD (FHIR-Directory) token | `ti idpd …`, `ti directory …` | [references/identity-idpd-directory.md](references/identity-idpd-directory.md) |
| talk to a Konnektor: cards, certificates, PIN status, sign, encrypt, decrypt, comfort signature | `ti connector …` | [references/connector.md](references/connector.md) |
| find out whether TI services answer | `ti probe ENV` | [references/connector.md](references/connector.md#probe) |
| profiles, keyring, sealed state, cache | `ti profile/store/cache …` | [references/store-and-profiles.md](references/store-and-profiles.md) |

Read the matching reference before writing the command; they carry the flags, report
fields and error kinds.

## Quick samples

```sh
# What does the TI read from this certificate?
ti --format json pki inspect card.pem | jq '.certificates[0].certificate_type'

# Is it valid? (chain to a TSL-verified root, profile, OCSP). Exit 0 valid, 1 not.
ti --format json pki verify card.pem --env ref

# Offline (cached trust material, no OCSP): says nothing about revocation
ti --format json pki verify card.pem --offline | jq '.revocation_checked'   # false

# A TLS server's chain; --fqdn is the host
ti --format json pki verify --connect epa-as-1.ref.epa4all.de

# CA bundle for curl/openssl, then use it
ti pki tsl bundle --env ref --connect epa-as-1.ref.epa4all.de -o epa.pem
curl --cacert epa.pem https://epa-as-1.ref.epa4all.de/

# Sign claims with an SMC-B P12 (password from a file, not the command line)
ti --format json identity sign --p12 smcb.p12 --p12-password-path pw.txt --claims - < claims.json \
  | jq -r .jws

# Which cards does the selected Konnektor have?
ti --format json connector get cards | jq -r '.cards[] | [.iccsn, .card_type] | @tsv'

# Are the TI services of the reference environment reachable?
ti --format json probe ref | jq '.access_paths'
```

## Names that trip people up

- Certificate types are gemSpec_PKI Tab_PKI_405 names: `C.HCI.AUT`, `C.FD.TLS-S`,
  `C.NK.VPN`. eGK certificates are `C.CH.*`, HBA `C.HP.*`, SM-B (SMC-B, HSM-B) `C.HCI.*`.
- Validation profiles drop the `C.`: `hci-aut`, `fd-tls-s`, `tsl-sig`, `idpd-sig`,
  `epa-vau-aut`, `zeta-guard-aut`. Type and profile arguments ignore case, treat `.` and
  `-` alike and accept a leading `C.`, so `--validation-profile C.HCI.AUT` equals
  `hci-aut`.
- A card is identified as ICCSN, Telematik-ID or handle. **Prefer ICCSN or Telematik-ID**:
  handles change when a card is re-inserted.

## Common options and environment

| Option / variable | Effect |
| --- | --- |
| `--format auto\|text\|markdown\|json`, `TI_FORMAT` | output format |
| `--env`, `TI_ENV` | `auto`, `prod`, `ref`, `test`, `dev` |
| `--profile NAME`, `TI_PROFILE` | which profile's cache/state/keyring |
| `--offline` | no requests; work from the cache |
| `-v`, `-vv` | diagnostics on stderr (`-vv` adds SOAP bodies / non-2xx bodies; secrets masked) |
| `-x`, `--cacert`, `--connect-timeout`, `-m`, `--retry`, `-A` | curl-style HTTP options (`HTTPS_PROXY`, `NO_PROXY`, `CURL_CA_BUNDLE`, … also honoured) |
| `-c NAME\|PATH`, `TI_CONNECTOR_CONFIG` | Konnektor `.kon` file |
| `--p12-password-path`, `TI_P12_PASSWORD_PATH` | file whose first line is the PKCS#12 password |

Without `--p12-password`/`--p12-password-path`, PKCS#12 input uses `00` (gematik's test
cards). Prefer the password-file form in scripts: it keeps the secret out of the
process list.

## Discovering output shape

`ti schema pki verify` prints the JSON Schema for a command's output; `ti schema`
alone prints all of them plus `error`. Use it before writing a `jq` filter for a command
you have not used, rather than guessing field names.

## Reporting results to the user

- Quote the verdict (`valid`) and, when false, the `errors`; mention `warnings` that
  matter (for example `ocsp_responder_not_rfc6960`, `issued_before_ca_revocation`).
- Say whether revocation was checked. `revocation_checked: false` (offline, `--at`) means
  a "valid" result says nothing about revocation.
- If `trust.note` is set, trust material was incomplete (e.g. offline with an empty
  cache); suggest passing the issuing CA with `--issuer` or going online.
- Never print secrets from reports: access tokens, comfort user IDs, `store show
  --reveal` output, passwords. Summarise instead.
