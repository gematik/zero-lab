# ti connector and ti probe

## Contents
- The .kon configuration file
- Read-only commands (safe)
- Commands that involve a PIN (ask first)
- Sign, verify, encrypt, decrypt
- Comfort signature
- Timeouts, caching, proxy
- Error kinds
- Probe

## The .kon configuration file

`-c NAME|PATH`, else `TI_CONNECTOR_CONFIG`, else the one `ti connector use` selected,
else `default`. A name is looked up as `NAME` and `NAME.kon` in the current directory,
then in `~/.config/telematik/connectors/` (`$XDG_CONFIG_HOME` if set). The format is the
one the former Go `ti` used.

```sh
ti --format json connector configs      # list .kon files; "selected" marks the default
ti connector use praxis                 # select one for later commands
```

Sample `~/.config/telematik/connectors/praxis.kon` with basic credentials:

```json
{
  "version": "1.0.0",
  "url": "https://konnektor.example.com:8443",
  "mandantId": "M1",
  "workplaceId": "W1",
  "clientSystemId": "C1",
  "userId": "U1",
  "credentials": {
    "type": "basic",
    "username": "${KON_USER}",
    "password": "${KON_PASSWORD}"
  },
  "env": "ru",
  "expectedHost": "konnektor.example.com"
}
```

Mutual TLS instead (`type: pkcs12`; `data` is the base64 PKCS#12, `${…}` allowed):

```json
"credentials": { "type": "pkcs12", "data": "${KON_P12_B64}", "password": "${KON_P12_PASSWORD}" }
```

Other fields: `rewriteServiceEndpoints` (Konnektor behind NAT/port forward: use the host of
`url` for every service endpoint), `insecureSkipVerify` (test Konnektors only),
`trustStore` (array of base64 DER CA certificates as anchors, or end-entity
certificates as pins).

Rules that matter:
- `${NAME}` is expanded **only** in `credentials.username`, `.password` and `.data`,
  from the environment. Anywhere else it is an error, and an unset variable is an
  error rather than an empty string. This is deliberate: a `.kon` file from someone else
  must not be able to send your environment variables to a foreign host.
- `-v` names the variables that were expanded, never their values.
- PKCS#12 client certificates must be P-256, P-384 or RSA for now (TLS runs on ring,
  which has no brainpool).
- Don't write real credentials into a `.kon` file you create for the user; use the
  `${…}` form and tell them which variables to export.

## Read-only commands (safe)

```sh
ti --format json connector -c praxis get info          # configuration and product
ti --format json connector get services                # "used": versions this tool calls
ti --format json connector get cards
ti --format json connector get identities              # Telematik-IDs of HBAs and SMC-Bs
ti --format json connector get certificates CARD       # ECC and RSA, with PEM
ti --format json connector get status                  # VPN and operating errors
ti --format json connector get expiration [CARD]
ti --format json connector describe card CARD          # includes each PIN's status
ti --format json connector describe certificate CARD C.AUT     # as `pki inspect`
ti --format json connector verify certificate CARD C.AUT       # or --file; exit 0/1
ti connector export certificate CARD C.ENC > enc.pem   # PEM on stdout; -o FILE, --der
ti connector export certificate CARD > all.pem         # every certificate, one bundle
```

CARD is an ICCSN, a Telematik-ID or a card handle (prefer the first two).

`describe card` reads each user PIN's status **without asking for it**:
`pins[].status` is `VERIFIED` (no entry needed), `VERIFIABLE` (entry needed),
`TRANSPORT_PIN`/`EMPTY_PIN` (set a PIN first), `BLOCKED` (unblock with PUK) or
`DISABLED`, with `left_tries`; a failed query leaves `status` null and sets `error`.
Check this *before* proposing any PIN-involving step.

```sh
# Which SMC-Bs need their PIN verified?
ti --format json connector describe card 80276883110000163974 \
  | jq -r '.pins[] | select(.status != "VERIFIED") | [.pin, .status, .left_tries] | @tsv'
```

SMC-KT, KVK and eGK are restricted on the Konnektor's SOAP API: calls about them fail
with `card_restricted`.

## Commands that involve a PIN (ask first)

These wait for a person at the card terminal. Run them only when the user asked for
exactly that, and warn them before. A `REJECTED` result costs a try; `left_tries` says
how many remain.

```sh
ti --format json connector verify pin CARD [PIN]       # exit 0 accepted, 1 not
ti --format json connector change pin CARD [PIN]
```

PIN is `PIN.CH`, `PIN.QES` or `PIN.SMC`; give it only for an HBA (it has two). A wrong
type is exit 2 `pin_type`. `--card-timeout SECS` (default 300) bounds the wait.

## Sign, verify, encrypt, decrypt

```sh
ti --format json connector sign letter.txt --card CARD            # CAdES, detached → letter.txt.p7s
ti --format json connector sign report.pdf --card CARD            # PDF/A → report.signed.pdf (PAdES)
ti --format json connector sign letter.txt --card CARD --crypt rsa  # RSA instead of the default ECC
ti --format json connector verify signature letter.txt --signature letter.txt.p7s   # exit 0/1
ti --format json connector verify signature report.signed.pdf     # PAdES: the PDF alone
ti --format json connector encrypt letter.txt --to recipient.pem  # CMS → letter.txt.p7m
ti --format json connector encrypt letter.txt --to-card 80276883110000162094   # for that card's C.ENC
ti --format json connector decrypt letter.txt.p7m --card CARD     # plaintext written mode 0600
```

- An HBA asks for PIN.QES at the terminal **for each signature**; an SMC-B's PIN must
  be verified before. Both: only on the user's request.
- PAdES needs PDF/A, and the Konnektor refuses an already-signed PDF.
- Output files are never replaced without `--force` (error `output_exists`).
- `decrypt` needs the plaintext's media type as given to `encrypt` (reported as
  `mime_type`); both default to the file extension. If you encrypt a file with an
  unusual extension, record the `mime_type` and pass it back on decrypt.
- Encrypt to several recipients by repeating `--to` / `--to-card`.

## Comfort signature

One PIN.QES entry for many HBA signatures.

```sh
ti --format json connector comfort activate HBA     # PIN.QES once, at the terminal
ti --format json connector comfort status HBA
ti connector sign a.txt --card HBA && ti connector sign b.txt --card HBA   # no PIN until count/time runs out
ti --format json connector comfort deactivate HBA
```

- `activate` stores a new random user ID for that HBA. Anyone with the same context can
  then sign without a PIN, so it is sealed in the profile's state: it needs a keyring
  (`ti profile create`). Without one, `store_no_keyring`.
- The ID is masked in `-vv` and removed by `deactivate`. `--comfort-user-id` or
  `TI_COMFORT_USER_ID` supplies one instead.
- Deactivate when the work is done.

## Timeouts, caching, proxy

- `--connector-timeout SECS` (default 10) per call; `--card-timeout SECS` (default 300)
  for calls that wait at the terminal.
- `-v` prints one line per call, `-vv` the SOAP bodies (the `Authorization` header never
  appears).
- The service directory is cached like trust material: `--no-cache` bypasses it,
  `ti cache clear` removes it.
- A proxy is used for the Konnektor **only when `-x` is given**; the proxy environment
  variables do not apply to it.

## Error kinds

| Kind | Exit | Meaning |
| --- | --- | --- |
| `connector_config` | 2 | missing/invalid `.kon`; the message lists every problem |
| `connector_unreachable` | 3 | no answer |
| `connector_fault` | 3 | the Konnektor refused; its code and text are in `message` |
| `connector_unsupported` | 3 | no version of a needed service that this tool speaks |
| `connector_failed` | 3 | other failure |
| `card_restricted` | 3 | SMC-KT, KVK, eGK |
| `pin_type` | 2 | wrong PIN type |
| `output_exists` | 5 | use `--force` only if replacing is intended |
| `store_no_keyring` | – | run `ti profile create` |

## Probe

Is a TI environment reachable?

```sh
ti probe ref                          # live table on a terminal; exit 0 none failed, 1 otherwise
ti --format json probe prod           # one document once all probes are done
ti --format json probe --env test | jq -r '.probes[] | select(.status != "ok") | [.name, .detail] | @tsv'
```

- ENV is `prod`, `ref`, `test`, `dev` (also `pu`, `ru`, `tu`); positional wins over
  `TI_ENV`; a positional that disagrees with an explicit `--env` is exit 2.
- All probes run in parallel, 3 s per request. TLS is not verified (the question is
  reachability).
- Each probe has an `access` path: `ti-vpn` (needs a Konnektor's or TI-Gateway's VPN:
  `idpd-ti`, `erx`, `epa-1`, `epa-2`) or `internet` (`idpd-internet`, `fhir-directory`,
  `popp`, `catalog` and its instances). `access_paths[].available: false` for `ti-vpn`
  just means "no TI VPN here", not a broken service.
- `status`: `ok` expected answer, `warn` an answer but not the expected one, `fail` no
  answer. Hosts under `splitdns.ti-dienste.de` resolve only inside the TI.
- `TI_PROBE_ENDPOINTS_PATH` replaces the built-in list with a JSON object per
  environment of `{"name","access","kind","url"}`.
