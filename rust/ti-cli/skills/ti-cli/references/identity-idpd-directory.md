# ti identity, idpd, directory

These three chain together: an *identity* (AUT certificate + key) signs; `idpd`
uses it to get an authorization code; `directory login owner` uses `idpd` internally to
get a FHIR-Directory token.

## Contents
- Identity sources
- identity inspect / sign
- idpd authenticate
- directory login
- Error kinds

## Identity sources

An identity is the AUT certificate (digitalSignature set, contentCommitment not set)
with its key, from exactly one of:

| Flag | Source |
| --- | --- |
| `--p12 FILE` | PKCS#12 export (several certificates/keys fine; the AUT pair is selected) |
| `--cert FILE --key FILE` | PEM; key as PKCS#8 `PRIVATE KEY` or `EC PRIVATE KEY`; extra certificates in the file are the chain |
| `--card CARD` | a card at the Konnektor (`-c`/`--connector NAME\|PATH`, `TI_CONNECTOR_CONFIG`, or the one `connector use` chose). Signs through ExternalAuthenticate, so **PIN.SMC must already be verified** (`connector verify pin`). |

Keys must be ECDSA on brainpoolP256r1 or P-256, else error `key_unsupported`.
P12 password: `--p12-password`, else first line of `--p12-password-path` /
`TI_P12_PASSWORD_PATH`, else `00`.

## identity inspect / sign

```sh
ti --format json identity inspect --p12 smcb.p12 --p12-password-path pw.txt
ti --format json identity inspect --cert smcb-aut.pem --key smcb-aut.key
ti --format json identity inspect --card 80276883110000163974             # selected Konnektor
ti --format json identity inspect --card SMC-B-7 --connector praxis       # another one

echo '{"iss":"my-client","iat":1760000000,"exp":1760000300,"nonce":"abc123"}' > claims.json
ti --format json identity sign --p12 smcb.p12 --claims - < claims.json            # ES256 JWS, x5c
ti --format json identity sign --p12 smcb.p12 --claims claims.json --typ JWT --header kid=aut
ti --format json identity sign --p12 smcb.p12 --claims claims.json --alg BP256R1  # brainpool key only
ti --format json identity sign --p12 smcb.p12 --claims claims.json | jq -r .jws   # just the compact JWS
```

- `inspect` reports `telematik_id`, `signing` (`alg`, `curve`), `certificate` (as in
  `pki inspect`) and `chain`. No AUT pair found: exit 4, `identity_not_found`.
- `sign` takes the claims as a JSON object (`-` is stdin) and returns `jws` plus the
  `header` as sent. The tool adds no claims: you supply `iat`, `exp`, `nonce` yourself.
- `alg` is the key's (ES256 default; `BP256R1` is the same ECDSA/SHA-256 under gematik's
  name, for IDP-Dienst; needs a brainpool key). You cannot override it with `--header`.
- Headers the tool owns (`alg`, `x5c`, `crit`, …) are refused: exit 2 `header_invalid`.
  `--header NAME=VALUE` takes VALUE as JSON, else text.
- Claims that are not an object: exit 4 `claims_invalid`.
- ePA `clientAttest` and entitlement JWTs are `identity sign` with the respective claims.

## idpd authenticate

Runs the Authenticator-Modul flow (gemSpec_IDP_Frontend) for an authorization URL a
relying party produced (for ePA, the Aktensystem's `authz_uri`). It returns `code` and
`state` from the IDP's redirect.

```sh
ti --format json idpd authenticate --env ref --p12 smcb.p12 --auth-url "$AUTHZ_URI"
ti --format json idpd authenticate --env ref --card SMC-B-7 --auth-url "$AUTHZ_URI"
ti --format json idpd authenticate --idp-url https://idp.example --auth-url "$URL" --p12 smcb.p12
ti --format json idpd authenticate --env ref --p12 smcb.p12 --auth-url "$AUTHZ_URI" | jq -r '.code'
```

- IDP is `--env` (`prod`, `ref`, `test`, `dev` as ref; `auto` is exit 2) or `--idp-url`.
- `--auth-url` must be https (http only on 127.0.0.1, for tests). Redirects are not
  followed; a 302 is the answer.
- Before the card signs, the IDP's certificates (discovery signer and `PuK_IDP_SIG`)
  are verified against the TSL with the `idpd-sig` profile and OCSP. A certificate the
  TSL does not vouch for is exit 3 `idpd_untrusted`, and nothing is signed.
  `idp.certificates` lists them with `verified`.
- `--idp-unverified` skips that check (for an IDP outside the TI PKI); the report then
  has `verified: false` and warning `idp_certificates_unverified`. Use only when the
  user says the IDP is a reference implementation.
- SSO tokens and alternative authentication (pairing) are not implemented.

## directory login

One subcommand per Auth-Service endpoint of the FHIR-Directory (VZD), all ending in an
access token (ES256 JWT) and the same report.

```sh
ti --format json directory login owner --env ref --p12 smcb.p12        # card via the IDP-Dienst
ti --format json directory login owner --env ref --card SMC-B-7
ti --format json directory login owner --env ref --regservice-token-path reg.jwt
ti --format json directory login service --env ref --client-id ID --client-secret-path secret.txt
ti directory login holder --env ref --client-id ID --client-secret-path secret.txt --token

# use the bearer
TOKEN=$(ti directory login owner --env ref --p12 smcb.p12 --token)
curl -H "Authorization: Bearer $TOKEN" "https://fhir-directory-ref.vzd.ti-dienste.de/…"
```

- Subcommands: `owner`, `holder`, `service`, `ti-provider`.
- Report fields: `endpoint`, `method` (`card`, `regservice`, `client_credentials`),
  `access_token`, `token_type`, `expires_in`, `expires_at`, `token` (decoded payload,
  **not verified**), `directory` (`base_url`, …), plus `idp`, `identity`, `challenge`
  or `client_id` where applicable. `--token` prints only the access token.
- Tokens are never cached: they are secrets and the caller keeps them. Don't echo them
  into logs or chat.
- `owner`: card via `--p12`/`--cert --key`/`--card`, or `--regservice-token-path FILE`
  (TI-Messenger RegService-OpenID-Token, BP256R1, C.FD.SIG role `oid_tim`).
- `holder`, `service`, `ti-provider`: client credentials at the directory's Keycloak.
  `--client-id` or `TI_DIRECTORY_CLIENT_ID`; the secret **only from a file**
  (`--client-secret-path` or `TI_DIRECTORY_CLIENT_SECRET_PATH`, first line).
- Directory is `--env`, or `--url BASE` with `--idp-url` (card) / `--auth-url` (client
  credentials); a missing one is exit 2 `arguments_invalid`, before anything is sent.
- Not implemented: `/tim-authenticate` and the decoupled gematik Authenticator app
  variant.

## Error kinds

| Kind | Exit | Meaning |
| --- | --- | --- |
| `identity_not_found` | 4 | no AUT pair in the source |
| `key_unsupported` | – | key is not brainpoolP256r1 / P-256 |
| `header_invalid` | 2 | a header the tool sets |
| `claims_invalid` | 4 | claims not a JSON object |
| `idpd_error` | 3 | IDP refused; message has `error`, `gematik_error_text`, `gematik_code` (e.g. 2030 "Karte unbekannt") |
| `idpd_unreachable`, `idpd_protocol` | 3 | no answer / answer not per spec (`-v` shows requests) |
| `idpd_untrusted` | 3 | IDP certificate not vouched for by the TSL |
| `directory_error` | 3 | directory refused; HTTP status + its `errors` in the message (e.g. 403 `Unknown Telematik ID`) |
| `directory_auth_server_error` | 3 | Keycloak refused; `error`, `error_description` |
| `directory_unreachable`, `directory_protocol` | 3 | no answer / unexpected answer (`-vv` logs non-2xx bodies) |
| `arguments_invalid` | 2 | missing URLs/arguments |
| `connector_*` | 3 | card path: Konnektor problem, e.g. a fault for an unverified PIN |
