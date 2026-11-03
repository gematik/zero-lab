# {bin} for scripts and agents

`{bin}` is the command-line tool for the gematik Telematikinfrastruktur (TI). Commands
are grouped by subsystem (`{bin} pki …`), and the conventions below hold for every one
of them. It never prompts. Every input is an argument, an environment variable, a file
or stdin.

## Rules for agents

- Never ask for a real `.kon` file, PKCS#12 file, PIN, password, client secret or token,
  and never print one: refer to it by its path. A `.kon` file is a secret as a whole; it
  holds the Konnektor's credentials. Samples with placeholders, to create or edit one,
  are fine (see the connector subsystem). To look at one, run `connector config show`,
  which says where each secret is kept but never shows it; never read the file itself.
- When a user pastes one, say it should not have been shared and should be replaced
  where that is possible. Do not repeat it, quote it, or carry it into commands or
  files.
- Secrets in output stay out of the conversation and logs: `access_token` and the
  output of `--token`, comfort user IDs, `store show --reveal`. Summarise instead.
- Commands that use a card's PIN or wait for the user at the card terminal
  (`connector verify pin`, `change pin`, `comfort activate`, `sign` and `decrypt`) run
  only when the user asks for that step; say before what the user will be asked for.
  `connector describe card` reads the PINs' status without asking for one: use it first.
- Commands that delete or re-key what cannot be fetched again (`profile delete`,
  `profile rotate`, `profile rewrap`, `store rm`, `store purge`) and `--force` run only
  when the user asks for them.
- `-k` only when the user asks for it.
- Report a verification with its verdict and `errors`, the `warnings` that matter, and
  whether revocation was checked (`revocation_checked`); a `trust.note` means the trust
  material was incomplete.

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
| 2 | wrong arguments, the environment cannot be told, no usable connector configuration, an output file that exists, or a store problem the user can fix |
| 3 | trust material unavailable or failed verification, or a remote party (server, Konnektor, IDP-Dienst, FHIR-Directory) did not answer or refused the call |
| 4 | input unreadable or without the expected content, or a key that cannot sign |
| 5 | output could not be written, or the store was busy or failed |

On failure with `--format json`, stderr carries
`{"schema":1,"error":{"kind","message","hint"}}`. Branch on `kind` and the exit code,
never on `message`. `hint` says what to do, when there is something.

## Error kinds

| Kind | Exit | When |
| --- | --- | --- |
| `arguments_invalid` | 2 | a combination of arguments the command cannot use |
| `environment_invalid` | 2 | an environment that does not fit the command |
| `environment_undetected` | 2 | `--env auto` found no evidence in the certificates |
| `output_exists` | 2 | the output file exists; `--force` replaces it |
| `http_setup` | 2 | `--cacert`, `--capath` or the proxy cannot be used |
| `unknown_schema` | 2 | `schema` for a command that has none |
| `cache_dir_unknown` | 2 | no cache directory can be derived |
| `connector_config` | 2 | no usable `.kon` file; the message lists every problem |
| `pin_type` | 2 | a PIN type that does not fit the card |
| `header_invalid` | 2 | a JWS header the tool sets itself |
| `store_not_found` | 2 | no such record, or the profile's key file is missing |
| `store_expired` | 2 | the record has expired |
| `store_malformed` | 2 | a record, keyring, key file or database does not parse |
| `store_unsupported_version` | 2 | a format this version does not know |
| `store_unknown_kid` | 2 | a record sealed under a key the keyring lacks |
| `store_auth_failed` | 2 | a record or key does not authenticate: wrong key file, or altered |
| `store_limit_exceeded` | 2 | a size or count above its limit |
| `store_invalid_argument` | 2 | a namespace, name or lifetime outside its rule |
| `store_capability_missing` | 2 | the backend lacks what a namespace needs |
| `store_no_keyring` | 2 | the profile has no keyring: `{bin} profile create` |
| `store_insecure_permissions` | 2 | the key file is readable by others |
| `trust_material_unavailable` | 3 | roots.json or the TSL could not be had or failed verification |
| `server_unreachable` | 3 | `--connect` reached no server or no handshake |
| `connector_unreachable` | 3 | the Konnektor did not answer |
| `connector_fault` | 3 | the Konnektor refused: its code and text in the message |
| `connector_unsupported` | 3 | it offers no version of a service this tool speaks |
| `connector_failed` | 3 | another Konnektor failure |
| `card_restricted` | 3 | a card type the Konnektor restricts (SMC-KT, KVK, eGK) |
| `signing_failed` | 3 | signing failed for another reason than a refusal |
| `idpd_error` | 3 | the IDP-Dienst refused |
| `idpd_unreachable` | 3 | the IDP-Dienst did not answer |
| `idpd_untrusted` | 3 | an IDP certificate the TSL does not vouch for |
| `idpd_protocol` | 3 | an IDP answer outside the specification |
| `directory_error` | 3 | the FHIR-Directory refused |
| `directory_auth_server_error` | 3 | its Keycloak refused the client credentials |
| `directory_unreachable` | 3 | the FHIR-Directory did not answer |
| `directory_protocol` | 3 | a directory answer outside the specification |
| `input_unreadable` | 4 | a file or stdin cannot be read |
| `no_certificate` | 4 | the input holds no certificate |
| `certificate_malformed` | 4 | the input is not a readable certificate |
| `p12_password` | 4 | the PKCS#12 password is wrong |
| `p12_unreadable` | 4 | not a readable PKCS#12 file |
| `identity_not_found` | 4 | no AUT certificate with its key in the source |
| `key_unsupported` | 4 | a key that is not ECDSA on brainpoolP256r1 or P-256 |
| `claims_invalid` | 4 | the claims are not a JSON object |
| `signature_malformed` | 4 | a signature neither DER nor r‖s |
| `output_failed` | 5 | stdout or a file could not be written |
| `state_file_failed` | 5 | the TSL state file could not be read, parsed or written; removing it restarts from the next verified TSL |
| `store_busy` | 5 | the database stayed locked |
| `store_backend_error` | 5 | an I/O or database error of the store |

## Common options and environment

- `TI_FORMAT` sets the default format.
- `TI_ENV` sets the default of `--env`: `auto`, `prod`, `ref`, `test` or `dev`. Every
  command that needs an environment takes `--env`. `pki verify` and `pki tsl verify`
  detect it with `auto` (their default); `pki roots list` and `pki tsl show` cannot, so
  `auto` from `TI_ENV` means `prod` there and `--env auto` is an error (exit 2,
  `environment_invalid`).
- Profiles: `--profile NAME`, else `TI_PROFILE`, else the one `{bin} profile use` chose,
  else `default`. A profile is shared with the other TI tools (zero-epa, zeta-cli): its
  cache (`cache.db`), its state (`state.db`) and its keyring. `TI_CACHE_DIR` and
  `TI_STATE_DIR` move the bases of the profiles' caches and states, `TI_STORE_KEK_PATH`
  names the key file; with all three a test or HITL session gets a separate store.
- The HTTP options and variables follow curl: `-x`/`HTTPS_PROXY`/`HTTP_PROXY`/
  `ALL_PROXY`, `--noproxy`/`NO_PROXY`, `--cacert`/`CURL_CA_BUNDLE`/`SSL_CERT_FILE`,
  `--capath`/`SSL_CERT_DIR`, `--connect-timeout`, `-m`, `--retry`, `-A`.
- `-k` skips TLS checks for downloads only and sets `insecure_transport` in the report;
  the trust material is still verified. Do not use it unless asked to.
- Downloads are cached in the profile's `cache.db`
  (`~/.cache/telematik/profiles/NAME/cache.db`). `--offline` makes no request and works
  from the cache.
- OCSP responses (`good`, `revoked`) are cached there too, for one hour and never past
  the response's `nextUpdate`, so the next run within the hour asks no responder. What
  is read back is verified again (signature, responder, certificate); `unknown`
  answers and errors are not cached. Every command that checks OCSP uses it.
- `{bin} cache clear` empties the profile's cache.
- What must stay secret or must not be lost (TSL state, comfort IDs, later tokens) is
  sealed in the profile's `state.db` and needs a keyring: `{bin} profile create` makes it
  once, with a key file at `~/.config/telematik/profiles/NAME/store.kek`. Without one,
  `ti` keeps none of it and says so (`store_no_keyring`). Losing the key file loses
  only the sealed records. Store errors have kinds `store_<code>` with a hint.
- `{bin} profile list|show|use NAME|delete NAME --yes` manage profiles; `use` writes the
  active file every TI tool reads. `{bin} profile rotate` starts a new sealing key and
  drops keys no live record uses; `{bin} profile rewrap --kek-file PATH` wraps the keys
  with another key file (then set `TI_STORE_KEK_PATH`). `{bin} store doctor [--json]
  [--deep]` checks the profile's key file, keyring, databases and records without
  changing them: each check `ok`, `warn` or `fail`, exit 1 if one fails; `--deep` opens
  every sealed record. `{bin} store ls [NS]` lists records (never ids or contents),
  `store show NS ID [--reveal]` one record, `store rm NS ID` and `store purge NS --yes`
  remove them, `store cleanup` removes expired ones (also done once a day on its own),
  `store migrate [--dry-run]` reports format levels. `TI_STORE_TRACE=1` writes one line per store operation to
  stderr (operation, namespace, the first 8 bytes of the name, code, duration), never a
  payload.

## Names

Certificate types are the gemSpec_PKI Tab_PKI_405 names (`C.HCI.AUT`, `C.FD.TLS-S`,
`C.NK.VPN`), in `certificate_type` and every `…_types` list. Profiles are named after
their type without `C.` (`hci-aut`, `fd-tls-s`, `tsl-sig`) or after their technical
role plus usage (`idpd-sig`, `epa-vau-aut`, `zeta-guard-aut`). Type and profile
arguments ignore case, treat `.` and `-` alike and accept a leading `C.`:
`--validation-profile C.HCI.AUT` is `hci-aut`. Cards keep their own names where a card is meant (`EGK`,
`HBA`, `SMC-B`, `C.AUT` in `connector`); eGK certificates are `C.CH.*`, HBA `C.HP.*`,
SM-B (SMC-B, HSM-B) `C.HCI.*`.

## Subsystem pki: certificates and trust

```sh
{bin} --format json pki inspect card.pem          # what the TI reads from a certificate
{bin} --format json pki verify card.pem           # chain, profile, OCSP; exit 0/1
{bin} --format json pki verify card.pem --offline # no network, no OCSP
{bin} --format json pki verify tls.pem --fqdn epa-as-1.ref.epa4all.de
{bin} --format json pki verify --connect epa-as-1.ref.epa4all.de   # the server's chain; --fqdn is the host
{bin} --format json pki profiles list
{bin} --format json pki profiles describe hci-aut
{bin} --format json pki profiles describe hci-aut --env ref   # tsl.cas: CAs the TSL allows for its types
{bin} --format json pki roots list --env ref
{bin} --format json pki tsl show --env ref        # CAs under the roots that signed them
{bin} --format json pki tsl show --rejected       # CAs no verified root signed
{bin} --format json pki tsl show --ca SMCB-CA51   # filter by name, also --provider, --root
{bin} --format json pki tsl verify tsl.xml tsl.sig --previous old.xml   # exit 0 valid, 1 not
{bin} --format json pki tsl verify tsl.xml tsl.sig --signer-status tsl.ocsp   # the published signature and status, no network
{bin} pki roots bundle --env ref > roots.pem      # CA bundle (PEM) for curl, openssl, Go
{bin} pki tsl bundle --env ref --ca SMCB -o smcb.pem   # the TSL's CAs, tsl show's filters
{bin} pki tsl bundle --env ref --ca KOMP-CA54 --ca KOMP-CA55 -o komp.pem   # repeated: any of
{bin} pki tsl bundle --env ref --connect epa-as-1.ref.epa4all.de --with-roots -o epa.pem
{bin} pki tsl bundle --env ref --cert chain.pem --p12 --p12-password changeit -o ts.p12
{bin} pki tsl bundle --env prod --issues TLS-S --with-roots -o tls.pem   # every TLS server CA
{bin} pki tsl bundle --env prod --issues TLS-S --with-roots --nist-only -o tls-nist.pem
{bin} pki roots bundle --p12 --p12-password changeit -o roots.p12   # Java truststore
{bin} pki tsl export --env ref -o tsl.xml         # the TSL as published, once it verified, with tsl.sig and tsl.ocsp
```

- `roots bundle`, `tsl bundle` and `tsl export` write the bundle or the TSL to stdout,
  or with `-o` to a file (`--force` replaces it). With `--format json` they report
  instead: each certificate's `pem` when nothing was written, `output` when a file was;
  `tsl export`'s report never carries the XML. `--p12` writes a PKCS#12 truststore
  (each certificate a Java `trustedCertEntry`, alias the common name in lower case) and
  needs `--p12-password`. `--nist-only` on `roots bundle` and `tsl bundle` keeps only
  the roots and CAs whose own key is not brainpool (GEM.RCA2, 6, 7, 9, 10 and their
  CAs); the walk and the TSL are still verified with brainpool.
- `tsl bundle` subsets: `--ca`, `--provider`, `--root` and `--issues` are repeatable (a
  repeated filter matches any of its values; different filters must all match).
  `--issues TYPE` keeps the CAs the TSL lets issue a certificate type whose name
  contains TYPE, ignoring case and `.` versus `-` (`C.FD.TLS-S` as in `certificate_type`,
  `fd-tls-s` as in the profile names): `TLS-S` for every TLS server CA (C.FD.TLS-S, C.ZD.TLS-S), `TLS` with the
  client type, `HCI.AUT` for SMC-B authentication; names are those of Tab_PKI_405. `tsl show` takes the same filters and
  reports each CA's `issuable_types`. `--connect HOST[:PORT]`
  and `--cert FILE` (both repeatable) keep only the CAs that issued those certificates
  or are among them: the bundle a client of that server needs. TI servers such as the
  ePA Aktensysteme send only their own certificate, so clients need the issuing CA from
  the TSL; curl, OpenSSL and Java accept such a CA as trust anchor by itself.
  `--with-roots` adds the roots the selected CAs chain to, for clients that accept only
  a self-signed anchor. A certificate whose issuer is neither a selected CA nor a root
  is named on stderr.

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
    `cached: true` when it came from the cache of an earlier run (`produced_at` says
    how old it is) rather than from the responder now.
    Under hard-fail an unreachable responder leaves no answer but an
    `ocsp_unavailable` error naming its URL.
  - `ocsp` is present with `--ocsp-responder` or `--ocsp-max-age`: the responder every
    request went to (`null`: each certificate's own) and `max_response_age_ms`.
  - `environment.detection` says how `--env auto` chose the environment. Pass `--env`
    when you already know it.
  - `trust.note` is set when the trust material is less than the full set, e.g.
    offline with nothing cached. Then pass the issuing CA with `--issuer`.
  - `trust.nist_only: true` with `--nist-only` (`pki verify`, `pki roots list`): the
    trust material, verified with brainpool, narrowed to the roots and TSL CAs whose
    own key is not brainpool, and the chain validated without brainpool. A brainpool
    chain is then not valid. The chain must still reach a non-brainpool root: a chain
    under a NIST CA whose root is brainpool (e.g. GEM.RCA8) is invalid here although
    curl and Java, taking the CA from `tsl bundle --nist-only` as an anchor, accept it.
- The TSL is verified whenever trust material is loaded; a list that fails is not used.
  `trust.tsl` names the list, its signer and the TSL signer CA; `trust.tsl_warnings`
  holds `no_ocsp_check` when the signer's OCSP status was not queried (offline, `--at`).
  `revocation.authorization` is `tsl_listed` for a responder the TSL lists for the
  issuing CA's TSP. A CA counts only if a verified root signed it and, with a verified
  TSL, the TSL names it (`ca_not_in_tsl`). A responder is asked only about a certificate
  that has passed everything else, so a failed one shows no revocation results.
  `--validation-profile` refuses a type the profile does not accept
  (`profile_type_mismatch`, an error, no longer a warning). A CA the TSL lists
  as revoked still vouches for what it issued before its `StatusStartingTime`
  (gemSpec_PKI Tab_PKI_271, TUC_PKI_002): such an end entity is valid with the warning
  `issued_before_ca_revocation`, a later one fails with `ca_revoked_in_tsl`. `tsl show`
  reports the time as `revoked_since`; `tsl bundle` leaves revoked CAs out, because
  curl and Java cannot apply the date rule.
- The validity model follows the certificate type (gemKPT_PKI_TIP 2.4). For the nonQES
  certificates of an SMC-B or HBA (C.HCI.AUT, .ENC, .OSIG, C.HP.AUT, .ENC) each CA
  counts as it was when it issued the certificate below (Kompromissmodell): a CA that
  has expired since gives the warning `issued_before_ca_expiry`, one that had expired
  before is `expired`. Every other type, components and the eGK, needs every
  certificate of the chain valid at the reference time (shell model). The end entity
  itself is always checked at the reference time.
- `pki verify --at T`: OCSP answers for the time of the query and its status is judged
  at T (gemSpec_PKI TUC_PKI_006 8a/8b). A certificate revoked after T is valid with the
  warning `revoked_after_reference_time`; `chain[].revocation` keeps `status: revoked`
  and the `revoked_at` time, `at` is T.
- `tsl verify TSL SIG` checks a TSL file and the `.sig` published next to it: signature, signer under the embedded TSL signer CA,
  `NextUpdate` (`--grace`), the signer's OCSP status (not with `--offline` or `--at`),
  and with `--previous` the sequence. `result` is `valid` or `invalid`; an invalid one
  has `code` (gemSpec_PKI Tab_PKI_274, e.g. `detached_signature_error`), `rule`
  (`TSLDET-nnn` or `TSLSIG-nnn`) and `detail`, and the list fields are null. A valid one may carry
  `warnings` and `skipped` entries. `tier` is `prod` or `nonprod`: ref, test and dev
  share one TSL signer CA.
- `{bin} pki verify-signature --cert CERT --data FILE --signature FILE` checks one
  ECDSA-SHA256 signature against the key of CERT (PEM or DER; `-` reads stdin): exit 0
  valid, 1 not, with `valid`, `signature_format` (`der`, or `raw` for r‖s of 64 bytes)
  and the signer's `certificate`. It says nothing about the certificate itself; that is
  `pki verify`. ePA clients check a VAU's `signed_pub_keys` with it.
- The password of PKCS#12 input: `--p12-password`, else the first line of the file
  `--p12-password-path` (or `TI_P12_PASSWORD_PATH`) names, else `00`. Prefer the file
  from scripts: it keeps the password out of the command line and the process list.

## Subsystem identity: the SMC-B or HBA identity

```sh
{bin} --format json identity inspect --p12 smcb.p12 --p12-password-path pw.txt
{bin} --format json identity inspect --cert smcb-aut.pem --key smcb-aut.key
{bin} --format json identity inspect --card 80276883110000163974            # the selected Konnektor
{bin} --format json identity inspect --card SMC-B-7 -c praxis               # another one
{bin} --format json identity sign --p12 smcb.p12 --claims - < claims.json     # ES256 JWS, x5c
{bin} --format json identity sign --p12 smcb.p12 --claims claims.json --typ JWT --header kid=aut
```

- An identity is the AUT certificate (digitalSignature set, contentCommitment not set)
  together with its key: an SMC-B's C.HCI.AUT or an HBA's C.HP.AUT, never the HBA's
  C.HP.QES. It comes from one of `--p12 FILE` (several certificates and keys are
  fine: the AUT pair is selected; a card vendor's export), `--cert FILE --key FILE`
  (PEM; the key as PKCS#8 `PRIVATE KEY` or `EC PRIVATE KEY`; further certificates in
  the file are its chain) or `--card CARD` (ICCSN, Telematik-ID or handle at the
  Konnektor the `connector` commands use: `-c`/`--connector-config NAME|PATH` or
  `TI_CONNECTOR_CONFIG`, else the selection of `connector use`, else `default`; the
  card's C.AUT ECC certificate; signing goes through the Konnektor's
  ExternalAuthenticate, so the card's PIN must be verified before with `connector
  verify pin`: PIN.SMC for an SMC-B, PIN.CH for an HBA). Keys are ECDSA on
  brainpoolP256r1 or P-256; nothing else signs (error kind `key_unsupported`).
- `inspect` reports `telematik_id` (the admission statement's registration number),
  `signing` (`alg` ES256, `curve`), the `certificate` as `pki inspect` describes it and
  `chain`, the CAs found with it. No source holds an AUT pair: exit 4,
  `identity_not_found`.
- `sign` takes the claims as a JSON object from `--claims FILE` (`-`: stdin) and returns
  `jws`, the compact serialization, with `header` as sent: `alg` ES256 (the key's,
  never yours), `typ` (`--typ`, default `JWT`), `x5c` the certificate, and every
  `--header NAME=VALUE` (VALUE is JSON, else text). `iat`, `exp` and `nonce` are claims
  you pass; the tool adds none. A header the tool sets (`alg`, `x5c`, `crit`, …): exit
  2, `header_invalid`; claims that are not an object: exit 4, `claims_invalid`. A
  Konnektor that refuses to sign is a `connector_*` error (exit 3), e.g. a fault for an
  unverified PIN.
- `--alg ES256` (default) or `--alg BP256R1`: the same ECDSA with SHA-256 under RFC
  7518's name (ePA) or gematik's (the IDP-Dienst); `BP256R1` needs a brainpool key.
- ePA's `clientAttest` and entitlement JWTs are `identity sign` with the respective
  claims; the IDP-Dienst's challenge response is `idpd authenticate`.

## Subsystem idpd: the IDP-Dienst

```sh
{bin} --format json idpd authenticate --env ref --p12 smcb.p12 --auth-url "$AUTHZ_URI"
{bin} --format json idpd authenticate --env ref --card SMC-B-7 --auth-url "$AUTHZ_URI"
{bin} --format json idpd authenticate --idp-url https://idp.example --auth-url "$URL" --p12 smcb.p12
```

- `authenticate` runs the Authenticator-Modul flow of gemSpec_IDP_Frontend for the
  authorization URL a relying party made (for ePA, the Aktensystem's `authz_uri`): it
  fetches and verifies the IDP's signed discovery document and keys, fetches the
  challenge, signs the nested JWT with the identity's key (`BP256R1`, `x5c`), encrypts
  the answer to `PuK_IDP_ENC` and posts it, and returns `code` (and `state`) from the
  IDP's redirect, with `idp`, `identity` and the challenge's `client_id`, `scope`,
  `redirect_uri`. The identity is given as for `identity`; a card's PIN (PIN.SMC,
  PIN.CH for an HBA) must be verified before.
- The IDP is `--env` (`TI_ENV`; `prod`, `ref`, `test`, `dev` as ref; `auto` is exit 2)
  or `--idp-url BASE`. `--auth-url` must be https (http only on 127.0.0.1, for tests).
  Redirects are not followed: a 302 is the answer.
- Exit 3 when the IDP refuses: error kind `idpd_error`, the message carries `error`,
  `gematik_error_text` and `gematik_code` (e.g. `access_denied: Karte unbekannt
  (gematik_code 2030, …)`). `idpd_unreachable` when no answer came, `idpd_protocol`
  when the answer is not what the specification says (`-v` shows each request).
- Before the card signs, the IDP's certificates are checked against the TSL: the
  discovery document's signer (`puk_disc_sig`, its `x5c`) and `PuK_IDP_SIG` (the JWK's
  `x5c`, whose key must be the JWK's), each with the idpd-sig profile (C.FD.SIG, role
  `oid_idpd`) and OCSP, in the environment of `--env`, or with `--idp-url` the one the
  certificate shows. `PuK_IDP_ENC` has no certificate; the verified discovery document
  names it. `idp.certificates` lists both with `key`, `subject`, `sha256`, `verified`.
  A certificate the TSL does not vouch for: exit 3, `idpd_untrusted`, nothing signed.
  Trust material that cannot be had is `trust_material_unavailable` as for `pki verify`.
- `--idp-unverified` skips the check (an IDP outside the TI PKI, e.g. a reference
  implementation): `verified` is false and `warnings` carries
  `idp_certificates_unverified`.
  SSO tokens and alternative authentication (pairing) are not implemented.

## Subsystem directory: the FHIR-Directory (VZD)

```sh
{bin} --format json directory login owner --env ref --p12 smcb.p12        # card via the IDP-Dienst
{bin} --format json directory login owner --env ref --card SMC-B-7
{bin} --format json directory login owner --env ref --regservice-token-path reg.jwt
{bin} --format json directory login search --env ref --p12 smcb.p12       # for the Search API
{bin} --format json directory login service --env ref --client-id ID --client-secret-path secret.txt
{bin} directory login holder --env ref --client-id ID --client-secret-path secret.txt --token
```

- `login` has one subcommand per Auth-Service endpoint of gemSpec_VZD_FHIR_Directory,
  named as the token's `iss` names it; every one ends in the directory's access token
  (an ES256 JWT) and the same report: `endpoint`, `method` (`card`, `regservice`,
  `client_credentials`), `access_token` (`Authorization: Bearer`),
  `token_type`, `expires_in`, `expires_at` (seconds since the epoch, local clock),
  `token` (the payload as decoded, not verified: `iss`, `sub`, `aud`, `scope`, `iat`,
  `exp`), `directory` (`base_url`, `endpoint_url`, `authorization_url`), and, where they
  apply, `idp`, `identity`, `challenge` (card) or `client_id` (client credentials), else
  null; `warnings` as for `idpd authenticate`. `--token` prints only the access token.
  Tokens are not cached: a bearer token is a secret, and the caller keeps it.
- `owner` with a card (`--p12`, `--cert --key`, `--card`): `GET /owner-authenticate`
  redirects to the IDP-Dienst authorization URL the directory made (its `client_id`,
  `scope`, `redirect_uri`, `state`, PKCE — opaque, passed on as is); the
  Authenticator-Modul flow of `idpd authenticate` runs for it; the IDP's redirect to
  `/signin-gematik-idp-dienst` answers with the token (24 h, `sub` the Telematik-ID). The
  redirects must stay between the directory and its IDP, or the flow stops before
  anything is signed (`directory_protocol`). The IDP's certificates are checked as for
  `idpd authenticate` (`--idp-unverified`, `idpd_untrusted`, `idp.certificates`).
- `search` (`--p12`, `--cert --key`, `--card`): the token for the Search API (`/search`)
  of an SMC-B or HBA. The directory issues a card identity no other: it is the owner
  token of the card flow above (`endpoint` is `owner`, `method` `card`), which also
  carries `owner:write`. `directory.search_url` is the Search API's URL; the warning
  `search_not_in_audience` says the token's `aud` does not name it. A RegService token
  or client credentials are not taken here; Fachdienste search with `service`.
- `owner --regservice-token-path FILE`: exchanges a TI-Messenger RegService-OpenID-Token
  (BP256R1, C.FD.SIG with role `oid_tim`) at `/owner-authenticate` as a bearer.
- `holder`, `service`, `ti-provider`: client credentials at the directory's Keycloak
  (realms `RSDirectoryAdministration`, `Service-Authenticate`, `TI-Provider`; Basic
  authentication), the Keycloak token exchanged at `/holder-authenticate`,
  `/service-authenticate`, `/ti-provider-authenticate`. `--client-id` or
  `TI_DIRECTORY_CLIENT_ID`; the secret only from a file, `--client-secret-path` or
  `TI_DIRECTORY_CLIENT_SECRET_PATH` (first line). Keycloak's refusal is exit 3,
  `directory_auth_server_error`, with its `error` and `error_description`.
- The directory is `--env` (`TI_ENV`; `prod`, `ref`, `test`, `dev` as ref; `auto` is
  exit 2): `fhir-directory[-ref|-tu].vzd.ti-dienste.de`, its IDP-Dienst, and Keycloak at
  `auth[-ref|-test].vzd.ti-dienste.de:9443`. Or `--url BASE` with `--idp-url` for a card
  and `--auth-url` for client credentials; a missing one is exit 2,
  `arguments_invalid`, before anything is sent.
- Exit 3 when the directory refuses: `directory_error`, the message carries the HTTP
  status, the directory's `message` and its `errors` (`attributeName: attributeError`);
  `directory_unreachable` when no answer came; `directory_protocol` when the answer is
  not what the specification says (a status without the directory's JSON document
  carries the body as text; `-vv` logs every non-2xx body). IDP failures keep their
  kinds (`idpd_*`). An identity the directory has no entry for is refused at the
  sign-in: HTTP 403 `Validation Failure: Unknown Telematik ID`.
- Not implemented: `/tim-authenticate` (a Matrix OpenID token), and the decoupled variant
  for the gematik Authenticator app: this tool is the Authenticator-Modul itself; an
  authorization URL from elsewhere is `idpd authenticate --auth-url`.

## Subsystem connector: the Konnektor

```sh
{bin} --format json connector configs                   # the .kon files; "selected" is the default
{bin} connector use praxis                              # select one for later commands
{bin} --format json connector config show [NAME]        # the .kon without its secrets
{bin} --format json connector config test [NAME]        # step by step to the cards; exit 1 if one fails
{bin} --format json connector config new NAME --url ADDRESS --env ru --mandant M --client-system C \
    --workplace W --basic USER --password-path FILE --pin-sha256 HEX   # tested, then saved 0600
{bin} --format json connector config set NAME workplaceId=W2     # members without secrets
{bin} --format json connector config edit NAME --p12 FILE --p12-password-path FILE   # new credentials
{bin} --format json connector config pin NAME --pin-sha256 HEX   # renew the pin
{bin} --format json connector -c praxis get info        # configuration and product
{bin} --format json connector get services              # "used": the versions this tool calls
{bin} --format json connector get cards
{bin} --format json connector get identities            # Telematik-IDs of HBAs and SMC-Bs
{bin} --format json connector get certificates CARD     # ECC and RSA, with PEM
{bin} --format json connector get status                # VPN and operating errors
{bin} --format json connector get expiration [CARD]
{bin} --format json connector describe card CARD          # with each PIN's status
{bin} --format json connector describe certificate CARD C.AUT   # as pki inspect
{bin} --format json connector verify certificate CARD C.AUT     # or --file; exit 0/1
{bin} --format json connector verify pin CARD [PIN]             # exit 0/1
{bin} --format json connector change pin CARD [PIN]
{bin} --format json connector sign FILE --card CARD            # CAdES → FILE.p7s; a PDF/A → NAME.signed.pdf (PAdES)
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
  (`$XDG_CONFIG_HOME` if set). The format is the one the former Go `ti` used, so its files
  keep working.
- A `.kon` file is JSON. With placeholders, as an agent may write one:

  ```json
  {
    "url": "https://konnektor.example:443",
    "mandantId": "MANDANT",
    "clientSystemId": "CLIENT-SYSTEM",
    "workplaceId": "WORKPLACE",
    "userId": "USER",
    "env": "ru",
    "credentials": {
      "type": "basic",
      "username": "${KON_USER}",
      "password": "${KON_PASSWORD}"
    }
  }
  ```

  `url`, `mandantId`, `clientSystemId`, `workplaceId` and `credentials` are required;
  `userId` is needed by some calls (with an HBA), `env` is `ru`, `tu` or `pu`.
  Credentials are `basic` (`username`, `password`), `pkcs12` (`data` the base64
  PKCS#12, `password`) for mutual TLS, or `none` for a Konnektor that does not
  authenticate client systems; a brainpool client key cannot be used.
  `trustStore` is a list of base64 DER certificates for the Konnektor's TLS (a CA is an
  anchor, an end-entity certificate a pin; empty: the system's roots), `expectedHost`
  the name its certificate must carry when it differs from the host in `url`,
  `rewriteServiceEndpoints: true` sends every service to the host of `url` (a Konnektor
  behind NAT or a port forward; without it, a service endpoint outside the origin of `url`
  or `expectedHost` is refused, error kind `connector_unsupported`, before anything is
  sent), `insecureSkipVerify: true` skips the server check (test
  Konnektors only). The message of `connector_config` lists every problem at once.
- `config test` runs the steps `file` (valid, mode 0600, secrets in plain text, an
  `https` url: the service directory is read over https only), `tcp`, `tls` (the
  server certificate against the pin or a CA of `trustStore`), `auth` (the client
  certificate before it is offered, and whether the Konnektor accepts the client), `sds` (product and service versions), `context`
  (GetCards with the call context) and `cards`; each finding is `ok`, `warn`, `fail` or
  `skip` with a `hint`, and a failed step skips the rest. With `env: pu`,
  `insecureSkipVerify` and credentials `none` fail; elsewhere they warn. It uses no PIN
  and no cache, so run it first when a connector command fails with `connector_config`
  or a transport error. With `-x`, `tcp` and `tls` are skipped.
- `config new`, `edit` and `pin` ask on a terminal; without one (as for an agent)
  every answer comes from an option, and a missing one is exit 2 naming it, never a
  wait. Run them with options only, and only when the user asks for a configuration.
  Secrets come from files (`--password-path`, `--p12-password-path`), never as values;
  `config set` takes no credentials. The server certificate is trusted only through
  `--pin-sha256` (the user read the hash from the Konnektor's management; never take it
  from the server you are pinning), `--pin-cert FILE` or `--insecure-skip-verify` (test
  Konnektors). `new` tests the file before saving it with mode 0600; a failed test saves
  nothing (exit 1) unless `--no-test`. `--rewrite-endpoints` for a Konnektor behind NAT.
  An `http` address is refused everywhere; with `env pu`, `new`, `set` and `edit` refuse
  `insecureSkipVerify` and credentials `none` (exit 2). A changed server certificate makes `config test` fail
  with `action: "renew_pin"`; `config pin NAME` renews it.
- `${NAME}` is expanded only in `credentials.username`, `.password` and `.data`, from
  the environment; anywhere else it is an error, and so is an unset variable, so a
  `.kon` file from someone else cannot send environment variables to its host. `-v`
  names the variables, never their values. Write credentials as `${…}` and tell the
  user which variables to set; never write real ones into a file.
- CARD is an ICCSN, a Telematik-ID (as in the card's C.AUT) or a card handle. Handles
  change when a card is re-inserted; prefer the ICCSN or the Telematik-ID.
- PIN is `PIN.CH`, `PIN.QES` or `PIN.SMC`; needed only for an HBA, which has two. PIN
  commands wait for the user at the card terminal: never run them unasked. A
  `REJECTED` result costs a try; `left_tries` says how many remain.
- `describe card` reads each user PIN's status without asking for it: `pins[].status`
  is the Konnektor's `VERIFIED` (no entry needed), `VERIFIABLE` (entry needed),
  `TRANSPORT_PIN` or `EMPTY_PIN` (set a PIN first), `BLOCKED` (unblock with the PUK) or
  `DISABLED`, with `left_tries`; a failed query leaves `status` null and sets `error`.
- SMC-KT, KVK and eGK are restricted on the Konnektor's SOAP API: calls about them fail
  with error kind `card_restricted`.
- A `connector_fault` keeps the Konnektor's code and text in its message. For faults
  about the information model of gemSpec_Kon the error's `hint` names the cause, the
  `.kon` fields concerned and where to fix it: 4004 to 4007 (unknown Mandant, client
  system, workplace, card terminal), 4010 to 4012 (not assigned to the Mandant), 4021
  (call context incomplete), 4053 and 4092 (no terminal local to the workplace, no
  Remote-PIN-KT), 4204 (client system not authenticated), 4060 and 4093 (terminal or
  card busy), 4263 (comfort signature switched off). The Konnektor's administrator
  fixes the information model; the user fixes the `.kon` file.
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
  sealed in the profile's state, so `comfort activate` needs a keyring
  (`{bin} profile create`); it is masked in `-vv`, and removed by `comfort deactivate`; deactivate it when the
  work is done. `--comfort-user-id` or `TI_COMFORT_USER_ID` supplies one instead.

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
  `noHealthRecord`), `directory` (the FHIR-Directory's `/owner-authenticate`, which
  without a token redirects to the IDP-Dienst; not followed), `catalog`
  (the TI platform's service-discovery `catalog.json`), `http` (any answer), `dns` (a
  TCP connection to a DNS server, `dns://IP`, port 53).
- The catalog's `service_instances` are probed too (`source: "catalog"`).
- Each probe has an `access` path: `ti-vpn` (only through a Konnektor's or TI-Gateway's
  VPN: `idpd-ti`, `erx`, `epa-1`, `epa-2`) or `internet` (`idpd-internet`,
  `fhir-directory`, `popp`, `catalog` and the catalog's instances). The text shows a
  block per path. `access_paths[].available` is false when every endpoint of a path
  failed; for `ti-vpn` that means no TI VPN, and the text says so once and grays the
  block. Names are lowercase kebab-case, `<service>-<n>` for numbered instances.
- `prod` also probes the Bestandsnetze of gematik's `Bestandsnetze.xml` (2.1.36) on the
  path `bestandsnetz`: networks the Konnektor routes into through the TI VPN when the
  practice booked them. Each is named by its lowercase ID (`snk` for KV-SafeNet) and
  checked through a known HTTPS host (`snk`: `portal.kv-safenet.de`, `orgti`), else
  with `dns` at its first DNS server. A Bestandsnetz that does not answer is `warn`,
  never `fail`, so it leaves the exit code at 0; the text lists those not routed on one
  line (`! not routed: kzvwl, demis, …`), with a row for each that answered.
- `TI_PROBE_ENDPOINTS_PATH` replaces the built-in list: a JSON object per environment
  of `{"name", "access", "kind", "url"}`.
- `status`: `ok` the expected answer, `warn` an answer but not the expected one (or no
  answer from a Bestandsnetz), `fail` no answer; `answered` is false for every transport
  failure; `detail` is `{kind} …` when ok (`oidc discovery`, `catalog, 6 instances`,
  `http 403`), otherwise the cause (`HTTP 404`, `issuer … differs`, `DNS lookup failed`,
  `timeout`, `connection refused`, `TLS error`). Hosts
  under `splitdns.ti-dienste.de` resolve only inside the TI.

