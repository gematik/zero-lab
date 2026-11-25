# Release Notes

# Release go/kv v0.7.0

Replicas that start together against an empty database all start, and the revocation sets zero-pep-proxy and zaddy
share. Verified on the release branch: `just check` across all Go modules passed; kv on Postgres (Postgres 18,
`TEST_DATABASE_URL`, with `-race`) passed on 2026-11-25.

### added
- `kv/revoked`: revocation sets shared between replicas over the store and the bus (TASK-313).

### fixed
- `postgres.Open` applies the schema in one transaction under an advisory lock. Before, two processes that opened
  the same database at the same moment raced on the schema: one failed with `duplicate key value violates unique
  constraint "pg_type_typname_nsp_index"` on an empty database, or with `deadlock detected` (TASK-423).

# Release go/zaddy v2.11.9-zero.1

zaddy is now versioned as the Caddy it builds with plus our revision (TASK-422): this is Caddy 2.11.9 with our
first revision on it, the image is `zero-caddy:2.11.9-zero.1`, and `zero-caddy` prints `2.11.9-zero.1`. Verified on
the release branch: `just check` across all Go modules passed; `govulncheck` reports no vulnerabilities.

### breaking
- The module path is `github.com/gematik/zero-lab/go/zaddy/v2` (TASK-422).
- The image tag is the version alone; `-caddy<version>` is no longer appended.
- A policy with a SessionCookie enforcer is refused at provisioning without `revocations_database_url` (TASK-313).
- `enforce_policy` refuses a non-canonical path and checks the DPoP `htu` against the path as received (TASK-359,
  TASK-360).

### added
- `revocations_database_url`: zaddy follows the revocations zero-pep-proxy shares over the kv store and bus, before it
  serves, and does not start when it cannot read them (TASK-313).
- The `protected_resource_metadata` handler serves RFC 9728 metadata from the `pep` block, with `scopes_supported` and
  `metadata_member`; every 401 names it in `resource_metadata` (TASK-379).
- Without `jwks_path` the authorization server's keys come from its RFC 8414 metadata through the egress client, read at
  start and refreshed every 15 minutes in the background, never on the request path (TASK-379).
- The egress client takes the forward proxy, with credentials from `egress_proxy_credentials_path` (TASK-407).

### changed
- Every access token names the resource and says it is one by its `typ` (TASK-366).
- OpenTelemetry 1.47.0, fixing GO-2026-6974 and GO-2026-6975 (baggage parsing reachable from every request; TASK-418).
- Every dependency at its latest version that builds with Caddy 2.11.9 (TASK-421). quic-go v0.63.0 and
  go.step.sm/crypto v0.91.0 stay: Caddy 2.11.9 does not build with their latest releases. The module needs Go 1.27.3
  (slackhq/nebula v1.12.0).
- pep, kv and egress are pinned at main a574be18 (pseudo-versions); their changes since go/pep v0.29.0 and
  go/kv v0.6.0 are not tagged yet, and egress has no tag.

# Release 2026-11-22: go/kv v0.6.0, go/dpop v1.0.0-beta.4, go/pep v0.29.0, go/pep/proxy v0.6.0

The request checks of servers.md rule 28 and the RFC 9700 findings of TASK-259 for the PEP, and key files read
once at start (servers.md rule 8). Verified for all four on main at da17652c:
- `just check` across all Go modules passed; `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- OpenID Federation (`just oidf-test`) against https://app-ref.federationmaster.de; kv on Postgres (Postgres 18,
  `TEST_DATABASE_URL`) and the revocations of zero-pep-proxy over Postgres (`PEP_PG_DSN`): all passed on
  2026-11-22.
- Live logins on zerobin with `spilikin/zero-pep-proxy:0.5.1-dev.aa2d9929` (main at aa2d9929, the code of this
  release): Techniker Krankenkasse RU2 (OpenID Federation, decoupled) and the gematik IDP-Dienst through the
  gematik Authenticator and the TI-Gateway, 2026-11-22.

# Release go/kv v0.6.0

### breaking
- `LoadKeyring` and `LoadKeychain` read their file once, at start, and no longer follow it; a changed file takes
  effect with a rollout (servers.md rule 8). `Current`, `Lookup`, `Entries`, `Revoked`, `Ready` and `NameKeys`
  do no file I/O (TASK-396).
- `WithKeychainCheck` is removed: it looked only at a changed file. A consumer holds the file it starts with
  against what is sealed through `Entries` and `Revoked`.

# Release go/dpop v1.0.0-beta.4

### added
- `IsToken68`: the token68 syntax of DPoP and Bearer credentials (RFC 9110 Section 11.2), for go/pep (TASK-353).

# Release go/pep v0.29.0

### breaking
- The Bearer enforcer refuses a sender-constrained token (any `cnf` member) with 401 `invalid_token`; an
  `any_of` of bearer and DPoP still admits it with its proof (TASK-365).

### security
- Bearer credentials are read as DPoP ones are: one `Authorization` header, the scheme in any case, token68
  within 16 KiB, else 400 before a token is parsed. An access token and a session snapshot are held to their
  size and compact form before they are parsed (servers.md rule 28, TASK-353).

# Release go/pep/proxy v0.6.0

### breaking
- A request whose `Host` is neither the host of `PEP_PUBLIC_URL` nor a name in the new `PEP_HOSTS` is answered
  421 before anything looks at it. A deployment whose front proxy sends another Host sets `PEP_HOSTS`
  (TASK-354).
- `/oauth2/start`, `/oauth2/sign_in` and the callback declare their parameters: 400 for one that occurs twice,
  an unknown one, an `rd` outside its grammar (a backslash or a control character included), an issuer the
  chooser does not list and a scope the backend was not configured with. The callback refuses a repeated
  parameter and ignores an unknown one. The shipped Caddyfile encodes the return-to (TASK-351).
- The gateway answers 400 to a path that is not canonical before any route matches; a prefix matches on a
  segment boundary only, and a non-canonical route prefix is refused at load (TASK-350).
- Key files are read at start (go/kv v0.6.0): rotating the session store key is a rollout.

### security
- A redirect login completes only in the browser that started it (RFC 9700 Section 2.1.1): a callback without
  the cookie of the session its `state` names is refused before the code is redeemed, and the session and its
  state are removed. Decoupled (OpenID Federation) and authenticator (idpd) logins are cross-device and
  complete without the cookie; `docs/DESIGN.md` §3 names the risk that remains and the mitigations in force
  (TASK-364).
- The first callback that names a state consumes it, whatever its outcome (RFC 9700 Section 4.2.4); every
  answer of the callback carries `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (TASK-369).
- The gateway removes the session cookie and the snapshot from what it forwards upstream and leaves the
  application's cookies as they came (RFC 9700 Sections 4.9 and 4.13, TASK-370).
- The request header is bounded at 64 KiB, and a session cookie that is not the 43 base64url characters the
  server sets names no session without the store being asked (TASK-354).

# Release go/kv v0.5.0

The keychain gets the format it is meant to keep, before anything but a test installation uses it (TASK-388),
and `Reseal` reaches the records of before the marks (TASK-387).

### breaking
- The keychain file has one format and the one of v0.4.0, taken from the notification service of ZETA Guard, is
  no longer read. A file states its `purpose`, its `entries` (`id`, `version`, `activeFrom`, `kekId`, the names
  of its `keys`, `wrapped`) and what is `revoked`. Everything an entry says is bound into its wrapping as
  associated data; before, only the id was, so an entry could be given another time.
- What is wrapped is a JSON object of named keys. Every entry has `seal`; `name` is optional, and the name key in
  force is that of the newest entry at or below the sealing one that has one.
- `ParseKeychain` and `LoadKeychain` take the purpose and refuse a file for another.
- `LocalKEK.Extend` makes a file or its next entry and replaces `NewEntry`.

### added
- `WithKeychainCheck`: a consumer looks at a changed file before its keys are taken, and refuses one that lacks
  an entry still needed. `Entries` and `Revoked` say what a file holds.
- `Marker.Marks`, `Resealer.SealedByKeys` and `Resealer.Mark`, for that check.

### fixed
- `Resealer.Reseal` also writes a record again when the current key sealed it but the store below marks it
  otherwise or not at all. Such a record was counted among the others in every walk and never marked, so a
  store that came from a version without marks never ran out of others (TASK-387).

### verified
- `just check` across all Go modules passed on 9e4530a8 (main), 2026-11-19; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (Postgres 18, `TEST_DATABASE_URL`) passed on the branches of pull requests 93 and 95, whose kv
  code is what main holds (3bd24153); it was not run again for the tag.

# Release go/kv v0.4.0

What a server needs to change the keys that seal its records without losing the records that outlive a key
(TASK-381). Nothing existing changes its signature, except that `postgres.Open` gains variadic options.

### added
- `Keychain`: a key ring of versioned entries (`<family>-v<N>`, `activeFrom`), each holding a key that seals and
  a key for names, wrapped together under a key-encryption key that an `Unwrapper` holds (servers.md rule 19).
  The file format is the keychain of the notification service of ZETA Guard. `LocalKEK` is the unwrapper for
  development. A keychain follows its file like `Keyring` and asks the key service only for new entries.
- `WithKeychainAgreement` and `Keychain.Ready`: an entry whose time has come is in force only when the caller
  says the replicas agree on it (servers.md rule 22).
- `Marker`: a store keeps a mark beside each record and finds the records with another mark or none.
  `NewMemory` has `WithMemoryMark`; a wrapping store over one without marks returns `ErrNotMarker`.
- `Resealer` on the store of `NewSealed`: `SealedBy`, `Reseal`, `Rename`, and over a marked store `Others` and
  `CountOthers`. `SealedMarker` and `WithSealedClass` make the mark of a sealed record the format of the seal,
  the ID of its key and a class the caller chooses.
- `NameKey`.

### changed
- `kv/postgres` keeps marks in two nullable columns, `mark` and `marked_at`, added without rewriting the table.
  A row written by a version before the marks counts as not marked.

### verified
- `just check` across all Go modules passed on f89259c5 (main), 2026-11-18; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (Postgres 18, `TEST_DATABASE_URL`) passed on the branch of pull request 91, whose kv code is
  what main holds (6caf44a6); it was not run again for the tag.

# Release go/oidf v0.54.2

### fixed
- `FetchSignedJwks` takes a signed key set that states no `exp`, which OpenID Federation 5.2.1 leaves optional;
  0.54.1 refused it, so no login could begin at a provider that publishes one, such as the reference IDP
  https://gsi-ref.dev.gematik.solutions (TASK-376). Such a key set is never kept in the document store: every call
  fetches it and verifies it with the keys of the provider's entity statement, so a replaced set is not served
  again. A key set that states `exp` is held to it as before, and the master's IdP list still has to state its
  `exp`.

### verified
- `just check` across all Go modules passed on 35375b02; `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
  The recipe loops had to be made to parse under macOS bash 3.2 first (TASK-377).
- The OpenID Federation suite (`just oidf-test`) and `TestNewAtALiveFederationMaster` passed against
  https://app-ref.federationmaster.de on 35375b02, 2026-11-18.
- The entity statement and signed key set of every provider on the IdP lists of
  https://app-ref.federationmaster.de (108) and https://app.federationmaster.de (119) were fetched and verified
  on 35375b02, 2026-11-18: all 227 passed. Two of them, both in the reference federation, state no `exp`:
  https://gsi-ref.dev.gematik.solutions and https://sidp-c01-ru.d-trust.net/realms/sidpdtr01.

# Release 2026-11-18: oidf and kv pinned to current modules

No code changes: each module's go.mod pins the current versions, so a build outside the workspace resolves the
same code the workspace tests.

## go/oidf v0.54.1

### changed
- Requires openid v0.55.1.

## go/kv v0.3.1

### changed
- Requires jackc/puddle v2.2.4 (indirect).

# Release 2026-11-17: errors without peer input (rule 14), mounted trust bundles, shared DPoP replays in zaddy, pkcs12 P12-041 parity

Errors refusing a peer's input name the field, a fixed reason, an HTTP status or a registered error code; they
no longer quote what the peer sent, nor the JSON decoder's message, which quotes member names and values
(TASK-337, servers.md rule 14). The decoder's error still unwraps, so `errors.Is` and `errors.As` work as before.
Apart from tipki's new package, idpd's BundleTrust and zaddy's new option, no exported API changes.

## go/brainpool v1.4.1

### fixed
- A refused JWK or token no longer names the key type, curve or alg it carried (TASK-337).

## go/tipki v0.33.0

### added
- `bundlefile` (TASK-289): the current TrustStore of a mounted trust bundle, plain or gzipped (one member, 16 MiB
  read and decompressed), read again when its content changes, so a ConfigMap's symlink swap is seen. A replacement
  that does not verify, is older or carries an older list never replaces the store in use, which stands until
  `fetched_at` plus 24 h or the list's NextUpdate. `New` fails when no valid bundle loads; `Current` never hands out
  an empty store.

### fixed
- A refused bundle or `roots.json` is not quoted, and a bundle too old is refused without its label (TASK-337).

## go/openid v0.55.1

### fixed
- ID token claims that do not decode are named, not quoted; a key set's server is named by its status code, not
  its reason phrase; an unknown issuer is not repeated (TASK-337).

## go/pep v0.28.1

### fixed
- A refused token's kid, alg and claims stay out of errors; each refusal names the claim or a fixed reason
  (TASK-337).

## go/pep/proxy v0.5.1

### fixed
- A refusal by the PAR, authorization or token endpoint names the endpoint, the status and a registered OAuth
  error code; the body, an unregistered code and `error_description` stay out of errors and the callback's log.
  Gateway claims and an undecodable OAuth error are named, not quoted (TASK-337).

## go/idpd v0.3.0

### breaking
- `NewBundleTrust` takes a `*slog.Logger`; `ClientConfig.Logger` is new; `BundleTrust` has `Close` (TASK-289).

### changed
- `BundleTrust` reads its bundle through `tipki/bundlefile`: gzipped bundles are accepted, the file is read again
  every minute, and a bad or missing replacement keeps the bundle in use until its age limit instead of refusing at
  once (IDPV-005, TASK-289).
- idpd logs nothing on the default logger (TASK-338): the PEM errors of `SignWithSoftkeyPEM` reach the caller
  through the signer, and the debug lines, one of them the whole discovery document, are gone.

### fixed
- An IDP-Dienst's error, in a body or a redirect, is named by its status and a numeric `gematik_code`;
  `error` and `gematik_error_text` stay in the fields (TASK-337).

## go/zaddy v0.9.0

### added
- `dpop_replays storage` in the global `pep` block (TASK-310): accepted DPoP proofs are kept in Caddy's configured
  storage, shared by every replica on the same storage, so a proof replayed at another replica is refused (RFC 9449
  §11.1). Each record is checked and written under its storage lock; any storage error refuses the proof (rule 16);
  expired records are swept every minute. Without the option replays stay in memory per replica, with a warning.

## go/epa v0.28.0

### changed
- `vau`: the IV's counter is written big-endian, as gematik lib-vau writes it (A_24628-01, TASK-346). Receivers
  read the IV from the record, so both orders interoperate.
- cloudflare/circl leaves go/epa: the Kyber tests decapsulate committed vectors made once with circl v1.6.5
  (TASK-349).
- The proxy's answers name an Aktensystem's errorCode again when I_Authorization_Service,
  I_Entitlement_Management or I_Information_Service register it, so a client tells a missing record from a
  missing entitlement or a locked account; another code is named generically, `errorDetail` never (TASK-337).

### fixed
- An Aktensystem's answers, VAU error messages, decoder messages and the KVNR stay out of errors and logs; a
  VAU error message is named by its code (TASK-337).

## go/pkcs12 v1.0.0-rc.5

### changed
- The P12-041 check of PrivateKeyInfo follows the rules now stated in spec/pkcs12 (TASK-334): OIDs of 1 to 39
  octets with minimal arcs of at most 2^32-1, parameters one DER element, a fixed set of universal types, depth
  64. A keyBag's segmented publicKey [1] is joined before the check (TASK-335).
- Refused now, as ti-pkcs12 refuses them (TASK-335): BIT STRING segments with more than 7 unused bits or unused
  bits without content, and non-minimal high tag numbers. Depth is counted per layer from the outermost element
  (P12-004).
- Go and Rust agree on the 62 check and 22 keyBag vectors in `spec/pkcs12/testdata/private-key-info.json`, which
  seed `FuzzCheckPrivateKeyInfo`, and on 300,000 mutated inputs.

## verified
- `just check` across all Go modules passed on 2f5a36fe and again on 34d7228e, the branch with TASK-289 and TASK-310 as merged (main 6c6c7a43 has the same Go code); there idpd's `mod-check` waited on the tipki tag with `bundlefile`, which `just sync` pins in this release. `go get -u` changed nothing in the modules released; `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- OpenID Federation (`TestFederation`, `TestNewAtALiveFederationMaster`) against app-ref, kv on Postgres 17.
- idpd: trust download (IDPV-007), IDP certificates with the exported reference bundle (IDPV-005), SMC-B login, on 2f5a36fe and again on ae88a976 with `bundlefile`.
- ePA connect at provider 1 and provider 2 with `EPA_VAU_CERT_VERIFY=enforce`. ePA entitlement passed, run by the maintainer on 2026-11-17.

# Release go/epa v0.27.0

### breaking
- `vau`: `Decrypt` and `DecryptResponse` take the request's counter, and a response carrying another request's
  counter is refused before decryption (`ErrResponseCounter`, A_24633, TASK-345). The minimum record length is
  72 bytes. `EncryptNestedResponseData` and `DecryptNestedRequestData` change with it.
- `vau`: CBOR is decoded strictly (TASK-344): a duplicate key, a key in another case, an unknown key in a message
  of fixed form, a tag, null (except `ocsp_response`, read as absent), trailing bytes and bodies beyond their bound
  (64 KiB per message, 128 MiB per response) are refused with sentinel errors that name at most a field.
  Unknown attributes of the server's keys and of error messages are ignored whatever they hold
  (A_24425-01, A_24635).

### security
- Kyber768 v3.02 is built on the standard library's `crypto/mlkem` and `crypto/sha3`; cloudflare/circl is
  only a test comparison (TASK-343, decision-18).
- Server key verification (TASK-342, A_24624) stays optional: off, warn or no verifier go on with one warning
  naming what was not checked or did not hold. With `enforce`, the handshake is refused before M3 for an
  empty or wrong `cert_hash`, expired keys, a missing, not good, older than 24 h or foreign-issued stapled OCSP
  response, a certificate the CertData CA did not sign, a profile other than `epa-vau-aut`, an environment
  other than the channel's, or a chain or signature the verifier refuses. The CertData fetch runs under the
  handshake's context with a bounded body. `OpenChannelContext` is new; `OpenChannelVerified` is unchanged.

### fixed
- Errors no longer quote a peer's key ID; a peer's error text is quoted and cut to 200 characters.

### verified
- `just check` across all Go modules passed on 951341fc; the merge onto main changed no Go code; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- ePA connect (`TestEPA_Connect/provider2`) against the reference environment passed on 951341fc in warn and in
  enforce mode, "VAU signed keys verified"; ePA entitlement (`TestEPA_Entitle/provider2`) in enforce mode passed,
  run by the maintainer on 2026-11-16. Provider 1 was not tried.

# Release go/oidf v0.54.0

### breaking
- One configuration type for YAML and JSON: `FileConfig` and what it holds carry json tags with the names of the
  yaml ones, so a program reads a relying party from either format (TASK-341).
- The names change in both formats: `sub` is `entity`, `fed_master_url` is `master`,
  `fed_master_entity_statement_uri` is `master_entity_statement_uri`. A file with the old names is refused at
  start as one with an unknown field.
- `fed_master_jwk` is gone: `master_jwk_path` names a file with the master's JWK as JSON, which the host reads
  like the relying party's keys and hands over as `Keys.Master`. `Jwk.UnmarshalYAML` is removed.

### verified
- `just check` across all Go modules passed on 0faf2a6f; the merge onto main changed no Go code. `api-lint` was
  skipped without `GEMATIK_API_TOOLS_DIR`.
- The OpenID Federation suite and `TestNewAtALiveFederationMaster` passed against
  https://app-ref.federationmaster.de on 4e8d7ee9, 2026-11-16.

# Release go/pep/proxy v0.5.0

### breaking
- zero-pep-proxy reads the relying party with oidf v0.54.0's names (`entity`, `master`,
  `master_entity_statement_uri`, `master_jwk_path`); configurations with the old names are refused at start and
  must change with this image (TASK-341). zero-lab-k8s `values-pep.yaml` changes with it.

### verified
- As go/oidf v0.54.0; kv on Postgres (Postgres 17) passed on 4e8d7ee9.

# Release go/metsubushi v0.3.1

### fixed
- `GET /` answers curl and programs with the request echoed back, as `/api/anything` does: method, URL,
  query arguments, every header and the client address, so a smoke test behind the PEP sees the headers it
  added. 0.3.0 answered with the pod info of `/api/info` (TASK-340).

### verified
- `just lint golangci modernize test` for metsubushi; a test checks the echoed header and query argument.

# Release 2026-11-15: encoding/json/v2 across the Go modules

Every module below reads and writes JSON with encoding/json/v2 and requires go 1.27.0 (TASK-323). Where
JSON comes from outside, a member named twice, a member name in another case and invalid UTF-8 are refused,
where v1 kept the last duplicate, folded case and replaced bad bytes (servers.md rule 28). Formats that are
ours refuse unknown members; someone else's (OAuth, OIDC, JOSE, gematik's) still ignore them. Signed, hashed
and compared output is written with sorted members and stays byte-identical to v1's; `<`, `>` and `&` are no
longer escaped in other output, which is the same JSON. go/pdp stays on v1 and is not released: zeta-pdp-go
replaces it.

Verified for all of them, on main at 38962403 (code identical to 8c7d770b):
- `just check` across all Go modules passed on 8c7d770b; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. Dependencies were bumped and tidied on 62a5f58a; nothing newer since.
- OpenID Federation (`just oidf-test` and `TestNewAtALiveFederationMaster`) against
  https://app-ref.federationmaster.de; kv on Postgres (Postgres 17); idpd SMC-B, idpd IDP certificates
  (against a reference bundle from `ti pki trust export --env ref`) and idpd trust download; ePA connect
  against provider 2 of the reference environment (VAU, authorization, record status, consent): all passed
  on 2026-11-15. Provider 1 was not tried. ePA entitlement was waived by the maintainer: it needs the VSDM
  key, and connect already shows the Aktensystem's answers decoded under exact member names.

# Release go/openid v0.55.0

### breaking
- `Login.Claims` is a `jsontext.Value` (was `json.RawMessage`).
- `providers` no longer logs the providers it builds; the host logs them (TASK-332).

### changes
- encoding/json/v2: `TokenResponse.Claims` refuses a member twice, invalid UTF-8 and names in another case.

# Release go/oidf v0.53.0

### breaking
- The `Extra` maps of `Metadata`, `OpenIDRelyingPartyMetadata` and `FederationEntityMetadata` hold
  `jsontext.Value` (was `json.RawMessage`).

### changes
- encoding/json/v2; the signed entity statement and signed JWKS are written with one set of options, sorted
  and escaped as before, and a test pins their bytes.

# Release go/dpop v1.0.0-beta.3

### security
- A proof whose header or payload names a member twice, or is not UTF-8, is refused
  (`invalid_dpop_proof`); before, a claim named twice in the payload was accepted with the last value. Member
  names match exactly.

### fixed
- `WriteTokenError` answers when a description is not UTF-8, where it would have panicked under v2.

# Release go/nonce v0.24.0

### changes
- go 1.27.0.

# Release go/kv v0.3.0

### changes
- go 1.27.0.

# Release go/brainpool v1.4.0

### changes
- encoding/json/v2: JWKs and tokens refuse a member twice, invalid UTF-8 and names in another case; JOSE
  headers and claims are written with sorted members, as before. go 1.27.0.

# Release go/pkcs12 v1.0.0-rc.4

### changes
- go 1.27.0; the conformance corpus is read with encoding/json/v2.

# Release go/tipki v0.32.0

The first tag since v0.31.1, carrying the TLS checks, the trust download and the OCSP responder rules
(TASK-288).

### breaking
- OCSP asks only about the end entity, and a responder is trusted as TUC_PKI_006 says: one only the
  verified TSL names is accepted as `tsl_listed` with the warning `ocsp_responder_not_rfc6960`.
  `SkipSubCARevocation` and `ResponderAuthorization.CA` are gone (TASK-270).
- The warning `issued_before_ca_expiry` is `ca_expired` (TASK-270).

### added
- `titls`: the ti profile's TLS server check (spec/pki-validation), a web profile, a `tls.Config` per
  profile, a bounded verdict cache, and `NewWebHTTPClient` for hosts (TASK-98). The web profile accepts RSA
  2048 to 2999 bits with `key_phased_out` and a missing revocation status with `revocation_unavailable`,
  and does not reuse such a verdict (TASK-282).
- `fetch`: TSL download and refresh for every environment (TASK-98.4).
- `OCSPChecker` bounds its result cache and the responders it rests (TASK-234).

### changes
- A path that cannot be built is `chain_incomplete` whatever its links are signed with (TLSV-020, TASK-233).
- encoding/json/v2: the bundle reader still refuses unknown members and now names no member it refuses;
  roots.json, gematik's format, ignores unknown members.

# Release go/idpd v0.2.0

### breaking
- `NewClient` takes the host's HTTP client; there is no default (TASK-98.5).
- The IDP-Dienst kind no longer logs the providers it builds; the host logs them (TASK-332).

### changes
- The TLS to the IDP-Dienst is checked on the web profile, and trust material can be downloaded with
  `tipki/fetch` (TASK-98).
- encoding/json/v2: a response is exactly one JSON value; a member twice and invalid UTF-8 are refused.

# Release go/epa v0.26.0

### breaking
- An Aktensystem is reached only under a configured TLS verification; zero-epa uses the ti profile over its
  own TSL (TASK-98.5). Configuration such as `EPA_TI_BIN` is read in `cmd/` and handed in (TASK-89).

### added
- VAU-nonPU-Tracing outside production, and no plaintext in the request log (A_24477, A_27671, TASK-216).

### changes
- encoding/json/v2. The Aktensystem's answers are read within 1 MiB; the entitle body within 256 bytes,
  unknown members refused. An Aktensystem error page that is not UTF-8 keeps the proxy's answer JSON.

# Release go/pep v0.28.0

### breaking
- Enforcer policies (also zaddy's configuration) refuse unknown members, so a misspelled member stops the
  start instead of being ignored.
- Without `WithSlogger` nothing is logged; the enforcers log through the context's logger (TASK-332).

### security
- Access token claims and JWK sets refuse a member twice, nested ones too, and invalid UTF-8; a token with
  `exp` twice is refused. Session cookie claims refuse unknown members.

# Release go/pep/proxy v0.4.0

### breaking
- `Config.Logger` and `PDPConfig.Logger` receive the proxy's events; nil logs nothing, where the default
  logger was used (TASK-332). zero-pep-proxy passes its logger and logs the configured providers itself.
- Session records refuse unknown members; records written before still open. A later new member needs a
  staged rollout, or older replicas treat those sessions as absent.

### fixed
- A return target that is not UTF-8 falls back to `/` instead of failing the login start.
- `writeJSON` answers 500 when a value cannot be encoded, instead of an empty body.

# Release go/zaddy v0.8.0

### changes
- Caddy v2.11.9; pep v0.28.0, so the enforcer configuration refuses unknown members.

# Release go/metsubushi v0.3.0

### added
- `GET /` answers the `/api/info` JSON unless `Accept` names `text/html`, which gets the page; both carry
  `Vary: Accept` (TASK-336).

# Release go/pdp v0.24.0

### breaking
- `authzserver.NewFromConfigFile` is gone; `New` always refused what it built (TASK-312).
- `Config.OIDFKeys` loads the relying party's keys: zero-pdp reads one PEM key per file
  (`key_pem_path`, `cert_pem_path`); an inline `jwk`, a `jwk_path` and RSA keys are refused at start
  (TASK-317). `Config.OIDFDocuments` keeps the federation's signed documents, in zero-pdp the kv
  store (TASK-293).
- The entity statement must carry what gemSpec_IDP_FD Tabelle 4, A_27505 and A_27585 require of a
  relying party (`organization_name`, `keywords`, `contacts`, `ti_features_supported`, https
  redirect URIs); the start stops when it cannot be signed (TASK-315).

### fixed
- A pushed `request_uri` and an authorization code are good once, also across replicas (TASK-316).

### changes
- Dependencies bumped: go-jose v4.1.9, go.yaml.in/yaml/v4 v4.0.0, pgx v5.13.0, golang.org/x
  crypto v0.59.0, sync v0.25.0, text v0.44.0; openid v0.54.0, oidf v0.52.0.

### verified
- `just check` across all Go modules passed on 62a5f58a, with zaddy's bump checked on its own
  (lint, vuln, tests); `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (`go test ./kv/postgres`, Postgres 17) passed on 51a0bb83.
- PDP end to end (`just pdp-e2e`) passed on 51a0bb83 against a local zero-pdp: 9 passed; federation
  PAR, cross-client introspection and the entity statement checks skipped for lack of their
  variables. The two entity statement checks passed against a zero-pdp with a federation
  configured (the reference federation's relying party `directory-ref`).
- PDP HITL was waived by the maintainer on 2026-11-15. The federation login leg, oidf v0.52.0, passed
  live through TK RU2 in zero-pep-proxy v0.3.0 on zerobin; zero-pdp's own login was not run.

# Release go/pep/proxy v0.3.0

### breaking
- The relying party's key files hold one PEM key each (`key_pem_path`, `cert_pem_path`); an inline
  `jwk` or a `jwk_path` is refused at start, and so is an RSA key (TASK-317).
- The entity statement must carry what gemSpec_IDP_FD Tabelle 4 and A_27505 require of every
  relying party: `organization_name`, `keywords` with `product_type:` and `product_type_version:`,
  `contacts` and `ti_features_supported`; every `redirect_uris` entry is https without query or
  fragment (A_27585). A configuration without them is refused at start (TASK-315).

### added
- The federation's signed documents are kept in the PEP's kv store, so replicas share them; each is
  verified again when read (TASK-293).
- Only IDPs on the federation master's list are resolved, and the ID token is judged by `acr`,
  `amr` and the claims asked for (oidf v0.52.0).

### verified
- `just check` across all Go modules passed on the branch merged at d8f24089; later commits change
  only go.mod pins and the backlog. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The OpenID Federation suite (`just oidf-test`) passed on 2026-11-15 against
  https://app-ref.federationmaster.de, on 51a0bb83.
- kv on Postgres (`go test ./kv/postgres`, Postgres 17) passed on 2026-11-15, on 51a0bb83.
- A live login through TK RU2 (decoupled) passed on 2026-11-15 on zerobin, image
  `spilikin/zero-pep-proxy:0.3.0-dev.51a0bb8`.

# Release go/oidf v0.52.0

### breaking
- `New(ctx, cfg, keys)` builds the relying party from `Keys`: a `crypto.Signer` for the federation
  key, a `KeyAgreement` (ECDH) for the ID token key and a `tls.Certificate` for mutual TLS, each
  P-256 with its kid. The library reads no file: `NewRelyingParty` and `KeyConfig` are gone, and
  `Kind(apiKey, documents, keys, built)` takes the host's key loader for `KeyFiles` (TASK-315,
  TASK-317).
- Every fetch takes a context: `NewOpenidFederation`, `FetchIdpList`, `FetchEntityStatement` and
  `FetchSignedJwks` take it first.
- `RelyingPartyConfig.Documents` is required: a store of the federation's signed documents, which
  the host wires (`MemoryDocuments` for tests and a single replica) (TASK-293).
- `AddEntityStatementHook` takes a hook that returns an error; a failing hook fails signing.
- The statement's required members (Tabelle 4, A_27505, A_27585) are refused when missing, and so
  is a gated development master without an API key (`ErrAPIKeyRequired`, TASK-322).
- `CodeChallengeMethod` and `OpenidProvider` are gone.

### added
- `RelyingParty.Client(ctx, issuer)` admits only IDPs on the federation master's signed list
  (A_25449), before any request to the issuer; `ExchangeIdentity` returns an `Identity` and refuses
  a lower `acr` than asked, a missing `amr` and missing essential claims (A_28484, A_22860-02).
  `Identity` and `Personal` redact the personal claims in `fmt` and `slog`.
- An unknown kid or ID token version refetches the IDP's statement once, rate-limited (A_22861).
- The entity statement is signed once and served as bytes, with ETag, `If-None-Match` and
  `Cache-Control`; it is signed again after an hour or on `Refresh(ctx)` (A_28857).
- Every value sent to or received from an IDP is checked against its grammar first and refused,
  never repaired (servers.md rule 28, TASK-320); fuzz targets cover each entry point.
- `oidftest`, an in-process test federation with a master and one IDP; `just mod-check` keeps it out
  of non-test packages.

### verified
- `just check` across all Go modules passed on the branch merged at d8f24089; later commits change
  only go.mod pins and the backlog. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The OpenID Federation suite (`just oidf-test`) and `TestNewAtALiveFederationMaster` passed on
  2026-11-15 against https://app-ref.federationmaster.de, on 51a0bb83.
- A live login through TK RU2 passed on zerobin on 2026-11-15 (see go/pep/proxy v0.3.0).

# Release go/openid v0.54.0

### breaking
- `AuthorizationQuery` returns an error: `Login` carries per-login `Scopes`, `ACRValues` and the
  OIDC `Claims` request parameter, which are checked before they are sent (TASK-296).
- `NewClient` and `FetchDiscoveryDocument` take a context first.
- JSON from the network is read with encoding/json/v2 under size, depth and member limits;
  duplicate members and invalid UTF-8 are refused (servers.md rule 28, TASK-320).

### added
- `IDTokenChecks.ACRValues`: the plain OIDC client refuses an `acr` it did not ask for
  (`ErrACRNotRequested`, TASK-318).
- `CheckAuthorizationCode`, `CheckProtectedHeader`, `ParseErrorResponse`, `UnmarshalObject` and
  `CheckJSONObject` for hosts that check what they receive.

### fixed
- The ID token check logs nothing through the default logger (TASK-317).

### verified
- `just check` across all Go modules passed on the branch merged at d8f24089; later commits change
  only go.mod pins and the backlog. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The development guide lists no gated suite as required for `openid`; its use by oidf passed the
  live runs listed there.

# Release go/pkcs12 v1.0.0-rc.3

### changes
- A decrypted or plain key bag yields a key only when it is one DER PrivateKeyInfo (RFC 5958); BER
  inside a key bag is normalised to DER first (spec/pkcs12 P12-041, TASK-326). A wrong password on a
  file without MAC no longer returns a key by chance; it fails as a wrong password does with a MAC.
  Both `pkcs12.Decode` and `legacy.Decode` hold to it.

### verified
- `just check` across all Go modules passed on the branch merged at d8f24089; later commits change
  only go.mod pins and the backlog. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- `spec/pkcs12/interop/run.sh` on 2026-11-15, OpenSSL 4.1.0: `pkcs12.Decode` 30 of 30,
  `legacy.Decode` and `ti-pkcs12` 61 of 61, all compared in full.
- The development guide lists no gated suite as required for `pkcs12`.

# Release go/pep/proxy v0.2.1

### fixed
- Gateway routes with `gate: snapshot` ask `Revocations`, as `/oauth2/auth` does: a session that was
  signed out or rotated no longer passes them until its snapshot expires (8 h by default), and a
  revocation check that fails denies. A snapshot route without revocations is refused at start
  (TASK-311).

### verified
- `just check` across all Go modules passed on 889847b6 (the branch merged with main); later
  commits change no Go code. `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- Revocations reaching another replica over Postgres (`PEP_PG_DSN`) passed on db34b723 for v0.2.0;
  this release does not change the revocation store or the bus.

# Release go/dpop v1.0.0-beta.2

### breaking
- `ReplayCache` is `Replays`, `MemoryReplayCache` is `MemoryReplays`, `NewMemoryReplayCache` is
  `NewMemoryReplays`, `ErrReplayCacheFull` is `ErrReplaysFull` and `Config.Replay` is
  `Config.Replays`: an entry lost before it expires lets a proof through twice, so it is no cache
  (TASK-309).
- `Replays.Seen`, `NonceSource.Valid` and `NonceSource.Fresh` take a context and return an error,
  so they can be kept in a store; `Verifier.Verify` takes the request's context first and passes it
  on. An error from either refuses the proof.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.

# Release go/nonce v0.23.0

### breaking
- `Record` is the interface `Redemptions`; its `Seen` reports true for a nonce redeemed before, as
  `dpop.Replays` does, and `New` takes it (TASK-309).
- `Source.Valid` and `Source.Fresh` take a context and return an error, to meet the new
  `dpop.NonceSource`.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.

# Release go/kv v0.2.0

### breaking
- `ReplayCache` and `NewReplayCache` are gone: kv holds nothing of dpop. A host builds its replays
  on `SetIfAbsent`, as zero-pdp does (TASK-309).

### added
- `WithSealedExpiry` seals each record with the time it ends (record format 2), so that whoever
  can write to the store cannot extend a record or put back a deleted one beyond its own lifetime;
  records of format 1 still open (TASK-304).
- `Swapper` replaces a value only while it is still the one a caller read, in memory, Postgres and
  through `NewSealed` (TASK-305).

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (`TEST_DATABASE_URL`, postgres:18-alpine) passed on db34b723.

# Release go/pep v0.27.0

### breaking
- `WithDPoPReplayCache` is `WithDPoPReplays`, and `Build` refuses a builder without it: the host
  picks the backend, `dpop.NewMemoryReplays` for a single replica (TASK-309).
- On the new dpop: nonce sources and replays receive the request's context.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (`TEST_DATABASE_URL`, postgres:18-alpine) passed on db34b723.
- The OpenID Federation suite was waived by the maintainer: this release changes no federation code.

# Release go/pdp v0.23.0

### breaking
- `authzserver.Config` takes `Sessions`, `NonceRedemptions` and `Replays` in place of `Store`, and
  `New` refuses a configuration without them or `NonceKeys` instead of keeping them in its own
  memory; `authzserver` imports no kv (TASK-306). `ErrSessionNotFound` and `DefaultSessionTTL` are
  exported for session stores.
- zero-pdp builds the kv-backed sessions, nonce redemptions and DPoP replays over its one store,
  under the keys used before; without `DATABASE_URL` that store is in memory, with the warning as
  before.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- kv on Postgres (`TEST_DATABASE_URL`, postgres:18-alpine) passed on db34b723.
- PDP end to end (`just pdp-e2e`) passed on db34b723 against a local zero-pdp on a sealed Postgres
  store; federation PAR, cross-client introspection and the entity statement checks skipped for
  lack of their variables. PDP HITL was waived by the maintainer: this release rewires the stores
  and changes no login code.

# Release go/pep/proxy v0.2.0

### breaking
- `Config` takes `Sessions` (a `SessionStore`) and `Revocations` in place of `Store` and `Bus`, and
  `New` refuses a configuration without either instead of keeping them in its own memory;
  `pep/proxy` imports no kv (TASK-307). `ErrSessionNotFound`, `LoginStateTTL` and
  `DefaultSnapshotTTL` are exported for the stores, `MemoryRevocations` and
  `NewMemoryRevocations` for a single replica.
- `Revocations` take a context and return an error; an error from `Revoked` denies the request.
  A revocation holds until the time its snapshot would expire.
- zero-pep-proxy builds the kv-backed sessions and revocations over its one store and bus, under
  the keys and channel used before; without `DATABASE_URL` the revocations are in memory, with a
  warning. It refuses to start when it cannot subscribe to the revocations or load the stored
  ones, where it logged and went on before.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- Revocations reaching another replica over Postgres (`PEP_PG_DSN`) passed on db34b723.

# Release go/zaddy v0.7.0

### changes
- zaddy chooses DPoP replays in memory itself, as pep did before, and warns at start that replay
  detection holds for this replica only (TASK-309).
- zaddy reads its DPoP nonce key file itself, once at provisioning, in the format of kv's keyring,
  and no longer requires kv (TASK-308). A rotated file takes effect with `caddy reload --force`, no longer
  while running. A malformed line, a key not of 32 bytes, a duplicate or invalid ID, or an empty
  file refuses provisioning.

### verified
- `just check` across all Go modules passed on db34b723; later commits change only release notes and
  go.mod pins. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.

# Release go/oidf v0.51.0

### breaking
- The federation API key comes from `api_key_path` in the relying party configuration; the
  `API_KEY` environment variable is no longer read (TASK-195). `AddAPIKeyTransport` takes the key as
  an argument, and `WithAPIKey` is new.
- The key goes only to https hosts below `.dev.gematik.solutions`; `xdev.gematik.solutions` and
  plain http no longer get it.

### fixed
- Mutual TLS keeps the base client's root certificates and minimum TLS version, where it fell back
  to the system's.
- ID tokens are bound to the login by their nonce, and the issuer of ID tokens and entity statements
  is checked; https is required, redirects are refused, reads are bounded, and a signed JWKS needs
  `exp` (go consolidation, PR #86).
- Federation member keys and ID token keys that state no `alg` are accepted, as RFC 7517 allows:
  T-Systems' IdPs in the reference federation publish theirs so. The trust anchor still has to state
  it.

### changes
- go-jose instead of jwx; `go/oauth` is now `go/openid`.

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The OpenID Federation suite (`just oidf-test`) passed on 2026-11-05, run by the maintainer.

# Release go/idpd v0.1.0

The first release under this name: the relying party of the gematik IDP-Dienst, formerly the
untagged `go/gemidp`.

### features
- The IDP-Dienst's certificates are verified: the discovery signer before its key is used, and
  `PuK_IDP_SIG` on every fetch, with the idpd-sig profile and hard-fail OCSP, against the bundle
  `ti pki trust export` writes (`trust_bundle_path`) or material it downloads itself
  (`trust_fetch`). There is no client without trust material (TASK-171, TASK-176, TASK-190).
- The signed discovery document must name the IDP asked as its issuer (TASK-194).

### changes
- Renamed from gemidp everywhere an operator sees it: the `idpd:` YAML key, `PEP_IDPD_*`, `IDPD_*`
  in the gated tests and `/idpd-callback`.

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The idpd suites passed on 2026-11-05, run by the maintainer: the IDP certificates, the trust
  download and the SMC-B login.

# Release go/pep v0.26.0

### breaking
- go-jose instead of jwx: verification is stricter. A token with no `alg`, one whose `alg` differs
  from its key's, HS256 with an oct key in a set, `crit` headers and nested JWS are refused.
- `pep` depends on `dpop` alone; DPoP is RFC 9449 on go-jose (TASK-95).

### features
- Resource server DPoP nonces: `Builder.WithDPoPNonces` makes an `authorization_dpop` enforcer with
  `nonce_required` check them, answer 401 `use_dpop_nonce` with a `DPoP-Nonce`, and hand out the
  next nonce on success (RFC 9449 Sections 8 and 9, TASK-131). Without a source, `nonce_required`
  still refuses with `internal_error`.
- `WithDPoPReplayCache` takes a replay cache the replicas share.

### fixed
- An invalid token is answered 401; no secret, token or session ID reaches a log (TASK-185).

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The OpenID Federation suite (`just oidf-test`) passed on 2026-11-05, run by the maintainer.

# Release go/pep/proxy v0.1.0

The first release of the reverse proxy and forward-auth gate, `zero-pep-proxy`, now its own module.

### features
- Logins at OpenID Connect providers, the gematik IDP-Dienst (`PEP_IDPD_*`) and OpenID Federation
  (`PEP_OIDF_RP_CONFIG_PATH`), with sessions in a sealed kv store (`PEP_SESSION_STORE_KEY_PATH`).

### security
- Browsers see generic text for failed logins, and the detail goes to the log with the request's
  code and state removed; an identity provider's error is no longer reflected (TASK-193).
- The login state is kept under a hash in the store (TASK-106).
- Every server bounds slow clients (10 s header, 120 s idle) and drains for up to 25 s on SIGTERM.

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The development guide lists no gated suite as required for `pep/proxy`.

# Release go/zaddy v0.6.0

### features
- DPoP nonces for `nonce_required`, sealed under the keyring `dpop_nonce_keyring_path` names in the
  `pep` block, or under a key of the process alone, with a warning (TASK-131).

### changes
- On `pep` v0.26.0: go-jose instead of jwx, stricter token verification.

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- The development guide lists no gated suite as required for `zaddy`.

# Release go/epa v0.25.0

### breaking
- zero-epa takes its settings from flags; viper's undocumented `PDP_` environment prefix is gone.
  `zero-epa version` is gone; the portal shows the version.
- Proxy names are limited to `A-Z a-z 0-9 . _ -`, and an empty `proxies` list is refused.
- The image runs as `65532:65532`; a volume over `/var/cache/ti` needs `fsGroup` 65532 (TASK-197).

### security
- Only the known providers are reached: another number is 404 before any login (TASK-181).
- No panic or exit on hostile VAU messages; forwarded bodies are closed (TASK-188).
- The entitlement JWT, headers, the authorization and code URLs and KVNRs stay out of the proxy's
  log, and `zero-epa config` prints secrets redacted (TASK-185).
- A production channel carries the production environment byte (TASK-180).
- One provider's slow login no longer holds the others (TASK-203).

### changes
- http.ServeMux instead of echo, explicit configuration validation instead of validator, slog
  instead of console-slog, go.yaml.in/yaml/v3 only; go.mod keeps 4 indirect dependencies of 27
  (TASK-91 to TASK-94).

### verified
- `just check` across all Go modules passed on 8d8ccc7; later commits change only go.mod pins and
  Rust. `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`.
- ePA connect and ePA entitlement passed on 2026-11-05, run by the maintainer; the image ran a
  probe against dev as the non-root user (TASK-197).

# Release go/openid v0.53.0

### breaking
- Discovery is https only: an issuer, or an authorization, token, JWKS, userinfo or revocation
  endpoint in the discovery document, that is not an https URL is refused (OpenID Connect Discovery
  1.0 section 3, TASK-194). A local provider over plain http no longer works.

### verified
- `just check` across all Go modules passed on 8d8ccc7; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for this module.

# Release go/metsubushi v0.2.2

### changes
- Built with golang:1.27, as `go.work` requires; lint findings cleared. No behaviour change.

### verified
- `just check` across all Go modules passed on 8d8ccc7; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for this module.

# Release go/pkcs12 v1.0.0-rc.2

### changes
- One decode spends at most 10,000,000 iterations on key derivation, all its derivations
  together: the MAC and each PBKDF2 once, each PKCS#12 PBE twice (key and IV), checked before each
  derivation (spec/pkcs12 P12-036, TASK-158). A crafted file of many bags no longer costs
  10,000,000 iterations per bag; it fails with `ErrLimitExceeded`. Both `pkcs12.Decode` and
  `legacy.Decode` keep one budget per call, and `VerifyMAC` one of its own. Producers use at most
  102,400 per count, so ordinary files are far below the budget.

### verified
- `just check` across all Go modules passed on ee1439e, which holds this change; `api-lint` was
  skipped without `GEMATIK_API_TOOLS_DIR`.
- `spec/pkcs12/interop/run.sh` on 2026-11-05, OpenSSL 4.1.0: `pkcs12.Decode` 29 of 29,
  `legacy.Decode` and `ti-pkcs12` 57 of 57, all compared in full. OpenSSL, pyca/cryptography 50.0.2
  and the JDK decode the new over-budget case, as they have no such budget.
- The development guide lists no gated suite as required for `pkcs12`.

### known limits
- `PFX`, `ContentInfo`, `MacData` and `DigestInfo` are aliases of an internal package, and their
  identifiers stay `asn1.ObjectIdentifier`.
- Keys and passwords are not wiped from memory, unlike `ti-pkcs12`.

# Release go/kv v0.1.0

### breaking
- `Store` gains `SetIfAbsent`, and loses `GetItem`; `Item` and `Entry.Metadata` are gone. The Postgres
  column stays, so that older replicas keep working during an upgrade.

### features
- `NewSealed` encrypts and authenticates every value, bound to its key, purpose and key ID, with key IDs
  for rotation without a restart; `Keyring`, `ParseKeyring` and `LoadKeyring` hold the keys.
- `ReplayCache`, and `Reap` to run `Cleanup` at an interval.

### verified
- `just check` across all modules passed on be5aceb; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- The Postgres suite passed on 2026-11-03 against a throwaway `postgres:17-alpine`: 12 tests.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/nonce v0.22.0

### breaking
- Nonces are sealed values with an expiry, so issuing one writes nothing. `Service` is now a type made by
  `New`, and `Redeem` takes a context. `NewKVService`, `HashicorpNonceService` and `Options` are gone.
- Single use holds through a `Record` on acceptance, and a store outage fails closed.

### features
- `Source`, from `NewSource`, for nonces that are only checked for validity, and `NewEphemeralKeys`.

### verified
- `just check` across all modules passed on be5aceb; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `nonce`.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/openid v0.52.0

The first release of `go/openid`, which takes over from `go/oauth`, whose last tag is v0.51.0 and stays
resolvable. The number continues from it.

### breaking, for a port from go/oauth
- A new module path: the `oidc` package is the root of `go/openid`, with the PKCE and assertion names in
  it, and `oauth/providers` is `openid/providers`. The `oidc` provider type and YAML key stay.
- JOSE is go-jose, not jwx, so keys in the API are `jose.JSONWebKey` and `jose.JSONWebKeySet`.

### verified
- `just check` across all modules passed on be5aceb; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `openid`.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/tipki v0.31.1

### changes
- Requires `go/brainpool` v1.3.0 by its tag instead of a pseudo-version. The code is that of v0.31.0.

### verified
- `just check` across all modules passed; `api-lint` was skipped without `GEMATIK_API_TOOLS_DIR`. The
  development guide lists no gated suite as required for `tipki`.
- `just idpd-trust-fetch-test` and `just idpd-smcb-test` failed on 2026-11-03: the reference OCSP
  responder answers unknown for the IDP's `disc.ru.idp` certificate. c736b56, on which both passed
  earlier that day, now fails the same way, so this is not this release's doing.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/pkcs12 v1.0.0-rc.1

The release candidate for a stable API. The exported names are pinned by a test, so adding one is a
decision, and `pkcs12` is an active module again. Open before v1.0.0: see known limits.

### breaking
- Removed from `pkcs12`: `ParseAuthenticatedSafe`, `ParseSafeContents`, `ParseCertBag`,
  `ParseEncryptedPrivateKeyInfo`, `ParseEncryptionAlgorithm`, `DecryptPBES2`, `DecryptLegacyPBE`,
  `DecryptEncryptedData`, `DecryptShroudedKeyBag`, `GetFriendlyName`, `GetLocalKeyID`,
  `ErrInvalidMAC`, the ASN.1 types behind them, and the OIDs `EncodeOptions` does not take.
- Removed from `pkcs12/legacy`: `ConvertWithOpenSSL`, `IsBER` and its OIDs. The packages
  `legacy/ber` and `legacy/rc2` are internal now.
- `EncodeOptions.KeyEncryption`, `CertEncryption` and `MacAlgorithm`, and the OIDs that go with
  them, are `crypto/x509.OID`. An empty `CertEncryption` writes plain certificates, as nil did.

### features
- `legacy.Parse` reads the outer structure of a file in DER or BER, so that a caller of `legacy` can
  insist on a MAC too.

### verified
- `just check` across all modules passed on the tree of ba166e7; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `pkcs12`.
- `spec/pkcs12/interop/run.sh` on 2026-11-03, OpenSSL 4.1.0: `legacy.Decode` and `ti-pkcs12` 56 of 56,
  `pkcs12.Decode` 28 of 28, all compared in full. The committed `matrix.md` is of an earlier run.
- A file written by `pkcs12.Encode` read in `ti-pkcs12` and `openssl pkcs12 -info`, and one written by
  `ti_pkcs12::encode` read in `pkcs12.Decode`. These were one-off runs: the corpus covers decoders only.

### known limits
- `PFX`, `ContentInfo`, `MacData` and `DigestInfo` are aliases of an internal package, and their
  identifiers stay `asn1.ObjectIdentifier`.
- A crafted file can cost seconds per bag: the iteration limit is per count, not per file (TASK-158).
- Keys and passwords are not wiped from memory, unlike `ti-pkcs12`.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/brainpool v1.3.0

### fixed
- `josebp` writes a JWK's coordinates at the curve's full length, as RFC 7518 requires (TASK-189).

### changes
- The module is active again; `go/tipki`'s trust path parses and verifies through it.

### verified
- `just check` across all modules passed on the tree of ba166e7; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `brainpool`.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/tipki v0.31.0

### breaking
- The `hci-aut` profile checks revocation hard-fail, like every other profile: an SMC-B whose OCSP
  answer cannot be had is refused under it, also under a configured soft-fail. An OCSP outage now
  blocks what this profile validates. A configured `disabled` still disables.
- `Finding.Code` and `OCSPError.Code` are of the new type `ErrorCode`, not `string`. Comparing with a
  literal still compiles; concatenating needs `string(code)`. `TSLError.Code` stays a string.

### features
- `ErrorCode` has a constant for each of `ti-pki`'s 25 codes, such as `CodePolicyMismatch`, and
  `ErrorCodes` lists them. `CodeProfileNotDetected` and `CodeProfileAmbiguous` complete that list:
  no finding uses them, since `SelectForCert` reports those cases itself.
- A README.

### verified
- `just check` across all modules passed on c736b56; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `tipki`.
- Run on 2026-11-03 through `idpd`, against this code: `just idpd-trust-fetch-test`, with a live
  TSL of the reference environment (sequence 10717), and `just idpd-smcb-test`.
- The corpus changed in 4 of 6104 verdicts, all `hci-aut` under soft-fail with the responder
  unavailable: 3 went from valid to invalid, and 1 stayed invalid with `ocsp_unavailable` in place of
  `role_oid_missing`.

### known limits
- As in v0.30.0: `idpd`, `pdp` and `pep/proxy` still pin `tipki` by pseudo-version until the next
  `just sync`, `ti-pki`'s matching changes are unreleased, and the tag is on
  `chore/go-consolidation`, not yet on `main`.
- A `Finding` made with a literal code still compiles; a test reads the source for that.

# Release go/tipki v0.30.0

The first release of `go/tipki`, the native TI trust path held to Rust's `ti-pki` through `spec/`. It
takes over from `go/gempki`, whose last tag is v0.23.1 and stays resolvable; the number starts at
0.30.0 to move clearly on from it.

### breaking, for a port from go/gempki
- A new module path and new names, such as `Admission` for `ParseAdmissionStatement`,
  `ProfessionOIDs` for `ProfessionOids` and `CertHciAut` for `CertTypeHciAUT`.
- `DetectCertificateType` returns `(type, bool)`. `IsKnownCertificateType`, `CheckRoleOID` and
  `ValidationError` are gone.
- Identifiers are `crypto/x509.OID`, not `asn1.ObjectIdentifier`: the `oid` tables, `Lookup`,
  `Format`, `CertificateType.OID`, `Spec`, `ProfessionOIDs`, `RequiredRoleOIDs`, `TypeOIDs` and
  `CATypes`. An `x509.OID` has no `==` and is no map key; compare with `Equal`, or `EqualASN1OID`
  against what the standard library hands over as `asn1.ObjectIdentifier`.
- `Admission` is stricter: it refuses trailing bytes, a registration number that is not
  PrintableString, and malformed profession items.
- An eGK AUT or ENC certificate without a type OID stays undetected, because its pseudonymous
  sibling looks the same.

### features
- `oid.Parse` reads an identifier in its canonical dotted form, and refuses what
  `x509.ParseOID` would read as another identifier, such as 1.2.030 for 1.2.30. `oid.MustParse` is
  for identifiers in source.
- The tables follow gemSpec_OID V3.26.0: `TechRoleZETAPrvApprov` is added and ZETA Guard is on
  `C.FD.AUT` only, like `ti-pki`.

### fixes
- A TSL's `ExtensionOID` that is not in canonical form is refused.
- An empty OID, which an unknown certificate type has, is listed nowhere.

### verified
- `just check` across all modules passed on 48c3e74; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`. The development guide lists no gated suite as required for `tipki`.
- Run on 2026-11-03 through `idpd`, against this code: `just idpd-trust-fetch-test`, with a live
  TSL of the reference environment (sequence 10717), and `just idpd-smcb-test`.

### known limits
- `idpd`, `pdp` and `pep/proxy` still pin `tipki` by pseudo-version until the next `just sync`, so
  their builds outside the workspace do not use this release yet.
- `ti-pki`'s matching table change is unreleased: it ships with that crate's next version.
- The tag is on `chore/go-consolidation`, not yet on `main`.

# Release go/epa v0.24.1

### features
- The first page shows TI services and all proxies in two compact columns, names the providers
  IBM, RISE and EY, and refreshes the proxies every 5 seconds. Rounds do not overlap and a hidden
  tab polls nothing.

### changes
- `GET /status` goes through a guard, because checking a provider without a session opens one:
  callers share one result for 5 seconds, and a failed provider reports its last error for 60
  seconds without being contacted. A failure can so stay visible for up to a minute after the
  provider recovered.

### verified
- `just check` across all modules passed on 26c1402; `api-lint` was skipped without
  `GEMATIK_API_TOOLS_DIR`.
- `TestEPA_Connect` ran on 2026-11-03 on epa.t20r.cloud, built from 26c1402 with this version.
  ref passed. dev failed once at provider 1 with `TLS handshake timeout`, before the code this
  release changes, then passed three times in a row. The same host also timed out in the running
  proxy's logs that day, so this reads as that endpoint being intermittent; it was not proven.

### known limits
- Opening a session holds the session manager's lock through the whole login, so a slow login at
  one provider delays the proxy's others (TASK-203).
- The guard covers the status endpoint only: other calls still try to open a session at a
  provider that is down.
- As in v0.24.0: nothing checks at start that the version fits `x-useragent`, `TestEPA_Connect`
  and `ti` 0.5.0 do not cover provider 3, and the image runs as root (TASK-197).

# Release go/epa v0.24.0

### features
- The first page of the portal shows whether the TI services answer, per environment the
  proxies use and per access path, through the new `GET /api/probe`. It runs `ti probe`, shares
  one run per environment and reuses the result for a minute. This says the services answer,
  not that they can be trusted: `ti` does not verify TLS for it.

### changes
- Provider 4 is left out of the providers a proxy talks to until it works.
- The image downloads `ti` 0.5.0 from its GitHub release, pinned by SHA-256, instead of building
  it.
- `github.com/google/uuid` and `github.com/segmentio/ksuid` are replaced by the standard library,
  `golang.org/x/crypto` is no longer a direct dependency.

### fixes
- The portal's `esc()` escapes quotes, since its results also go into HTML attributes.
- The VAU key derivation's input is kept in its own buffer.

### verified
- `TestEPA_Connect` (`just epa-connect-test`) passed on 2026-11-03 against dev and ref: VAU,
  authorization, record status and consent at providers 1 and 2. It ran on epa.t20r.cloud,
  built from 3b23a28 with this version, with an SMC-B identity of that server.
- The running proxy opened sessions at providers 1 to 3 in dev and at 1 and 2 in ref.

### known limits
- A build's version goes into `x-useragent`, where the aggregators allow at most 15 characters:
  a longer `VERSION` build argument, such as `0.23.1-dev.3b23a28`, makes every provider refuse
  the VAU handshake. Nothing checks this at start yet.
- ref's provider 3 could not be reached: `epa-as-3.ref.epa4all.de` did not resolve.
- `TestEPA_Connect` covers providers 1 and 2 only, and `ti` 0.5.0 probes `epa-1` and `epa-2` only,
  so the first page says nothing about provider 3.
- The image still runs as root (TASK-197).

# Release go/dpop v1.0.0-beta.1

A rewrite against [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) on go-jose v4; the first
release with a stable API in view. `TRACEABILITY.md` maps every normative statement the module
implements to the tests that prove it.

### breaking
- New API. Client: `Key` (`NewKey`, `NewKeyFromSigner` over a `crypto.Signer`), `Key.Proof`,
  `Key.Sign`, `Key.Thumbprint`, `AccessTokenHash`. Server: `Verifier` (`NewVerifier`, `Config`),
  `Verifier.Verify(header, Request)`, `AccessToken`, `Error` with `WriteTokenError`,
  `Verifier.WriteChallenge`, `Verifier.Challenge`, `SetNonce`. `PrivateKey`, `FromJWK`,
  `NewBuilder`, `DPoP`, `Parse`, `ParseRequest`, `ParseOptions`, `SignRequest`, `DPoPError`,
  `CalculateAccessTokenHash` and `DPoPHeaderName` are gone.
- The expected URI is the server's own (`Request.URI`); `Host` and `X-Forwarded-Proto` are no
  longer used to rebuild it.

### features
- Every check of Section 4.3: one DPoP header, a single token68 JWT, required claims read by
  exact name and type, `typ` `dpop+jwt`, an allowlist of asymmetric algorithms (`none` and MAC
  cannot be configured), signature by the embedded `jwk`, no private key in it, `htm`, `htu`
  after RFC 3986 normalization without query and fragment, the server nonce, the `iat` window
  in both directions, `ath` and the key binding of the access token.
- Grant binding by thumbprint (`dpop_jkt`, Section 10); replay detection through a
  `ReplayCache` keyed by a SHA-256 of key, `htu` and `jti` (Section 11.1), with a bounded
  `MemoryReplayCache` that fails closed; server nonces through a `NonceSource` (Sections 8, 9).
- Responses as the RFC prescribes: 400 with an RFC 6749 error body and `DPoP-Nonce` for
  authorization servers, 401 with a `WWW-Authenticate: DPoP` challenge carrying `algs` for
  resource servers, uncacheable when a nonce is sent.
- Proofs signed through `crypto.Signer` with ECDSA P-256/384/521 and Ed25519 keys; `jti` from
  130 random bits.
- Time from a `Clock`; the module never reads the system clock itself.
- Known-answer tests from the RFC's own examples (Figures 2, 7, 13, 14; the `jkt` of Section
  6.1), one test per check, fuzz targets for the verifier, URI normalization and credentials.

### changed
- Dependencies: go-jose v4 only; lestrrat-go/jwx and its modules are gone.

# Release go/brainpool v1.2.0

### breaking
- `josebp.JWT.HeadersJson` and `PayloadJson` are renamed to `HeadersJSON` and `PayloadJSON`;
  `josebp.JSONWebKey.Algortihm` is renamed to `Algorithm`. The JSON encoding of a JWK is unchanged.

### fixed
- `josebp.ParseToken` with `WithKey` no longer panics on a signature that is shorter than the
  curve requires; a signature of the wrong length is an error.

### changed
- Tests use the standard library only; testify, and with it go.yaml.in/yaml/v3, is no longer a
  dependency.
- Clean under the workspace golangci-lint configuration; doc comments for the exported josebp API.
- update golang.org/x/crypto to v0.58.0

# Release go/pkcs12 v0.100.0

### features
- `legacy.Decode` reads BER-encoded files and RC2-40/128, two-key Triple DES and DES-EDE3-CBC
  in PBES2 in pure Go; no OpenSSL subprocess any more. New subpackages `legacy/ber` (BER to DER)
  and `legacy/rc2` (RFC 2268).
- `ErrLimitExceeded`: iteration counts above 10,000,000 are refused before any key derivation.
- MAC with SHA-224; friendly names with UTF-16 surrogate pairs; passwords outside the BMP
  encoded as surrogate pairs, as OpenSSL and Java do.
- Language-neutral specification, generated conformance corpus and interoperability matrix in
  `spec/pkcs12`.

### fixed
- An unknown PBKDF2 PRF fails with `ErrUnsupportedAlgorithm` instead of falling back to SHA-1.
- `EncodeWithOptions` no longer modifies the caller's options, honours `CertEncryption`
  (certificates are now encrypted by default, as OpenSSL does) and writes `hmacWithSHA*` as
  PBKDF2 PRF instead of the digest OID. Files written by earlier versions stay readable.
- Trailing data, unsupported public-key modes and unknown safe content types are rejected
  instead of ignored.

### changed
- `legacy.ConvertWithOpenSSL` is deprecated and converts in Go.
- Test fixtures with private keys removed; keys are generated per test run.
- License headers in every source file.
- update golang.org/x/crypto to v0.58.0

This lab project ist yet to yield a first release. Stay tuned!

**Every module — library and command — is versioned solely by its own git tag**
`go/<module>/vX.Y.Z`, bumped only when that module changes. There is no shared version and
no version variables. See the [Development & Release Guide](./go/docs/development.md) for the
step-by-step workflow.

### Local development (go.work)

The tracked `go.work` workspace resolves every in-repo module from its local source. Edit any
library (e.g. `brainpool`) and the change is immediately used by every command (e.g. `zero-epa`)
when you build, test, or run inside the workspace — no tags, no go.mod edits.

### Versions come from git tags

Each module's version is its latest `go/<module>/vX.Y.Z` tag. `go install <cmd>@vX.Y.Z`
reports its version automatically (Go embeds the module version in the build info); local
and Docker builds stamp it from `git describe` (clean `0.20.2` on a tag, `0.20.2-3-g…` past
it, `dev` when untagged). Manage with `just versions`, `just changed`, and
`just tag <module> <version>`.

Commands are installable directly (the `@` takes the bare semver; Go maps the `go/<mod>`
subdirectory to the tag):

```
go install github.com/gematik/zero-lab/go/epa/cmd/zero-epa@v0.20.2
go install github.com/gematik/zero-lab/go/pdp/cmd/zero-pdp@v0.22.2
```

The `ti` command-line tool is the Rust one (`rust/ti-cli`, `cd rust && just install`); the
Go `ti` and `kon` modules are archived at `go/ti/v0.23.4` and `go/kon/v0.21.4`. `gempki` is archived at `go/gempki/v0.23.1`; its successor is the Rust `ti-pki`, and the tag keeps it `go get`-able for external consumers.

`zero-caddy` combines its version with the upstream Caddy version as SemVer build metadata,
e.g. the binary reports `zero-caddy 0.20.2+caddy2.11.4` and the Docker image is tagged
`zero-caddy:0.20.2-caddy2.11.4` (`+` is illegal in Docker tags).

### Releasing a change

A tagged build (`go install`, tag-pinned Docker) runs **outside** the workspace, so a command
resolves libraries from its `go.mod`. To make a tagged build pick up a library change:

1. Edit the library; build/test/run locally (go.work uses it directly).
2. Commit and **push** the change.
3. `just sync` — repins every in-repo `require` to the branch tip (records the pushed
   commits' pseudo-versions). Commit and push the `go.mod`/`go.sum` updates.
4. `just tag <module> <version>` for each changed module (use `just changed`), then
   `just push-tags`.
5. `go install …/<cmd>@<tag>` now builds the command at its tag with the updated library code.

`just tidy` only syncs `go.mod`/`go.sum` to imports (no version changes). `just upgrade`
deliberately bumps external dependencies; after running it, re-run `just sync` before tagging.

If `proxy.golang.org` 404s a freshly pushed tag (negative cache), set
`go env -w GOPRIVATE=github.com/gematik/zero-lab` to install via direct VCS fetch.
