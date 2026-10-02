<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes zero-lab Rust

Every crate is released on its own, tagged `rust/<crate>/vX.Y.Z`. Pending changes are listed
per crate under "Unreleased"; a release moves its crate's entries into a section of their own.

## Unreleased

### ti-xmldsig

#### added
- `Document::parse`: strict XML 1.0 in UTF-8 without DTDs, bounded by `Limits` (size,
  depth checked before parsing, attributes, namespaces, nodes); errors name the rule of
  `spec/tsl-xmldsig` they enforce.

### ti-connector-client

#### added
- `Dotkon`: the `.kon` format of the Go and Kotlin clients, with `${NAME}` expanded
  only in credentials, only as plain names, and never from unset variables.
- `ServiceDirectory`: `connector.sds` parsing, version choice per binding, endpoint
  rewriting, and loading through a `ti_cache::Cache`.
- `Connector` over a caller-supplied `Transport` with short and long `Timeouts`;
  one generic SOAP call for every generated operation; faults with the gematik error
  trace read leniently.
- `Connector::cards`: `list`, `get`, and `find` by ICCSN, Telematik-ID or handle
  (EventService 7.2); `Connector::status`, the Konnektor's VPN and operating state.
- `Connector::certificates`: `read`, `read_all` (ECC, then RSA where present),
  `expiration`, `verify` (CertificateService 6.0); `CardCertificate` with the parsed
  certificate, its admission and Telematik-ID.
- `Connector::pins`: `status`, `verify`, `change` (CardService 8.1); `PinType`.
- `Connector::auth`: `external_authenticate` (AuthSignatureService 7.4), ECDSA
  signatures returned raw (R‖S) also from Konnektors that answer in DER.
- Generated bindings (`api`) for EventService 7.2, CardService 8.1 and 8.2,
  CertificateService 6.0, AuthSignatureService 7.4, SignatureService 7.5 and 7.4,
  EncryptionService 6.1.
- Feature `ureq`: `ureq::UreqTransport` over blocking ureq with rustls and ring;
  mutual TLS from `pkcs12` credentials (read by ti-pkcs12; P-256/P-384 keys without
  their public key, as Java keystores write them, are completed), the `.kon` trust store
  with Go's semantics (pins by equality, CA chains checked for `expectedHost`, also
  sent as SNI; the system's roots when empty), `insecureSkipVerify`, per-request
  timeouts, basic auth. `Error::Config` for unusable credentials or trust stores.
- Environment-gated tests against a real Konnektor (`tests/e2e.rs`).
- `Connector::signatures` (SignatureService 7.5): `sign` (CAdES detached, PAdES for
  PDF/A; several documents per job, each a `ToSign` with the short text a QES needs), `verify`, `job_number`, `stop`, comfort signature
  (`activate_comfort`, `deactivate_comfort`, `mode`). `Connector::encryption`
  (EncryptionService 6.1): `encrypt` (CMS for recipients' certificates) and `decrypt`
  (with the card's C.ENC; the plaintext's media type is required, the Konnektor checks
  it).
- A session recorded with an eHEX Konnektor replayed offline (`tests/recorded.rs`):
  every request byte for byte as the Konnektor accepted it. The e2e tests record new
  sessions with `TI_TEST_KON_RECORD_DIR`.

### ti-pki

#### added
- `Certificate::signature_algorithm`, `checks::key_usage_name` and
  `checks::ext_key_usage_name`, for tools that display certificates.
- Path validation rejects a critical extension this crate does not process (RFC 5280
  §4.2) in every certificate but the root: `ErrorCode::UnrecognizedCriticalExtension`,
  `path::PROCESSED_EXTENSIONS`, `Certificate::critical_extensions`. New OpenSSL fixtures
  and cross-checks.
- OCSP responders that are not RFC 6960 conform are accepted as delegates of the same
  TSP: id-kp-OCSPSigning, valid, certified by a TSL CA a root signed, both CAs under one
  TSP. `RevocationResult::authorization` records how a responder was authorized, and the
  validator reports the deviation as an `ocsp_responder_not_rfc6960` warning. For that,
  `tsl::Intermediate` carries each CA's TSP, `TrustStore::provider_of` looks it up, and
  `RevocationChecker::check` receives the trust store.
- gempki port, phase 6 (parity): OpenSSL cross-validation tests (test PKI chains, the
  real reference SMC-B chain, every production TSL CA, the OCSP fixtures); live tests
  against gematik's endpoints behind `just real-world`; invariant tests for OID labels
  and profile roles; `docs/gemlibpki-comparison.md`.
- gempki port, phase 5 (validator): `Validator` (chain building through the supplied and
  the store's TSL intermediates, path validation with the end-entity requirements, the
  gemSpec_Krypt key check, revocation for the end entity and, unless
  `skip_sub_ca_revocation`, every CA; `allow_expired` and `max_clock_skew` from the
  configuration), `validate_pem`; `profile` with smb-aut, epa-vau-aut, idp-sig and
  zeta-guard-aut, `lookup`, `select_for_cert` and `Profile::validator` (a profile can
  tighten the configured revocation mode, never loosen it); `trustdomain` (production vs
  non-production from the embedded roots, the chain or gematik's markers);
  `revocation::Unchecked`; `PathOptions::max_clock_skew`; `CertResult::revocation`. A
  quick-start doctest on real reference certificates; `validate` example.
- gempki port, phase 4 (OCSP): `ocsp::request` (SHA-1 CertID, as TI responders
  require), `ocsp::verify_response` (CertID binding, RFC 6960 responder authorization,
  certHash, the TUC_PKI_006 time window) and `ocsp::OcspChecker` (feature `load`);
  `revocation::{RevocationChecker, RevocationResult, RevocationStatus, apply_revocation}`
  with `gempki`'s revocation table; `load::Transport::post` with `PostRequest`, for
  reqwest, files and the mock. The OCSP ASN.1 types are the crate's own. `sha2` is no
  longer optional; `sha1` is new. OpenSSL-generated OCSP fixtures. `ocsp` example.
- gempki port, phase 3 (TSL): `tsl::Tsl::parse` (quick-xml and serde; sequence number,
  issue and next-update times, every service with its certificate, status and supply
  points), `Tsl::intermediate_cas`, `tsl::match_to_roots` (keeps a CA only if a root
  signed it; reports the others with a `Rejection`), `TrustStore::with_intermediates` and
  `TrustStore::intermediates`, `Timestamp::parse_rfc3339`. The loading layer parses the
  TSL and stores the matched intermediates. The TSL is not authenticated: the TSL-Signer
  anchors and `TrustConfig::tsl_anchor` are removed. `tsl` example; `chain --tsl`.
- gempki port, phase 2 (chains): `build_chain` (authority key identifier first, name
  fallback, bounded, cycle-safe, partial chain on failure), `validate_path` (validity, CA
  constraints, path length, link signatures, end-entity checks), `checks` (key usage,
  extended key usage, policies, roles), the Tab_PKI_405 type table with gemSpec_PKI
  baselines (`CertificateType::spec`) and `detect_certificate_type` (policies, then the
  admission fallback). `chain` example.
- gempki port, phase 1 (roots): `TrustStore` (dedup by key identifier, lookup by
  common name and key identifier), roots.json parsing (both document forms), the
  A_28419 cross-certificate walk with a per-direction stop report and a loop guard
  (`roots::walk`, `roots::load`, `roots::verify_cross_signed`),
  `Certificate::verify_signed_by`. The loading layer's roots verification is real now.
  `roots` example.
- `algorithms::rsa` (default feature `rsa`): RSA PKCS#1 v1.5 and PSS with SHA-256/384/512,
  with Wycheproof vectors. The embedded prod roots.json now yields the same ten roots as
  `gempki`.
- Tests run on an OpenSSL-generated test PKI (`just test-pki`); the Rust certificate
  builder is gone and `test-util` no longer pulls in `sha2`.
- gempki port, phase 0 (foundations): `Certificate` (parsed once, original DER kept,
  extensions decoded), `parse_pem_certificates`, admission statement, `key::classify_key`
  (gemSpec_Krypt tiers), the full gemSpec_OID tables with names (`oid::lookup`,
  `oid::format`), `ValidationError`/`ValidationWarning`/`ValidationResult`, `time` (moved
  from `load`, RFC 3339 display) and the `testing` test-PKI builder (`test-util`).
  `inspect` example.
- `algorithms`: signature verification through `rustls_pki_types::SignatureVerificationAlgorithm`;
  `STANDARD` (ECDSA P-256, P-384), `brainpool` module (brainpoolP256r1, brainpoolP384r1,
  default feature `brainpool`), `DEFAULT`, `find`. `TrustConfig::algorithms`, checked by
  `validate` against the anchor's key type. Wycheproof vectors for all four.
- `load` feature: `Transport`, `CacheStore`, `Clock` and `Loader` traits; `HttpLoader`,
  `CachingLoader`, `StaticLoader` with CBOR `Bundle`, `FallbackLoader`, `FileTransport`
  (`os`); `Reloader` with `TrustStoreHandle`, `ReloadPolicy` (production `hard_expiry`
  capped at 24 h) and `ReloadStatus`. Verification of loaded material is stubbed until
  the gempki port.
- `reqwest` feature: `ReqwestTransport` with conditional requests.
- `tokio` feature: `spawn_reloader`, `on_sighup`, `AdminTrigger`.
- `TrustConfig::roots_url`.
- `TrustConfig`: environment as data, with `preset_prod`, `preset` (behind
  `dangerous-nonprod`), `for_anchor`, `for_lab_ca` (behind `test-util`) and `validate`.
- Embedded GEM.RCA8 anchor and production roots.json; TEST-ONLY anchors and non-prod
  roots.json behind `dangerous-nonprod`.
- Crate skeleton.
- `OcspChecker` repeats a query after an OCSP status error (transport failure, `tryLater`,
  `internalError`, no OCSP response) up to `OCSP_STATUS_RETRIES` (3) times; if all fail,
  the responder rests for `OCSP_STATUS_PAUSE` (5 min) and is not asked meanwhile (A_30044
  (4), A_30046 (3), C_12791).
- `OcspChecker` reuses `good` and `revoked` results for `OCSP_CACHE_TTL` (1 h, after
  A_23225), at most until the response's `nextUpdate`; `with_cache_ttl` changes it, zero
  turns it off. Unknown results and errors are not cached (A_30046 (6), C_12791).
- `Validator::expected_fqdn` / `with_expected_fqdn` and `checks::fqdn`: a host named in
  the end entity's commonName must be the expected one, ignoring case and a trailing dot;
  new error code `fqdn_mismatch` (A_30046 (5), C_12791).
- `ErrorCode::ALL`: every code in declaration order, for schemas and documentation.
- Supplied OCSP responses (embedded in a signature, sent in an ASL handshake):
  `ResponseCheck::stapled` checks a response at a reference time (`thisUpdate` ≤ t ≤
  `nextUpdate`, no tolerance, no maximum age), with no certHash required for eGK
  certificates; `ocsp::StapledOcsp` is a `RevocationChecker` over such responses. The
  signer is still authorized by its issuer, as an RFC 6960 delegate or as a delegate of
  the same TSP, not by a TSL listing (A_30046 (7), C_12791).
- Profile `fd-tls-s`: the C.FD.TLS-S certificate of a Fachdienst TLS server, the type
  baseline without a role, default for the type; pair it with the expected FQDN.
- `Certificate::subject_alt_names`: the subject alternative names in OpenSSL notation
  (`DNS:…`, `IP:…`, `email:…`, `URI:…`), for display.

#### changed
- `Timestamp`, `Clock` and `SystemClock` come from `ti-types`, so every TI crate
  shares them; the paths `ti_pki::{Timestamp, Clock}` and `ti_pki::load::SystemClock`
  stay as re-exports.
- The caching layer lives in `ti-cache`, so other crates cache their own artefacts
  (e.g. a Konnektor's service directory) with the same store and policy.
  `load::{CacheStore, CacheEntry, CacheError, CachePolicy, MemoryCacheStore, Meta,
  Source, Conditional}` are re-exports of it, joined by `Cache`, `Cached` and
  `CacheLookupError`; `CachingLoader` is built on `ti_cache::Cache`, unchanged in
  behaviour.
- reqwest transport errors carry their causes (refused, timed out, unknown issuer),
  not only reqwest's "error sending request".
- `Env` and `Tier` now come from `ti-types` and are re-exported.
- An OCSP answer with status unknown is taken as is, without a certHash check (A_30046
  (2), C_12791): it used to fail as `ocsp_response_invalid`, which no revocation mode
  downgrades.
- `Validator::validate` checks the required admission roles last, and only for a
  certificate that is valid otherwise (A_30046 (4), C_12791); `ee_checks` no longer
  contains the role check. A certificate that fails elsewhere no longer reports
  `role_oid_missing` as well.
- `HttpLoader` compares the TSL by the SHA-256 published next to it (`.sha2`) before
  downloading: the list in hand with that hash (entity tag `sha256:<hex>`) is "not
  modified", and a download must match the hash. Without a readable hash over HTTP the TSL
  is fetched as before (A_30044 (2), C_12791).

#### removed
- `TrustConfig::accept_test_only_policies` is removed: gematik's test cards carry the
  production policy OIDs, so there was nothing for it to relax.

### ti-pkcs12

#### added
- PKCS#12 decoding (`decode`, `is_pkcs12`, `Pkcs12::pairs`): DER and BER, the password
  integrity mode (HMAC-SHA-1/2), PBES2 with AES-CBC, and behind the default `legacy`
  feature the PKCS#12 PBEs with 3DES and RC2. Parity with `go/pkcs12` on its fixtures,
  without its OpenSSL conversion for BER files.
- `Error::is_wrong_password`.
- `Pkcs12::encryption` names what each algorithm protects (`Encryption`, `Target`).
- Feature `encode`: `encode` writes certificates and keys with their attributes as DER
  with PBES2 AES-256-CBC (PBKDF2-HMAC-SHA-256, 2048 iterations) and an HMAC-SHA-256 MAC,
  the OpenSSL 3 defaults; the caller supplies the randomness.

### ti-cache

#### added
- `Cache`: freshness, revalidation, offline and stale-on-error over any `CacheStore`,
  keyed by string, with the origin passed per call (moved from ti-pki's
  `CachingLoader`). `CacheStore`, `CacheEntry`, `Meta`, `Source`, `CachePolicy`,
  `Conditional`, `OriginResponse`, `Cached`, `CacheLookupError`, `MemoryCacheStore`.
- `Cache::clock`, so origins stamp `fetched_at` with the clock the cache ages by.

### ti-types

#### added
- `Env`, `Tier`, `EnvParseError`; `serde` and `clap` features.
- `Timestamp` and `Clock` (moved from ti-pki), `SystemClock` behind `std`.

## Release ti-cli 0.1.2, 2026-10-02

### added
- `pki verify --fqdn NAME`: the certificate must name `NAME` if its commonName names a
  host (`fqdn_mismatch` otherwise).
- `pki inspect` and `pki verify` show the subject alternative names (`alt. names`); `pki
  inspect` JSON has `subject_alt_names`.
- `pki verify --connect HOST[:PORT]`: verifies the chain a TLS server presents, fetched
  directly or through an HTTP proxy; the server must prove it holds the key (its handshake
  signature is verified with ti-pki's algorithms, brainpool included), and `--fqdn`
  defaults to HOST. Error kind `server_unreachable`, exit 3.

### changed
- The `pki verify` schema lists the possible `code`s of errors and warnings as an `enum`,
  kept equal to ti-pki's `ErrorCode::ALL` by a test; schema version 1 may add codes.
- `pki inspect` and `pki verify` share one layout: subject and issuer as labelled fields
  (common name, organization, …), lists without dashes, then a "Trust" tree from the
  certificate down to its root. `inspect` builds it from the cached or embedded trust
  material without validating it and says so; `verify` marks each certificate ✓ or ✗ and
  adds its OCSP answer, replacing the "Chain" section. JSON is unchanged.

### removed
- `probe` no longer checks ePA 3, for the time being.

## Release ti-cli 0.1.1, 2026-09-27

### removed
- `-V`/`--version`: `ti version` shows the version, as in the Go `ti`.

## Release ti-cli 0.1.0, 2026-09-27

### added
- `probe ENV`, the Go `ti probe` with protocol checks: OIDC discovery (IDP), RFC 9728
  (ZETA-protected PoPP, VSDM and DiPag), the eRX VAU certificate, the ePA
  Information Service, the TI platform's
  service-discovery catalog and every instance it lists; parallel, 3 s per request, TLS
  unverified; a live table on a terminal, lines as they finish when piped, JSON or
  Markdown once all are done; exit 1 when a probe failed. Endpoints are embedded
  (`TI_PROBE_ENDPOINTS_PATH` replaces them).
- `connector`, the Go `ti connector` with the same `.kon` files: `configs`, `use`,
  `get info|services|cards|certificates|status|identities|expiration`,
  `describe card|certificate` (the latter as `pki inspect`), `verify pin|certificate`,
  `change pin`. Cards by ICCSN, Telematik-ID or handle; `-c`/`TI_CONNECTOR_CONFIG`,
  `--connector-timeout`, `--card-timeout`, `--no-cache`; the service directory cached;
  `-v` one line per call, `-vv` the SOAP bodies; error kinds `connector_*`,
  `card_restricted`, `pin_type`. Exit 3 now also means the Konnektor failed.
  PIN entry shows a spinner, the terminal's progress state (OSC 9;4) and a desktop
  notification (OSC 9) while the card terminal waits.
- `connector sign` (CAdES detached, PAdES for PDF/A; ECC by default), `verify
  signature`, `encrypt` (CMS for recipients' certificates) and `decrypt` (plaintext
  mode 0600), `comfort activate|status|deactivate` with a random user ID per activation
  (A_20073-01, A_20074) kept owner-only in the state directory and masked in `-vv`;
  `--comfort-user-id`/`TI_COMFORT_USER_ID`. Output files are never replaced without
  `--force`.
- `connector export certificate CARD [REF]`: a card's certificates as PEM on stdout (or
  `-o FILE`, `--der`); `encrypt --to-card CARD` encrypts for a card's C.ENC directly.
- `cache clear` also removes cached Konnektor service directories.
- `ti`, the command-line tool: `pki inspect` (PEM, DER or stdin; type,
  profile, admission, policies, key admissibility), `pki profiles list|describe`.
  Output: `--format auto|text|markdown|json` (`TI_FORMAT`); auto is colored text on a
  terminal and Markdown when piped; times in the system time zone. Global options:
  `--color`, `-v`, `--cache-dir`
  (`TI_CACHE_DIR`), and curl-like HTTP options (`-k`, `--cacert`, `--capath`, `-x`,
  `--noproxy`, `--connect-timeout`, `-m`, `--retry`, `-A`), validated and shown with `-v`;
  they take effect once commands download trust material.
- `pki verify`, offline: chain to the embedded roots, path, key and profile checks;
  `--env auto|prod|ref|test|dev` (`TI_ENV`), `--issuer`, `--intermediates`, `--profile`,
  `--at`. Revocation is not checked yet and reported as such. Exit 0 valid, 1 not valid,
  2 when the environment cannot be told.
- `pki verify` online: roots.json and the TSL downloaded, cached under the cache
  directory and verified against the anchor; OCSP for the end entity and its CAs, with
  the outcome per certificate. `--offline` uses the cache or the embedded roots. The
  HTTP options take effect over ureq (TLS on rustls/ring with the OS store, `--cacert`,
  `--capath`, `-k`, proxies, timeouts, `--retry`, user agent); `-v` logs each request.
- `pki roots list` and `pki tsl show` (`--ca`, `--provider`, `--root`, `--rejected`):
  the trust material behind `verify`, per environment; the TSL's CAs with the roots
  that signed them, described from their certificates only.
- `cache clear`: deletes the downloaded trust material (only the `ti-pki/` subtree).
- `schema [COMMAND]`: JSON Schema of every command's output and of errors, embedded
  and tested against real output; `agent`: the embedded AGENTS.md usage guide for the
  whole tool; `version`.
- Output: sectioned terminal views; lists of objects as tables with a chosen focus
  column first, on the terminal and in Markdown; compact Markdown otherwise; PEM for
  certificates in JSON and Markdown; dates alone in lists and `2023-02-09 00:00 CET`
  elsewhere.
- `pki inspect` and `pki verify` read PKCS#12 (`.p12`/`.pfx`, DER or BER, legacy
  encryption included) through ti-pkcs12, with `--p12-password` (default `00`). The
  certificate with its key comes first and is `verify`'s end entity; `inspect` reports
  `private_key`. A wrong password is error kind `p12_password`, exit 4.
- `pki inspect` reports the PKCS#12 container (`pkcs12`: encoding, MAC, encryption per
  part, keys with their certificate; `friendly_name` and `local_key_id` per
  certificate).
- `pki pkcs12 convert` (re-encode as DER, PBES2 AES-256, SHA-256 MAC, mode 0600,
  `--force` to replace).
- `completions bash|zsh|fish|elvish|powershell`.
- `just cli-targets`: release binaries for Linux x86_64 (musl), Windows x86_64 and macOS
  on Apple silicon.
- Release builds are stripped, fully LTO-optimised and abort on panic.
- The executable's name comes from `ti_cli::BIN`.
- Releases: `just release X.Y.Z` (checks, three binaries, `SHA256SUMS`, commit and tag,
  GitHub release with these notes, then the Homebrew formula): `brew install
  spilikin/tap/ti` installs the release binaries.

### changed
- Text output no longer cuts lines to the terminal width.
