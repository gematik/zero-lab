<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes zero-lab Rust

Every crate is released on its own, tagged `rust/<crate>/vX.Y.Z`. Pending changes are listed
per crate under "Unreleased"; a release moves its crate's entries into a section of their own.

## Unreleased

### added
- New crate: certificate verification for a server workload as a process beside it, protocol
  `pki/1` of `spec/ti-rpc`, over stdio or a Unix socket. Trust material comes from a mounted
  directory and nothing is written to disk; OCSP goes only to the responders of a chain that
  has verified. The production build holds no TEST-ONLY anchors.

### ti-cli

#### added
- `ti pki verify --connect HOST` gives a TLS server's verdict under the `web` TLS profile of
  `spec/pki-validation` for a server that is not the TI's (TASK-283): the chain judged in
  the handshake against the system's roots (or `--cacert`), the name, the keys, the
  validity period and the revocation status, with its source and the warnings
  `key_phased_out` and `revocation_unavailable`; exit 0 valid, 1 refused.
  `--validation-profile web` forces it (only with `--connect`); `auto` keeps a server with
  a TI certificate type, or issued by a CA of the TSL at hand, with the TI's validation,
  and says which and why. Its JSON has its own schema, `ti schema pki verify tls-server`.

#### changed
- `ti probe` shows a `web` server accepted with a warning (an RSA-2048 certificate, no
  revocation status from any source) as a yellow `!` with the warning, not as a failure
  (TASK-282).
- A Konnektor error names the `.kon` configuration it concerned (TASK-284):
  `Konnektor praxis: transport: …` instead of `Konnektor: transport: …`; its address and
  the calls stay with `-v`. Error kinds, exit codes and hints are unchanged.

### ti-cache

#### added
- `CacheControl`: the freshness a `Cache-Control` field grants (RFC 9111 §5.2), doubtful
  values counting as stale; fuzzed (`just fuzz-ti-cache`).
- `CachePolicy::origin_freshness`: the origin's lifetime decides freshness within
  `FreshnessBounds`; off by default, so existing users keep `max_age`.
- `Cache::force`: `expire` at most once per `CachePolicy::min_forced_interval` and key.

#### changed
- Renamed from `ti-store`, as it holds only the HTTP cache since the sealed store left: the
  package and crate are `ti-cache` and `ti_cache`. `ti-pki`'s re-exports keep their names.

### ti-client

#### added
- New crate (decision-15, TASK-249): the native host the `ti` command-line tool and the desktop
  app share, not published. `block_on` for the product clients' futures, `FileCache` (the
  `CacheStore` of the profile's cache directory, as ti-cli kept it) and `files` (private,
  atomically written files), all moved from ti-cli. It holds no protocol logic.
- `connector`: ti-connector-client's `Transport` over ureq (`UreqTransport`), the TCP and TLS
  probe of `config test` (`probe`, `check_config`, `TestOptions`) and `server_certificate`,
  moved from ti-connector-client's `ureq` feature. TLS is ti-tls's `konnektor` profile, with the
  operating system's verifier (rustls-platform-verifier) for an empty trust store.
- `tls`: an agent per ti-tls profile (`agent`, the profile's rustls configuration in ureq's
  connector chain) and the `web` profile's revocation sources over ureq (`UreqFetch`), moved
  from ti-tls's `ureq` feature.
- `net` and `http`: the curl-like settings (`Net`: `-k`, `--cacert`, `--capath`, the proxy as
  curl picks it, timeouts, `--retry`, user agent) and the transports built from them, moved
  from ti-cli: ti-pki's `load::Transport` with retries (`Http`), reporting each request to an
  `Observer` the host passes instead of printing, and the IDP-Dienst's and FHIR-Directory's
  transport (`UreqTransport`, from ti-idpd-client's `ureq` feature), which implements both
  clients' traits.
- `Client`: the transports made from one `Net` and observer (`downloads`, `idp`,
  `connector`). It is Send and Sync and every method blocks.
- The operations of `ti`'s pki commands (TASK-250), moved from ti-cli with typed inputs and
  results, the results deriving `Serialize` in the shape of the commands' JSON:
  `trust::Session` (roots.json and the TSL loaded, cached and verified, the TSL state that
  rejects an older list, the embedded roots offline) over the profile's `Dirs`;
  `pki::verify`, `pki::inspect`, `pki::signature`, `pki::tsl` (overview, CA filter, bundle
  selection, a TSL file's verdict), `pki::roots`, `pki::bundle`, `pki::export` (the trust
  bundle); `pkcs12` (re-encoding), `identity` (the SMC-B or HBA AUT identity from PKCS#12,
  PEM or a card at the Konnektor, and its JWS), `idp_trust` (the IDP-Dienst's certificates
  against the TSL), `input` (PEM, DER, PKCS#12), `peer` (a TLS server's chain) and
  `text::span`. The TSL and key-usage rules they apply are ti-pki's (`Tsl::verify_file`,
  `load::verify_read_back`, `load::AtTime`, `cert_type::is_authentication`).
- `Error` covers what the operations report (certificates, PKCS#12 files, trust material, the
  TSL rollback, state and cache files, identities, signatures); it moved from `net`, which
  re-exports it. A session's warnings reach the front end through a closure, and what it
  reads and keeps through the client's `Observer`.
- The operations of `ti`'s connector commands (TASK-250), moved from ti-cli:
  `connector::store` (the `.kon` files found, listed, selected and written as the Go `ti`
  keeps them), `connector::Session` and `connect` (a Konnektor with its service directory
  through the cache), `card_user` (one user ID per HBA, kept in a private file of the
  profile's state), `connector::cards` (info, services, cards, certificates, status,
  identities, expiration, a card described, PIN verification and change, the Konnektor's
  verdict on a certificate), `connector::documents` (sign, verify a signature, encrypt,
  decrypt, comfort signature, export) and `connector::setup` (a `.kon` file shown, judged,
  refused and tested). They return ti-connector-client's `model`; a wait at the card
  terminal reaches the front end as a closure called with a `Wait`, documents come and go
  as bytes, and no PIN passes through. `pkcs12::keep_pair` keeps one pair of a file.
  `Error` gains `ConnectorConfig`, `CardRestricted`, `PinType`, `Refused` and `Write`.
- The operations of `ti idpd authenticate` and `ti directory login` (TASK-250), moved from
  ti-cli: `idpd::authenticate` (the Authenticator-Modul flow with an identity, as a `Card`
  that signs `BP256R1`), `directory::{card, search, regservice, client_credentials}`, and
  `directory::owner`, the owner login that joins the directory's steps and the IDP-Dienst
  flow, with `OwnerTokens`, the host's `ti_directory_client::tokens::Tokens` (renewed
  before expiry and after a refusal). They return ti-idpd-client's and
  ti-directory-client's `model`; the transport is the one `Client::idp` makes, or a test
  double. `Error` gains `Idpd` and `Directory`.
- `watch` (TASK-250): the client's `Watcher`, set with `Client::watched`, is called before
  each request to the Konnektor, the IDP-Dienst and the FHIR-Directory and once its answer
  is in, with the method, URL, SOAP operation, status, bodies and time; a Konnektor body
  with its comfort user ID masked, never a credential. `Client::idp` and
  `Client::connector` return their transports in `Watched`, so a front end shows the
  requests without wrapping a transport, and `connector::setup::test` takes the `Client`.
- `Identity::from_card` (TASK-250): the identity of a card at the Konnektor, found, its
  card session's user and its ECC C.AUT read through the connector operations, in place of
  `Identity::on_card`, which left these calls to the front end.
- `probe` (TASK-250): `ti probe`'s checks, moved from ti-cli: the endpoints of each
  environment (`endpoints`, the built-in list or the front end's), the agents per TLS
  profile (`Agents`, the `ti` one over the environment's verified TSL with OCSP), the probes
  run in parallel with progress through a closure (`run`), what an answer means per kind
  and path (`Status`, `available`), and the `Report` in the shape of the JSON. The live
  table stays the front end's. `Error` gains `ProbeEndpoints`.
- `profile` and `pki::profiles` (TASK-250): the profiles' directories below their bases
  (`Bases`, `validate_name`), listed with their sizes and deleted, a symlink removed rather
  than followed; the validation profiles listed and described, with the CAs of a verified
  TSL that may issue a profile's types. Which bases and profile are in effect stays the
  front end's configuration.
- `pki::tsl::Loaded::sha256` and `connector::store::remove_copy` (TASK-250): the digest
  `tsl export` reports and the removal of an edited `.kon` copy, which ti-cli did itself.
- `jwks::RemoteJwks` (decision-15, TASK-251): jwz's `KeyResolver` (and `AsyncKeyResolver`)
  over HTTP, taking over every rule of the unreleased crate ti-jwks: the JWK Set at an
  `https` `jwks_uri` over the IDP-Dienst's agent, no redirect followed, 64 KiB and 100 keys
  at most, kept in a ti-cache store fresh for the origin's `Cache-Control` within
  5 min–24 h (1 h without), revalidated with `ETag`/`Last-Modified`, no stale set when the
  origin fails (`KeyUnavailable`, the cause as its source), an unknown `kid` refetching
  the set at most once a minute. The candidates are jwz's `JwkSet::signing_keys`.
  `with_transport` takes another `jwks::Transport`, such as a test's.


#### changed
- ureq 3.5 (pinned `~3.5`, TASK-272): its 3.4 releases left connection reuse, transfer
  encoding and the TLS handshake's timeout unfixed.
- The web transports accept a server the `web` profile accepts with a warning (an RSA-2048
  end entity, no revocation status; TASK-282). `probe` reports such a server as a warning,
  the warnings in its detail (`TLS web: revocation_unavailable`), where it failed before.
  `http::web_verifier` and `http::web_check` build the profile as `web_config` does.
- `peer::web_server_verdict`: a TLS server's verdict under the `web` TLS profile, reached
  in a handshake at a given instant (`TlsServerVerdict`: the chain, the verdict with its
  status source and warnings, the roots); `pki::verify::server_profile` picks `ti` or `web`
  for a `--connect` server (TASK-283).

### ti-tls

#### changed
- The `web` profile's two deviations from gemSpec_Krypt (TASK-282, `spec/pki-validation`
  Deviations): an end entity with RSA 2048 to 2999 bits is accepted with the warning
  `key_phased_out` (A_28976 asks for 3000; below 2048 stays `key_not_admissible`), and a
  server whose revocation status no source gives is accepted with `revocation_unavailable`
  (A_27857-02), where both were refused. A revoked status still refuses. A verdict without a
  status is not reused; a reused verdict keeps its warnings. `Verdict::status_source` names
  the source of the status (`StatusSource`), `verdict::KEY_PHASED_OUT` and
  `REVOCATION_UNAVAILABLE` the warnings, and `WebVerifier::with_warning_observer` tells the
  host of each accepted server and its warnings. `Code::RevocationUnavailable` is no longer
  returned.

#### added
- New crate (TASK-97): TLS server verification under `spec/pki-validation`. `TiVerifier` (the
  `ti` profile through ti-pki) and `WebVerifier` (the `web` profile: the system's roots,
  rustls-webpki paths, gematik's and the ZETA SDK's key, hash, name, validity and revocation
  rules) as rustls verifiers; `client_config` offers TLS 1.3/1.2, AES-GCM with ECDHE, P-256 and
  P-384 only. Verdicts are reused until their certificate, status or snapshot ends.
- `konnektor`: the Konnektor's TLS as its `.kon` file configures it, moved from
  ti-connector-client's ureq transport (decision-15, TASK-249). `konnektor::Trust` verifies
  pins by equality, CA chains for `expectedHost` (or the URL's host), the operating system's
  trust through a verifier the host supplies for an empty trust store, and any certificate
  with `insecureSkipVerify`; `Trust::client_config` takes the client certificate and key the
  host decoded. `konnektor::server_name` is `expectedHost`, else the URL's host.

#### removed
- The `ureq` feature and the module `ureq` (decision-15, TASK-249): `agent` and `UreqFetch`
  are ti-client's (`ti_client::tls`). ti-tls holds no HTTP client.

### ti-idpd-client

#### added
- `model` (TASK-250): the read-only projections of a completed flow the front ends show,
  `IdpInfo`, `CertificateInfo` (a certificate by subject and SHA-256 fingerprint) and
  `ChallengeInfo`; the feature `serde` derives `Serialize` for them.
- `probe` (TASK-266): the path a connectivity probe asks (`PATH`) and what a discovery
  document there says (`answer`, `Answer`), read without verifying it: it tells the
  IDP-Dienst from a gateway and trusts nothing.

#### removed
- The `ureq` feature and `ureq::UreqTransport` (decision-15, TASK-249): the crate has no HTTP
  client. ti-client's `http::UreqTransport` is the blocking transport, without
  `UreqTransport::agent`; `ti_client::http::idp_agent` makes the agent, verified under ti-tls's
  `web` profile.

#### security
- The discovery document's signer is checked before its key verifies the document
  (IDPV-001): `discovery::parse` takes the `trust::CertificateTrust` and asks it about the
  `x5c` certificate first, so a refused certificate stops the flow whatever the signature
  says. `Discovery::signer_checked` records the answer (TASK-223).

#### fixed
- A `Location` with a `%` before a non-ASCII character no longer panics: the query is decoded
  byte by byte, and `%+F` is no longer read as an escape. Found by the new fuzz targets.
- A code redirect whose `code` is empty is malformed, as one without `code` is.

#### changed
- Renamed from `ti-idpd`: product clients are named `ti-<product>-client` (decision-15). The
  package and crate are `ti-idpd-client` and `ti_idpd_client`, the fuzz recipe
  `just fuzz-ti-idpd-client`.
- `discovery::parse` takes the `Idp` asked and refuses a signed document that names another
  issuer.
- `authenticator::authenticate` takes a `trust::CertificateTrust` and hands it the
  discovery document's signer and `PuK_IDP_SIG`'s certificate before anything is
  signed; a refusal is `Error::Untrusted`. `trust::Unverified` keeps the former
  behaviour and its warning. `Authenticated::certificates` records what was checked;
  `Discovery::warnings` is gone, `Discovery::signer_chain_der` is new.
- `PuK_IDP_SIG` must carry `x5c` with a certificate for the JWK's key
  (`discovery::key_certificates`).
- The card signs asynchronously: `authenticator::Identity::signer` is a
  `jwz::keys::AsyncSigner`, so a card at the Konnektor signs without blocking;
  `authenticator::authenticate` and `challenge::respond` are `async`. Every `Signer` is
  an `AsyncSigner`, and with one the future is ready at its first poll (TASK-60).
- `http::Transport::send` is `async` without a `Send` bound, as the other TI crates'
  transports, so a browser's fetch can carry the flow (decision-15, TASK-245).
- `trust::CertificateTrust::check` is `async` without a `Send` bound: a check may need the
  TSL or OCSP, and a browser host cannot block for them. `discovery::parse` is `async`, as it
  asks the trust check; `authenticator::authenticate` takes the check as a generic `&C`
  rather than `&dyn CertificateTrust` (decision-15).
- Time is a function `impl Fn() -> Timestamp` (ti-types) in `authenticator::authenticate`,
  `discovery::parse` and `challenge::parse`, no longer a `now: u64`: each token is judged
  at the time read when it arrives, not at the start of a login that may wait for a PIN
  (decision-15).

### ti-directory-client

#### added
- `probe` (TASK-266): the path a connectivity probe asks (`PATH`, `/owner-authenticate`)
  and what its answer says (`answer`, `Answer`): a redirect to an IDP-Dienst's
  authorization URL is the directory.

#### changed
- Renamed from `ti-directory`, as `ti-idpd-client` (decision-15): the package and crate are
  `ti-directory-client` and `ti_directory_client`, the fuzz recipe
  `just fuzz-ti-directory-client`.
- No dependency on ti-idpd-client: no product client depends on another (decision-15).
  The crate has its own `http` module (`Request`, `Response`, `Method`, `TransportError`,
  and `Transport`, async without a `Send` bound); `Env` is ti-types', `Idp` is no longer
  re-exported. `Directory::new` takes the IDP-Dienst's base URL, `Directory::idp_url`
  replaces `Directory::idp`.
- `owner::login` and `owner::Login` are gone: the host runs the IDP-Dienst flow between
  `owner::authorization_url` and `owner::sign_in`, which takes the IDP's redirect URL in
  place of ti-idpd-client's `CodeRedirect`. `Error::Idpd` is gone; `Error::Token` is a token the
  host could not provide.
- `exchange::login_bearer` and `exchange::login_client_credentials` are `async`, as
  ti-idpd-client's transport is (TASK-245).

#### added
- `model` (TASK-250): the read-only projection of a login the front ends show, `Token` with
  `DirectoryInfo`, and `Credential`; the feature `serde` derives `Serialize` for them.
  `Token::for_search` names the Search API (`Directory::search_url`) and warns with
  `Warning::SearchNotInAudience` when the token's `aud` does not.
- `tokens::Tokens`, implemented by the host: the access token for the directory's API
  and the report that the directory refused one (401). `tokens::send` sends a request with
  it and, after a 401, once more with the next token (RFC 6750 §3.1).
- New crate: the gematik FHIR-Directory's Auth-Service (gemSpec_VZD_FHIR_Directory
  V1.7.0, I_VZD_Owner) as its clients see it, sans I/O:
  `Directory::for_env` (PU, RU, TU with the environment's IDP-Dienst and Keycloak),
  `Endpoint` (owner, holder, service, ti-provider with path and realm), `owner` (the card
  flow with its redirect guards), `keycloak`
  (client credentials with Basic authentication), `exchange` (the bearer exchange,
  `login_client_credentials`, `login_bearer`), `token` (`AccessToken`, `TokenClaims`),
  `DirectoryError` and `OAuthError`. `/tim-authenticate` is not implemented.

### ti-jwz

#### added
- New crate: the gematik TI profiles for jwz, `ti()` and (feature `legacy`) `ti_legacy()`
  (adds `BP256R1`), with `registry()`.
- Module `brainpool` (feature `legacy`): gematik's `BP256R1` and `BP-256` for jwz, legacy
  only: `register`/`registry`, `Bp256` (ECDSA and ECDH on bp256), `backend` (any jwz
  backend plus BP-256), `BrainpoolEs256Key` for ePA's `ES256` on brainpool keys; JWE
  encryption to `BP-256` keys (decryption not yet supported). Interop fixtures against Go
  josebp and Python jwcrypto in both directions (`just jwz-interop`, checked by
  `cargo test`). It was the crate jwz-brainpool until TASK-225: brainpool is TI-only, so
  it lives with the TI profiles, and jwz stays a JOSE library without it.

#### changed
- The profiles are built from constants (TASK-271): `ti()` is
  `Profile::new("ti", 2)` with jwz's `ECDSA_NIST`, `ECDH_ES_DIRECT_P256`, `DIRECT` and
  `AES_256_GCM` and this crate's `EPA_BRAINPOOL_KEYS`; `ti_legacy()` is `ti()` with
  `BRAINPOOL_SIGNATURES`. `ti()` lists `BP-256` among its signing curves, so ePA's ES256 on
  brainpool keys passes it by a stated rule, not as a side effect, and jwz's `strict()`
  refuses it. `BRAINPOOL_KEY_AGREEMENT` (`legacy`) lets a client encrypt to the IDP's
  `BP-256` key; no profile lists it, as brainpool JWE is not decrypted. `BP_256` is also
  available without `legacy`, as a name; `BrainpoolEs256Key` states its curve.

### ti-xmldsig

#### added
- `Document::parse`: strict XML 1.0 in UTF-8 without DTDs, bounded by `Limits` (size,
  depth and attributes checked before parsing, namespaces, nodes); errors name the rule of
  `spec/tsl-xmldsig` they enforce.
- Exclusive XML Canonicalization 1.0 without comments: `Document::exc_c14n`,
  `exc_c14n_by_id`, `exc_c14n_by_name`; checked against the C14N and Exc-C14N
  specification examples, the W3C `merlin-exc-c14n-one` vectors, the reference digests of
  published TSLs, property tests and Kani proofs (`just verify-formal`).
- `Document::verify_tsl_signature`: the enveloped XMLDSig/XAdES signature of a TSL
  against the fixed profile (TSLSIG-010 – 015, 019 – 022, nothing outside it accepted) and
  the SHA-256 digests of both references, compared in constant time (TSLSIG-017). Returns
  `SignedTsl`: canonical `SignedInfo`, range-checked `r ‖ s`, the signer certificate bound
  by `CertDigest`, its serial number as written, and the canonical content to read
  (TSLSIG-023). The ECDSA check and the certificate are left to the caller; the
  `verify` example shows both.

### ti-wasm

#### added
- **Breaking for consumers:** `verify_tsl(xml, sig, ocsp?, env, now, roots_json?, grace_seconds)`
  and `new TrustContext(xml, sig, env, now, roots_json?, grace)` take the list's detached
  `.sig`; the view loses `signature.signing_time` (TASK-166).
- `TrustContext`: `new TrustContext(xml, env, now, roots_json?, grace)` verifies once,
  `check(der_or_pem, now)` returns `schemas/check.json`; for certificate checks in the
  browser. The smoke test cross-checks it with `ti pki verify --offline`.
- New crate: the TSL view and certificate description for JavaScript through wasm-bindgen,
  server and browser alike.
  `verify_tsl`, `describe_certificate`, `trust_urls` and `version` return JSON
  (`schemas/tsl-view.json`, `schemas/certificates.json`, typed in `js/types.d.ts`); the
  caller passes the bytes and the instant, the module has no network and no clock.
  `just wasm-build`, `wasm-size`, `wasm-smoke` (Node on the real TSLs, cross-checked with
  `ti pki tsl verify`) and `wasm-vendor`.

### ti-connector-client

#### removed
- The `ureq` feature and the module `ureq` (decision-15, TASK-249): the crate has no HTTP
  client and no TLS library. `UreqTransport`, `server_certificate` and `probe` are
  ti-client's (`ti_client::connector`), the verification of the `.kon` trust ti-tls's
  (`ti_tls::konnektor`); `check_config` and `TestOptions` became `check::run` and
  `check::Options` here, with ti-client's probe passed in.

#### added
- `model` (TASK-250): the Konnektor's cards, certificates, PIN states and outcomes, status,
  identities, expiry dates, services, product, and its verdicts on certificates and
  signatures, as the front ends show them; `Serialize` with the new feature `serde`.
  `Severity` reads an error condition's severity by TAB_KON_503, one not known an error.
- The Konnektor's rules the `ti` CLI applied itself: `PinType::choose` and `UnfitPin` (the
  PIN a card has), `has_user_sessions` (an HBA's card session belongs to one user ID,
  TAB_KON_510), `is_restricted` (SMC-KT, KVK and eGK on the SOAP API), `IDENTITY_CARDS`,
  `Certificates::telematik_id` (from the ECC C.AUT), `SignatureFormat::for_document` and
  `to_verify`, `media_type` (PDF/A for PAdES), `short_text` and `SHORT_TEXT_MAX` (the
  schema's 30 characters), `edit::validate` (a file judged without its environment) and
  `edit::pins` (the trust store's server certificates).
- `check::run`: the configuration checks from the file to the cards, with the host's TCP
  and TLS probe (or none, behind a proxy) and its transport; `check::host_port`.
- `Credentials::client_identity`: the client certificate and key `pkcs12` credentials
  present in the handshake.
- `Request::redacted_body`: a request's body as it may be shown, the content of every
  `UserId` element masked (TASK-250).

#### changed
- Base64 through `base64ct` in constant time, in the generated bindings (wsdl2openapi
  ddb0a65) and the hand-written code alike; `base64` leaves the crate. Whitespace stays
  ignored, and an encoding with non-zero padding bits is refused.

#### added
- `Dotkon`: the `.kon` format of the Go and Kotlin clients, with `${NAME}` expanded
  only in credentials, only as plain names, and never from unset variables.
- `ServiceDirectory`: `connector.sds` parsing, version choice per binding, endpoint
  rewriting, and loading through a `ti_store::Cache`.
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
- `Credentials::None` (`"credentials": {"type": "none"}`): no client certificate and no
  `Authorization` header; `Credentials::kind`.
- `config::ConfigView`: a `.kon` file without its secrets, for front ends: where the
  password and the PKCS#12 bytes are kept (plain, `${NAME}`, absent), whether a user ID
  is set, the PKCS#12 client certificate (`config::client_certificate`: subject,
  validity, key, whether ring can sign with it, encryption) and the trust store as pins
  and CAs with their SHA-256. ti-pkcs12 is now a regular dependency.
- `check`: the test of a `.kon` configuration as pure functions of what the host
  observed, steps `file`, `tcp`, `tls`, `auth`, `sds`, `context`, `cards`, each finding
  `ok`, `skip`, `warn` or `fail` with a hint; a failed step skips the rest. An `http`
  url fails (the service directory is read over https only); with `env: pu`,
  `insecureSkipVerify` and credentials `none` fail, elsewhere they warn. `ureq::check_config` runs the
  steps against a Konnektor (`ureq::probe` connects and records the server certificate
  also when the handshake fails), the service directory and GetCards through the
  caller's transport.
- `Fault::hint` and `fault_hint`: what to do about faults on the information model
  (4004 to 4007, 4010 to 4012, 4021, 4053, 4060, 4092, 4093, 4204, 4263), formerly in
  ti-cli.
- `edit`: `.kon` files written by front ends: `normalize_address` (URL, host,
  host:port, IP, [IPv6]:port; always https, http refused), `NewConfig::to_json`, `set`
  for the members without secrets, `with_credentials`, `with_pin` (CAs stay),
  `refusals` (what a change brings that is not allowed: an http url anywhere,
  insecureSkipVerify and none in a pu file).
  `ureq::server_certificate` fetches the certificate to pin without trusting it.
  `check::Finding::action`: `renew_pin` for a server certificate that is not the pinned
  one.
- Fuzz target `dotkon` (`just fuzz-ti-connector-client`): the parser, the file check and
  the redacted view.
- Fuzz targets `sds` (the service directory, its bindings and rewrite) and `soap` (every
  Konnektor call on any answer), seeded from the recorded runs.

#### fixed
- A call goes only to an endpoint at the origin of the `.kon` url or its `expectedHost`:
  same scheme, host and port; otherwise `DiscoveryError::ForeignEndpoint`, a new variant,
  and nothing is sent. `check::sds` takes the `Dotkon` as well (breaking).
- `ServiceDirectory::rewrite_endpoints` keeps no endpoint outside the `.kon` origin: it
  also rewrites `HTTPS://…`, and removes what is no http(s) URL with a host. Found by the
  target `sds`.

### ti-pki

#### added
- `model::{ValidationProfile, TypeRequirements, TslCas, TslCa}` (TASK-250): a validation
  profile as `ti pki profiles` shows it, what it requires of each type it accepts, and the
  CAs of a verified TSL that may issue those types.
- `Tsl::verify_file` (feature `brainpool`, TASK-250): a TSL file verified the way
  `spec/tsl-detached` asks of a consumer, in one operation: the detached signature and the
  signer, the sequence against a previous list (TSLSIG-053), a supplied signer status taking
  the place of the query (TSLDET-020), and the query only at the current time (TSLDET-023),
  through a checker the host opens when it is needed. `TslFile`, `FileVerdict`, `FileError`.
- `load::AtTime`, `load::NoNetwork`, `load::read_back` and `load::verify_read_back` (the last
  with `brainpool`, TASK-250): the loader of a validation at another time, which never loads
  the published signer status (TSLDET-023); the set a load verified, read back from the
  cache without the network under the load's age rules (TSLDET-015), and checked to be the
  very list the load verified (TSLSIG-053, `ReadBackError`). Moved from the `ti` CLI.
- `cert_type::is_authentication`: an AUT certificate by its key usage (PROF-002), as an SMC-B's
  or HBA's identity needs it. Moved from the `ti` CLI.
- `model` (TASK-248): the response model of ti-pki's use cases, plain types that only map,
  with no I/O, no validation and no clock of their own, always compiled; `Serialize` with the
  new `serde` feature. They are the JSON the `ti` CLI and its WebAssembly build publish, which
  their schemas describe, and replace the ti-report crate:
  - `Certificate::new(cert, now)`: a certificate as `ti pki inspect` shows it (`Key`,
    `ProfileHint`, `Admission`, `Oid`, `TypeOid`); `validity(cert, now)`.
  - `Finding`, `CertSummary` and `rejection_code`: the TSL findings as `ti pki tsl verify` and
    `tsl show` report them.
  - `Tsl::new(env, &offline::Tsl::verify(..), now)`: a TSL verified for one environment as
    one document for web views: signature verdict and warnings, list and scheme metadata,
    the roots walked from the anchor with the CAs each signed, every service by provider
    with its certificate types and the chain of its certificate, and every certificate
    named, keyed by its lower-case SHA-256 hex. A failed list yields the verdict only.
  - `Check::new(&check, certs, &outcome, now)` and `TslState::new(material)`: an offline
    check as one document: verdict, profile, type, errors, warnings and the trust tree, end
    entity first; revocation is not checked.
  - `SCHEMA`, the version of every document.
- `offline::Tsl::verify` (features `load`, `brainpool`): a TSL verified for one environment
  by its detached files, its CAs matched to the roots of a supplied roots.json if that walks
  from the anchor, of the embedded one otherwise, and the chain of every service certificate
  in accord towards a verified root (TASK-248).
- `offline::Check` (feature `load`): an environment's TSL and roots.json verified once
  without a network, a supplied roots.json used only if it walks from the anchor, then any
  number of certificates validated against them with revocation disabled, under the profile
  picked for the end entity or as a chain only. It returns Rust types: `Material` (the
  roots' `RootsSource` and why supplied roots were not used, the verified TSL or why it was
  rejected) and `Outcome` (`ProfileChoice` and the `ValidationResult`). Taken from
  ti-report's `CheckContext` (TASK-247).
- `Certificate::fingerprint_sha256` (upper-case hex pairs joined by `:`, as OpenSSL prints
  them) and `Certificate::to_pem` (TASK-247).
- `tls::ServerCheck`: a TLS server of the TI under the `ti` profile of `spec/pki-validation`
  (TUC_PKI_018 with Tab_PKI_273, C.FD.TLS-S and C.ZD.TLS-S, the host in the commonName or a
  `dNSName`, wildcards as RFC 9525 has them, OCSP stapled within the grace period or asked),
  with the spec's result codes; `TrustStore::with_tsl_ca_types_for_tests` (`test-util`).

#### changed
- **Schema change:** `ErrorCode::IssuedBeforeCaExpiry` (`issued_before_ca_expiry`) is renamed
  `ErrorCode::CaExpired` (`ca_expired`), in `spec/pki-path` and `go/tipki` alike (TASK-270);
  its message says why the expired CA is still accepted.
- **Revocation is checked for the end entity only (TASK-270, VALID-008).** A CA's standing is its
  status in the verified TSL (TUC_PKI_018 step 5, Tab_PKI_271: in accord, or revoked after the
  end entity was issued, expired HBA/SMC-B CAs included), and no responder is asked about a CA
  (step 7). The `Validator` sends one OCSP request per certificate instead of one per link.
- **OCSP responders are authorized as TUC_PKI_006 step 5 does (OCSP-001).** The issuing CA or its
  RFC 6960 delegate (id-kp-OCSPSigning, valid now) are accepted silently; otherwise a responder
  whose certificate the verified TSL lists as an OCSP service, under any TSP, with
  id-kp-OCSPSigning and valid now, is `ResponderAuthorization::TslListed { tsp }` and the
  warning `ocsp_responder_not_rfc6960`, where a listed responder used to pass without one; any
  other is `ocsp_responder_untrusted`. Whether the responder's CA is a TSL CA of the issuing
  CA's TSP no longer matters, and an unlisted responder of another CA is refused. A listed
  responder outside its validity is refused although the TSL's status covers the signers of
  expired HBA/SMC-B CAs: the maintainer's decision.
- `TrustStore::with_listed_responders_for_tests` (feature `test-util`).
- The `hci-aut` profile checks revocation hard-fail, like every other profile: an SMC-B whose OCSP
  answer cannot be had is refused, also under a configured soft-fail.
- The OID tables follow gemSpec_OID V3.26.0: `TECH_ROLE_ZETA_PRV_APPROV` (`oid_zeta-prv-approv`,
  1.2.276.0.76.4.332) is added and ZETA Guard is allowed on `C.FD.AUT` only. The draft change
  C_12646, which the tables had applied, withdrew the first and added `C.FD.TLS-C` to the second;
  the released table does neither.
- `Validator` asks no OCSP responder about a certificate that has already failed: the address is in the certificate, and
  a forged one could otherwise send a request anywhere. A report on such a certificate shows no revocation results.
- A CA the verified TSL states no certificate types for may issue none: `cert_type_ca_not_authorized`, where
  `cert_type_unchecked` warned and let it pass. That code is gone (TUC_PKI_007 step 9a).
- A profile's validator refuses a certificate whose type the profile does not accept, `profile_type_mismatch`.
- With a verified TSL, every CA of a chain must be one it names in use, or the certificate is `ca_not_in_tsl`. A CA
  supplied with the certificate gets no standing from a root's signature alone.
- A certificate with a compressed EC public key no longer parses, whatever it is for; before, only a TSL signer was
  refused, at TSLSIG-035. The TI issues uncompressed points.
- A signature with unused bits no longer verifies, on a certificate or an OCSP response, and neither does a response
  whose signature algorithm is not a SEQUENCE. Those bytes are outside what a signature covers, so a copy with
  them changed passed as the same response.

#### added
- Profile `dipag-vau-aut` (`profile::DIPAG_VAU_AUT`): the C.FD.AUT certificate of the
  Digitale Patientenrechnung VAU, selected by its role `oid_dipag-vau` (gemSpec_DiPag_FD
  A_27411-01; TASK-198). `ti pki verify` picks it automatically and accepts it as
  `--validation-profile dipag-vau-aut`.
- `oid::all()`: every identifier the module declares, for the corpus another implementation is held to.

#### fixed
- `TrustStoreHandle::snapshot` refuses a list past its `NextUpdate` and the grace period. A
  reload that only confirmed unchanged material did not verify it again, so a source supplying
  the same list kept it in use (TSLSIG-054).

#### security
- The OCSP response parser no longer panics on a GeneralizedTime with a multibyte
  character across its 14th byte, which a hostile responder could use to end the
  process. Found by the new `ocsp_response` fuzz target (TASK-166).

#### removed
- `Validator::skip_sub_ca_revocation`: no CA is asked about any more, so there is nothing to
  skip (TASK-270).
- `ResponderAuthorization::SameTspDelegate`, the unlisted delegate of another CA of the same TSP
  accepted with a warning, and `TslListed`'s field `ca`: the TSL authorizes a responder by
  listing it and binds it to no CA (TASK-270).
- **The XMLDSig path and `ti-xmldsig` are gone, with `roxmltree` and `proptest`.** A list
  without a fitting `.sig` no longer verifies, in every environment, and `.sig` exists only
  on the plain-HTTP CRL host of A_21182: a network that blocks it cannot take new lists,
  and for up to an hour after each publication (A_21178) the new list waits for its `.sig`.
  This is a recorded deviation from TUC_PKI_012 (`spec/tsl-detached`, doc-3). Gone from the
  API: `SignedTsl::signing_time`, `VerifiedTsl::signing_time`, the code
  `xml_signature_error`. `FileTransport::new` takes the signature file,
  `TrustStore::from_material` the detached files, and `TrustConfig::tsl_detached_url` is
  required. A bundle without the signature is refused on import: export it again.
- The features `reqwest` and `tokio` with `ti_pki::reqwest` and `ti_pki::tokio`, and the
  examples `ocsp` and `validate`, which needed them; `ti pki verify` does what they did.
  Nothing used them: a host implements `load::Transport` and calls `Reloader::tick` on
  its own runtime.

#### added
- The TSL is verified by gematik's detached signature file (`spec/tsl-detached`,
  gemSpec_TSL A_21175 ff.; TASK-166): `tsl_signature::verify`,
  `parse_detached_signature`, `Tsl::parse_verified(xml, sig, …)`,
  `Tsl::parse_verified_with_status`, `embedded_config_for(sig)`, and
  `VerifiedTsl::check_signer_status_supplied` for the `.ocsp` published next to the list.
  The loaders fetch `.xml`, `.sig` and `.ocsp` as one set from
  `TrustConfig::tsl_detached_url`: `Artifact::TslSignature` and `TslSignerStatus`,
  `load::Detached` on `TrustMaterial::detached`, the two files as optional fields of a
  `Bundle`. The list comes from the plain-HTTP origin only under the hash from HTTPS, and
  from HTTPS itself when no hash can be read. A signed `revoked` stops the list at any age.
  A set that fails is fetched once more, keeping the set in hand (`Loader::revalidate`,
  `Cache::expire`, `Cache::stored`), and a cached `.sig` stays usable at any age while
  HTTPS confirms its list. The reloader asks the network for the signer's status only when
  none came with the list.
- `ti-pki/fuzz`: `just fuzz-ti-pki` runs the `detached_signature`, `tsl_xml` and
  `ocsp_response` targets, seeded from the published sets.
- The validity model follows the end entity's type (gemKPT_PKI_TIP 2.4): the
  Kompromissmodell for C.HCI.AUT/ENC/OSIG and C.HP.AUT/ENC, under which each CA must have
  been valid when it issued the certificate below and one expired since gives the
  warning `ca_expired` (`ErrorCode::CaExpired`); the shell model
  for every other type. `ValidityModel` and `PathOptions::model` are new (breaking for
  callers that build `PathOptions`).
- A certificate OCSP reports revoked after the reference time is valid for that time,
  with the warning `revoked_after_reference_time`; at or before it, and without a
  `revocationTime`, it stays `revoked` (gemSpec_PKI TUC_PKI_006 variants 8a and 8b;
  TASK-1). The response's freshness is still judged against the clock of the query.
- A CA the TSL lists as revoked (`SERVICE_STATUS_REVOKED`) with a `StatusStartingTime`
  is no longer dropped: end entities it issued before that time validate, with the
  warning `issued_before_ca_revocation`; later ones fail with `ca_revoked_in_tsl`
  (gemSpec_PKI Tab_PKI_271, TUC_PKI_002 step 5; TASK-4). `tsl::Intermediate` gains
  `revoked_since`, `TrustStore::revoked_since` reads it.
- `cert_type::fold_name`: the one input rule for type and profile names;
  `CertificateType::from_str` and `profile::lookup` use it.
- Renamed after their gemSpec references (decision-5): profiles `SMB_AUT`/`smb-aut` to
  `HCI_AUT`/`hci-aut`, `IDP_SIG`/`idp-sig` to `IDPD_SIG`/`idpd-sig`, 24 `oid::INST_*`
  constants (e.g. `INST_ARZTPRAXIS` to `INST_PRAXIS_ARZT`, `INST_GEMATIK` to
  `INST_BS_GEMATIK`), `CERT_TYPE_CM_TLSCS` to `CERT_TYPE_CM_TLS_C`.
- `TrustStore::subset(algorithms)`: the roots and intermediates whose own key the set
  supports, e.g. `algorithms::NIST` for a client without brainpool.
- `OcspChecker::with_store`: keeps `good` and `revoked` responses in a `CacheStore`
  as well, so separate processes share them; the store holds the DER response, which is
  verified again as of its fetch time when read, so a shared store can withhold a
  response but not forge one. `OcspChecker` gains a third type parameter, defaulting to
  `NoStore`. `RevocationResult::from_cache` tells a reused answer from a fresh one.
- `anchors::GEM_RCA7`, the production anchor, and `algorithms::NIST`: everything but
  brainpool, to verify as a client without brainpool would (the roots walk ends at
  GEM.RCA8 and GEM.RCA5; no TSL verifies).
- `checks::ext_key_usage_name` names `id-tsl-kp-tslSigning` (0.4.0.2231.3.0), the TSL
  signer's extended key usage, which showed as the bare OID.
- `TrustStore::from_material(config, roots_json, tsl_xml, now)` (feature `load`): the trust
  store and verified TSL from documents already in memory, synchronously, as the loaders
  verify them, without going through the `Reloader`.
- `oid::CV_ROOTCERT` and `oid::CV_CERT` (`oid_cv_rootcert`, `oid_cv_cert`, gemSpec_OID):
  the types the TSL states for its CV certificate services, which had no name.
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
- `load` feature: `Transport`, `CacheStore` and `Loader` traits; `HttpLoader`,
  `CachingLoader`, `StaticLoader` with CBOR `Bundle`, `FallbackLoader`, `FileTransport`
  (`os`); `Reloader` with `TrustStoreHandle`, `ReloadPolicy` (production `hard_expiry`
  capped at 24 h) and `ReloadStatus`. Verification of loaded material is stubbed until
  the gempki port.
- `reqwest` feature: `ReqwestTransport` with conditional requests.
- `tokio` feature: `spawn_reloader`, `on_sighup`, `AdminTrigger`.
- `TrustConfig::roots_url`.
- `TrustConfig`: environment as data, with `preset_prod`, `preset` (behind
  `dangerous-nonprod`), `for_anchor`, `for_lab_ca` (behind `test-util`) and `validate`.
- Embedded anchor and production roots.json; TEST-ONLY anchors and non-prod
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
- TUC_PKI_007 against the verified TSL: an end entity whose type the issuing CA's TSL
  entry does not list fails with `ErrorCode::CertTypeCaNotAuthorized` (1061,
  CERT_TYPE_CA_NOT_AUTHORIZED); one whose issuer has no stated types is the warning
  `CertTypeUnchecked`. `Service::type_oids`, `TrustStore::tsl_types_of`,
  `Validator::cert_type` (set by `with_type_baseline`).
- OCSP responders the verified TSL lists as an OCSP service of the issuing CA's TSP,
  certified by a CA of that TSP that a root signed, are authorized as
  `ResponderAuthorization::TslListed`, without the `ocsp_responder_not_rfc6960` warning
  (`TrustStore::listed_responder_tsps`; the loader fills the listing from the verified
  TSL). A listing under another TSP authorizes nothing.
- `Certificate::subject_alt_names`: the subject alternative names in OpenSSL notation
  (`DNS:…`, `IP:…`, `email:…`, `URI:…`), for display.
- `tsl_signature::verify` (feature `brainpool`): the signature of a TSL, part A of
  `spec/tsl-xmldsig` — the XML profile and digests through `ti-xmldsig`, the signer
  certificate bound by serial number, a brainpoolP256r1 key, and the ECDSA value over
  the canonical `SignedInfo` through the configured algorithm set. Failures carry the
  result code of Tab_PKI_274 (`TslCode`) and the rule.
- `Tsl::parse_verified` (feature `brainpool`), part B: a C.TSL.SIG signer issued by
  one of `TrustConfig::tsl_signer_anchors` (name, AuthorityKeyIdentifier, signature), signer and
  anchor valid at the given time without skew, KeyUsage exactly nonRepudiation,
  ExtendedKeyUsage exactly `id-tsl-kp-tslSigning`, and the rest of Tab_PKI_252_01; the
  list is then parsed from the signed bytes. `parse_verified_prod` verifies for
  production; `parse_verified_auto` for whichever environment's embedded TSL signer CA
  issued the signer, reporting the `Tier`; `tsl_signature::embedded_config_for` returns
  that preset for adjustment.
- TSL update rules (`spec/tsl-xmldsig` parts C and D): `VerifiedTsl::check_signer_status`
  queries the signer's OCSP status through any `RevocationChecker`, RFC 6960
  authorization only, with the result codes of TSLSIG-041/042 (`cert_revoked`,
  `certhash_mismatch`, `ocsp_status_error`, …); without it the list carries the warning
  `no_ocsp_check`. `VerifiedTsl::check_sequence` against a stored `TslState` (`Id`,
  sequence number ≥ 10000). `NextUpdate` with `TrustConfig::tsl_grace_period`
  (`validity_warning_1`, `validity_warning_2`). A verified list skips services it cannot
  process (`Tsl::skipped`); `Tsl::id` is the list's `Id`.
- Loading verifies the TSL: `Reloader` swaps in a list only after its signature, signer,
  `NextUpdate` and sequence verified; `Reloader::with_signer_status` adds the signer's
  OCSP status, `Reloader::with_stored_tsl` the state to persist across restarts
  (`ReloadStatus::tsl_state`, `ReloadStatus::tsl_warnings`). `VerifyError::tsl` carries
  the result code. `ReloadPolicy::validate` caps the interval at 24 h
  (`MAX_RELOAD_INTERVAL`).
- `anchors::GEM_TSL_CA3` and, with `dangerous-nonprod`, `anchors::GEM_TSL_CA28_TEST_ONLY`:
  the TSL signer CAs, pinned by SHA-256; `anchors::TSL_SIGNER_CAS_PROD` and
  `TSL_SIGNER_CAS_NONPROD` list them per tier.
- A TSL signer CA the TSL announces (`TSLServiceCertChange`) that is not configured is
  the warning `tsl_anchor_announced`, logged by the tokio driver; it is never adopted, a
  release adds it to the list (part E of `spec/tsl-xmldsig` is not implemented).
- Certificate type `C.TSL.SIG` (`CertificateType::TslSig`, identified by
  `oid_policy_gem_tsl_signer`) and profile `tsl-sig`.

#### changed
- `TrustStoreHandle` keeps the current material under a `std::sync::RwLock`, not `arc-swap`,
  which is no longer a dependency.
- `TrustMaterial::body` and `meta` answer `Option`,
  since the two detached artefacts may be absent; `TrustMaterial::etags` lists all four.
- `revocation::apply_revocation` takes the reference time the chain is validated for.
- `Bundle` is JSON (format version 2) instead of CBOR, with the bodies in base64 and
  the anchor hash in hex; minicbor is no longer a dependency. Version-1 bundles are
  rejected: export them again.
- Every preset is anchored at GEM.RCA7 (P-256; TEST-ONLY outside prod) instead of the
  brainpool GEM.RCA8 (prod) and GEM.RCA8 TEST-ONLY (test). The trusted roots are the same:
  GEM.RCA8 cross-certifies GEM.RCA7, and the walk from it reaches every root; it now
  lists GEM.RCA7 first.
- `TrustConfig` has new fields `tsl_signer_anchors`, a list, and `tsl_grace_period` (breaking for
  struct literals; struct update on a preset or `for_anchor` is unaffected): GEM.TSL-CA3
  in production, GEM.TSL-CA28 TEST-ONLY in the non-production presets; grace 0, at most
  30 days. `validate(Tier::Prod)` rejects a TEST-ONLY TSL signer anchor.
- `Reloader` has a third type parameter, the signer status checker (default `Unchecked`,
  i.e. none); `tokio::spawn_reloader` takes any. The TSL is no longer loaded
  unauthenticated: a list that fails verification is never used.
- `Tsl` has new fields `id`, `skipped` and `scheme` (`SchemeInfo`: version, type, scheme
  and operator name, postal and electronic addresses, `PointersToOtherTSL` with
  `primary_location()` / `backup_location()`).
- `Timestamp` comes from `ti-types`, so every TI crate shares it; the paths
  `ti_pki::Timestamp` and `ti_pki::load::Timestamp` stay as re-exports.
- Time enters as a function `impl Fn() -> Timestamp`, no longer as a `Clock`
  (decision-15): `HttpLoader`, `CachingLoader`, `Reloader`, `TrustStoreHandle` and
  `OcspChecker` take one, a host passes `Timestamp::now`. `Clock` and `SystemClock` are
  gone; `FixedClock` (`test-util`) is a settable time for tests, passed as
  `|| clock.now()`.
- The caching layer lives in `ti-store`, so other crates cache their own artefacts
  (e.g. a Konnektor's service directory) with the same store and policy.
  `load::{CacheStore, CacheEntry, CacheError, CachePolicy, MemoryCacheStore, Meta,
  Source, Conditional}` are re-exports of it, joined by `Cache`, `Cached` and
  `CacheLookupError`; `CachingLoader` is built on `ti_store::Cache`, unchanged in
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

#### changed
- One decode may spend `MAX_ITERATIONS` (10,000,000) iterations on key derivation in total,
  all its MAC, PBKDF2 and PBE derivations together (spec/pkcs12 P12-036), where each count was
  bounded alone: a file of many bags no longer costs 10,000,000 iterations per bag.
  `Error::LimitExceeded` reports the derivation that would exceed the budget.
- PBES2 is read and written by the crate itself over `pbkdf2`, `aes` and `cbc`; `pkcs5`,
  `scrypt` and `salsa20` are gone from the tree. Files written are byte for byte the same.
  What a file can do differently: a `keyLength` other than the cipher's key size is now
  `Error::Malformed` (P12-032) instead of a failed decryption, parameters that do not
  decode are `Error::Malformed` instead of `Error::UnsupportedAlgorithm`, and salts longer
  than 32 bytes are read.

#### added
- `CertificateBag::trusted_key_usage` and `oids::TRUSTED_KEY_USAGE`: Oracle's trusted key
  usage attribute, read and written, which makes a certificate bag a trusted certificate
  entry in Java (OpenSSL's `-jdktrust`). A new field: breaking for struct literals.
- PKCS#12 decoding (`decode`, `is_pkcs12`, `Pkcs12::pairs`): DER and BER, the password
  integrity mode (HMAC-SHA-1/2), PBES2 with AES-CBC, and behind the default `legacy`
  feature the PKCS#12 PBEs with 3DES and RC2. Parity with `go/pkcs12` on its fixtures,
  without its OpenSSL conversion for BER files.
- `Error::is_wrong_password`.
- Iteration counts of the MAC, the PKCS#12 KDF and PBKDF2 must lie in 1 to
  `MAX_ITERATIONS` (10,000,000; spec/pkcs12 P12-036): above it decoding fails with
  `Error::LimitExceeded` before anything is derived, 0 is `Error::Malformed`. PBES2 accepts
  PBKDF2 only (P12-030); scrypt is `Error::UnsupportedAlgorithm`.
- `Pkcs12::encryption` names what each algorithm protects (`Encryption`, `Target`).
- Feature `encode`: `encode` writes certificates and keys with their attributes as DER
  with PBES2 AES-256-CBC (PBKDF2-HMAC-SHA-256, 2048 iterations) and an HMAC-SHA-256 MAC,
  the OpenSSL 3 defaults; the caller supplies the randomness.

### ti-store

#### removed
- The features `store` and `test-util`: the sealed store (`ti_store::store`) is gone with
  its AES-GCM, HKDF and HMAC dependencies. `Cache` and `CacheStore` are unchanged.

#### added
- Renamed from ti-cache; the cache API is unchanged under `ti_store`.
- Feature `store`: `ti_store::store`, the sealed store of spec/store: `Backend`,
  `MemoryBackend`, `Store`, `Keyring` with `KeyFileWrapper`, `Sealer`, `KeyWrapper`,
  `Random`, the namespace `registry`, `profile` resolution, format `levels`, the files
  backend's formats (`files`), and `StoreError` with the spec's result codes. Passes the
  spec/store corpus; fuzz targets for every parser.
- `Cache`: freshness, revalidation, offline and stale-on-error over any `CacheStore`,
  keyed by string, with the origin passed per call (moved from ti-pki's
  `CachingLoader`). `CacheStore`, `CacheEntry`, `Meta`, `Source`, `CachePolicy`,
  `Conditional`, `OriginResponse`, `Cached`, `CacheLookupError`, `MemoryCacheStore`.
- `Cache::now`, so origins stamp `fetched_at` with the time the cache ages by.
- The cache reads the time through a function `impl Fn() -> Timestamp` it keeps as its
  type parameter, no longer through a `Clock` (decision-15).

### ti-types

#### added
- `Env`, `Tier`, `EnvParseError`; `serde` feature, the crate's only dependency.
- `Timestamp` (moved from ti-pki); `Timestamp::now`, the system clock, behind `std` (not
  on wasm32-unknown-unknown, where std has no clock and every call would panic). Time
  enters the TI crates as a function `impl Fn() -> Timestamp`, so hosts pass
  `Timestamp::now` and tests a closure (decision-15).

## Release ti-cli 0.6.0, 2026-11-08

### security
- Every https server is verified under the `web` profile of `spec/pki-validation` (TASK-97):
  the OS roots or those of `--cacert`/`--capath`, end-entity keys ECDSA P-256/P-384 or
  RSA ≥ 3000, no SHA-1, MD5 or SHA-224, serverAuth, at most 398 days of validity, and a
  revocation status by OCSP or CRL, or no connection. The TSL download points, the IDP-Dienst
  and the FHIR-Directory pass it (`cargo test -p ti-client --test web_real_world --
  --ignored`). `-k` no longer reaches the IDP-Dienst and the FHIR-Directory, as documented: it
  skips the check for downloads only. `-v` names the profile.
- `ti probe` verifies every https endpoint, where it checked none (TASK-228): ePA under the
  `ti` profile, against the environment's TSL and roots with OCSP; the IDP-Dienst, E-Rezept
  and the internet services under `web`. A refused certificate fails the probe as an answer
  (`TLS web: unknown issuer`), and the JSON gains `tls: {profile, verified}`. The endpoint
  list takes `"tls": "ti"` per endpoint; `web` is the default.

### added
- `ti pki trust export -o FILE`: roots.json, the TSL, its signature and its signer's status as
  one bundle file for a server or an air-gapped site, written whole and only once a consumer's
  load of it verified.
- `ti connector config list` lists the .kon files, where the other `config` commands are.
  `connector configs` still works, no longer in `--help`, and `connector use` without a name
  shows the same list. `ti schema` knows the list as `connector config list`, and
  `connector use` as either of its two answers.

### removed
- The sealed store: `ti store`, `ti profile create|use|show|rotate|rewrap`, `TI_STORE_KEK_PATH`,
  `TI_STORE_BACKEND` and `TI_STORE_TRACE` are gone, with the `store_*` error kinds, the
  SQLite databases (`state.db`, `cache.db`), the keyring and the key file. They are not
  read: files of the former store may be removed by hand (`~/.local/state/telematik/profiles`,
  `~/.cache/telematik/profiles`, `~/.config/telematik/profiles`). `ti profile list` and
  `delete` stay.
- SOCKS proxies: `-x socks5://` and a `socks5://` in the proxy variables are refused with
  `http_setup` (exit 2), and `ureq`'s `socks-proxy` feature, `socks` and `byteorder` are
  gone.

### changed
- **Schema change:** the warning `issued_before_ca_expiry` of 0.6.0-rc.1 is `ca_expired` in
  `pki verify`'s JSON (TASK-270): every certificate is issued before its CA expires, and what
  it reports is a CA that has expired while its certificate is still accepted under the
  Kompromissmodell. The trust tree marks a CA that carries only warnings with a yellow `!`
  instead of ✓ or ✗; the end entity keeps ✓ or ✗, its warnings are in the findings.
- `ti connector config set` takes its configuration from `-c` or the selection, like the other
  connector commands, no longer as an argument.
- State and cache are plain files below `~/.local/state/telematik/ti` and
  `~/.cache/telematik/ti` (`%LOCALAPPDATA%` on Windows). `--profile NAME` or `TI_PROFILE`
  chooses `profiles/NAME` below them, created on first use; no profile is remembered
  between runs and no name is reserved. For a throwaway run use `--profile "$(uuidgen)"`
  or `TI_STATE_DIR=$(mktemp -d) TI_CACHE_DIR=$(mktemp -d)`.
- The TSL state is kept on every run without setup, except with `--at`, so an older TSL is rejected from the
  first verified list on. A corrupt TSL state file is refused with `state_file_failed`
  naming it, where it was ignored.
- Comfort IDs lie unencrypted in private files (mode 0600 in a directory of mode 0700), no
  longer sealed, as `hba-user/KONNEKTOR/CARD`. Existing IDs, sealed or in `comfort/`, are not
  migrated: **activate comfort signature again.** On POSIX such a file or directory that is a symbolic
  link or open to group or others is refused.
- Homebrew releases go to `gematik/tap` (`brew install gematik/tap/ti`), with the earlier
  versions from `spilikin/tap`. Installs from `spilikin/tap` stay at 0.5.0: `brew uninstall ti
  && brew install gematik/tap/ti` switches.

### fixed
- `pki verify` accepts an SMC-B under an expired HBA/SMC-B CA whose responder answers for it
  (TASK-270): a reference SMC-B under GEM.SMCB-CA9 TEST-ONLY, valid under the Kompromissmodell,
  failed with `ocsp_responder_untrusted`, because the CA itself was asked at the production
  root responder its AIA names. Only the end entity is asked now, as TUC_PKI_018 does; a CA's
  standing is its status in the verified TSL. The revocation line says so (`OCSP for the end
  entity, the CAs by the TSL`), and `chain[].revocation` is set for the end entity only.
- `connector config test` reports a Konnektor that requires a client certificate as
  refusing basic credentials every time (TASK-262): under TLS 1.3 the refusal follows the
  handshake and was now and then lost to a reset, which passed the auth step.
- `ti probe` puts the Bestandsnetze on one line, the names grouped by result (TASK-235):
  production lists 17, and a row each pushed the TI VPN and Internet off the screen and the
  redrawn table into the scrollback. `--format json` keeps each one's detail.
- `ti probe -k` checks no TLS certificate, ePA's included, and loads no TSL; answers are
  judged as usual, the detail says `TLS unchecked` (in yellow), `tls.verified` is null, and a
  warning names it.
- `-k` warns "the TLS certificates of download servers are not checked".
- `pki tsl show`, `pki tsl export` and `pki trust export` use the list their load verified
  against the TSL state. They read it back from the cache without asking the origin again, a
  stale entry could send that read there, and refuse any other list. `tsl export` writes the
  signature and status the list verified with, no status with `--at`, and none that is past
  its age online (TSLDET-015). Past the age limit they refuse with `--offline`, where they
  showed the cached list.
- `connector get status` colors a condition by its severity: Info is not red.
- Every call on an HBA uses one user ID, so PIN commands, `verify certificate`, `export` and
  the like work while comfort signature is on, where they ended in 4018, and need no `userId`
  in the `.kon` file: the one in the HBA's file under `hba-user/` of the profile's state, else
  the `.kon` file's, else a new one kept there. `comfort activate` writes a new ID to that
  file and `comfort deactivate` removes it. A 4018 says what to do.
- `connector sign` asks the Konnektor whether a comfort session runs, so `comfort` is no
  longer true for a session that has ended. `user_id_stored` is gone from `connector comfort`.
- A rejected older TSL hints at what it means and how to recover, not at the network.
- Proxy variables no longer reach the Konnektor, as `AGENTS.md` always said: only `-x`
  sets a proxy for it.
- A Konnektor whose service directory names another origin than the `.kon` url is refused
  before anything is sent, and `connector config test` fails at `sds`, with the hint to
  `rewriteServiceEndpoints`. Before, credentials and documents went wherever the directory
  said, plain http included. **A Konnektor behind NAT that worked without the rewrite now
  needs it.**
- `--card` (identity, directory login) chooses its Konnektor with `-c`/`--connector-config`
  like the `connector` commands; `--connector` stays as an alias.
- `pki verify` applies the Kompromissmodell to the nonQES certificates of SMC-B and HBA
  (gemKPT_PKI_TIP 2.4.2, gemSpec_PKI Tab_PKI_271): an SMC-B or HBA certificate whose CA
  has expired since it was issued is valid with the warning `ca_expired`; it was
  rejected as `expired`. Components and the eGK keep the shell model. The trust tree of
  `pki inspect` and `pki verify` shows such a CA as a warning, a yellow `!` and "expired
  …, accepted under the Kompromissmodell", no longer as a red error.

### security
- crypto-bigint 0.7.10, ctutils 0.4.6 and tokio 1.54.1 (RUSTSEC-2026-0387,
  RUSTSEC-2026-0385, RUSTSEC-2026-0386); crypto-bigint 0.7.6, which fixed the first,
  was yanked since.

### added
- `pki tsl verify TSL SIG [--signer-status FILE.ocsp]`: the signature file is a required
  argument, because the list is verified by gematik's detached signature file, and the
  signer's status can come from the published response instead of a network query. `tsl
  show`, `bundle` and `export` load the two files from the environment's automated download
  point. Reports lose `signing_time`, and `xml_signature_error` became
  `detached_signature_error` (`spec/tsl-detached`, TASK-166). `tsl export -o` writes the
  `.sig` and `.ocsp` next to the list. **Lists need their `.sig`: scripts calling `pki tsl
  verify FILE` must pass it as the second argument.**

### changed
- `ti pki verify --validation-profile` fails a certificate whose type the profile does not accept: `profile_type_mismatch`
  is an error, it was a warning. New error `ca_not_in_tsl`. The warning `cert_type_unchecked` is gone: a CA the TSL
  states no types for fails with `cert_type_ca_not_authorized`. A report on a certificate that already failed shows no
  revocation results, because no responder is asked about it.
- Konnektor faults about the information model carry a hint naming the cause, the
  `.kon` fields concerned and where to fix it (gemSpec_Kon): 4092 (no Remote-PIN-KT
  for the workplace), 4053, 4004 to 4007 (unknown Mandant, client system, workplace,
  card terminal), 4010 to 4012 (not assigned to the Mandant), 4021 (call context
  incomplete), 4204 (client system not authenticated), 4093 and 4060 (card or terminal
  busy). The fault's code and text are unchanged; the hint is in the text and in the
  JSON error's `hint`.
- `ti agent` states the rules agents follow with the tool (never ask for or print a real
  `.kon` file, PKCS#12 file, PIN or token; PIN and destructive commands only on
  request), lists every error kind with its exit code, describes the `.kon` format with
  a sample of placeholders, and names the Konnektor fault hints. A test keeps the list
  of error kinds equal to the binary's: `output_exists` is exit 2, `key_unsupported` 4,
  the `store_*` kinds 2, except `store_busy` and `store_backend_error`, which are 5.
- `ti` without arguments and a command group without its subcommand show the commands
  without the output, profile, HTTP and Konnektor options every command shares; `-h` and
  `--help` both show everything. A set `TI_FORMAT` or `TI_CACHE_DIR` no
  longer turns the help of `ti` without arguments into an error.

## Release jwz 0.2.1, 2026-11-08

### fixed
- The README on crates.io described 0.1: its contents section now lists what 0.2 brings
  (key resolvers, `Ed25519`, profiles that bind signing, keys and headers, error causes)
  under a heading without a version, and links the release notes.

## Release jwz 0.2.0, 2026-11-08

### added
- `jwk::KeyResolver` and `jwk::AsyncKeyResolver` (TASK-243): where a verifier gets the keys
  that may have signed a JWS, implemented by the host over its own fetching and cache;
  jwz never fetches. `JwkSet` implements both.
- `JwkSet::signing_keys(kid, alg)`: the keys with the header's `kid` (all when it names
  none) whose `use` and `key_ops` allow signatures and whose `alg`, if stated, is the
  accepted one (RFC 7517 §4.2–4.5).
- `Jws::verify_with` and `Jws::verify_with_async`: each resolved key is made a verifier for
  the accepted algorithm and tried; a key that does not fit is passed over, and
  `VerificationFailed` follows when none verifies. A resolved key is a candidate, never
  trusted for having been fetched.
- Every `Fn() -> u64` is a `jwt::Clock`, so a host passes time as a function, as it does to
  the ti crates; `SystemClock` and `FixedClock` stay.
- `ErrorCode::KeyUnavailable` and a public `Error::new`, for the host's implementations of
  jwz's traits (a resolver whose origin failed).
- `Error::with_source` (TASK-273): a host's implementation of a jwz trait attaches its own
  error, which reaches the caller through `source()` and never appears in `Display`; code,
  context and equality are unchanged. **Breaking:** `Error` is no longer `Copy`, nor
  `UnwindSafe` and `RefUnwindSafe`: a host's cause need not be, as `std::io::Error` is not.
- `Header::parse`: a header from JSON, read as a token's is, so a host can ask a
  `KeyResolver` without a token at hand.
- `Ed25519` and `Ed448` (RFC 9864, TASK-241): fully specified EdDSA names. `Ed25519` signs
  and verifies, with a key on Ed25519 only; `Ed448` is reserved. A JWK whose `alg` says
  `Ed25519` is no key for `EdDSA`, nor the reverse. The constant `profile::ED25519`.
- **Breaking:** signing and encryption check the header they produce against the policy
  (RFC 8725 §3.11, TASK-276): a missing `typ` or `kid` the policy requires, a key
  reference it does not opt into, a `crit` it does not understand, `b64` and, for JWE,
  `zip` are refused with `PolicyViolation` or `Critical` before anything is signed or
  encrypted. A profile with a `typ` no longer signs a token without it.
- **Breaking:** `Profile::strict()` lists `Ed25519` instead of the polymorphic `EdDSA`,
  which RFC 9864 deprecates: an `EdDSA` token is refused under `strict`, and a key for
  `EdDSA` signs under it no more. A profile that must talk to an older peer adds
  `profile::EDDSA`; `rfc7518-interop` has both.
- `docs/guide.md`: verifying from a JWK Set with `verify_with`, why jwz never fetches keys,
  why time is a function, and an `AsyncKeyResolver` over the browser's `fetch`.
- Profiles as explicit lists (TASK-271): `profile::Algorithms` bundles and the constants
  `ECDSA_NIST`, `EDDSA`, `HMAC`, `ECDH_ES_P256`, `ECDH_ES_DIRECT_P256`, `AES_KW`,
  `DIRECT`, `AES_GCM`, `AES_128_GCM`, `AES_256_GCM` and `Algorithms::NONE`;
  `Profile::new(name, version)`, a profile without algorithms on the strict defaults.
- `Policy::signing_curves`, the curves a signing key may be on, and `JwsKey::curve`, the
  curve a key states (`SoftwareKey` and the `test-util` doubles state theirs).
- `Policy::check_signing_key` and `Policy::check_encryption`, the acceptance of what is
  signed and encrypted.

### changed
- **Breaking:** `jws::sign`, `jws::sign_async` and `jws::json::sign` take `policy` and
  `registry` after the signer(s). They and the encrypt functions below refuse an
  algorithm, a content encryption, a signing key's curve or an ECDH-ES recipient's curve
  the policy does not list (`PolicyViolation`), so jwz no longer produces tokens its
  profile would refuse.
- **Breaking:** encryption follows RFC 7516's split of what is per recipient from what
  all share. `jwe::Recipient` (formerly `jwe::json::Recipient`, still re-exported there)
  holds a recipient's `alg`, key and header parameters, protected in the compact
  serialization and unprotected in the JSON one. `jwe::encrypt(plaintext, enc,
  &recipient, policy, registry, backend)`; `jwe::json::encrypt(plaintext, &shared,
  recipients, policy, registry, backend)`, where `jwe::json::Shared` holds `enc`, the
  protected header parameters and `aad`.
- **Breaking:** `Profile::with` takes `&Algorithms` and appends its lists without
  duplicates, changing nothing else; it took another profile and formed a union.
- **Breaking:** verification (`verify`, `verify_async`, `verify_with`,
  `verify_with_async`) refuses a key on a curve the profile does not list with
  `PolicyViolation`, and an EdDSA key that states no curve; `verify_with` passes such
  keys over. A key that states no curve is taken to be on its algorithm's registered
  one, so ES256 keys behave as before; `strict()` now refuses ES256 with a
  brainpoolP256r1 key (ti-jwz's `ti()` lists it).
- **Breaking:** `Policy` has the field `signing_curves`; a `Policy` written as a struct
  literal must set it. `strict` and `rfc7518-interop` are built with `Profile::new` and
  `with`, at version 2; what they accept is otherwise unchanged.

### removed
- **Breaking:** `Policy::with` and `ClaimsPolicy::with` (unions of policies): compose
  algorithm lists with `Profile::with`, and set the other fields directly.

### fixed
- A `typ` with the prefix `application/` and a further `/` no longer equals the type without
  the prefix (RFC 7515 §4.1.9, TASK-278): `application/a/b` is not `a/b`.

## Release jwz 0.1.0, 2026-11-06

### added
- New crate: JOSE with an open algorithm registry, pluggable keys and crypto backends, and
  validation profiles (ADR `jwz/docs/adr/0001-jwz.md`). Milestone 1
  starts with `jwa`, an open registry of algorithm, curve and key-type names
  (RFC 7518, RFC 8037; RSA, PBES2, CBC-HMAC and post-quantum names reserved; `none`
  unrepresentable), and `crypto`, the backend traits (ECDSA, EdDSA, ECDH, AEAD, key wrap,
  HMAC, hash, RNG) with async counterparts. The `rsa` feature refuses to build until RSA
  is implemented.
- `crypto::rustcrypto::RustCrypto` (feature `crypto-rustcrypto`): P-256 ECDSA and ECDH,
  Ed25519, AES-GCM, AES Key Wrap, SHA-2 and (feature `hmac`) HMAC on the RustCrypto 0.14
  line; `Send + Sync`; browser randomness on `wasm32-unknown-unknown`.
- `jwk`: JWK (EC, OKP, oct, RSA data model) and JWK Set, RFC 7638 thumbprints, strict
  parsing (duplicate members, base64url) and `Jwk::check` against a registry.
- `keys`: `Signer`, `Verifier`, `KeyAgreement` on RustCrypto's `signature` traits with
  `dyn`-compatible async forms; `SoftwareKey` and `SoftwareAgreementKey` over any
  backend; `MockHsm`, `TestKms` and `FixedRng` (feature `test-util`).
- `jws` (feature `jws`): compact and JSON serializations (RFC 7515), parse under a
  policy, `Jws<Unverified>` → `Jws<Verified>`, `sign`/`sign_async`; `header`: `Header` and
  `HeaderParams`; `profile`: `Policy::check_jws`, `Profile::strict`,
  `Profile::rfc7518_interop`, composition with `with`; `x5c`: chain and `x5t#S256`
  handling, `ChainValidator`.
- `jwe` (feature `jwe`): compact and JSON serializations (RFC 7516), ECDH-ES with the
  Concat KDF (RFC 7518 §4.6), ECDH-ES+A128/192/256KW, `dir`, A128/192/256KW,
  A128/192/256GCM; `Jwe<Encrypted>` → `Jwe<Decrypted>`, `decrypt_async`; `zip`, RSA,
  PBES2 and CBC-HMAC refused by `Policy::check_jwe`; `keys::SymmetricKey`;
  `crypto::Extended` for curves the base backend lacks.
- `jwt` (feature `jwt`): `Claims` with `validate` against `profile::ClaimsPolicy`
  (now part of `Profile`), `Clock`, `SystemClock` (not on wasm32-unknown-unknown, where
  std has no clock and every call would panic), `FixedClock`.
- `Policy::key_agreement_curves`: the curves an ECDH-ES `epk` may be on, checked by
  `Policy::check_jwe`.
- `Policy::require_kid`: a token must name its key with a non-empty `kid`. It replaces
  `Profile::keys` (`KeyConstraints`), which no check ever read: a JWS key's curve is the
  key the caller chooses, and an `epk`'s curve is `key_agreement_curves`.
- Fuzz targets for every parser (`fuzz/`: JWS and JWE compact and JSON, JWK, claims),
  run with `just fuzz-jwz`.
- Verification (`docs/VERIFIED.md`): the Concat KDF core proven equal to SP 800-56A
  §5.8.1 / RFC 7518 §4.6.2 and panic-free in F* (hax), Kani proofs of the base64url round
  trip, the compact splitter, policy and claims composition and the KDF layout,
  compile-fail tests of the type-state; `docs/traceability.md` generated and checked by
  a test; design-time results stamped (`verification/stamps`, `just jwz-recheck`).
- Browser tests (`tests/browser.rs`, `just jwz-browser`, stamped): RFC 7515, RFC 8037 and
  RFC 7520 known answers, key generation, JWS and JWE round trips in headless Chrome.
- `guide`: a guide across the modules, compiled by the doc tests.
- RFC 7517 key use (TASK-220): a JWK Set ignores a key it cannot read (§5) instead of
  failing whole; `key_ops` may not repeat a value or disagree with `use` (§4.3); and
  `use`/`key_ops` bind a key to what it may do, `Jwk::allows(KeyPurpose)`, enforced by
  `SoftwareKey`, `SoftwareAgreementKey`, `SymmetricKey` and JWE encryption, so a key
  marked `enc` no longer signs or verifies (§4.2).
- `concat_kdf` refuses an OtherInfo longer than `usize` (reachable only on 32-bit
  targets), which the F* proof showed the 32-bit length checks alone do not exclude.

## Release ti-cli 0.5.0, 2026-10-22

### security
- rustls-webpki 0.103.16 and webpki-root-certs 1.0.10: certificate paths through the
  distrusted emSign intermediates and the emSign ECC Root CA - G3 are no longer accepted
  for Konnektor and download TLS (RUSTSEC-2026-0382, RUSTSEC-2026-0383).

### added
- Store profiles shared with the other TI tools (spec/store): `--profile`, `TI_PROFILE`,
  `TI_STATE_DIR`, `TI_STORE_KEK_PATH`, `TI_STORE_BACKEND`. `ti profile create` makes a
  profile's keyring and key file; `profile list`, `show`, `use` and `delete --yes`
  manage profiles; `profile rotate` and `profile rewrap --kek-file` manage its keys.
  `ti store doctor [--json] [--deep]` checks a profile without changing it; `store ls`,
  `show [--reveal]`, `rm`, `purge --yes`, `cleanup` and `migrate [--dry-run]` inspect and
  maintain its records. Expired records are removed once a day on their own.
  `TI_STORE_TRACE=1` traces store operations. Store failures have the error kinds
  `store_<code>` with a hint.

### changed
- The download cache is the profile's `cache.db`; `TI_CACHE_DIR` and `--cache-dir` name
  the base of the profiles' caches. The old cache folder is no longer used. `cache clear`
  reports `profile`, `path` and `removed_records`.
- The TSL state and comfort signature IDs are sealed in the profile's `state.db` and are
  kept only once the profile has a keyring; files of earlier versions are read until
  then and moved into the store afterwards. `connector comfort activate` needs a
  keyring.
- `pki verify --profile` is `--validation-profile`; `--profile` selects the store
  profile in every command.
- `pki verify --nist-only` says in its help that the chain must reach a root whose key is
  not brainpool, unlike curl and Java, which take a TSL CA of `tsl bundle --nist-only`
  as an anchor.
- `pki inspect` without a cached TSL no longer calls a TSL-listed issuer untrusted: the
  trust tree says the TSL is not loaded and names `ti pki tsl show --env ENV`, which
  loads it. `inspect` still never downloads.
- `probe` groups the endpoints by access path, TI-VPN and Internet, and says once when
  none of the TI-VPN block answers (`access_paths[].available` in JSON) instead of a row
  of failures; each probe carries `access`. Endpoint names are lowercase kebab-case
  (`idpd-ti`, `fhir-directory`, `erx`, `epa-1`, `popp`, `catalog`), and the internet IDP
  is probed as `idpd-internet`. `TI_PROBE_ENDPOINTS_PATH` files need `access`.
- `connector get cards` and `get certificates` show each card's terminal (CtId and slot);
  handles and terminal IDs longer than 20 characters are shortened in the tables of
  `get cards`, `get certificates`, `get identities` and `get expiration`
  (`0a1b2c3d…7e8f9a0b`), whole with `-v` and in JSON.
- `connector get certificates` names the subject and Telematik-ID once above the table
  when every certificate of the card carries the same, instead of in every row.
- `connector describe card` shows the Telematik-ID of an HBA or SMC-B (from its C.AUT;
  `telematik_id` in JSON), the insert time in local time and the certificates' expiry
  as `valid until` with the date alone. It shows whether each user PIN is verified, needs entry (with
  the tries left), is still a transport PIN or is blocked (CardService GetPinStatus);
  the JSON has `pins`.
- `pki verify --at` judges the OCSP status at that time: a certificate revoked since is
  valid then, with the warning `revoked_after_reference_time`; the revocation line says
  that OCSP answered now and was judged at `--at`.

## Release ti-cli 0.4.0, 2026-10-11

### added
- `tsl show` reports `revoked_since` for a CA the TSL lists as revoked (shown in the
  table); `tsl bundle` leaves such CAs out. `pki verify` knows the codes
  `ca_revoked_in_tsl` and `issued_before_ca_revocation`.
- `pki tsl bundle --connect HOST[:PORT]` and `--cert FILE` (repeatable): only the TSL
  CAs that issued those certificates or are among them, the bundle a client of a TI
  server needs (the ePA Aktensysteme send only their own certificate); `--with-roots`
  adds the roots the selected CAs chain to. `--ca`, `--provider` and `--root` of
  `tsl show` and `tsl bundle` are repeatable (any of the values).
- `--issues TYPE` on `tsl show` and `tsl bundle` (repeatable): the CAs the TSL lets issue
  a certificate type whose name contains TYPE, e.g. `TLS-S` for every TLS server CA;
  `tsl show` reports each CA's `issuable_types`.
- `tsl bundle --nist-only`: only the TSL CAs (and with `--with-roots` roots) whose own
  key is not brainpool.
- `directory login owner|holder|service|ti-provider`: a FHIR-Directory (VZD) access
  token from each Auth-Service endpoint (ti-directory). `owner` by card through the
  IDP-Dienst's Authenticator-Modul flow, or `--regservice-token-path` (a TI-Messenger RegService-OpenID-Token); `holder`,
  `service` and `ti-provider` with client credentials at the directory's Keycloak
  (`--client-id`, `--client-secret-path`, `TI_DIRECTORY_CLIENT_*`). One report for every
  path (`endpoint`, `method`, `access_token`, `expires_at`, the decoded claims), `--token`
  for the bare bearer. Error kinds `directory_error`, `directory_auth_server_error`,
  `directory_unreachable`, `directory_protocol`; IDP failures keep the `idpd_*` kinds;
  `arguments_invalid` for argument combinations clap cannot check. Schema
  `directory login`.
- `probe` checks the environment's FHIR-Directory (kind `directory`): its
  `/owner-authenticate` must redirect to an IDP-Dienst authorization URL.
- `idpd authenticate` and `directory login` check the IDP's certificates (the discovery
  document's signer and `PuK_IDP_SIG`'s) against the TSL with the idp-sig profile and
  OCSP before the card signs (TASK-27): `idp.certificates` in the report, error kind
  `idpd_untrusted`; `--idp-unverified` skips the check and keeps the
  `idp_certificates_unverified` warning. `-vv` logs the body of every non-2xx answer.

### changed
- Names follow gemSpec (decision-5): the profiles `smb-aut` and `idp-sig` are now
  `hci-aut` (Tab_PKI_405 C.HCI.AUT) and `idpd-sig` (role `oid_idpd`); `--profile` and
  `profiles describe` accept a type or profile name in any case, with `.` or `-` and an
  optional `C.` (`C.HCI.AUT`); the `tsl show` field is `issuable_types`; every TSL type
  shows its Tab_PKI_405 name.
- `--nist-only` no longer verifies the trust material without brainpool: the roots walk
  and the TSL are always verified with brainpool, and only the result is narrowed to the
  roots and TSL CAs whose own key is not brainpool. GEM.RCA9 and GEM.RCA10 (reached only
  through brainpool cross certificates) and the TSL's non-brainpool CAs are now part of
  it; `pki verify --nist-only` validates against that subset (TASK-28, TASK-29).
- OCSP responses are cached on disk with the trust material (one hour, never past
  `nextUpdate`; `good` and `revoked` only), for `pki verify`, the TSL signer's status,
  and the IDP certificates of `idpd authenticate` and `directory login`: a second run
  within the hour asks no responder. `pki verify` marks such answers `cached` (JSON
  `chain[].revocation.cached`). `cache clear` removes them too (TASK-2).

## Release ti-cli 0.3.0, 2026-10-10

### added
- `pki inspect --short`: a table row per certificate (subject, expiry, Telematik-ID);
  JSON stays the full report.
- `--nist-only` on `pki verify` and `pki roots list`: verify as a client without brainpool
  would (roots up to the first brainpool signature, no TSL); reports carry
  `trust.nist_only`.
- `pki roots bundle` and `pki tsl bundle`: the trusted roots, and the TSL's CAs a
  verified root signed (with `tsl show`'s filters), as a CA bundle: PEM, or with `--p12`
  a PKCS#12 truststore for Java. `pki tsl export`: the TSL as published, once it
  verified. To stdout or `-o FILE`; the Go `ti`'s `roots bundle`, `tsl intermediates` and
  `tsl fetch`.
- `pki verify --ocsp-responder URL` sends the chain's OCSP requests to one responder,
  e.g. a relay; `--ocsp-max-age DURATION` accepts older responses than ti-pki's 37.5 s.
  The report carries `ocsp` when either is given.
- `identity inspect` and `identity sign`: the SMC-B AUT identity (digitalSignature, no
  contentCommitment, key present) from a PKCS#12 file, a PEM certificate and key, or a
  card at the Konnektor (ExternalAuthenticate); `sign` makes a compact ES256 JWS with
  `x5c` from a JSON object of claims, on brainpoolP256r1 (jwz-brainpool) or P-256. Error
  kinds `identity_not_found`, `key_unsupported`, `claims_invalid`, `header_invalid`,
  `signing_failed`. For `epa` (TASK-24).
- `pki verify-signature --cert --data --signature`: one ECDSA-SHA256 signature, DER or
  r‖s, against a certificate's key (exit 0/1; `signature_malformed`).
- `--p12-password-path FILE` / `TI_P12_PASSWORD_PATH` on `pki inspect`, `pki verify` and
  the identity commands: the PKCS#12 password from a file's first line, off the command
  line. `--p12-password` still wins when given; the default stays `00`.
- `idpd authenticate --env|--idp-url --auth-url <identity>`: the IDP-Dienst's
  Authenticator-Modul flow (ti-idpd) from the relying party's authorization URL to the
  authorization code, with the identity's key signing `BP256R1`. Error kinds
  `idpd_error` (the IDP refused, with its `gematik_*` fields in the message),
  `idpd_unreachable`, `idpd_protocol`; `warnings` carries `idp_certificates_unverified`
  until TASK-27. `identity sign --alg BP256R1` for the IDP's algorithm name.

### changed
- The trust anchor is GEM.RCA7 (ti-pki): `pki roots list` marks it and lists it first.

## Release ti-idpd 0.1.0, 2026-10-10

### added
- New crate: the gematik IDP-Dienst as a Primärsystem's Authenticator-Modul sees it
  (gemSpec_IDP_Dienst V2.2.0, gemSpec_IDP_Frontend V1.7.1). Sans I/O: `discovery`
  (the signed discovery document, verified with its `x5c` signer; `PuK_IDP_SIG` and
  `PuK_IDP_ENC`), `challenge` (the challenge verified and valid, the nested JWT signed
  by a jwz `Signer` and encrypted `ECDH-ES`/`A256GCM` to `PuK_IDP_ENC`, the code from
  the redirect, the IDP's `gematik_*` error members as `IdpError`), `authenticator`
  (the whole flow over a `Transport`), `http` (requests and responses as data). The
  `ureq` feature adds a blocking transport. The IDP's certificates are reported as
  `Warning::IdpCertificatesUnverified` until they are checked against the TSL
  (TASK-27); the relying-party side, SSO and pairing are out of scope.

## Release ti-cli 0.2.0, 2026-10-05

### added
- `ti pki tsl verify FILE`: a TSL file's signature and signer under the embedded TSL
  signer CA, `NextUpdate` (`--grace DAYS`), the signer's OCSP status unless `--offline`
  or `--at`, and with `--previous` the sequence; `--env auto` (default) detects
  production or not. Exit 0 valid, 1 not valid with the gemSpec_PKI result code and the
  `spec/tsl-xmldsig` rule.

### changed
- Trust material is loaded with the TSL verified (`spec/tsl-xmldsig`), the signer's OCSP
  status queried online, and the TSL's `Id` and sequence number kept in the state
  directory so an older list stays rejected (`-v` shows the file; one that cannot be read
  or written is a warning). `trust.tsl_warnings` reports
  `no_ocsp_check`; `pki tsl show` names the signer and its CA. `pki roots list` and
  `pki tsl show` take `--at`, and `pki verify --at` verifies the trust material at that
  time too.
- Every command that needs an environment takes `--env` with `TI_ENV` as its default;
  `probe` too, besides its positional `ENV`, which wins over `TI_ENV` and must agree
  with an explicit `--env`. `TI_ENV=auto` means `prod` for `pki roots list` and
  `pki tsl show`, which have nothing to detect from; `--env auto` there, and `auto` for
  `probe`, are usage errors (`environment_invalid`).
- `pki profiles describe NAME --env ENV` lists the CAs the environment's verified TSL
  allows to issue the profile's types; `pki verify` reports `cert_type_ca_not_authorized`
  and `cert_type_unchecked`.
- `pki verify` shows the TSL as a trust chain of its own under the certificate chain:
  the list, its signer with its OCSP status, and the TSL signer CA (`trust.tsl` in the
  JSON). A responder the TSL lists for the issuing CA's TSP reads "listed in the TSL"
  (`tsl_listed`) and no longer warns.

### fixed
- Names with a multi-valued RDN, such as an HBA's `GN=…+SN=…+SERIALNUMBER=…+CN=…`: `pki
  inspect` showed the whole RDN as the given name and found no common name, and issuer
  names in chains and `tsl show` fell back to the full DN. Every value is now its own field,
  RFC 4514 escapes (`\+`, `\C3\A4`) are undone, and a name without a common name shows as
  "given name surname".
- `pki inspect` labels every name attribute x509-cert prints: TITLE, POSTALCODE, EMAIL,
  PSEUDONYM, INITIALS, DESCRIPTION, DNQUALIFIER, UID, DC and organizationIdentifier
  showed unlabelled, the latter as hex DER (`#0c07…`), which is now decoded to its text.

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
