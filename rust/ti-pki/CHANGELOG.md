# Changelog

## [Unreleased]

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
- `Env` and `Tier` now come from `ti-types` and are re-exported.
- Crate skeleton.
