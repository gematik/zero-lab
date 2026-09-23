# Changelog

## [Unreleased]

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
