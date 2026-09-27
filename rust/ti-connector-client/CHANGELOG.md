# Changelog

## [Unreleased]

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
  PDF/A; several documents per job), `verify`, `job_number`, `stop`, comfort signature
  (`activate_comfort`, `deactivate_comfort`, `mode`). `Connector::encryption`
  (EncryptionService 6.1): `encrypt` (CMS for recipients' certificates) and `decrypt`
  (with the card's C.ENC; the plaintext's media type is required, the Konnektor checks
  it).
- A session recorded with an eHEX Konnektor replayed offline (`tests/recorded.rs`):
  every request byte for byte as the Konnektor accepted it. The e2e tests record new
  sessions with `TI_TEST_KON_RECORD_DIR`.
