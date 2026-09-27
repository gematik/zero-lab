# Changelog

## [Unreleased]

- `Dotkon`: the `.kon` format of the Go and Kotlin clients, with `${NAME}` expanded
  only in credentials, only as plain names, and never from unset variables.
- `ServiceDirectory`: `connector.sds` parsing, version choice per binding, endpoint
  rewriting, and loading through a `ti_cache::Cache`.
- `Connector` over a caller-supplied `Transport` with short and long `Timeouts`;
  one generic SOAP call for every generated operation; faults with the gematik error
  trace read leniently.
- `Connector::cards`: `list` and `get` (EventService 7.2).
- `Connector::certificates`: `read`, `read_all` (ECC, then RSA where present),
  `expiration`, `verify` (CertificateService 6.0); `CardCertificate` with the parsed
  certificate, its admission and Telematik-ID.
- `Connector::pins`: `status`, `verify`, `change` (CardService 8.1); `PinType`.
- `Connector::auth`: `external_authenticate` (AuthSignatureService 7.4), ECDSA
  signatures returned raw (R‖S) also from Konnektors that answer in DER.
- Generated bindings (`api`) for EventService 7.2, CardService 8.1 and 8.2,
  CertificateService 6.0, AuthSignatureService 7.4, SignatureService 7.5 and 7.4,
  EncryptionService 6.1.
