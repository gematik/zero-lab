# Changelog

## [Unreleased]

- PKCS#12 decoding (`decode`, `is_pkcs12`, `Pkcs12::pairs`): DER and BER, the password
  integrity mode (HMAC-SHA-1/2), PBES2 with AES-CBC, and behind the default `legacy`
  feature the PKCS#12 PBEs with 3DES and RC2. Parity with `go/pkcs12` on its fixtures,
  without its OpenSSL conversion for BER files.
- `Error::is_wrong_password`.
- `Pkcs12::encryption` names what each algorithm protects (`Encryption`, `Target`).
- Feature `encode`: `encode` writes certificates and keys with their attributes as DER
  with PBES2 AES-256-CBC (PBKDF2-HMAC-SHA-256, 2048 iterations) and an HMAC-SHA-256 MAC,
  the OpenSSL 3 defaults; the caller supplies the randomness.
