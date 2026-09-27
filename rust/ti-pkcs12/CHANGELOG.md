# Changelog

## [Unreleased]

- PKCS#12 decoding (`decode`, `is_pkcs12`, `Pkcs12::pairs`): DER and BER, the password
  integrity mode (HMAC-SHA-1/2), PBES2 with AES-CBC, and behind the default `legacy`
  feature the PKCS#12 PBEs with 3DES and RC2. Parity with `go/pkcs12` on its fixtures,
  without its OpenSSL conversion for BER files.
