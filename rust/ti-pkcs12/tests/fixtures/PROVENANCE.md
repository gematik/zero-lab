# Provenance of the ti-pkcs12 fixtures

All keys here are test keys; none protects anything.

## The Go fixtures (this directory, `legacy/`)

- **Source:** `go/pkcs12/testdata` and `go/pkcs12/legacy/testdata` of this repository, copied
  unchanged in 153a69a0 (2026-09-27). Go's copies were created in 43e97a55 (2026-02-05) and
  deafd001 (2026-02-06) and removed from `go/pkcs12` in 06cfb300 (2026-10-13), so these files are
  now the only copy of the OpenSSL-generated set. `README.md` and `generate_test_data.sh` are Go's
  and describe Go's tests; they are kept unchanged because `tests/decode.rs` pins every copied
  file by SHA-256 (`fixtures_are_the_go_ones`).
- **The OpenSSL-generated files** (`*.p12` and `*.pem` here): written by `generate_test_data.sh`
  with the OpenSSL of 2026-02-05; the exact OpenSSL version is unknown. Private keys and CSRs
  were not copied.
- **`legacy/cgm.p12`, `legacy/secunet.p12`** and their password files: two connector client
  identities as the vendors (CGM KoCoBox, secunet) deliver them, BER-encoded, RC2-40 and 3DES,
  HMAC-SHA-1 MAC. No tool regenerates them. The same files, byte for byte, are
  `spec/pkcs12/testdata/vendor` (described in its `README.md`, pinned by its `SHA256SUMS`).
- **`go-baseline.json`:** the certificates, keys, attributes and pairs `go/pkcs12`'s decoder
  reported for each file, written in 153a69a0 (2026-09-27). The program that wrote it was not
  committed; for the two BER files Go read an `openssl pkcs12 -legacy` re-export, which is why
  `tests/decode.rs` compares their attributes against `openssl pkcs12 -info` instead.

**Refresh:** none is planned: the files are pinned, and regenerating them changes every digest
and the baseline. To replace them, run `generate_test_data.sh` in an empty directory, copy the
`.p12` and certificate files here, update the digests in `tests/decode.rs` and rewrite
`go-baseline.json` from `go/pkcs12`'s decoder (`go/pkcs12` itself now tests against the
generated corpus of `spec/pkcs12`).

## `truststore/`

`openssl-jdktrust.p12`, a Java truststore as OpenSSL 4 writes it, added in 21633ca9
(2026-10-10). `truststore/README.md` gives its content and the commands that write it; rerun
them to refresh it.
