# Provenance of the ti-pkcs12 fixtures

All keys here are test keys; none protects anything.

## The Go fixtures (this directory, `legacy/`)

- **Source:** `go/pkcs12/testdata` and `go/pkcs12/legacy/testdata` of this repository, copied
  unchanged in 153a69a0 (2026-09-27). Go's copies were created in 43e97a55 (2026-02-05) and
  deafd001 (2026-02-06) and removed from `go/pkcs12` in 06cfb300 (2026-10-13), so these files are
  now the only copy of the OpenSSL-generated set. `README.md` is Go's and describes Go's tests;
  it is kept unchanged because `tests/decode.rs` pins every copied file by SHA-256
  (`fixtures_are_the_go_ones`).
- **The OpenSSL-generated files** (`*.p12` and `*.pem` here): written in 43e97a55 with the
  OpenSSL of 2026-02-05 (version unknown), by commands the script committed then did not match
  (another password, friendly names, iteration counts). `generate_test_data.sh` was rewritten
  in TASK-412 to write each of them as it is.
- **`keys/`:** the TEST-ONLY CA, server and EC keys of those files, as `go/pkcs12/testdata` held
  them in 43e97a55 (the EC key converted from SEC1 to PKCS#8, the same key). A plain run of
  `generate_test_data.sh` writes only what is missing; `FORCE=1` writes the certificates and
  `truncated.p12` byte for byte again, the `.p12` files with new salts and IVs and
  `random.p12` with new data (the script names them), so their digests in `tests/decode.rs`
  follow while `go-baseline.json` holds.
- **`legacy/cgm.p12`, `legacy/secunet.p12`** and their password files: two connector client
  identities as the vendors (CGM KoCoBox, secunet) deliver them, BER-encoded, RC2-40 and 3DES,
  HMAC-SHA-1 MAC. No tool regenerates them. The same files, byte for byte, are
  `spec/pkcs12/testdata/vendor` (described in its `README.md`, pinned by its `SHA256SUMS`).
- **`go-baseline.json`:** the certificates, keys, attributes and pairs `go/pkcs12`'s decoder
  reported for each file, written in 153a69a0 (2026-09-27). The program that wrote it was not
  committed; for the two BER files Go read an `openssl pkcs12 -legacy` re-export, which is why
  `tests/decode.rs` compares their attributes against `openssl pkcs12 -info` instead.

**Refresh:** none is planned: the files are pinned. To add a file, add it to
`generate_test_data.sh` and run it; it writes only that file, whose digest goes into
`tests/decode.rs` and whose decoding by `go/pkcs12` goes into `go-baseline.json`. A `FORCE=1`
rebuild changes the digests of the randomised files only (`go/pkcs12` itself now tests against
the generated corpus of `spec/pkcs12`).

## `truststore/`

`openssl-jdktrust.p12`, a Java truststore as OpenSSL 4 writes it, added in 21633ca9
(2026-10-10). `truststore/README.md` gives its content and the commands that write it; rerun
them to refresh it.
