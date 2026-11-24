# Provenance of the ti-pkcs12 fixtures

All keys here are test keys; none protects anything.

## The OpenSSL-generated files (this directory)

- **Written by** `generate_test_data.sh` (`just test-pkcs12` in `rust/`), with OpenSSL 4.1.0 on
  2026-11-24 (TASK-419, TASK-420). A plain run writes only what is missing; `FORCE=1` writes
  the certificates and `truncated.p12` byte for byte again, the `.p12` files with new salts and
  IVs and `random.p12` with new data (the script names them), so their digests in
  `tests/decode.rs` follow.
- **`keys/`:** the TEST-ONLY CA, server and EC keys, as `go/pkcs12/testdata` held them in
  43e97a55 (2026-02-05; the EC key converted from SEC1 to PKCS#8, the same key).
- **Certificates:** serial numbers from `serial_of` (`spec/fixtures.sh`), fixed instants. Until
  TASK-419 they had the serial numbers of 43e97a55.
- **`high-iter.p12`:** 600,000 iterations for its MAC and for both PBKDF2 derivations
  (`-iter 600000`), 1,800,000 of the 10,000,000 a decode may spend (P12-036). Every other file
  has OpenSSL's default of 2048.
- **`README.md`:** Go's description of the set from `go/pkcs12/testdata`, which describes Go's
  tests of then; kept for the table of files.
- **History:** the set was copied from `go/pkcs12/testdata` in 153a69a0 (2026-09-27) and removed
  from `go/pkcs12` in 06cfb300 (2026-10-13); `go/pkcs12` tests against the generated corpus of
  `spec/pkcs12`.

## `legacy/`

`cgm.p12`, `secunet.p12` and their password files: two connector client identities as the
vendors (CGM KoCoBox, secunet) deliver them, BER-encoded, RC2-40 and 3DES, HMAC-SHA-1 MAC. No
tool regenerates them. The same files, byte for byte, are `spec/pkcs12/testdata/vendor`
(described in its `README.md`, pinned by its `SHA256SUMS`).

## `go-baseline.json`

The certificates, keys, attributes and pairs `go/pkcs12` decodes from every `.p12` here and in
`legacy/`, or the conformance code of its error. Written by `baseline/` (Go, `go/pkcs12` and the
standard library), which `generate_test_data.sh` runs on every run; never edited by hand. It
depends on the content of the files, not on their salts and IVs, so a `FORCE=1` rebuild leaves
it as it is.

**To add a file:** add it to `generate_test_data.sh` and run it. It writes that file and its
entry in `go-baseline.json`; the file's digest goes into `tests/decode.rs`.

## `truststore/`

`openssl-jdktrust.p12`, a Java truststore as OpenSSL 4 writes it, added in 21633ca9
(2026-10-10). `truststore/README.md` gives its content and the commands that write it; rerun
them to refresh it.
