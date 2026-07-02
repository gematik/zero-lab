# Provenance: Wycheproof brainpoolP256r1 ECDSA test vectors

`ecdsa_brainpoolP256r1_sha256_test.json` is vendored verbatim from Project
Wycheproof (C2SP/wycheproof).

- Source: `testvectors_v1/ecdsa_brainpoolP256r1_sha256_test.json`
- Upstream commit: `878e5366008753df2064d40c49f8e2f50f9c6af7`
- File SHA-256: `0c1bb62a715cf20a0de88d5e81d05dbd8d0b439e4e8edd88d2229e98961583d4`
- Schema: `ecdsa_verify_schema_v1.json` (485 tests)

Each test group carries an ECDSA public key (uncompressed `04‖x‖y` hex) and a set
of `{msg, sig (ASN.1 DER), result}` cases. The loader verifies each signature
with `bp256.Verify` and asserts it matches `result` (`valid` must verify,
`invalid` must not; `acceptable` may go either way and is treated as a soft
expectation — see the loader for the exact policy).
