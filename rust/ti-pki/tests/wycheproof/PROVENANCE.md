# Wycheproof test vectors

From [C2SP/wycheproof](https://github.com/C2SP/wycheproof), `testvectors_v1/`, unmodified.
Licence: Apache-2.0. Run by [`../wycheproof.rs`](../wycheproof.rs) against ti-pki's
signature algorithms; `acceptable` cases are not asserted.

| File | Commit | Added |
| --- | --- | --- |
| `ecdsa_secp256r1_sha256_test.json`, `ecdsa_secp384r1_sha384_test.json`, `ecdsa_brainpoolP256r1_sha256_test.json`, `ecdsa_brainpoolP384r1_sha384_test.json` | `3fa63dd0344abb611f1fb1d77e119938603ea230` | `146716a6`, 2026-09-23 |
| `rsa_signature_2048_sha256_test.json`, `rsa_signature_3072_sha384_test.json`, `rsa_signature_4096_sha512_test.json`, `rsa_pss_2048_sha256_mgf1_32_test.json`, `rsa_pss_2048_sha384_mgf1_48_test.json`, `rsa_pss_4096_sha512_mgf1_64_test.json` | unknown (not recorded) | `4916a869`, 2026-09-23 |

Refresh: download the same files from a newer commit of `testvectors_v1/`, record the
commit above (and in the header of `../wycheproof.rs`), run `cargo test -p ti-pki
--all-features --test wycheproof`.
