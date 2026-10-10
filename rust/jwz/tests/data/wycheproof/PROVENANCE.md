# Wycheproof test vectors

From [C2SP/wycheproof](https://github.com/C2SP/wycheproof), `testvectors_v1/`, commit
`12fd3aaf33eb5fa1f52e026912ee00c054f9d984`, unmodified. Licence: Apache-2.0.

| File | Used by |
| --- | --- |
| `ecdsa_secp256r1_sha256_p1363_test.json` | ES256 through JWK parsing and `SoftwareKey` |
| `ed25519_test.json` | EdDSA through JWK parsing and `SoftwareKey` |
| `ecdh_secp256r1_ecpoint_test.json` | P-256 ECDH of the RustCrypto backend |
| `aes_gcm_test.json` | A128/192/256GCM (96-bit IV, 128-bit tag groups only) |
| `aes_wrap_test.json` | A128/192/256KW |

Refresh: download the same files from a newer commit, update the hash above, run
`cargo test -p jwz --test wycheproof`.
