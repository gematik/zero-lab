# Wycheproof test vectors

From [C2SP/wycheproof](https://github.com/C2SP/wycheproof), `testvectors_v1/`, commit
`12fd3aaf33eb5fa1f52e026912ee00c054f9d984` (the same as jwz's), unmodified. Licence:
Apache-2.0.

| File | Used by |
| --- | --- |
| `ecdsa_brainpoolP256r1_sha256_p1363_test.json` | `BP256R1` through JWK parsing and `SoftwareKey`, `ES256` through `BrainpoolEs256Key` |
| `ecdh_brainpoolP256r1_test.json` | BP-256 ECDH of `Bp256`; public keys in the canonical uncompressed SubjectPublicKeyInfo only (other encodings are X.509 parsing tests, not ECDH) |

Refresh: download the same files from a newer commit, update the hash above, run
`cargo test -p jwz-brainpool --test wycheproof`.
