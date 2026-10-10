# jwz dependencies

Every dependency, what it does for jwz and why it is not written inline. Audit status is
the workspace's `cargo vet` state (`rust/supply-chain/`): *audited* by an imported audit
set, or *exempted* (trusted without a recorded audit, listed by `just vet-suggest`).

## Always

| Crate | What for | Why not inline | Vet |
| --- | --- | --- | --- |
| `zeroize` | wiping secrets (private keys, CEKs, shared secrets) on drop | compiler-proof volatile writes are subtle | exempted |
| `serde`, `serde_json` (no_std, `alloc`) | JSON objects of JWKs, headers and claims | a JSON parser is large and security-relevant; serde_json is the most used and fuzzed one | exempted |
| `base64ct` | base64url, strict and constant-time | constant-time decoding is easy to get wrong | exempted |
| `signature` | RustCrypto's `Signer`/`Verifier`, which jwz's key traits build on | the point is to share RustCrypto's traits (ADR 0001) | exempted |

## `crypto-rustcrypto` (default backend)

| Crate | What for | Why not inline | Vet |
| --- | --- | --- | --- |
| `p256` | P-256 ECDSA (ES256) and ECDH | curve arithmetic is never hand-written here (no new primitives) | exempted |
| `ed25519-dalek` (`fast`, `zeroize`) | Ed25519 (EdDSA); `fast` = precomputed tables, speed before size | as above | exempted |
| `sha2` | SHA-256/384/512 | as above | exempted |
| `aes-gcm` (`aes`) | A128/192/256GCM | as above | exempted |
| `aes-kw` | AES Key Wrap (RFC 3394) for A*KW and ECDH-ES+A*KW | as above; jwz adds the RFC 3394 minimum length the crate does not enforce | exempted |
| `getrandom` | the operating system's random source; `Crypto.getRandomValues` on `wasm32-unknown-unknown` (`wasm_js`, enabled for that target only) | the only portable OS randomness; replaceable through `RustCrypto::with_rng` | exempted |

Transitive crates of note: `curve25519-dalek` (Ed25519 arithmetic), `elliptic-curve`,
`ecdsa`, `primeorder` (P-256 arithmetic), `aes`, `ghash`, `r-efi` (getrandom on UEFI
only), `wasm-bindgen`/`js-sys` (browser randomness only).

## Optional

| Crate | Feature | What for | Vet |
| --- | --- | --- | --- |
| `hmac` | `hmac` | HS256/384/512 | exempted |
| `subtle` | `hmac` | constant-time MAC comparison | exempted |

## Proof only (`cfg(hax)`)

| Crate | What for | Vet |
| --- | --- | --- |
| `hax-lib` (`macros`) | the pre- and postconditions of the Concat KDF core that F* proves (`docs/VERIFIED.md`); compiled only when hax extracts jwz, never in a build, but present in `Cargo.lock` with `hax-lib-macros`, `hax-lib-macros-types`, `num-bigint`, `num-integer` and `uuid` | exempted |

## Development only

`futures-lite` (driving async tests), `serde_json` with `std` (reading test vectors).

## Never

`openssl`, `ring`, `aws-lc-rs` and `cryptoki` must not appear in jwz's tree;
`just jwz-backends` fails if they do. A backend that needs one is a crate of its own.
