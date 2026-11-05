# unsafe in the cores' dependencies

The crates with `unsafe` code that the cores may depend on, and why
([design.md, section 8](./design.md#8-dependencies)). `just unsafe-free` reads the three
tables below: the cores with the features their builds may enable, the targets, and the
exceptions. A crate missing here, or present in another version than the one approved,
fails the check; review its `unsafe` (`cargo run -p unsafe-audit -- inventory`) and ask
the maintainer before adding or changing a row.

Most rows are cryptography (CPU intrinsics and constant-time barriers that safe Rust cannot
express), the operating system's random source, and the reference casts and unchecked UTF-8
conversions of RustCrypto's and serde's encoders. Crates marked *replace* have their own
task.

## Cores

| Core | Features |
|---|---|
| ti-types | std, serde |
| ti-cache | – |
| ti-pki | brainpool, rsa, load, os, dangerous-nonprod |
| ti-pkcs12 | legacy, encode |
| ti-connector-client | – |
| ti-report | – |
| jwz | std, jws, jwe, jwt, crypto-rustcrypto, hmac |
| jwz-brainpool | – |
| ti-jwz | legacy |
| ti-idpd | – |
| ti-directory | – |

## Targets

| Target |
|---|
| aarch64-apple-darwin |
| x86_64-unknown-linux-musl |
| x86_64-pc-windows-gnu |
| wasm32-unknown-unknown |

## Exceptions

| Crate | Version | Why | Approved |
|---|---|---|---|
| aes | 0.9.3 | AES-NI and ARMv8 AES intrinsics: AES-GCM (jwz JWE), AES-CBC (PKCS#12) | 2026-10-29 |
| base16ct | 1.0.0 | constant-time hex: unchecked UTF-8 of the ASCII it wrote | 2026-10-29 |
| base64 | 0.23.1 | only the generated Konnektor bindings: unchecked UTF-8 of its own output; *replace* with base64ct: TASK-159 | 2026-10-29 |
| base64ct | 1.8.3 | constant-time Base64: unchecked UTF-8 of the ASCII it wrote | 2026-10-29 |
| block-buffer | 0.12.1 | the block buffer of every hash (SHA-1, SHA-2): unchecked slices and uninitialised blocks | 2026-10-29 |
| cmov | 0.5.4 | constant-time conditional moves in inline assembly, so the compiler cannot branch on secrets | 2026-10-29 |
| const-oid | 0.10.2 | cast of `[u8]` to its `repr(transparent)` OID reference | 2026-10-29 |
| cpufeatures | 0.3.1 | CPU feature detection for the intrinsics above (cpuid, sysctl, getauxval) | 2026-10-29 |
| crypto-bigint | 0.7.10 | casts between `repr(transparent)` limb and word types (ECDSA, RSA arithmetic) | 2026-10-29 |
| curve25519-dalek | 5.0.0 | SIMD backends of Ed25519 (jwz EdDSA) | 2026-10-29 |
| der | 0.8.2 | casts of `str`/`[u8]` to their `repr(transparent)` ASN.1 string types | 2026-10-29 |
| elliptic-curve | 0.14.1 | casts of `repr(transparent)` non-zero scalars and non-identity points | 2026-10-29 |
| flagset | 0.4.7 | construction of flag sets from declared bits (der's bit strings) | 2026-10-29 |
| getrandom | 0.4.3 | the operating system's random source (getrandom, getentropy, ProcessPrng system calls); in the browser Crypto.getRandomValues | 2026-10-29 |
| hybrid-array | 0.4.15 | fixed-size arrays of generic length for every RustCrypto type: casts, uninitialised arrays | 2026-10-29 |
| inout | 0.2.2 | in-place in/out buffers of the block ciphers: raw pointers | 2026-10-29 |
| itoa | 1.0.18 | integer formatting into an uninitialised buffer (serde_json) | 2026-10-29 |
| libc | 0.2.189 | C library declarations for getrandom and cpufeatures | 2026-10-29 |
| memchr | 2.8.3 | SIMD byte search (serde_json, quick-xml) | 2026-10-29 |
| num-traits | 0.2.19 | float-to-int conversion after its range check (crypto-bigint) | 2026-10-29 |
| once_cell | 1.21.4 | wasm32 only: wasm-bindgen's lazy statics | 2026-10-29 |
| pem-rfc7468 | 1.0.0 | unchecked UTF-8 of the PEM it wrote | 2026-10-29 |
| polyval | 0.7.3 | carry-less multiplication intrinsics (CLMUL, PMULL) for GHASH in AES-GCM | 2026-10-29 |
| rustls-pki-types | 1.15.1 | transmute of an IPv6 address from `[u16; 8]` to `[u8; 16]` | 2026-10-29 |
| serde | 1.0.229 | unchecked UTF-8 of formatted numbers | 2026-10-29 |
| serde_core | 1.0.229 | unchecked UTF-8 of formatted numbers | 2026-10-29 |
| serde_json | 1.0.151 | unchecked UTF-8 and unreachable hints in the serializer | 2026-10-29 |
| sha1 | 0.11.0 | SHA-1 intrinsics (SHA-NI, ARMv8): OCSP CertIDs, PKCS#12 MAC and KDF | 2026-10-29 |
| sha2 | 0.11.0 | SHA-256 and SHA-512 intrinsics and assembly | 2026-10-29 |
| subtle | 2.6.1 | the optimisation barrier of constant-time choices (volatile read) | 2026-10-29 |
| unicode-ident | 1.0.26 | wasm32 only: unchecked table lookup in wasm-bindgen's support crate | 2026-10-29 |
| wasm-bindgen | 0.2.128 | wasm32 only: JavaScript interop for Crypto.getRandomValues (getrandom) | 2026-10-29 |
| zeroize | 1.9.0 | volatile writes that wipe secrets without the compiler removing them | 2026-10-29 |
| zmij | 1.0.23 | float formatting in serde_json into an uninitialised buffer | 2026-10-29 |
