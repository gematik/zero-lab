# jwz

JOSE for Rust: JWS, JWE, JWK and JWT with an open algorithm registry, pluggable keys and
crypto backends, and validation profiles as a policy layer. Pure Rust on the RustCrypto
0.14 line by default, `no_std` + `alloc`; builds for `wasm32-unknown-unknown` and is
tested in headless Chrome.

Start with the guide (`jwz::guide` in the API documentation, [`docs/guide.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/guide.md)).

## Standards

| RFC | Title | In jwz |
| --- | --- | --- |
| [7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature (JWS) | compact and JSON serializations |
| [7516](https://www.rfc-editor.org/rfc/rfc7516) | JSON Web Encryption (JWE) | compact and JSON serializations |
| [7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key (JWK) | JWK and JWK Set |
| [7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms (JWA) | ES256; ECDH-ES (P-256, direct and +A128/192/256KW), A128/192/256KW, `dir`, A128/192/256GCM; HS256/384/512 (feature `hmac`). Not yet: P-384, P-521, RSA |
| [7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token (JWT) | claims and their validation |
| [7520](https://www.rfc-editor.org/rfc/rfc7520) | Examples of Protecting Content Using JOSE | test vectors |
| [7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprint | thumbprints |
| [8037](https://www.rfc-editor.org/rfc/rfc8037) | CFRG Curves in JOSE | Ed25519 keys; the polymorphic `EdDSA` (deprecated by RFC 9864) |
| [9864](https://www.rfc-editor.org/rfc/rfc9864) | Fully-Specified Algorithms for JOSE and COSE | `Ed25519` (in `strict`); `EdDSA` deprecated, accepted only where a profile lists it; `Ed448` registered, not implemented |
| [8725](https://www.rfc-editor.org/rfc/rfc8725) | JSON Web Token Best Current Practices | traced in full: what jwz meets and what is the application's, in the [guide](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/guide.md#rfc-8725-what-jwz-does-and-what-is-yours) |
| [draft-ietf-oauth-rfc8725bis-10](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/10/) | JSON Web Token Best Current Practices (revision of RFC 8725) | followed at revision -10, its additions traced in the same guide section; a later revision is checked when it appears |

Every requirement jwz implements is traced to the tests that prove it:
[`docs/traceability.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/traceability.md).

## What's in it

- `jwz::jwa`: the algorithm registry, with RFC 9864's fully specified `Ed25519` (the
  polymorphic `EdDSA` is deprecated and kept for older peers);
- `jwz::crypto`: the backend traits (sync and async) and the RustCrypto backend
  (P-256 ES256 and ECDH, Ed25519, AES-GCM, AES Key Wrap, SHA-2, HMAC);
- `jwz::jwk`: JWK and JWK Set, RFC 7638 thumbprints, strict parsing, and the
  `KeyResolver` / `AsyncKeyResolver` seam through which a verifier gets keys the host
  fetches and caches (jwz never fetches);
- `jwz::keys`: key traits on RustCrypto's `signature` traits, `SoftwareKey`, and test
  doubles for HSM and KMS signers (`test-util`);
- `jwz::jws`: compact and JSON serializations, `Jws<Unverified>` → `Jws<Verified>`,
  sync and async signing, and `verify_with` / `verify_with_async` over resolved keys;
- `jwz::jwe`: compact and JSON serializations, ECDH-ES (direct and with A128/192/256KW),
  `dir`, A128/192/256KW, A128/192/256GCM; `Jwe<Encrypted>` → `Jwe<Decrypted>`, async key
  agreement; further curves through `crypto::Extended`;
- `jwz::jwt`: claims, `ClaimsPolicy`, `Clock` (any `Fn() -> u64` is one);
- `jwz::profile`: `Policy` (the single acceptance check, for what jwz parses, verifies,
  signs and encrypts: algorithms, key curves and headers), profiles as explicit lists
  built from constants (`ECDSA_NIST`, `ED25519`, `ECDH_ES_P256`, `AES_GCM`, ...) with
  `Profile::new` and `Profile::with`, and the `strict` and `rfc7518-interop` profiles;
  `jwz::x5c`: chain decoding and the `ChainValidator` seam;
- errors with a stable code and fixed text, carrying a host's own cause where its
  resolver or validator failed.

What changed from release to release:
[`ReleaseNotes.md`](https://github.com/gematik/zero-lab/blob/main/rust/ReleaseNotes.md).

## Design principles

- **Strict by default.** Every parse, signature and encryption takes a policy; the
  default accepts only modern algorithms, and anything permissive is an explicit choice.
  A profile lists its algorithms and the curves its keys may be on, and jwz produces
  nothing its profile would refuse: not an algorithm, a key curve or a header (`typ`,
  `kid`, key references) it does not allow. `none` cannot be expressed, and the token header
  never picks the algorithm: the key does.
- **Trust in the types.** A `Jws<Unverified>` has no payload and a `Jwe<Encrypted>` no
  plaintext; they appear only after verification or decryption.
- **Keys as functions.** Signing and key agreement go through traits, sync and async, so
  HSMs, smartcards and remote signers work without handing over key bytes.
- **Open, pluggable crypto.** Algorithms live in an open registry and the primitives behind
  backend traits; the default backend is pure Rust, and the core builds without any.
- **Small and portable.** `no_std` + `alloc`, no network I/O, no `unsafe`
  (`#![forbid(unsafe_code)]`), and `wasm32-unknown-unknown` as a first-class target.

The reasoning is in the design record, [`docs/adr/0001-jwz.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/adr/0001-jwz.md).

## How it is checked

- **Specification tests:** the requirements, examples and known answers of the RFCs above,
  and Wycheproof vectors for the primitives behind the backend traits. Tests are named after the requirement they prove, and
  every reference is traced to its tests in
  [`docs/traceability.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/traceability.md).
- **Fuzzing:** a fuzz target per parser (compact and JSON JWS and JWE, JWK, claims).
- **Formal verification:** the Concat KDF is proven correct for every input in F* (via
  hax), and the parsing invariants (base64url, compact splitting, policy composition) are
  model-checked with Kani. Two compile-fail tests prove the type-state. Each result is
  stamped with the hash of its inputs, and the build fails when an input changed after
  the proof last ran. Scope and limits: [`docs/VERIFIED.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/VERIFIED.md).
- **Mutation testing:** a release needs a minimum mutation score, measured on the code
  as released.
- **In the browser:** known answers and round trips in headless Chrome on
  `wasm32-unknown-unknown`.
- **Minimal, verified dependencies:** each one evaluated before it is added, and the
  tree audited with `cargo vet` and `cargo deny`:
  [`docs/dependencies.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/dependencies.md).

## Features

| Feature | Default | What |
| --- | --- | --- |
| `std` | yes | `SystemClock` (not on wasm32-unknown-unknown), std error integration |
| `jws`, `jwe`, `jwt` | yes | the token formats |
| `crypto-rustcrypto` | yes | the pure-Rust backend |
| `hmac` | no | HS256/384/512 |
| `rsa` | no | reserved: refuses to build until RSA is implemented |
| `test-util` | no | test signers and fixed random sources for downstream tests |

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
