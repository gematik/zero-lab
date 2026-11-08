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
| [8725](https://www.rfc-editor.org/rfc/rfc8725) | JSON Web Token Best Current Practices | §3.4: cryptographic inputs validated (peer points on the curve) |

Every requirement jwz implements is traced to the tests that prove it:
[`docs/traceability.md`](https://github.com/gematik/zero-lab/blob/main/rust/jwz/docs/traceability.md).

## What's in 0.1

- `jwz::jwa`: the algorithm registry;
- `jwz::crypto`: the backend traits (sync and async) and the RustCrypto backend
  (P-256 ES256 and ECDH, Ed25519, AES-GCM, AES Key Wrap, SHA-2, HMAC);
- `jwz::jwk`: JWK and JWK Set, RFC 7638 thumbprints, strict parsing;
- `jwz::keys`: key traits on RustCrypto's `signature` traits, `SoftwareKey`, and test
  doubles for HSM and KMS signers (`test-util`);
- `jwz::jws`: compact and JSON serializations, `Jws<Unverified>` → `Jws<Verified>`,
  sync and async signing;
- `jwz::jwe`: compact and JSON serializations, ECDH-ES (direct and with A128/192/256KW),
  `dir`, A128/192/256KW, A128/192/256GCM; `Jwe<Encrypted>` → `Jwe<Decrypted>`, async key
  agreement; further curves through `crypto::Extended`;
- `jwz::jwt`: claims, `ClaimsPolicy`, `Clock`;
- `jwz::profile`: `Policy` (the single acceptance check, for what jwz parses, verifies,
  signs and encrypts), profiles as explicit lists built from constants (`ECDSA_NIST`,
  `EDDSA`, `ECDH_ES_P256`, `AES_GCM`, ...) with `Profile::new` and `Profile::with`, and
  the `strict` and `rfc7518-interop` profiles; `jwz::x5c`: chain decoding and the
  `ChainValidator` seam.

## Design principles

- **Strict by default.** Every parse, signature and encryption takes a policy; the
  default accepts only modern algorithms, and anything permissive is an explicit choice.
  A profile lists its algorithms and the curves its keys may be on, and jwz produces
  nothing its profile would refuse. `none` cannot be expressed, and the token header
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

Copyright 2026 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/rust/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
