# What is verified in jwz, and how

Four kinds of evidence, each with a clear boundary. Every design-time result is stamped
in `verification/stamps/` with the SHA-256 of its inputs; `cargo test -p jwz --test
stamps` (part of `just check`) fails when an input changed after the proof last ran, and
`just jwz-recheck` reruns what is stale.

## 1. F*: the Concat KDF, for every input (hax)

`src/jwe/ecdh.rs`, module `kdf`: `be32`, `other_info` and `rounds`, extracted by hax
0.4.2 (`just verify-hax-jwz`) to `verification/hax/extraction/` and checked by F*
2025.10.06 against `verification/hax/Jwz.Kdf.Spec.fst`, a transcription of NIST SP
800-56A Rev. 2 §5.8.1 and RFC 7518 §4.6.2.

| Function | Proven |
| --- | --- |
| `be32(n)` | equals the 32-bit big-endian encoding of `n` |
| `other_info(alg, apu, apv, bits)` | equals `Datalen(alg) ‖ alg ‖ Datalen(apu) ‖ apu ‖ Datalen(apv) ‖ apv ‖ BE32(bits)`, for all inputs whose lengths fit 32 bits and whose total fits `usize` |
| `rounds(h, z, oi, reps, out)` | appends `H(BE32(i) ‖ Z ‖ OtherInfo)` for `i = 1, …, reps`, in order, for every hash `h` |
| all three | panic-free (no overflow, no out-of-bounds) on 32-bit and 64-bit targets |

Boundary:

- The hash is a parameter (`kdf::Digest`): the proof holds for every hash. SHA-256 itself
  is RustCrypto's `sha2`, covered by its own test vectors and the RFC 7518 Appendix C
  vector in jwz's tests.
- `concat_kdf`, the public wrapper, is not extracted: it checks the lengths (the
  preconditions above, including the total for 32-bit targets, found by this proof),
  computes `reps = ceil(key_len / hash_len)`, keeps secrets in zeroizing buffers and
  truncates to `key_len`. A unit test checks that layout exhaustively for every key
  length up to three rounds, and the RFC 7518 Appendix C vector checks it end to end.
- hax's models of `Vec` and slices, and F*'s and Z3's soundness, are trusted.

## 2. Kani: parsing safety and composition, for bounded inputs

`src/proofs.rs`, `just verify-formal-jwz` (Kani 0.68). Bounds are exhaustive within the
stated sizes.

| Proof | Property | Bound |
| --- | --- | --- |
| `base64url_round_trip_1/2/3` | RFC 7515 §2: `decode(encode(b)) == b` | every input of 1, 2 and 3 bytes (each padding case) |
| `compact_split_is_exact` | RFC 7515/7516 §7.1: size cap first; exactly N parts iff N-1 dots; the parts are the text between the dots | every token of up to 6 bytes over `a` and `.`, every cap up to 7 |
| `policy_union_keeps_both_and_adds_nothing` | `Policy::with` keeps every element of both lists, adds none, no duplicates | a list and any 2 values, equal or not |
| `key_reference_union_is_the_or` | an opted-in key reference stays opted in, and only those | all 256 combinations |
| `claims_policy_union_only_widens` | larger skew and age, `exp` required only if both require it, issuer and audience only if both agree | all values |
| `media_type_comparison_is_symmetric_and_case_insensitive` | RFC 7515 §4.1.9 `typ` comparison | every pair of ASCII strings of up to 3 bytes |
| `concat_kdf_refuses_unrepresentable_lengths` | a key length of 0 or above 2^32/8 bytes is refused before anything is hashed | every `usize` |

Not model-checked, and why:

- base64url canonicity (each accepted spelling is the encoding of its bytes): base64ct's
  constant-time decoder over symbolic strings exhausts CBMC's memory. Covered by the
  RFC 7515 §2 negative tests (padding, alphabet, trailing bits) and fuzzing.
- `concat_kdf` around the proven core: dropping its zeroizing buffer runs zeroize's
  inline-assembly barrier, which Kani does not support. The unit test
  `sp_800_56a_5_8_1_layout_around_the_core` checks the same layout exhaustively for every
  key length up to three rounds.

Boundary: serde_json is not model-checked (too large for CBMC); everything that parses
JSON is covered by tests, the RFC vectors and fuzzing instead.

## 3. Compile-time: the type-state

An unverified JWS has no payload accessor and an encrypted JWE no plaintext accessor:
two `compile_fail` doc tests (`src/jws/mod.rs`, `src/jwe/mod.rs`) fail to compile with
E0599 exactly, and run with every `cargo test`.

## 4. In the browser

`tests/browser.rs` of jwz and jwz-brainpool, `just jwz-browser`: wasm32-unknown-unknown in
headless Chrome (Chrome for Testing), random numbers from `Crypto.getRandomValues`.

- jwz: RFC 7515 A.3 (ES256), RFC 8037 A.4 (EdDSA) and RFC 7520 §5.8 (A128KW, A128GCM)
  known answers; generated ES256 and EdDSA keys sign and verify, and differ; ECDH-ES,
  ECDH-ES+A256KW and A256KW round trips; claims with a caller's clock.
- jwz-brainpool: every Go josebp and Python jwcrypto JWS of the interop fixtures
  verifies; the browser makes the same tokens as the native build, byte for byte; ePA's
  ES256 on a generated brainpool key.

Stamped as `verification/stamps/browser.toml`. Its inputs are the backend, the clock,
brainpool, the manifests and the tests: a change elsewhere in jwz does not ask for a new
browser run, because the same code is already tested natively.

## Not verified, but tested

- JSON parsing (duplicate members at every depth, strict types): unit tests, the RFC
  7515/7516/7520 vectors, `fuzz/` (`just fuzz-jwz`).
- The cryptographic primitives (ECDSA, EdDSA, ECDH, AES-GCM, AES-KW, HMAC): RustCrypto,
  checked through jwz's backend traits against Wycheproof (`tests/wycheproof.rs`).
- Interoperability of brainpool tokens: `jwz-brainpool/tests/interop.rs` against Go
  josebp and Python jwcrypto.

Specification references and the tests named after them: `docs/traceability.md`.
