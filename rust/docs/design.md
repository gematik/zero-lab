# Design of the Rust crates

Status: accepted, October 2026. Binding for all development: every change is held
against the goals below (root `CLAUDE.md`). The open questions and gaps are tracked here;
the details live in each crate's docs and in [development.md](./development.md).

## Goals

The crates are the reference implementation of zero-lab's TI building blocks: one core
that runs unchanged in a CLI, a server, a browser, an air-gapped installation and,
through bindings, in Go, Java and Swift hosts. That forces nine properties on every core
crate:

1. **Sans I/O.** The core does no network, file or clock access of its own.
2. **Transport independent.** The host supplies HTTP through a small trait; any client
   works, and none is a dependency of the core.
3. **Portable.** Every core crate builds for `wasm32-unknown-unknown`; the protocol and
   crypto cores are `no_std` + `alloc` where the crates they build on allow it.
4. **Trust from verification, never from the source.** Bytes are untrusted whatever
   delivered them; only signatures and the anchor decide.
5. **Pluggable cryptography, private keys as functions.** Primitives sit behind traits a
   backend implements, and a private key is never passed by value: code that signs,
   decrypts or agrees on a key holds something it can ask to do so, so the key can stay
   in a security key (FIDO SK), the Secure Enclave, a TPM, a smartcard behind a
   Konnektor, an HSM, WebCrypto or a cloud KMS.
6. **Testable logic.** Every decision is a pure function of its inputs (bytes, time,
   configuration), so it is tested without a network, a card or a clock, and the same
   tests run natively, under wasm and against shared spec corpora.
7. **Verified, not only tested.** Formal verification where we write subtle code
   ourselves, and the whole Rust toolchain for safety and security (lints, fuzzing,
   property tests, mutation testing, supply-chain checks) as part of the build.
8. **Few dependencies, all of them stable, maintained and evaluated.** Each one is code
   we ship and vouch for. `core`/`alloc`/`std` first, an existing dependency before a
   new one, a small tested function of our own before a crate for a small job;
   cryptography and parsers of hostile input only from evaluated implementations
   (RustCrypto, rustls, ring, dalek, serde). No pre-release or unmaintained crate unless
   nothing stable exists, and then as a listed known compromise with its exit trigger.
   The tree shrinks over time: the policy is in the root `CLAUDE.md`.
9. **Fuzzed.** Everything that reads bytes an attacker can choose has a fuzz target, and
   a crash found by fuzzing becomes a regression test before it is fixed.

## Layers

```text
 hosts      ti-cli (ureq, rustls/ring)   ti-wasm (wasm-bindgen)   servers (reqwest, tokio)
              │                            │                        │
 adapters   `ureq` / `reqwest` / `tokio` / `os` features: the only code that does I/O
              │
 engines    ti-idpd  ti-directory  ti-connector-client  ti-report       (sans I/O)
              │
 core       ti-pki (+ load)  ti-xmldsig  jwz (+ jwz-brainpool, ti-jwz)  ti-pkcs12
              │
 vocabulary ti-types (Env, Tier; no_std, no dependencies)   ti-cache (policy, store trait)
```

A crate depends only downwards. Adapters are Cargo features of the crate they serve,
off by default; `just core-deps` proves `ti-pki` without them contains no HTTP client
and no executor, and `just wasm32` that the cores build for the browser.

## Sans I/O and pluggable transports

Engines model a protocol as data: they build requests and consume responses, and the
host performs them. `ti_idpd::http::Request`/`Response` carry the IDP flow, which the
CLI drives with ureq and a browser could drive with `fetch`; a redirect is an answer
there, so the transport must not follow it. `ti_connector_client::Transport` leaves TLS
(client certificates from PKCS#12, the `.kon` trust store), proxies, connection reuse
and timeouts to the host. `ti_pki::load::Transport` fetches roots.json and the TSL with
conditional requests (`ETag`, `If-Modified-Since`) and posts OCSP.

Rules:

- Traits carry no `Send`/`Sync` bounds, so they can sit on single-threaded browser APIs;
  generic structs bound their parameters with `MaybeSend`/`MaybeSync` instead.
- Async where a host may need it (browser, servers), sync where the only host is blocking
  (the IDP flow in the CLI). Every sync implementation can serve an async trait.
- Time is a parameter (`Clock`, or a `now` argument), never `SystemTime::now()` in a core.
- Randomness comes from the crypto backend (`getrandom` underneath), never from a
  global the host cannot replace.
- The core does not log; it returns outcomes (`ReloadOutcome`, warnings in results) and
  the host decides what to log.

Open: the three `Transport` traits differ (artefact-shaped async get/post in ti-pki,
request/response sync in ti-idpd, SOAP-shaped async in ti-connector-client). One shared
HTTP vocabulary would let a host write one adapter. It cannot live in ti-types (no I/O
vocabulary there by its admission rule); a small `ti-http` crate of plain data types and
one async trait is the candidate, decided before any of these crates reaches 1.0.

## Pluggable cryptography and keys as functions

Two rules, for every crate:

1. **Crypto is pluggable.** No protocol code calls a cryptographic library directly; it
   reaches primitives through traits, and a backend supplies them. The pure-Rust
   RustCrypto backend is a feature; others (WebCrypto, an HSM, a cloud KMS, aws-lc for a
   FIPS path) are crates of their own implementing the same traits, so the core's tree
   never contains them.
2. **Private keys are used by function, not by value.** An API that needs a private key
   takes a capability: `Signer` / `AsyncSigner` (sign these bytes), `KeyAgreement` /
   `AsyncKeyAgreement` (derive a shared secret with this public key), and a decrypting
   counterpart where a protocol needs one. It never takes scalar bytes, a PKCS#8 blob or
   a PEM string. Keys are bound to one algorithm, so a token header cannot choose
   another. Async forms exist because HSMs, KMS and WebCrypto answer asynchronously;
   every sync key is also an async one.

The private-key rules in the root `CLAUDE.md` bind Rust and Go alike; this section
explains them. Hardware-bound keys are first-class, behind the same abstraction: security keys (FIDO
SK), the Secure Enclave, TPM 2.0, smartcards (SMC-B, HBA, eGK via a Konnektor), HSMs and
cloud KMS. What they share, and what the abstraction therefore must not assume away:

- **Not exportable.** There is no private key to read, copy, serialise or zeroize; the
  key is a handle and the public key. No API may need more.
- **Algorithms are the device's.** The Secure Enclave and most TPMs sign P-256 only (TPMs
  also RSA, some P-384); security keys P-256 and Ed25519; brainpool only smartcards and
  HSMs. A key reports what it can do, and protocol code picks from that set or fails
  with a clear error; it never falls back to a software key.
- **Digest or message.** The Secure Enclave and TPMs sign a digest, Ed25519 and some
  HSM mechanisms the whole message. The signer interface says which it takes, and the
  hashing for prehashed keys happens once, in shared code.
- **Not every key signs arbitrary data.** A FIDO security key signs WebAuthn or SSH
  structures (authenticator data with a client-data hash), not raw messages; it can
  serve protocols built for it (WebAuthn, SSH), not a plain JWS. The abstraction exposes this instead of hiding it.
- **Slow, asynchronous and interactive.** A signature can wait for a touch, a PIN, a
  biometric or a card in a reader, and can be cancelled or time out. Signing is async,
  cancellable, and errors distinguish "user cancelled", "device absent", "PIN blocked"
  and "not permitted" from cryptographic failure.
- **Attestation.** Where the device provides it (TPM, Secure Enclave via App Attest or
  DeviceCheck, FIDO), the key can present attestation of where it lives; protocols that
  rely on hardware binding verify it and do not trust a claim.
- **Platform glue stays at the edge.** Enclave, TPM and FIDO access needs platform APIs
  (Security.framework, TSS or the kernel's TPM device, CTAP over HID); each is an
  adapter crate or package implementing the key traits, never a dependency of a core.

Private key bytes exist only inside software key implementations (`SoftwareKey`) and the
file formats that carry them (`ti-pkcs12`, PEM in `ti-cli`), always in `Zeroizing`
buffers. Loading a key from a file yields a key object, and the rest of the code cannot
tell it from a smartcard.

Where this holds today:

- jwz: JWS and JWE talk only to the key traits; the backend's raw-scalar primitives are
  used by `SoftwareKey` alone. The parts that must be identical for every backend, such
  as the Concat KDF of ECDH-ES, are implemented once over the backend's hash and are what
  Kani and hax verify.
- ti-idpd: the challenge is signed through a `&dyn Signer`; `ti idpd` passes a
  software key from a PKCS#12 identity today.
- ti-pki only verifies (public data), through `rustls-pki-types`' verification trait with
  RustCrypto behind it; `brainpool` and `rsa` are features, and `TrustStore::subset`
  restricts a store to what a client supports.

Open:

- ti-idpd takes the synchronous `Signer`, but a card signs through the Konnektor
  (`AuthSignatureService`), which answers asynchronously. The flow must take an
  `AsyncSigner` before SMC-B and HBA authentication via the Konnektor (roadmap stage 5).
- ti-connector-client's mutual TLS hands the PKCS#12 key to rustls by value
  (`with_client_auth_cert`). rustls supports keys as functions through
  `sign::SigningKey` and a client certificate resolver; the transport should take a
  signing key from there, so the Konnektor client certificate can live in an HSM.
- The key traits do not yet report capabilities (algorithms, digest or message, user
  interaction) or attestation, and their errors do not distinguish a cancelled touch or
  a blocked PIN from a cryptographic failure; there are no Enclave, TPM or FIDO adapters.
- Signature verification is pluggable only at the algorithm level; a verifier backend
  trait like jwz's would let a FIPS or WebCrypto host verify certificates too.

## Air-gapped and offline operation

Trust material (roots.json, the TSL) is loaded by composable loaders:

```text
Reloader ── FallbackLoader ─┬─ CachingLoader ── HttpLoader ── Transport
                            └─ StaticLoader ◄── Bundle (offline file)
```

- An air-gapped installation uses `StaticLoader` alone, from a `Bundle` exported on a
  connected machine, or a `FileTransport` over mounted files (Kubernetes ConfigMaps).
- A bundle needs no signature: it is verified on import like any other source, and its
  anchor hash rejects one exported for another environment before verification.
- Freshness still applies offline: material ages out by `hard_expiry`, so a production
  air-gapped site imports a fresh bundle at least daily. Missing OCSP is reported as such,
  never silently treated as `good`.
- `dangerous-nonprod` keeps TEST-ONLY anchors and relaxed policies out of production
  binaries entirely; `just nonprod-absent` checks the bytes are absent.

## WebAssembly

`ti-wasm` exposes `ti-report` (TSL view, certificate description) to JavaScript. Its
exports are pure: downloads, caching and the clock belong to the caller, because the TI
download hosts send no CORS headers and OCSP responders speak plain HTTP. One module
serves Node and the browser. `#[wasm_bindgen]` glue is the only `unsafe` in the
workspace; `just wasm-unsafe-free` keeps it out of ti-wasm's own sources, and all logic
stays in crates under `unsafe_code = "forbid"`. Builds favour verification speed over
module size (`opt-level 3`, `wasm-opt -O3`).

The browser tests of jwz and jwz-brainpool run in headless Chrome at design time
(`just jwz-browser`, stamped).

## Testable logic

Sans I/O is what makes the logic testable, and the tests are designed in, not added:

- **Decisions are pure.** Validation, policy, protocol steps and parsers take bytes, a
  time and a configuration and return a result; nothing reads the clock, the network or
  the environment on the way. A test states its inputs completely.
- **Seams are traits.** Transports, clocks, cache stores, crypto backends and keys are
  traits, so tests substitute scripted transports (`test-util`), fixed clocks, in-memory
  stores and mock HSM signers instead of patching globals.
- **Results explain themselves.** Outcomes carry the reason (error codes, warnings,
  `ReloadOutcome`), so a test asserts *why* something was rejected, not only that it was.
- **Specs drive tests, and tests name them.** Rules carry IDs in `spec/<topic>` with a
  corpus and a `CONFORMANCE.md`. A test is named after the requirement it proves
  (`p12_036_…`, `tslsig_066_…`, `a_28419_…`, `rfc_7516_5_2_…`), the implementing code
  cites it in a comment, and a generated traceability table (jwz's
  `docs/traceability.md`) shows which requirement has code and tests; one without a
  test is a gap. Fixtures are canonical in `spec/`, copies are hash-pinned. The naming
  rules are in the root `CLAUDE.md`.
- **Test vectors from outside.** Wycheproof for every primitive, the W3C C14N suites,
  gematik's reference data (ref-GemLibPki), and interop fixtures cross-checked against
  independent implementations (Go, Python, OpenSSL).
- **Same tests everywhere.** Native, `wasm32` in headless Chrome (`just jwz-browser`),
  and live tests against the TI test environments kept apart from the offline suite.
- **Live tests are gated, loud and required for releases.** A test that needs a live
  system (TI environments, Konnektor, card, browser) is `#[ignore = "needs …: just …"]`
  or fails without its configuration; it never passes silently. Each suite has a
  recipe, a row in `development.md` "Gated tests" and the crates whose release requires
  it; the release PR records the runs.

## Making the sources safe and secure

The language gives memory safety; the tools below go after the rest: logic errors,
panics on hostile input, timing, resource exhaustion and the supply chain. Each runs in
`just check` (every change), `just audit` (before a tag) or at design time with a
stamped result that `just check` holds to.

| Tool | What it shows | When | Today |
|---|---|---|---|
| `unsafe_code = "forbid"` | no `unsafe` in our code (ti-wasm glue excepted, `just wasm-unsafe-free`) | check | all crates |
| clippy `pedantic`, rustdoc, `missing_docs` | lint-clean, documented API | check | all crates |
| feature matrix (`just features`), `wasm32`, `core-deps`, `nonprod-absent` | every feature combination builds; cores stay I/O-free; no TEST-ONLY bytes in prod | check | all crates |
| Kani | bounded model checking: no panics, overflows or out-of-bounds, and stated properties | design time, stamped | ti-xmldsig C14N, jwz (base64url, compact, ECDH) |
| hax → F* | functional correctness against the spec | design time, stamped | jwz Concat KDF (SP 800-56A §5.8.1) |
| cargo-fuzz | no panic, hang or broken invariant on any input (see Fuzzing) | release, design time | jwz parsers only |
| proptest | properties over generated inputs | check | ti-xmldsig |
| Wycheproof, spec corpora, interop | known-answer and edge cases | check | jwz, jwz-brainpool, ti-pki, ti-xmldsig |
| cargo-mutants | the tests notice when the code changes | before a release | per crate, by hand |
| Miri | undefined behaviour | only if `unsafe` ever enters | n/a |
| cargo-deny, cargo-audit, cargo-vet | licences, bans, sources, advisories, audited crates | check / audit | workspace |
| cargo-semver-checks, MSRV, cargo-machete | no accidental breaks, declared toolchain, no unused deps | audit / check | workspace |

Required of every crate that parses untrusted input or holds a security decision:

- a fuzz target for each parser of untrusted input;
- property tests for invariants (round trips, canonical forms, monotone policies);
- Kani harnesses for code with arithmetic on lengths and offsets, and formal proof for
  cryptographic constructions we implement ourselves;
- resource limits on attacker-controlled parameters (sizes, depths, iteration counts,
  KDF cost) checked before any work is done;
- secret material in `Zeroizing` buffers, constant-time comparison (`subtle`) of digests
  and MACs, private keys used by function only (above);
- hostile input parsed strictly: DER through `der`, XML without DTDs, JSON through serde
  with unknown fields rejected where the format is ours.

### Fuzzing

Every parser of untrusted input and every function that makes a decision on it is
fuzzed with cargo-fuzz (libFuzzer). The layout is jwz's:

- One fuzz crate per library crate, `<crate>/fuzz`, outside the workspace, so libFuzzer
  and the nightly toolchain never enter the workspace's lock file and checks. The nightly
  is pinned (`JWZ_NIGHTLY` today, one shared variable once there are more).
- One target per entry point, documented with what it asserts. A target asserts more
  than "no panic": what parses survives its own serialization, a canonical form is a
  fixed point, a verdict is the same through every API that reaches it, limits hold.
- Seeds are committed (`fuzz/seeds/<target>`), drawn from the spec corpora, Wycheproof
  and real TI artefacts (TSL, roots.json, OCSP responses, certificates); the growing
  corpus is not.
- `just fuzz-<crate> seconds` runs every target and fails on a crash; a short run is
  part of a release, long runs happen at design time and after changes to a parser.
- A crash is minimised (`cargo fuzz tmin`), added as a unit test with the input in the
  crate's test data, then fixed.
- Structure-aware targets (`arbitrary`) where random bytes rarely get past the outer
  format, such as DER inside base64 inside JSON, or XML around a signature.

Targets required, by crate:

| Crate | Entry points |
|---|---|
| jwz | JWS and JWE compact and JSON, JWK and JWK Set, JWT claims (exist) |
| ti-pki | certificate and chain parsing, roots.json, TSL (`quick-xml`), OCSP responses, `TrustStore` validation of a parsed chain, offline bundle |
| ti-xmldsig | XML parsing, C14N, signature verification of a TSL-shaped document |
| ti-pkcs12 | `decode` with password, MAC and KDF parameters, legacy PBEs |
| ti-connector-client | `.kon` files, SOAP responses and faults, service directory |
| ti-idpd, ti-directory | discovery document, IDP keys and challenge, redirects, token responses |
| ti-report | TSL view and certificate description (what ti-wasm hands to JavaScript) |

Gaps against that today:

- Fuzzing covers jwz only; every other row of the fuzz table above is missing. Most
  urgent: ti-pki (TSL, OCSP, certificates), ti-xmldsig and ti-pkcs12, which read files
  and responses from outside before any signature is checked.
- Requirement naming is new: only jwz has a traceability table, and 57 of its 82
  references have no test named after them; the other crates' tests do not yet carry
  requirement IDs in their names.
- The Konnektor end-to-end tests (`ti-connector-client/tests/e2e.rs`) return early when
  `TI_TEST_KON_PATH` is unset and so show as passed; they should be `#[ignore]` with
  their variable and get a `just` recipe.
- Mutation testing runs by hand; a mutation score per crate before release would make it
  a gate.
- No coverage measurement (`cargo llvm-cov`) to show which rules lack tests.
- Dependencies short of goal 8: `rsa` and `pkcs1` are release candidates (a known
  compromise, with Marvin unpatched); `socks` comes in through ureq's `socks-proxy`
  feature and is barely maintained; `scrypt` and `salsa20` come with pkcs5's `pbes2`
  though PKCS#12 never needs scrypt; two XML parsers (`quick-xml`, `roxmltree`) read
  hostile input; `jiff` (local time in CLI output) and `arc-swap` (one use) could go.
- cargo-vet exempts most of the tree (241 of 272 crates); audits should be imported
  from trusted organisations and grown for the crates that handle secrets.

## Bindings (planned)

Hosts do HTTP, engines stay sans I/O: uniffi for Swift and Kotlin/Java, wasm-bindgen for
the browser, and `ti serve` over a Unix socket or stdio for Go and server Java, built for
latency; its protocol (CBOR, protobuf or PKCS#11 semantics) is open. Go never links Rust (no cgo); where Go needs a function natively, both sides
implement a shared specification in `spec/` ([Go design](../../go/docs/design.md#go-and-rust)). See backlog doc-1 for the trade-offs and the roadmap.
