# Rust profile

How the Rust crates meet the [repository's rules](../../docs/README.md). The rules
themselves live there; this profile maps them to Rust and adds what only Rust needs. The
details live in each crate's docs and in [development.md](./development.md).

## 1. Role and units

The crates are the reference implementation of zero-lab's TI building blocks
([architecture](../../docs/architecture.md)): one core that runs unchanged in a CLI, a
server, a browser, an air-gapped installation and, through bindings, in other hosts.

```text
 hosts      ti-cli (ureq, rustls/ring)   ti-wasm (wasm-bindgen)   servers (their own)
              │                            │                        │
 adapters   `ureq` / `os` features, ti-tls (rustls): the only code that does I/O or holds a TLS library
              │
 engines    ti-idpd  ti-directory  ti-connector-client  ti-report  ti-jwks   (sans I/O)
              │
 core       ti-pki (+ load)  jwz (+ ti-jwz)         ti-pkcs12
              │
 vocabulary ti-types (Env, Tier; no_std, no dependencies)   ti-cache (HTTP cache policy, cache store trait)
```

A crate depends only downwards. Adapters are Cargo features of the crate they serve,
off by default; `just core-deps` proves `ti-pki` without them contains no HTTP client
and no executor, and `just wasm32` that the cores build for the browser. The protocol and
crypto cores are `no_std` + `alloc` where the crates they build on allow it.

## 2. Sans I/O and transports

Engines model a protocol as data: they build requests and consume responses, and the
host performs them. `ti_idpd::http::Request`/`Response` carry the IDP flow, which the
CLI drives with ureq and a browser could drive with `fetch`; a redirect is an answer
there, so the transport must not follow it. `ti_connector_client::Transport` leaves TLS
(client certificates from PKCS#12, the `.kon` trust store), proxies, connection reuse
and timeouts to the host. `ti_pki::load::Transport` fetches roots.json and the TSL with
conditional requests (`ETag`, `If-Modified-Since`) and posts OCSP.

- Traits carry no `Send`/`Sync` bounds, so they can sit on single-threaded browser APIs;
  generic structs bound their parameters with `MaybeSend`/`MaybeSync` instead.
- Async where a host may need it (browser, servers), sync where the only host is blocking
  (the IDP flow in the CLI). Every sync implementation can serve an async trait.
- Time is a parameter (`Clock`, or a `now` argument), never `SystemTime::now()` in a core.
- Randomness comes from the crypto backend (`getrandom` underneath), never from a
  global the host cannot replace.
- The core does not log; it returns outcomes (`ReloadOutcome`, warnings in results) and
  the host decides what to log.

The offline loaders of `ti_pki::load` (`StaticLoader`, `Bundle`, `FileTransport`,
`FallbackLoader`, `Reloader`) implement [offline operation](../../docs/architecture.md#offline-and-air-gapped-operation);
`dangerous-nonprod` keeps TEST-ONLY anchors and relaxed policies out of production
binaries entirely, and `just nonprod-absent` checks the bytes are absent.

TLS peer verification of TI endpoints is the core's
([architecture](../../docs/architecture.md#the-host-owns-the-transport-the-core-owns-trust)):
ti-pki is to supply a rustls `ServerCertVerifier` that validates the chain against the
verified TSL with the profile, algorithm and OCSP rules, and the ureq
adapters use it for TI endpoints (TASK-97). Today ti-connector-client verifies the
Konnektor by its `.kon` pins and CAs, and other TLS goes through the platform verifier.

The three `Transport` traits differ today (artefact-shaped async get/post in ti-pki,
request/response sync in ti-idpd, SOAP-shaped async in ti-connector-client); whether a
small `ti-http` crate unifies them before 1.0 is TASK-64.

## 3. Keys and cryptography

The default backend is RustCrypto: jwz reaches every primitive through `jwz::crypto`
traits gathered by a `Backend`, with the pure-Rust backend behind the `crypto-rustcrypto`
feature; WebCrypto, HSM, KMS or aws-lc backends are crates of their own, so jwz's tree
never contains them. ti-pki verifies through `rustls-pki-types`' verification trait with
RustCrypto behind it; `brainpool` and `rsa` are features, and `TrustStore::subset`
restricts a store to what a client supports.

| [Key rule](../../docs/design/keys.md) | Rust |
|---|---|
| sign | `jwz::keys::Signer`, `AsyncSigner` (every `Signer` is an `AsyncSigner`) |
| key agreement, decrypt | `jwz::keys::KeyAgreement`, `AsyncKeyAgreement` |
| one algorithm per key | `JwsKey::algorithm` |
| capabilities, interaction errors, attestation | to add (TASK-62) |
| software key | `jwz::keys::SoftwareKey`, built from `ti-pkcs12` or PEM at the edge (`ti-cli`) |
| zeroized key bytes | `Zeroizing` buffers |
| TLS client key | rustls `sign::SigningKey` with a certificate resolver (TASK-61) |

JWS and JWE talk only to the key traits; the backend's raw-scalar primitives are used by
`SoftwareKey` alone. The Concat KDF of ECDH-ES is implemented once over the backend's
hash and is what Kani and hax verify.

## 4. Errors and result codes

Each crate has one error enum (`thiserror`, `#[non_exhaustive]`) whose variants carry the
reason; where a shared specification defines result codes, the spec's table maps them to
the variants (for example `spec/pkcs12`: `limit_exceeded` is `Error::LimitExceeded`), and
the interop adapter in `spec/<topic>/interop/rust` prints the code.

## 5. Testing

- `cargo nextest`; unit tests next to the code, integration tests in `tests/`.
- Requirement-named tests: `fn p12_036_mac_iterations_above_the_limit_are_refused()`,
  `fn rfc_7516_5_2_…()`; the implementing code cites the requirement in a comment, and
  jwz's `tests/traceability.rs` generates and checks `docs/traceability.md`
  (`JWZ_BLESS=1` rewrites it). The ti crates (ti-pki, ti-pkcs12, ti-idpd, ti-directory,
  ti-connector-client, ti-cli, ti-wasm) do the same through the dev-only `traceability`
  crate, which also reads spec rules (`TSLDET-013`), gematik afos, use cases and tables
  (`A_28419`, `TUC_PKI_006`, `Tab_PKI_405`) and spec rule IDs in string literals, refuses a
  spec rule `spec/` does not define, and lists requirement-named tests no citation takes;
  `TRACE_BLESS=1 cargo test -p <crate> --test traceability` rewrites a table.
- Gated tests are `#[ignore = "needs TI_TEST_KON_PATH: just <recipe>"]`, run by their
  recipe with `--ignored`, and fail when run without their variable; the suites are in
  [development.md](./development.md#gated-tests).
- Scripted transports and fixed clocks from the `test-util` features, mock HSM signers in
  jwz; Wycheproof, the W3C C14N suites, ref-GemLibPki and interop fixtures (Go, Python,
  OpenSSL); jwz and ti-jwz's brainpool also in headless Chrome (`just jwz-browser`, stamped).

## 6. Verification and tooling

| Category | Rust tool | When | Today |
|---|---|---|---|
| unsafe-code ban, lints, documented API | `unsafe_code = "forbid"` (ti-wasm glue excepted, `just wasm-unsafe-free`); the cores' dependencies only with an approved exception (`just unsafe-free`, [section 8](#8-dependencies)); clippy `pedantic`, rustdoc, `missing_docs` | check | all crates |
| build matrix and layer checks | `just wasm32`, `just core-deps`, `just nonprod-absent`; `just features` | check; `just features` before a release (`check-full`) | all crates |
| bounded model checking | Kani | design time, stamped | jwz (base64url, compact, ECDH) |
| functional proof | hax → F* | design time, stamped | jwz Concat KDF (SP 800-56A §5.8.1) |
| fuzzing | cargo-fuzz (below) | release, design time | jwz, ti-cli, ti-pki and ti-connector-client parsers |
| known-answer, corpora, interop | Wycheproof, spec corpora, interop runs | check | jwz, ti-jwz, ti-pki, ti-pkcs12 |
| undefined behaviour | Miri | only if `unsafe` ever enters | n/a |
| mutation testing | cargo-mutants (`just mutants-record`, `just mutants-gate`) | before a release; `just release` refuses a crate without a score for its current code or below its threshold in `mutation-scores.toml` | per crate |
| coverage | cargo-llvm-cov (`just coverage`), with the cited requirements whose code no test runs | on demand | all crates |
| supply chain | cargo-deny, cargo-audit, cargo-vet | check / audit | workspace |
| compatibility | cargo-semver-checks, MSRV, cargo-machete | audit / check | workspace |

Hostile input is parsed strictly: DER through `der`, XML through `quick-xml` into typed
structures without entity expansion, read for the TSL only from bytes its detached
signature covers, JSON through serde with unknown fields rejected where the format is ours; secrets
in `Zeroizing`, digests and MACs compared with `subtle`.

Design-time results are stamped in `jwz/verification/stamps/*.toml`; `just jwz-recheck`
reruns the checks whose inputs changed, and `just check` fails on a stale stamp.

## 7. Fuzzing

cargo-fuzz (libFuzzer). One fuzz crate per library crate, `<crate>/fuzz`, outside the
workspace, so libFuzzer and the nightly toolchain never enter the workspace's lock file
and checks; the nightly is pinned (`JWZ_NIGHTLY` today, one shared variable once there
are more). Seeds in `fuzz/seeds/<target>`; `just fuzz-<crate> seconds`; crashes minimised
with `cargo fuzz tmin`; structure-aware targets with `arbitrary`.

| Crate | Entry points |
|---|---|
| jwz | JWS and JWE compact and JSON, JWK and JWK Set, JWT claims (exist) |
| ti-pki | certificate and chain parsing, roots.json, the detached TSL signature, TSL (`quick-xml`), OCSP responses, `TrustStore` validation of a parsed chain, offline bundle |
| ti-pkcs12 | `decode` with password, MAC and KDF parameters, legacy PBEs |
| ti-connector-client | `.kon` files, SOAP responses and faults, service directory |
| ti-idpd, ti-directory | discovery document, IDP keys and challenge, redirects, token responses |
| ti-jwks | a `jwks_uri`'s answers: status, `Cache-Control`, the set within its limits |
| ti-tls | the chain a TLS server presents, under the `web` profile (`fuzz-ti-tls`) |
| ti-report | TSL view and certificate description (what ti-wasm hands to JavaScript) |

## 8. Dependencies

`core`/`alloc`/`std` first; preferred libraries: RustCrypto, rustls and ring, dalek,
serde. External dependencies are declared once in `[workspace.dependencies]` (ti-wasm's
pinned `wasm-bindgen` aside), with their reason as a comment where it is not obvious and
`default-features = false` where the crate allows it; crates inherit them. Weigh the tree with `cargo tree -i <crate>`. Supply-chain checks: `cargo deny`
(licences, advisories, bans, sources) in `just check`; `cargo audit`, `cargo vet`, MSRV
and semver in `just audit` before tagging. Known compromises, each with its exit trigger,
are in [development.md](./development.md#known-compromises).

**No `unsafe` in a core, also not through its dependencies.** The cores are ti-types,
ti-cache, ti-pki, ti-pkcs12, ti-connector-client, ti-report, jwz,
ti-jwz, ti-jwks, ti-idpd and ti-directory, with every feature but their adapters
(the `ureq` transports, ti-types' `clap`) and `test-util`.
The hosts are ti-cli and ti-wasm: a crate that reaches the terminal, the operating system
or foreign code through `unsafe` (rpassword) belongs there. What counts is what
ends up in the program on the release targets and wasm32: normal dependencies, not proc
macros or build scripts. A crate with `unsafe` enters a core only through an entry in
[unsafe-exceptions.md](./unsafe-exceptions.md) with its exact version, the reason and the
maintainer's approval date; a new version is reviewed again before its row changes.
`just unsafe-free` (in `just check`) runs `unsafe-audit`, which parses every crate of each
core's tree with `syn` and fails on a crate with `unsafe` that is not listed, a listed
crate in another version, and a row no core needs any more; `cargo run -p unsafe-audit --
inventory` prints the sites per crate.

## 9. Crossing languages

The core offers itself to other languages as [interop](../../docs/interop.md) describes:
`ti` subprocesses and stateless helpers (`ti-<group>-helper`, JSON lines over stdio or a
Unix socket, TASK-120) for Go servers, wasm-bindgen for the browser (`ti-wasm`), uniffi
for Swift, Kotlin/Java and C# (clients only, planned). On a process boundary the Rust
side decodes requests from borrowed slices into reused buffers. `ti-wasm` exports are pure; `#[wasm_bindgen]` glue
is the only `unsafe` in the workspace, kept out of ti-wasm's own sources, and all logic
stays in crates under `unsafe_code = "forbid"`. Builds favour verification speed over
module size (`opt-level 3`, `wasm-opt -O3`). The decision record is backlog doc-1.

## 10. Servers

No standalone Rust workload yet. A helper runs inside a server workload, as a child
process or as a sidecar container from the same image, and follows the
[server rules](../../docs/design/servers.md) there: stateless (no profile, store, cache or
key file; trust material supplied from a mounted directory and kept in memory), non-root,
read-only root filesystem, a Unix socket with file permissions and peer checks, no
network listener, probes after the handshake, graceful shutdown, telemetry without
leaking, inside the workload's enclave. The helpers (TASK-120) and the producer of trust
material for containers (TASK-173) are built on the loaders in
[development.md](./development.md#trust-material-loading).

## 11. Build and release

Versions, tags (`rust/<crate>/vX.Y.Z`), release notes and `just release` / `just publish`
are in [development.md](./development.md); the gated suites each crate's release needs
are in its "Gated tests" table.

## 12. Status

Gaps against the rules are backlog tasks: the crate labels (`ti-pki`,
`ti-pkcs12`, `jwz`, …) together with `fuzz`, `tests`, `deps`, `keys`. Most relevant now:
fuzz targets beyond jwz (TASK-44 to TASK-49), requirement-named tests outside jwz
(TASK-50, TASK-51), the silently passing Konnektor end-to-end tests (TASK-52), keys as
functions in ti-idpd and ti-connector-client (TASK-60, TASK-61), key capabilities and
attestation (TASK-62).
