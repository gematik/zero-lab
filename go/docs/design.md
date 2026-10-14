# Design of the Go modules (draft)

Status: draft for review. The Go counterpart of [../../rust/docs/design.md](../../rust/docs/design.md):
the same goals, held the way Go does it. It describes what the modules already follow,
and lists the gaps.

## Role of Go in zero-lab

Rust is the maintained core: PKI and TSL validation, JOSE with brainpool, the TI
protocols, smartcard and Konnektor access. Go keeps what Go is best at: servers and
relying parties (`pdp`, `pep`, `zaddy`, `bff`), their libraries (`oauth`, `oidf`, `dpop`,
`nonce`, `kv`, `gemidp`), and the ePA client (`epa`). How the two meet is in
[Go and Rust](#go-and-rust): never through cgo, either across a process boundary or by a
native Go implementation of a shared specification.

## Goals

1. **Standard library first, zero dependencies preferred.** A library module imports
   the standard library and, where it lacks something, `golang.org/x`. A third-party
   module is the exception that needs a reason (below).
2. **Small interfaces, defined by the consumer.** Accept interfaces, return concrete
   types. The seams are the standard ones wherever they fit: `io.Reader`,
   `http.Handler`, `*http.Client` / `http.RoundTripper`, `crypto.Signer`,
   `crypto.Decrypter`, `*slog.Logger`, `context.Context`.
3. **No ambient I/O in libraries.** A library reads no environment variable, flag or
   file it was not handed, uses no `http.DefaultClient`, starts no goroutine it cannot
   stop, and does not log except through a logger it was given. Configuration is a struct
   the command fills in; secrets arrive as `*_PATH` files read by the command.
4. **Trust from verification only.** Where bytes came from (HTTPS, a file, a cache, Redis
   or Postgres in `kv`) never makes them trusted; signatures, the anchor and the spec
   rules decide. A compromised store or upstream can deny service, never grant access.
5. **Standard crypto, private keys as functions.** Cryptography comes from the standard
   library (`crypto/...`, `crypto/tls`, `crypto/mlkem`, `crypto/hkdf`). A private key is
   held as a `crypto.Signer` or `crypto.Decrypter` (or `*ecdh.PrivateKey` behind a
   function for key agreement), never as bytes or a JWK value, so it can be hardware
   bound: a security key (FIDO SK), the Secure Enclave, a TPM, an HSM or PKCS#11 token, a
   cloud KMS, or the Rust `ti` with the card behind a Konnektor.
6. **Testable logic.** Decisions are functions of their inputs: requests, time,
   configuration. Time comes in as a parameter or a `func() time.Time`; HTTP through an
   injected client or `httptest`; stores through their interface.
7. **Verified with the Go toolchain.** `go vet`, staticcheck, golangci-lint (with gosec),
   the race detector, govulncheck and fuzzing are part of every change, not a release
   chore.
8. **Fuzzed.** Every parser of attacker-chosen bytes has a native Go fuzz test.
9. **Few dependencies, all stable, maintained and evaluated.** Same policy as the root
   `CLAUDE.md`, applied the Go way: a module of our own with a few dozen tested lines
   beats a third-party module for a small job.
10. **No cgo.** Every Go binary builds with `CGO_ENABLED=0`: static, cross-compiled,
    without a C toolchain or a Rust library linked in. Go uses Rust through a process
    boundary, or implements the same specification natively.

## Go and Rust

### No cgo, no linked Rust

cgo (and purego or libffi loading of a Rust library) is not used. It would bring a C
toolchain into every build, break static cross-compilation, put memory-unsafe glue and a
second runtime into the server process, and tie Go releases to Rust ABI details. The
cost it would save, a process boundary, is small for everything but per-request hot
paths, and those are implemented natively (below).

### Two ways to use Rust functionality

**Across a process boundary**, with the Rust `ti` as the implementation:

| Mode | Fits | Example |
|---|---|---|
| subprocess per call | rare operations, CLIs, start-up checks | `epa` runs `ti identity sign`, `ti idpd authenticate`, `ti pki verify` |
| child process over stdio (`ti serve`) | repeated calls from one process, warm caches, no extra container | planned |
| Unix socket service (`ti serve --listen unix:…`) | several processes or a sidecar container; access by socket permissions | planned |
| network service | shared across hosts, with its own authentication and TLS | only where a sidecar is impossible |

Rules for every boundary:

- The contract is versioned and written down (`spec/ti-rpc`): methods, request and
  response schemas, error codes, limits. The CLI's `--format json` output follows the
  same schema, so a subprocess and the RPC service return the same shapes.
- Go talks to it through a small typed client package behind a consumer interface, so
  callers cannot tell a subprocess from a socket, and tests use a fake.
- Secrets stay on the Rust side: private keys, PINs and card handles never cross the
  boundary (as in `epa` today, where the key never enters the Go process). What crosses
  is data to sign or verify and the verdicts.
- Inputs are validated on both sides and outputs are treated as untrusted by Go until
  parsed against the schema; timeouts, size limits and cancellation are part of the
  contract.
- The Go side checks the version of the binary or service at start-up and refuses an
  incompatible one.

### RPC performance

The RPC boundary must be as fast as the process boundary allows; it is on request paths,
and a slow boundary would push functions into native Go that should stay in Rust.

- **Long-lived peers, no per-call spawn.** `ti serve` starts once, loads and verifies its
  trust material once and keeps it hot (TrustStore, OCSP and key caches); a call does only
  the work of the call. Subprocess per call stays for rare operations and the CLI.
- **Unix domain sockets or stdio pipes by default**, TCP only across hosts. No HTTP, no
  TLS handshake on a local boundary; authentication of a local peer is the socket's file
  permissions (and `SO_PEERCRED` where available).
- **A binary encoding, no text on the hot path.** Bulk data (certificates, TSLs,
  messages to sign) travels as raw bytes, never base64 or hex. Which encoding is open
  (below).
- **Multiplexed and pipelined.** Request IDs let one connection carry many calls in
  flight; the Go client keeps a small pool of connections and never serialises callers
  behind one request. Batch methods (verify N certificates) where callers have N.
- **No avoidable copies or allocations.** Frames are read into reused buffers; the Go
  client pools them (`sync.Pool`), the Rust server decodes borrowed slices.
- **Measured, with budgets.** `spec/ti-rpc` states latency (p50, p99) and throughput
  budgets per method on reference hardware; `just bench` on both sides measures round
  trips over the real socket, and a regression beyond the budget fails the check.
- **Same semantics as the CLI.** The protocol carries the same methods, result codes and
  limits as `ti --format json`; JSON stays the human and debugging form, and a
  conformance test runs the corpus through both.
- **The codec is a parser of input from another process** and is fuzzed on both sides.

Open: the protocol. Candidates, to be decided with measurements and against the
dependency goal:

| Candidate | For | Against |
|---|---|---|
| CBOR (RFC 8949) | binary, self-describing, raw byte strings; Go already uses `fxamacker/cbor` (hardened, fuzzed) in `epa` | a Rust crate needed (minicbor was just removed); schema lives in the spec, not in the format |
| protobuf (gRPC or plain frames) | schema-first, generated code, mature tooling, streaming with gRPC | the largest dependency trees on both sides (`google.golang.org/protobuf`, gRPC; `prost`/`tonic`), code generation in the build |
| PKCS#11 semantics | the standard interface for keys as functions: HSMs, tokens and `ti` behind one API, sessions and object handles; fits goal 5 | a C API: native PKCS#11 in Go needs cgo, so only a remoted form over a socket (as p11-kit's RPC does) fits the no-cgo rule; covers keys and crypto, not TSL or IDP operations |

PKCS#11 and a general RPC are not exclusive: key operations could follow PKCS#11 while
verification and protocol calls use the general protocol.

**Natively in Go**, when a process boundary does not fit:

- on a per-request path where a round trip is measurably too slow (DPoP proof checks,
  token validation in the PEP);
- inside a binary that must stay single and self-contained (the Caddy plugin);
- where the operation is the server's own protocol rather than a TI core (the
  authorization server's endpoints, OpenID Federation as a relying party).

### A concise shared specification

Where Go and Rust implement the same function, neither implementation is the
specification; a document in `spec/<topic>` is. `spec/tsl-xmldsig` is the model:

- **Rules with identifiers** (`TOPIC-nnn`), MUST/SHOULD as in RFC 2119, each one testable,
  mapped to the gematik requirements and RFCs it implements; deviations listed.
- **Result codes** both implementations return, so verdicts compare exactly, not only as
  pass or fail.
- **A corpus with a manifest:** every fixture, its expected result code and the rules it
  covers; real artefacts and generated ones, TEST-ONLY key material only.
- **`CONFORMANCE.md`:** how an implementation proves conformance (the command or test
  entry point that runs the corpus), and the interoperability matrix of the last run.
- **Concise:** the spec states behaviour and limits, not code structure; an implementation
  built from it alone and passing the corpus is conformant.

Both implementations run the corpus in their own test suites, and an interop run checks
each against the other where both produce artefacts (tokens, signatures, lists). A
disagreement is a bug in one implementation or a hole in the spec, and the spec is fixed
first. Rust remains the reference for TI cores; for Go-only server protocols the spec is
written alongside the Go code and Rust follows only if it needs the function.

Candidates for shared specs today: DPoP proofs (`spec/dpop`), OpenID Federation trust
chains (`spec/oidf-sek`), the IDP-Dienst flow (`spec/idp-dienst`), the ZETA client, and
`spec/ti-rpc` for the boundary itself.

## Libraries and commands

```text
 commands   cmd/zero-pdp  cmd/zero-pep-proxy  cmd/zero-bff-pdp  cmd/zero-epa  zero-caddy
              │  flags, env, files, secrets (*_PATH), logger, servers, signals
 servers    pdp/authzserver  pep/proxy  bff/gateway  epa/vau        (http.Handler)
              │
 libraries  oauth  oidf  dpop  nonce  gemidp  kv  brainpool  pkcs12  (no ambient I/O)
```

- `main` and `cmd/` own the process: they read flags, environment and files, build the
  configuration structs, create the logger, the `*http.Client` and the stores, and wire
  them into handlers. Nothing below `cmd/` does that.
- A server package exports an `http.Handler` (or a constructor returning one) and a
  `Config` struct; it is served by `net/http` with explicit timeouts
  (`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`), body limits
  (`http.MaxBytesReader`) and graceful shutdown on the command's context.
- Routing uses `http.ServeMux` with method and path patterns; middleware is
  `func(http.Handler) http.Handler`.
- `context.Context` is the first parameter of anything that does I/O or waits, and
  cancellation is honoured.

## Servers

The server rules in the root `CLAUDE.md` bind Go and Rust alike. In Go terms:

- The service is a package with typed methods (`Authorize(ctx, AuthorizeRequest)
  (AuthorizeResponse, error)`); `http.Handler`s decode, call it and encode. The same
  service can sit behind another adapter (RPC, socket) without change.
- Request decoding is strict: `http.MaxBytesReader`, `json.Decoder` with
  `DisallowUnknownFields`, explicit `Validate()` methods, and URL, header and form values
  parsed into types before use.
- Shared state goes through `kv.Store`; the in-memory store is for tests and single-node
  development only, and production configuration rejects it.
- `kv` encrypts records in the workload before they reach Redis or Postgres (an AEAD
  envelope over the stored value, keyed per purpose, with the key name as associated
  data).
- Outbound HTTP goes through one constructor that applies the SSRF policy (allowed
  hosts, no private or link-local addresses after DNS resolution, no cross-host
  redirects, timeouts, response size limits).
- Images are `scratch` with a static `CGO_ENABLED=0 -trimpath` binary, `USER 65532`,
  base images pinned by digest, signed with provenance and an SBOM.
- Nonces, `state`, CSRF tokens and similar short-lived values are sealed (AEAD with a
  shared workload key, issue time and purpose in the associated data) and verified
  without a lookup; access tokens are signed JWTs (RFC 9068), sender-constrained with
  DPoP, validated offline by the PEP.
- The security state that remains uses `kv` with its transactional backend (Postgres): `Take` for
  single-use values, transactions for read-modify-write. Postgres runs replicated
  synchronously across zones (or a managed service with that guarantee).
- Caches use one shared pattern (keyed by input hash, configuration and trust-material
  version; bounded TTL; invalidated on trust-material reload; single-flight against
  stampedes), the same rules as `ti-cache` on the Rust side.
- Telemetry through one internal instrumentation interface with an OpenTelemetry or
  Prometheus exporter chosen in `cmd/`, and `slog` JSON to stdout; cloud services (KMS,
  attestation, managed databases) behind interfaces with an adapter per provider.

## Transport independence

A client library takes an `*http.Client` (or an `http.RoundTripper`) and never builds
its own TLS configuration or proxy policy; the command decides TLS, mutual TLS, proxies
and timeouts. Tests pass `httptest.Server.Client()`. Where a protocol has non-HTTP
transports (the VAU channel in `epa`), the core is written over `io.Reader`/`io.Writer`
or a small interface, and the network sits in an adapter.

## Cryptography and keys

- Standard library only. `brainpool` is the one exception, because the standard library
  has no brainpool curves: its field arithmetic is generated by Fiat Cryptography and
  formally verified there, wrapped in the shape of the standard library's `nistec`; it is
  frozen (bugfix and security only), and new brainpool work happens in Rust.
- Private keys are `crypto.Signer` / `crypto.Decrypter`. A key loaded from a file becomes
  one at the edge (`cmd/`), and the rest of the code cannot tell it from an HSM. JWKs
  are a wire format for public keys and for import and export, not how a private key is
  held.
- `epa` already follows this to the end: the SMC-B identity, its signatures and the
  IDP-Dienst flow run in the Rust `ti`, and the private key never enters the Go process.
- TLS through `crypto/tls` with its defaults; a server's certificate key is a
  `crypto.Signer` (`tls.Certificate.PrivateKey`), so it can be HSM-backed too.
- Randomness from `crypto/rand` only (`rand.Read`, `rand.Text` for identifiers, state,
  nonces and codes); no time-ordered IDs where an attacker could learn from them.

### Hardware-bound keys

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
  biometric or a card in a reader, and can be cancelled or time out. Signing takes a
  `context.Context`, is cancellable, and errors distinguish "user cancelled", "device
  absent", "PIN blocked"
  and "not permitted" from cryptographic failure.
- **Attestation.** Where the device provides it (TPM, Secure Enclave via App Attest or
  DeviceCheck, FIDO), the key can present attestation of where it lives; protocols that
  rely on hardware binding verify it and do not trust a claim.
- **Platform glue stays at the edge.** Enclave, TPM and FIDO access needs platform APIs
  (Security.framework, TSS or the kernel's TPM device, CTAP over HID); each is an
  adapter package implementing the key traits, never a dependency of a core.

In Go a hardware key is a `crypto.Signer` whose `Sign` honours `SignerOpts` (a digest
with its hash, or `crypto.Hash(0)` for the whole message as `ed25519` uses it); the
context-aware form and the capability and attestation queries are a small interface of
our own next to it.

## Testing

- Standard `testing` only: table-driven tests, subtests, `t.Helper`, `t.Cleanup`,
  `t.Context`. No assertion frameworks; a test states what it expected and what it got.
- Fakes over mocks: small hand-written implementations of the consumer's interface.
- `net/http/httptest` for handlers and clients, `testing/synctest` for code that waits
  or times out, golden files under `testdata/` for wire formats.
- Spec rules carry IDs (`spec/<topic>`); a test names the rule it covers, and fixtures
  are the shared corpora in `spec/` so Go and Rust are held to the same cases.
- Integration tests that need the TI, a Konnektor, a database or the Rust `ti` are
  guarded by environment variables and skip without them; the unit suite needs nothing.

## Tooling that makes the sources safe and secure

| Tool | What it shows | When | Today |
|---|---|---|---|
| `go vet`, staticcheck | correctness and API misuse | check | `just lint` |
| golangci-lint (gosec, errorlint, gocritic, revive, …) | security smells, error handling | check | `just golangci`, not in `just check` |
| `go test -race ./...` | tests pass, no data races | check | not in `just check` |
| `go test -fuzz` | no panic or broken invariant on any input | release, design time | `brainpool`, `pkcs12` only |
| govulncheck | reachable known vulnerabilities | check | `just vuln`, not in `just check` |
| `go mod tidy`, `go mod verify` | no stray or tampered modules | check | `just tidy` |
| gematik OpenAPI ruleset (Spectral) | business API contracts follow the gematik rules | check | `just api-lint` (skips without the internal ruleset) |
| modernize | current idioms of the Go release in use | check | `just check` |
| spec corpora, interop with Rust | same verdicts as the reference | check | partial |

Formal verification in the Rust sense (Kani, hax) has no maintained Go equivalent; Go
keeps security-critical algorithms out of hand-written code instead (standard library,
generated and verified Fiat code, or the Rust core), and covers the rest with fuzzing,
the race detector and the shared spec corpora.

### Fuzzing

- Native fuzz tests, `func FuzzXxx(f *testing.F)`, next to the code they cover, seeded
  with `f.Add` from the spec corpora and real artefacts; crashers land in
  `testdata/fuzz/FuzzXxx/` and are committed, which makes each one a regression test.
- A target asserts more than "no panic": what parses survives its own serialization,
  validation gives the same verdict through every entry point, limits hold.
- Required for every parser of attacker-chosen bytes: DPoP proofs, client assertions,
  PAR and token requests, entity statements and trust chains (`oidf`), ID tokens and
  JWKS (`oauth`), nonces, VAU messages and CBOR (`epa`), routes and policy files (`pep`).
- `just fuzz` runs every target for a short time and fails on a crash; long runs happen
  after changes to a parser.

## Dependencies

The policy is the root `CLAUDE.md`. In Go terms:

- Library modules aim for zero third-party requirements; `golang.org/x` is acceptable,
  test-only modules are not (use `testing`).
- A command may add what the standard library cannot do (a Postgres driver, a Caddy
  plugin host), with the reason recorded next to the requirement.
- Duplicates are removed: one YAML library, one JOSE library, one way to make IDs.
- `go.mod` follows the latest Go release and the latest release of every requirement;
  no `replace` directives on `main`.

## Gaps against this design today

- **The RPC protocol is undecided** (CBOR, protobuf, PKCS#11; see RPC performance), and
  there are no benchmarks or budgets yet, so neither that choice nor the native-or-RPC
  decision has numbers behind it.
- **No `spec/ti-rpc` yet:** `epa` parses the `ti` CLI's `--format json` output, whose
  schema the CLI publishes (`ti schema`) but which is not yet a spec in `spec/` with a
  corpus both sides test against; `ti serve` and its Go client do not exist yet.
- **No shared spec yet for the functions both sides implement** (DPoP, JOSE, OpenID
  Federation); only `spec/tsl-xmldsig` and `spec/pkcs12` exist.
- **`CGO_ENABLED=0`** is set in every Dockerfile, but `just check` and local builds do not
  enforce it.
- **Images:** `zero-pdp` and `zero-epa` set no `USER` and run as root; `zero-caddy` runs on
  `alpine` (shell and package manager in the TCB); base images are referenced by tag, not
  digest; images are not signed and carry no SBOM or provenance.
- **Server rules (root `CLAUDE.md`) not yet met:** no server terminates TLS itself
  (plain HTTP behind an ingress), so TLS ends outside the workload; `kv` stores records
  in plain text in Postgres, with no workload-side AEAD; keys come from files without
  attestation-bound release; `pdp/authzserver` falls back to an in-memory store, which
  breaks horizontal scaling if used in production; the servers have no deployment
  manifests, and the one there is (`metsubushi/k8s.yaml`, non-root, read-only root
  filesystem) has no topology spread or PodDisruptionBudget; outbound fetches in `oidf`
  (`FetchEntityStatement(iss)`) and `oauth` need an SSRF review (allowlist, private
  ranges, redirects, limits).
- **Observability:** no metrics or tracing export (neither OpenTelemetry nor Prometheus),
  no security-signal metrics or alerts (rule 14);
  logs go through `slog` but are not reviewed for personal data or tokens.
- **Protocol profiles:** `pdp` has PAR (single-use `request_uri` via `Take`) and PKCE,
  but has not been assessed against RFC 9700 and FAPI 2.0 as a whole; there are no wallet
  flows yet, so HAIP applies from the first OID4VCI or OID4VP endpoint on.
- **Further server rules (root `CLAUDE.md`, 16–26) not yet assessed:** there are no
  OpenAPI contracts in the repository, so no gematik API linting or contract
  tests yet; no start-up validation that rejects insecure production configuration
  (the in-memory store fallback is an example); no audit trail separate from the
  operational logs; no per-tenant data keys; no admission policy, chaos or DAST runs.
- **Servers start with bare `http.ListenAndServe`** (`zero-pdp`, `zero-pep-proxy`,
  `zero-bff`, `zero-bff-pdp`): no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` or
  `IdleTimeout`, so slow clients can hold connections open (slowloris), and no graceful
  shutdown on SIGTERM. There are no liveness, readiness or metrics endpoints at all, and
  so no admin listener either.
- **Nonces are stored, not sealed:** `pdp` issues every nonce into `kv`
  (`nonce.NewKVService`), a store round trip per nonce. The alternative
  `HashicorpNonceService` seals nonces with a key generated in process memory, so a
  nonce issued by one replica fails on another. Both should give way to one stateless
  sealed nonce (AEAD over issue time, purpose and binding) under a shared workload key,
  which also removes `go-secure-stdlib/nonceutil`.

- **`just check` runs neither the tests nor govulncheck nor golangci-lint**; it is
  `lint` and `modernize` only. The installed govulncheck is built with an older Go and
  fails on the current sources.
- **No hardware-key abstraction yet:** no capability, interaction or attestation
  interface next to `crypto.Signer`, and no Enclave, TPM or FIDO adapters (a TPM adapter
  without cgo would go through the kernel device and a pure-Go TSS such as
  `google/go-tpm`, subject to the dependency rules).
- **Private keys by value:** `pdp/authzserver` holds its signing key as a `jwk.Key`
  loaded from a file; it should hold a `crypto.Signer`.
- **Ambient I/O in libraries:** `pep/proxy` and `bff/gateway` read environment variables
  (`PEP_API_UPSTREAM`, `API_UPSTREAM`, …) themselves; that belongs in their commands.
  About 40 `time.Now()` calls outside tests mean decision code reads the clock.
- **Fuzzing** covers the frozen `brainpool` and `pkcs12` only; every server-side parser
  in the list above is missing.
- **Dependencies** (from the review, October 2026):
  - testify in production code (`epa/config.go` parses YAML with `testify/assert/yaml`);
  - three YAML libraries (`gopkg.in/yaml.v2` deprecated, `gopkg.in/yaml.v3` archived,
    testify's), to become `go.yaml.in/yaml/v3`;
  - `godotenv` (against secrets from `*_PATH` files), `segmentio/ksuid` and
    `google/uuid` (to become `crypto/rand.Text`), `phsym/console-slog` (to become
    `slog`), `x/crypto/hkdf` (to become `crypto/hkdf`);
  - `spf13/viper` and `labstack/echo` (about 40 modules; flags plus `os.Getenv` in
    `cmd/`, and `http.ServeMux`);
  - `go-playground/validator` (reflection, about 20 modules; explicit `Validate`
    methods are easier to review for the authorization server);
  - `lestrrat-go/jwx`: the largest unaudited cryptographic dependency, one maintainer,
    and a second JOSE implementation next to `brainpool/josebp`; strategy open;
  - to examine: `cloudflare/circl` (Kyber768 vs `crypto/mlkem`, depends on what the
    VAU specification requires), `hashicorp/go-secure-stdlib/nonceutil` (pre-1.0,
    MPL-2.0), `skip2/go-qrcode` (unmaintained since 2020), and whether `zaddy` needs
    Caddy's about 550 modules.
