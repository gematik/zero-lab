# Crossing languages

How code in one language uses functionality from another. The Go and Rust profiles map
this to their side; future bindings follow the same rules.

## No native core linked into a server process

A server process does not link another language's native library: no cgo in Go, no
purego or libffi loading of a Rust library, no JNI or JNA into a Java server. It would
bring a C toolchain into every build, break static cross-compilation, put memory-unsafe
glue and a second runtime into the server process, and tie releases to ABI details. The
cost it would save, a process boundary, is small for everything but per-request hot paths,
and those are implemented natively under a shared specification (below).

Client platforms are different: an app on iOS, Android, desktop or in the browser embeds
the Rust core through generated bindings (uniffi, wasm-bindgen), because there is no
process boundary to use and the binding generators keep the glue out of hand-written code.

## Three ways to use the core

**Across a process boundary**, with the Rust `ti` or a stateless helper as the
implementation:

| Mode | Fits | Example |
|---|---|---|
| `ti` subprocess per call | rare operations, CLIs, start-up checks, the ePA client today | `epa` runs `ti identity sign`, `ti idpd authenticate`, `ti pki verify` |
| helper as a child over stdio (`ti-<group>-helper`) | a server's repeated calls, trust material loaded once, one container | planned (TASK-120) |
| helper as a sidecar over a Unix socket (`ti-<group>-helper --listen unix:…`) | a sidecar container started from the same image; access by socket permissions and peer checks | planned (TASK-120) |
| network service | never for a helper: a helper has no network listener | — |

A helper is a stateless server binary: the hand-picked methods of one group with the JSON
types of `ti --format json`; no profile, configuration directory, store, cache file or
key file; trust material supplied by the host and kept in memory, the renewal policy
owned by the helper ([architecture](architecture.md#isolated-ti-functions)). Where it
runs and how it is deployed is in [servers](design/servers.md), its naming in
[naming and configuration](conventions/naming-and-config.md), its layout in images in
[git and releases](conventions/git-and-releases.md). The `ti` CLI keeps its profiles and
caches for humans. The decision record is decision-10.

**Through generated bindings**, on client platforms (above).

**Natively, under a shared specification, or translated**, when a process boundary does
not fit. Go decides per TI function, in this order (decision-10):

1. The server's own protocol (the authorization server's endpoints, DPoP, OpenID
   Federation as a relying party) is native Go.
2. A host that must be one self-contained `go install` binary (the Caddy plugin) and
   needs a core function uses the core compiled to WebAssembly and translated to Go
   (wasm2go), never a second implementation: the module imports nothing, one C ABI crate
   with every `unsafe` block in one file under Miri, guest memory read through
   bounds-checked slices, one instance per concurrent caller, bounded inputs, the
   generated file reproduced by a recipe and checked in CI, the generator pinned. No
   host needs it today.
3. Every other TI function goes through the helper.
4. A native implementation under a shared specification only where a measured
   per-request path needs it, and then with the specification, its corpus, a
   traceability table and an interop run against Rust in `just check`.

A TI certificate rule (path validation, TSL, OCSP, profiles, admission) is never
implemented in Go under 4 without that measurement; the SMC-B check of token exchange
goes through the helper.

## Rules for every process boundary

- The contract is versioned and written down (`spec/ti-rpc`): methods, request and
  response schemas, error codes, limits. The CLI's `--format json` output follows the
  same schema, so a subprocess and the RPC service return the same shapes.
- The calling side talks to it through a small typed client behind a consumer interface,
  so callers cannot tell a subprocess from a socket, and tests use a fake.
- Secrets stay on the side that owns them: private keys, PINs and card handles never cross
  the boundary (as in `epa` today, where the key never enters the Go process). What
  crosses is data to sign or verify and the verdicts.
- Inputs are validated on both sides and outputs are treated as untrusted until parsed
  against the schema; timeouts, size limits and cancellation are part of the contract.
- The caller checks the version of the binary or service at start-up and refuses an
  incompatible one.

## RPC performance

The RPC boundary must be as fast as the process boundary allows; it is on request paths,
and a slow boundary would push functions into native implementations that should stay in
the core.

- **Long-lived peers, no per-call spawn.** A helper starts once, verifies the trust
  material the host supplies once and keeps it hot in memory (TrustStore, OCSP caches); a
  call does only the work of the call. Subprocess per call stays for rare operations and
  the CLI.
- **Unix domain sockets or stdio pipes by default**, TCP only across hosts. No HTTP, no
  TLS handshake on a local boundary; authentication of a local peer is the socket's file
  permissions (and `SO_PEERCRED` where available).
- **A binary encoding, no text on the hot path.** Bulk data (certificates, TSLs,
  messages to sign) travels as raw bytes, never base64 or hex. Which encoding is open
  (below).
- **Multiplexed and pipelined.** Request IDs let one connection carry many calls in
  flight; the client keeps a small pool of connections and never serialises callers
  behind one request. Batch methods (verify N certificates) where callers have N.
- **No avoidable copies or allocations.** Frames are read into reused buffers on both
  sides.
- **Measured, with budgets.** `spec/ti-rpc` states latency (p50, p99) and throughput
  budgets per method on reference hardware; `just bench` on both sides measures round
  trips over the real socket, and a regression beyond the budget fails the check.
- **Same semantics as the CLI.** The protocol carries the same methods, result codes and
  limits as `ti --format json`; JSON stays the human and debugging form, and a
  conformance test runs the corpus through both.
- **The codec is a parser of input from another process** and is fuzzed on both sides.

Decided for the first helpers: JSON lines (TASK-120.2; TASK-116 measured no difference
in the median against length-prefixed binary at certificate-check sizes). Open: the
framing for bulk data (TASK-65). Candidates, to be decided with measurements and against
the dependency policy:

| Candidate | For | Against |
|---|---|---|
| CBOR (RFC 8949) | binary, self-describing, raw byte strings; Go already uses `fxamacker/cbor` (hardened, fuzzed) in `epa` | a Rust crate needed (minicbor was removed); schema lives in the spec, not in the format |
| protobuf (gRPC or plain frames) | schema-first, generated code, mature tooling, streaming with gRPC | the largest dependency trees on both sides (`google.golang.org/protobuf`, gRPC; `prost`/`tonic`), code generation in the build |
| PKCS#11 semantics | the standard interface for keys as functions: HSMs, tokens and `ti` behind one API, sessions and object handles; fits the key rules | a C API: native PKCS#11 in a server needs FFI, so only a remoted form over a socket (as p11-kit's RPC does) fits the rule above; covers keys and crypto, not TSL or IDP operations |

PKCS#11 and a general RPC are not exclusive: key operations could follow PKCS#11 while
verification and protocol calls use the general protocol.

## A concise shared specification

Where two languages implement the same function, neither implementation is the
specification; a document in `spec/<topic>` is. How to write one is in
[`spec/README.md`](../spec/README.md); `spec/tsl-xmldsig` and `spec/pkcs12` are the models.
Every implementation returns the specification's result codes in the same report schema
([architecture](architecture.md#isolated-ti-functions)), so verdicts compare exactly.

Both implementations run the corpus in their own test suites, and an interop run checks
each against the other where both produce artefacts (tokens, signatures, lists). A
disagreement is a bug in one implementation or a hole in the spec, and the spec is fixed
first. Rust remains the reference for TI cores; for protocols that exist only in one
language the spec is written alongside that code, and another language follows only if
it needs the function.

Candidates for shared specs today: certificate and TLS peer verification for TI endpoints
(`spec/pki-validation`: anchors, profiles, algorithm and key rules, OCSP; see
[architecture](architecture.md#the-host-owns-the-transport-the-core-owns-trust)), the
TSL's detached signature (`spec/tsl-detached`, TASK-166), DPoP proofs (`spec/dpop`),
OpenID Federation trust chains (`spec/oidf-sek`), the IDP-Dienst flow
(`spec/idp-dienst`), the ZETA client, and `spec/ti-rpc` for the boundary itself.
