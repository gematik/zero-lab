---
id: decision-10
title: >-
  Stateless Rust helpers in the same image are the server boundary; Go decides
  per TI function
date: '2026-11-01T16:11:00Z'
status: accepted
---
## Context

The Go PDP needs the TI certificate check for token exchange with an SMC-B proof, and
Go has no certificate trust code. doc-1 predicted "per-request work native in Go, the rest
through `ti serve`"; TASK-116 measured the bridges (a long-lived Rust process 1.3 ms per
check, wasm2go 5 ms, purego 2.3 ms with native code in the process, wazero 34 to 431 ms);
its draft decision-8 (branch `spike/go-rust-bridge`) is absorbed here. TASK-120 planned
helpers with a profile store and caches on disk. The maintainer added on 2026-11-01: the
PDP is zero trust; helpers for servers must carry no configuration or state; Unix sockets
over network; a compatible architecture without re-implementing SPIFFE or Istio, in one
image that supports several deployments; secondary stacks are clients only. The weighing
is doc-2.

## Decision

1. **Stateless Rust helpers are the way a server reaches the core.** One static binary per
   group (`ti-pki-helper`, `ti-idpd-helper`), shipped in the product's image, with no
   profile, configuration directory, store, cache file or key file; configuration by flags
   and environment; trust material supplied by the host from a mounted directory and kept
   in memory; the renewal policy owned by the helper, the I/O by the host.
2. **Two modes, one protocol, one client.** A child over stdio inside one container, or a
   sidecar container started from the same image over a Unix socket in a shared
   `emptyDir`. The sidecar rules of `docs/design/servers.md` hold in both modes: the
   helper is part of the measured workload, peer checks, no network listener, no secrets
   across the socket, bounded frames, versioned handshake, fail closed. Platform identity,
   mesh and attestation are consumed through their standard interfaces, never provided.
3. **Go decides per TI function, in this order:** (a) the server's own protocol (OAuth,
   DPoP, OIDC, OpenID Federation as a relying party) is native Go; (b) a host that must be
   one `go install` binary and needs a core function uses the core compiled to WebAssembly
   and translated to Go (wasm2go) under the conditions below, never a second
   implementation; (c) every other TI function goes through the helper; (d) a native
   implementation under a shared specification only where a measured per-request path
   needs it, and then with the spec, its corpus, a traceability table and an interop run
   in `just check`. The SMC-B check of token exchange is (c).
4. **wasm2go conditions:** the module imports nothing (no I/O, clock or randomness); one
   C ABI crate with every `unsafe` block in one file under Miri; guest memory read only
   through bounds-checked slices; one instance per concurrent caller; bounded inputs,
   since a running call cannot be cancelled; the generated file reproduced by a recipe
   and checked in CI; the generator pinned, and vendored if its single maintainer stops.
   No host needs it today: the Caddy plugin validates the PDP's tokens natively.
5. **Rejected:** cgo, purego and every native load; wazero (third-party code and `unsafe`
   in every program, too slow as an interpreter, a JIT otherwise); a universal `ti serve`
   with state on disk; a Java client of the helpers for servers (JVM is a client stack).
6. **A `ti` process per call stays** for rare operations, the CLI and, for now, epa.
7. **The TSL's detached signature replaces XMLDSig on the trust path** (TASK-166), which
   shrinks the core every stack embeds; the deviation from TUC_PKI_012 for internet
   consumers is recorded and, if the pre-release TI 2.0 requirements exclude it, taken
   to gematik's PKI team (TASK-167).

## Consequences

- `docs/interop.md`, `docs/design/servers.md`, `docs/architecture.md`,
  `docs/languages.md`, the naming and release conventions and both profiles carry the
  rules (TASK-165).
- TASK-120 and its subtasks are rewritten for stateless helpers; TASK-26's Java client is
  gone; TASK-120.7 (epa) waits for the ePA local setup design.
- The PDP's token exchange (TASK-168), OPA (TASK-169), HSM binding (TASK-170) and the Go
  relying parties' certificate verification (TASK-171) build on the helper.
- A Go implementation of a TI certificate rule is not proposed again unless (d) applies
  and is measured.
