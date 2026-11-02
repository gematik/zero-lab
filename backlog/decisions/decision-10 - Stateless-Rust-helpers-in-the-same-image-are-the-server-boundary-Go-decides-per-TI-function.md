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
   DPoP, OIDC, OpenID Federation as a relying party) is native Go; (b) every other TI
   function goes through the helper; (c) a native implementation under a shared
   specification only where a measured per-request path needs it, and then with the
   spec, its corpus, a traceability table and an interop run in `just check`. The SMC-B
   check of token exchange is (b).
4. **Go is human-reviewable** (maintainer, 2026-11-01, amending the first version of
   this decision): no translated or embedded executable code ships in Go. That rules out
   wasm2go, which the spike had kept for a host that must be one `go install` binary
   (the generated file has about 300,000 lines). Such a host, the Caddy plugin today,
   validates the PDP's tokens natively and carries no TI core function; needing more
   would be a design decision with its own task.
5. **Rejected:** cgo, purego and every native load; wazero (third-party code and `unsafe`
   in every program, too slow as an interpreter, a JIT otherwise); wasm2go (not
   reviewable); a universal `ti serve` with state on disk; a Java client of the helpers
   for servers (JVM is a client stack).
6. **A `ti` process per call stays** for rare operations, the CLI and, for now, epa.
7. **The TSL's detached signature replaces XMLDSig** (TASK-166; removal decided by the
   maintainer 2026-11-01, ahead of the requirements check), which shrinks the core every
   stack embeds. The deviation from TUC_PKI_012 for internet consumers is recorded, and the
   request for change goes to gematik's PKI team (TASK-167). A network that blocks the
   plain-HTTP CRL host can no longer take new lists until `.sig` is published on HTTPS.

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

## Amendment, 2026-11-02

Maintainer: critical flows use the smallest possible Go-native libraries. This replaces 3 (b) and (c)
and the last consequence above, for what is built natively: such a library needs no measured
per-request path. It keeps their safeguards: a shared specification, a corpus Rust writes and both
run, and tests named after the rules. It stays as small as the flow allows, and aligns to `ti-pki`
rather than to the old `gempki`.

First: `go/tipki`, certificate types, admission and profiles (`spec/pki-profiles`). It reads a
certificate and decides nothing about trust. Chain, TSL and OCSP are decided per flow, and with
them what remains of the helper.
