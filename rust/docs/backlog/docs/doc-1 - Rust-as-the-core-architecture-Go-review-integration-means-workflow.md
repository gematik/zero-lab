---
id: doc-1
title: 'Rust as the core: architecture, Go review, integration means, workflow'
type: specification
created_date: '2026-10-10 15:03'
---

# Rust as the core: architecture, Go review, integration means, workflow

Worked out 2026-10-10 while planning the epa integration (task-24). Not executed as a whole; the roadmap stages become tasks when their turn comes.

## 1. Go review

Dependency graph (intra-repo):

```
L0  brainpool        kv          pkcs12       oauth/oidc
L1  gempki(brainpool)  nonce(kv)  dpop(jwx)  oidf(oauth)  gemidp(brainpool/josebp, oauth, pkcs12 tests)
L2  kon(gempki, pkcs12, brainpool)   epa(gemidp, gempki, pkcs12, brainpool, oauth; vau: circl/kyber)
    pep(dpop, gemidp, kv, oauth, oidf)
L3  pdp(pep, dpop, gemidp, kv, nonce, oauth, oidf)   zaddy(pep, dpop, caddy)
    ti(kon, epa, gemidp, gempki, pkcs12, brainpool, oauth, sqlite)
L4  bff(pdp, pep, dpop, kv, nonce, gemidp, oauth, oidf)   metsubushi(—)
```

Clean cut: **client cluster** {`ti`, `epa`, `kon`, `gempki`, `pkcs12`} — no server imports
it. **Server cluster** {`pdp`, `pep`, `bff`, `zaddy`, `kv`, `nonce`, `dpop`, `oauth/oidc`,
`oidf`-RP, `gemidp`-RP, `brainpool`} stays Go; RP glue is one 7-method `oidc.Client`
interface; JOSE in Go is jwx + josebp (no jwz port). After this plan, `epa` is the first Go
module consuming the Rust stack; `gempki`, `pkcs12`, `kon`, `ti` become removable (`ti`,
`kon`: archive at `go/ti/v0.23.4`, `go/kon/v0.21.4`; `gempki`/`pkcs12` once `gemidp` RP
tests stop using `pkcs12`), `gemidp` stays for the servers' RP role, `brainpool` frozen.

## 2. Integration means (analysis)

| Means | Build | Deployment | Per-call | Isolation |
|---|---|---|---|---|
| cgo static | C linker per target, ends `CGO_ENABLED=0`, slower builds, race-detector friction, inherited by xcaddy users | one binary | <100 ns, pins a thread | none; needs `panic=unwind`+`catch_unwind` |
| purego | no C toolchain | `.so` on disk (extract), libc in image | ≈cgo | none |
| wazero | zero; Rust already wasm32 | embedded `.wasm`, fully static | 2–5× native crypto | sandboxed |
| subprocess per call | zero | static `ti` in image | 10–100 ms | full |
| child over stdio (JSON-RPC) | zero | same image, child dies with parent | ~50–150 µs + JSON, warm caches | process |
| UDS sidecar | zero | sidecar container, socket perms | same, multiplexed | process; also serves Java 17/21 servers without JNA |

Decision for `epa` (this plan): subprocess per call behind Go interfaces. Predicted general
rule: per-request work native Go; Rust reaches Go (and server Java) via `ti serve`
(JSON-RPC 2.0 over stdio/UDS on the schema-1 contract) with a typed Go client; wazero as
in-process fallback for per-update computation where a second binary is impossible
(xcaddy); cgo/purego rejected unless a measured per-request path needs them.

## 3. Target structure

```
zero-lab/
  ARCHITECTURE.md   Justfile (thin)   .github/workflows/{go,rust,interop,bindings}.yml
  spec/     tsl-xmldsig (exists), dpop, oidc-rp, oidf-sek, idp-dienst, zeta-client, ti-rpc
  interop/  Go-server harness drivers, oracles, binding smoke vectors, bench
  go/       server cluster unchanged; epa on the Rust ti; ticlient/ (later); client cluster archived
  rust/     core crates flat; ti-idpd (this plan), ti-oauth ti-oidc ti-oidf ti-zeta (sans-I/O
            engines); ti-rpc; bindings/{ti-ffi (uniffi), ti-wasm, ti-wasm-abi?}
  java/     uniffi Kotlin output + Java facade + jar; UDS client of ti-rpc for servers
  swift/    XCFramework build + Package.swift template → satellite github.com/gematik/zero-lab-swift
```

Bindings: uniffi proc-macros → Swift XCFramework (satellite repo), uniffi Kotlin (JNA) +
Java facade for JVM 17/21 (uniffi-bindgen-java needs Java 22+, 0.x — revisit at JVM 25);
wasm-bindgen stays for the browser. Hosts do HTTP; engines are sans-I/O. Rust and bindings
Apache-2.0, Go EUPL-1.2. GitHub Releases only.

## 4. Sync workflow

Spec-first (`spec/<topic>` rule IDs + corpus + CONFORMANCE.md), Rust-first (reference),
Go only for server counterparts; `just traceability` fails on a claimed rule without a
test; fixtures canonical in `spec/`, hash-pinned copies with PROVENANCE.md; `interop/`
runs Rust engines, `ti` CLI, `ti-rpc` and bindings against `zero-pdp` (`mockidp`),
`zero-pep-proxy`, `oidf` test federation via the `go/pdp/e2e` harness; tags per unit plus
`bindings/vX.Y.Z`; CI calls the existing `just check`s; compatibility matrix in
ARCHITECTURE.md.

## 5. Roadmap (one branch, plan and HITL proof per stage)

0 epa on the Rust `ti` (this plan: `ti identity`, `ti-idpd`, `ti idpd authenticate`) · 1 Go
footprint (archive `ti`, `kon`; status table) · 2 jwz prerequisites (TASK-15, TASK-18,
`oauth-dpop` + `openid-federation` profiles, TASK-20) · 3 `ti-oauth` (PAR, PKCE,
`private_key_jwt`, DPoP) · 4 `ti-oidc` · 5 `ti-idpd` completed (RP side, SMC-B via
Konnektor) · 6 `ti-oidf` · 7 `ti-zeta` (+ `ti zeta …`, e2e vs `zero-pdp`/`zero-pep-proxy`)
· 8 `ti serve`/`ti-rpc` + `go/ticlient` (+ Java UDS client) · 9 bindings (`ti-ffi`,
`java/`, `swift/`, `ti-wasm`) · later: `ti-wasm-abi` if needed, ePA VAU port (TASK-10).

## Sources

Arcjet "Calling Rust FFI libraries from Go" (purego, zigbuild); Stoolap "Calling a Rust
library from Go with CGO_ENABLED=0"; pact-go RFC #452 (purego); Apache OpenDAL Go binding
(purego+libffi); ncruces/go-sqlite3 (wasm in pure Go); libsignal and matrix-rust-sdk
(repo layouts, satellite repos); uniffi-rs bindings docs; IronCoreLabs/uniffi-bindgen-java
(Panama, Java 22+); NordSecurity/uniffi-bindgen-go (cgo, 0.x); GopherCon 2018 "Adventures
in Cgo Performance"; rust-cross/cargo-zigbuild.
