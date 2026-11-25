# zero-lab for agents

zero-lab holds building blocks for the German Telematikinfrastruktur (TI) in two workspaces:
Rust crates in [`rust/`](rust), the maintained core, and Go modules in [`go/`](go), the
servers, relying parties and the ePA client. Specifications both must meet are in
[`spec/`](spec/README.md).

This file is the map. Find the unit here, then read only the document its row names; there
is no need to open every module or README. It states no rules:

- **To change this repository**, the binding rules are in [`CLAUDE.md`](CLAUDE.md) and
  [`docs/`](docs/README.md). Read those the change touches before planning it.
- **To use the `ti` command-line tool**, its only description is
  [`rust/ti-cli/AGENTS.md`](rust/ti-cli/AGENTS.md), which the installed tool prints with
  `ti agent`.
- **To use a library**, read its row's document, then its API: `cargo doc -p <crate>` in
  `rust/`, `go doc ./...` in the module's directory.

Every unit of both workspaces has one row below; `just check` fails when one is missing.

## Which unit for which task

| Task | Rust | Go |
|---|---|---|
| Validate a TI certificate, read or verify the TSL, check OCSP | `ti-pki` | `tipki` |
| Verify a TLS server: a TI service, or an internet host under the hardened Web-PKI profile | `ti-tls` | `tipki/titls` (TI), `egress` (internet) |
| JWS, JWE, JWK, JWT | `jwz` | |
| JOSE and keys on brainpool curves, the TI's algorithm profiles | `ti-jwz` | `brainpool`, `brainpool/josebp` |
| Read or write a PKCS#12 file (`.p12`), also BER and legacy encryption | `ti-pkcs12` | `pkcs12`, `pkcs12/legacy` |
| Call a Konnektor: cards, PINs, signing, `.kon` configurations | `ti-connector-client` | |
| Log in at the IDP-Dienst with a smartcard or a software key | `ti-idpd-client` | `idpd` |
| Get tokens of the FHIR-Directory (VZD) | `ti-directory-client` | |
| All of the above from a shell or a script | `ti-cli` (`ti`) | |
| TSL and certificate reports in a browser | `ti-wasm` | |
| Keep a server's key in an HSM, reached through a sidecar | `ti-hsm-proxy` (`hsm-proxy`) | |
| ePA für alle: the VAU channel, a client proxy | | `epa` (`zero-epa`) |
| OpenID Connect login; relying party of the TI's OpenID Federation | | `openid`, `oidf` |
| DPoP proofs, for clients and servers (RFC 9449) | | `dpop` |
| Enforce access tokens, DPoP and sessions in front of an HTTP resource | | `pep`, `zaddy` (Caddy), `pep/proxy` |
| Check an HTTP request before a server's logic sees it | | `httpguard` |
| Outbound connections of a server to the internet | | `egress` |
| Shared state of a server's replicas: sessions, replay detection, revocations | | `kv` |
| Nonces that need no store | | `nonce` |

## Rust crates

A crate depends only on crates of a lower layer
([Rust profile](rust/docs/design.md#1-role-and-units)). The cores and engines do no I/O: the
host passes the transport, the clock and the keys. `jwz` is published on crates.io; every
other crate is taken by its git tag `rust/<crate>/vX.Y.Z`
([development guide](rust/docs/development.md)).

| Crate | Layer | What it is | Depends on | Read |
|---|---|---|---|---|
| [`rust/ti-types`](rust/ti-types) | vocabulary | Environments and identifiers of the TI; `no_std`, no dependencies | | [README](rust/ti-types/README.md) |
| [`rust/ti-cache`](rust/ti-cache) | vocabulary | HTTP-style caching policy (freshness, revalidation, stale on error) over a store the host supplies | ti-types | [README](rust/ti-cache/README.md) |
| [`rust/jwz`](rust/jwz) | core | JOSE: JWS, JWE, JWK, JWT with an open algorithm registry, keys as functions, pluggable crypto backends, validation profiles | | [README](rust/jwz/README.md), [guide](rust/jwz/docs/guide.md) |
| [`rust/ti-jwz`](rust/ti-jwz) | core | The TI's profiles for jwz (`ti()`, `ti_legacy()`) and brainpoolP256r1 | jwz | [README](rust/ti-jwz/README.md) |
| [`rust/ti-pki`](rust/ti-pki) | core | X.509 validation against the TI PKI: certificate types and profiles, TSL, OCSP, trust bundles; downloads only behind its `load` and `os` features | ti-cache, ti-types | [README](rust/ti-pki/README.md) |
| [`rust/ti-pkcs12`](rust/ti-pkcs12) | core | PKCS#12 decoding, BER and legacy encryption included; encoding behind `encode` | | [README](rust/ti-pkcs12/README.md) |
| [`rust/ti-connector-client`](rust/ti-connector-client) | engine | Client of the Konnektor's SOAP services and its `.kon` configuration; the bindings in `src/api` are generated | ti-cache, ti-pkcs12, ti-pki, ti-types | [README](rust/ti-connector-client/README.md) |
| [`rust/ti-idpd-client`](rust/ti-idpd-client) | engine | Client of the IDP-Dienst: the Authenticator-Modul flow of a Primärsystem | jwz, ti-jwz, ti-pki, ti-types | crate documentation (`src/lib.rs`) |
| [`rust/ti-directory-client`](rust/ti-directory-client) | engine | Client of the FHIR-Directory's Auth-Service: its token paths | ti-types | crate documentation (`src/lib.rs`) |
| [`rust/ti-tls`](rust/ti-tls) | adapter | TLS server verification as rustls verifiers: TI servers through ti-pki, internet servers under the `web` profile | ti-pki | [README](rust/ti-tls/README.md) |
| [`rust/ti-client`](rust/ti-client) | adapter | The native host library: transports over ureq, file storage, and each command's operation as a synchronous API | every crate above | [README](rust/ti-client/README.md) |
| [`rust/ti-cli`](rust/ti-cli) | host | `ti`, the command-line tool; only parses, prompts and prints | ti-client and the cores | [AGENTS.md](rust/ti-cli/AGENTS.md) to use it, [README](rust/ti-cli/README.md) |
| [`rust/ti-wasm`](rust/ti-wasm) | host | TSL and certificate reports as WebAssembly: pure functions, no network, no clock | ti-pki | [README](rust/ti-wasm/README.md) |
| [`rust/ti-hsm-proxy`](rust/ti-hsm-proxy) | host | `hsm-proxy`, a sidecar that serves gematik's HSM proxy gRPC interface on keys reached over PKCS#11; unreleased | | [README](rust/ti-hsm-proxy/README.md), [operating](rust/ti-hsm-proxy/docs/operating.md) |
| [`rust/traceability`](rust/traceability) | tooling | Writes and checks the crates' requirement traceability tables; a dev-dependency | | `src/lib.rs` |
| [`rust/unsafe-audit`](rust/unsafe-audit) | tooling | Checks that the cores' dependencies hold no `unsafe` beyond the approved exceptions | | [unsafe exceptions](rust/docs/unsafe-exceptions.md) |

## Go modules

Libraries read no environment, flag or file; a command's `cmd/` does
([Go profile](go/docs/design.md#1-role-and-units)). Each module is taken by its git tag
`go/<module>/vX.Y.Z`. A module without a README is described by its package comment, in the
file its row names.

| Module | Layer | What it is | Depends on | Read |
|---|---|---|---|---|
| [`go/brainpool`](go/brainpool) | library | Brainpool curves (RFC 5639), their X.509 certificates and keys, and `josebp`, JOSE on them | | [README](go/brainpool/README.md) |
| [`go/pkcs12`](go/pkcs12) | library | PKCS#12 encoding and decoding; `legacy` reads BER and the old encryption schemes | | [README](go/pkcs12/README.md) |
| [`go/tipki`](go/tipki) | library | The TI's PKI in Go: certificate types and profiles, trust bundles (`bundlefile`, `fetch`), OIDs (`oid`), TLS verification under the `ti` profile (`titls`) | brainpool | [README](go/tipki/README.md) |
| [`go/egress`](go/egress) | library | A server's connections to the internet: the `web` TLS profile and the egress client (https only) | | `doc.go` |
| [`go/httpguard`](go/httpguard) | library | The request checks every server runs first: path, single parameters, Host; standard library only | | `path.go` |
| [`go/kv`](go/kv) | library | Key/value store with TTLs behind one interface; `postgres` backend, `revoked` sets, sealed records | | `kv.go` |
| [`go/nonce`](go/nonce) | library | Nonces that verify themselves (AES-256-GCM), no store | | `nonce.go` |
| [`go/dpop`](go/dpop) | library | DPoP (RFC 9449) for clients and for servers that check proofs | | [README](go/dpop/README.md) |
| [`go/openid`](go/openid) | library | OpenID Connect login by authorization code with PKCE; `providers`, the list of identity providers a server offers | | `openid.go` |
| [`go/oidf`](go/oidf) | library | Relying party of the gematik OpenID Federation: entity statement, verified fetches, logins at federated providers | openid | `oidf.go` |
| [`go/oidftest`](go/oidftest) | test | A federation master and a sektoral IDP on one test server; imported by tests only | oidf, openid | `oidftest.go` |
| [`go/idpd`](go/idpd) | library | Client of the IDP-Dienst: relying party of its code flow, and the Authenticator that answers its challenge | brainpool, egress, openid, pkcs12, tipki | `client.go` |
| [`go/pep`](go/pep) | library | Policy enforcement point for HTTP: enforcers on access token, DPoP proof or session cookie, denials as OAuth errors | dpop | `pep.go` |
| [`go/pep/proxy`](go/pep/proxy) | command | `zero-pep-proxy`, an oauth2-proxy-style login gateway that keeps tokens on the server | pep, oidf, idpd, openid, kv, dpop, egress, httpguard, tipki, brainpool | [design](go/pep/proxy/docs/DESIGN.md) |
| [`go/zaddy`](go/zaddy) | command | `zero-caddy`, a Caddy build with pep as its handlers (`enforce_policy`, `protected_resource_metadata`) and the ZETA PEP headers | pep, dpop, kv, nonce, egress, httpguard | [README](go/zaddy/README.md) |
| [`go/epa`](go/epa) | command | `zero-epa`, a client of ePA für alle: the VAU channel (`vau`), authorization, a proxy with a developer portal; drives the Rust `ti` for brainpool identities and PKI (`ti`) | brainpool, egress, httpguard, tipki | `authz.go` |
| [`go/pdp`](go/pdp) | command | `zero-pdp`, a prototype policy decision point (OAuth authorization server); frozen, it gets no features, fixes or releases | most libraries | [e2e](go/docs/e2e.md) |
| [`go/metsubushi`](go/metsubushi) | command | A pod smoke-test endpoint that echoes the request and shows pod information | | [README](go/metsubushi/README.md) |

## Shared specifications

Where Rust and Go implement the same function, a specification with rule identifiers, result
codes and a test corpus decides, not either implementation ([`spec/`](spec/README.md)).

| Specification | Topic | Implemented by |
|---|---|---|
| [`spec/pki-path`](spec/pki-path/README.md) | Certificate chains from a trust bundle | ti-pki, tipki |
| [`spec/pki-profiles`](spec/pki-profiles/README.md) | Certificate types, admission, validation profiles | ti-pki, tipki |
| [`spec/pki-validation`](spec/pki-validation/README.md) | TLS server certificates under the `ti` and `web` profiles | ti-pki, ti-tls, tipki/titls, egress |
| [`spec/tsl-detached`](spec/tsl-detached/README.md) | TSL verification by the detached signature | ti-pki |
| [`spec/tsl-xmldsig`](spec/tsl-xmldsig/README.md) | TSL signer, update, anchor change, CA status | ti-pki |
| [`spec/pkcs12`](spec/pkcs12/README.md) | PKCS#12 decoding and encoding | ti-pkcs12, pkcs12 |

## Where the rest is

| What | Where |
|---|---|
| Principles, architecture, design rules, conventions | [`docs/`](docs/README.md) |
| Building, checking, releasing a workspace | [`rust/docs/development.md`](rust/docs/development.md), [`go/docs/development.md`](go/docs/development.md) |
| What changed in a release | [`rust/ReleaseNotes.md`](rust/ReleaseNotes.md), [`ReleaseNotes.md`](ReleaseNotes.md) (Go) |
| Requirement to code to test, per crate | `rust/<crate>/docs/traceability.md` |
| Open work, decisions | [`backlog/`](backlog), used through the `backlog` CLI ([rules](docs/conventions/backlog.md)) |
