---
id: doc-2
title: 'Stacks: what is common, what is separate'
type: specification
created_date: '2026-11-01T16:11:00Z'
---

# Stacks: what is common, what is separate

Worked out 2026-11-01 with the maintainer (TASK-165) when the Go PDP was about to gain
token exchange with an SMC-B client proof. That function needs the whole TI certificate
check, which Go does not have and Rust does, and it is the first case where doc-1's
prediction ("per-request work native in Go, the rest through a Rust process") had to be
applied. This document settles that case and the rule behind it for every stack. Its
decisions are recorded in decision-10; the rules it changes live in `docs/`.

## 1. Question and scope

Which TI functions are common to all stacks, which are specific to one host, and how does
each stack reach the common ones.

| Stack | Role | Hosts |
|---|---|---|
| Rust | the core and its reference implementation; the `ti` CLI; the browser (WebAssembly); helpers for servers | CLI, browser, helpers |
| Go | servers and relying parties; the ePA client | `zero-pdp`, `zero-pep-proxy`, `zero-bff-pdp`, `zero-caddy` (one binary), `zero-epa` |
| Swift, Kotlin/Java, C#/.NET, JavaScript/TypeScript | **clients only**, bindings over the Rust core (maintainer, 2026-11-01; .NET is new) | iOS, macOS, Android, JVM desktop and middleware, .NET desktop and middleware, browser |

No server is written in a secondary stack. The Java client of `ti serve` that doc-1 and
TASK-26 planned for Java servers is dropped.

## 2. Inventory of TI functions

Trust-critical means a defect accepts a forged certificate, a wrong key or a wrong peer.

| Function | Who needs it | Rust | Go today | Spec | Trust-critical |
|---|---|---|---|---|---|
| X.509 path validation with the TI profiles, key rules, admission extension | every host that checks a TI certificate: CLI, epa, PDP (token exchange), relying parties (IDP certificate), bindings | `ti-pki` (`validate`, `profile`, `admission`) | none (gempki archived); `go/epa/ti` runs `ti pki verify` | `spec/pki-validation` planned (TASK-97) | yes |
| TSL verification and update | the same | `ti-pki` (`tsl`, `tsl_signature`, loaders); XMLDSig in `ti-xmldsig` | none | `spec/tsl-xmldsig`; `spec/tsl-detached` to come (TASK-166) | yes |
| roots.json cross-certificate walk, compiled anchors | the same | `ti-pki` (`roots`, `anchors`) | none | part of the above | yes |
| OCSP request, response verification, responder authorization | the same | `ti-pki` (`ocsp`, `revocation`) | none | part of pki-validation | yes |
| TLS peer verification of TI endpoints | every host that talks to a TI endpoint | planned: rustls verifier (TASK-97) | planned: `VerifyConnection` through the shared rules (TASK-98) | pki-validation | yes |
| Brainpool curves, JOSE with brainpool | signing and verifying with SMC-B, HBA and IDP keys | `jwz-brainpool`, `ti-jwz` | `go/brainpool` (Fiat-verified, frozen), `josebp` | none; Wycheproof and OpenSSL cross tests | yes |
| IDP-Dienst flow, client side | CLI, epa, apps | `ti-idpd` | `go/gemidp` authenticator (epa uses `ti idpd authenticate`) | `spec/idp-dienst` candidate | yes |
| IDP-Dienst token verification, relying-party side | PDP, PEP, BFF | `ti-idpd` verifies the IDP certificate against the TSL (TASK-27) | `go/gemidp` takes the key from the discovery document **without verifying its certificate** (`shared.go:142`) | the same | yes, gap: TASK-171 |
| OpenID Federation trust chains | PDP as relying party | planned `ti-oidf` | `go/oidf`, one hop (master to IdP), no `authority_hints` walk | `spec/oidf-sek` candidate | yes |
| DPoP | PDP, PEP, every client of them | planned `ti-oauth` | `go/dpop`, RFC 9449, the only `TRACEABILITY.md` in `go/` | `spec/dpop` candidate | yes |
| OAuth 2.0 and OIDC, authorization server and relying party | PDP, BFF | planned `ti-oauth`, `ti-oidc` | `go/oauth`, `go/pdp/authzserver` (code, client credentials, refresh, PAR, private_key_jwt ES256) | the server's own protocol | yes, but generic |
| ePA VAU channel | epa | planned port (TASK-10) | `go/epa/vau` (Kyber768 via circl, CBOR) | none | yes |
| Smartcard and Konnektor access | CLI, epa, apps | `ti-connector-client` | none (epa uses `ti`) | none | yes |
| PKCS#12 | CLI, tests | `ti-pkcs12` | `go/pkcs12` | `spec/pkcs12`, corpus run by both | yes |
| Sealed store, profiles | CLI, epa | `ti-store` | `go/store` | `spec/store` | yes |
| Policy decisions | PDP | none | products and clients policy YAML | none | yes, moves to OPA |
| Server key custody | servers | none | signing key from a JWK file, **random key on failure** (`server.go:203-227`) | keys rules | yes, gap: TASK-88, TASK-170 |

What the table shows: the trust-critical TI functions exist once, in Rust, and Go has none
of the certificate trust. What Go has natively is the generic standards (OAuth, DPoP,
JOSE) and the brainpool arithmetic, which is generated and verified code, not a second
implementation of a TI rule.

## 3. Isolated TI functions

Confirmed by the maintainer (2026-11-01) as the rule for every stack; the text lives in
[architecture](../../docs/architecture.md#isolated-ti-functions):

- one unit per TI function; bytes and time in, a verdict with its reasons out;
- no I/O, no policy, no framework types inside the unit;
- the same report schema in every implementation, so a unit can be swapped between native
  and Rust, run against the shared corpus and audited on its own;
- the unit owns the **renewal policy** for its anchors (freshness, hard expiry, when to
  re-fetch, fallback order); loader adapters and the host's transport perform the I/O;
- the transport is always the host's ([transport independence](../../docs/architecture.md#transport-independence)).

How the existing units measure against it:

| Unit | Isolated | Note |
|---|---|---|
| `ti-pki` | yes | sans I/O, loaders as adapters, `Reloader` owns the policy, report schema 1 |
| `go/dpop` | yes | pure verification, clock as a function, traceability table |
| `go/pkcs12`, `ti-pkcs12` | yes | spec corpus on both sides |
| `go/gemidp` | no | verification and HTTP in one package; the certificate is not verified (TASK-171) |
| `go/oidf` | partly | verification mixed with fetching; one hop only |
| `go/pdp/authzserver` | partly | the server's own protocol; policy moves out to OPA (TASK-169) |
| bindings | by construction | the Rust core behind uniffi or wasm-bindgen; the host supplies transport, keys and clock |

## 4. Reaching the core, per host class

TASK-116 measured eight bridges for exactly the workload in question, an SMC-B checked
against the reference TSL without I/O (`spikes/go-rust-bridge/README.md` and
`results.md` on branch `spike/go-rust-bridge`, 2026-10-20, Darwin arm64):

| Bridge | Check p50 | Third-party Go at run time | Native code or JIT in the process | Isolation | Verdict |
|---|---|---|---|---|---|
| long-lived Rust process, stdio or Unix socket | 1.3 ms | none | no | process | **the server boundary** (stateless helpers, section 9) |
| `ti` per call | 35 ms | none | no | process | rare operations, the CLI, epa today |
| wasm2go (Rust to Wasm to generated Go) | 5 ms | none; 9.8 MB generated, no `unsafe` | no | bounds-checked slices | rejected: about 300,000 generated lines, and Go must be human-reviewable (maintainer, 2026-11-01) |
| purego (native library) | 2.3 ms | 2,100 lines, 80 `unsafe` | native Rust | none | rejected |
| wazero interpreter / JIT | 431 ms / 34 ms | 65,700 lines, 441 `unsafe` | no / JIT | sandbox | rejected |
| cgo | sub-microsecond | C toolchain in every build | native | none | rejected ([interop](../../docs/interop.md)) |

Per host class:

| Host | Way to the core |
|---|---|
| CLI (`ti`) | is the core |
| browser | wasm-bindgen (`ti-wasm`); pure exports, the page does downloads and clock |
| iOS, macOS, Android, JVM, .NET apps and middleware | uniffi bindings (Swift, Kotlin, Java facade); `uniffi-bindgen-cs` for C#, maturity to be evaluated before the profile (TASK-172) |
| Go servers (PDP, PEP, BFF) | stateless Rust helper in the same image, over stdio or a Unix socket (decision-10) |
| Go single-binary host (the Caddy plugin) | none: it validates the PDP's tokens natively and carries no TI core function; needing more is a design decision with its own task (Go is human-reviewable, so wasm2go is out) |
| epa (a client deployed like a server) | `ti` per call today; the helper in supplied mode is decided with the ePA local setup (TASK-120.7) |

## 5. The zero-trust PDP and the helper

The maintainer's concern: a verdict that arrives from another process is only as good as
that process. If the helper binary can be swapped, the PDP accepts what the attacker
wants. Three ways to get the SMC-B check into the PDP were weighed:

| Criterion | A: Go-native minimal stack | B: stateless Rust helper | C: wasm2go in process |
|---|---|---|---|
| trusted computing base | the Go binary | the Go binary and the helper, both in one measured image | the Go binary, with the generated code inside it |
| manipulation of the verifier | needs the image replaced | needs the image replaced; in the child mode the helper's digest is pinned in the manifest and it is executed from a verified file descriptor | needs the image replaced |
| second implementation of TI rules | **yes**: brainpool-aware chain building (`crypto/x509` cannot verify brainpool chains), OCSP with brainpool signatures (`x/crypto/ocsp` cannot), the profiles, the admission ASN.1, TSL XML to CA list, the roots walk: TUC_PKI_018, 006, 007 and 011 again, in hand-written Go | none | none |
| can be verified against the reference | only through a spec and corpus that do not exist yet (TASK-97) | it is the reference | it is the reference, translated |
| per-session latency | sub-millisecond | 1.3 ms | 5 ms |
| one binary | yes | no (two binaries, one image) | yes |
| fuzzing and verification burden | every new parser fuzzed in Go, no formal verification available | already in Rust | already in Rust; the generated code is checked by reproduction |
| operations | none | a second process to supervise; readiness after its handshake | a 10 MB generated file in the repository, a pinned generator, no cancellation inside a call |
| fits the Go profile | no: the profile keeps security-critical algorithms out of hand-written Go | yes | yes, under conditions |

**Recommendation (decision-10): B.** The helper is part of the PDP's trusted base, and
the rules in [servers](../../docs/design/servers.md) make that true rather than assumed:
one image for both binaries, every container digest in the signed manifest and in the
pod policy that attestation measures, no network listener, peer checks on the socket,
no secrets across it, fail closed. The zero-trust objection is answered by measuring the
helper with the PDP, not by trusting it separately. A is rejected because it is a second
implementation of the most trust-critical rules of the repository, in the language whose
profile forbids exactly that, and it would still need the spec and corpus before it could
be trusted. C was kept at first for a host that must be one binary; the maintainer's
rule of 2026-11-01 that Go is human-reviewable rules it out too (section 4).

What Go keeps natively in the token exchange: parsing the grant, checking the assertion's
signature against the verified certificate's key through `go/brainpool`, DPoP binding,
issuing the token, and handing the verified attributes to the policy (TASK-168).

## 6. The detached TSL signature

Found while weighing A: a Go-native path would need XMLDSig for the TSL, which is the
heaviest code on the trust path. gematik publishes a way around it.

**Facts** (gemSpec_TSL V1.25.0 section 6.3.1.3, A_21175 to A_21182; checked live on
2026-11-01):

- The TSL service publishes three files per environment on the CRL host, over plain
  HTTP: the TSL (`.xml`), a detached signature of the whole file (`.sig`) by the same TSL
  signer that signs the XML, and an OCSP response for that signer (`.ocsp`), renewed
  hourly. `.xml` and `.sig` are kept consistent and published together (A_21177).
- `.sig` is the ASN.1 structure `SEQUENCE { AlgorithmIdentifier ecdsa-with-SHA256,
  BIT STRING signature, Certificate signer }` (A_21179), the signature in the BSI
  TR-03111 5.2.2 format; 712 bytes in PU, signer brainpoolP256r1 issued by GEM.TSL-CA3.
- URIs (A_21182): PU `http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL.{xml,sig,ocsp}`,
  RU `http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref.{xml,sig,ocsp}`,
  TU `http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test.{xml,sig,ocsp}`.
  All answered 200. The HTTPS hosts `tsl.ti-dienste.de` that `ti-pki` uses serve `.xml`
  and `.sha2` only.
- The TSL signer CAs are compiled-in anchors of `ti-pki` (`anchors.rs`, decision-1), not
  entries of roots.json, so the signer certificate inside `.sig` chains to a constant.

**The deviation.** gemSpec_TSL calls the three files a fallback for Konnektors (A_21175).
gemSpec_PKI V2.28.0 section 8.2.6 (A_30044) tells internet consumers to use the HTTPS
hosts and to run TUC_PKI_001, whose step 4 is TUC_PKI_012 "XML-Signatur-Prüfung", with
the signer's OCSP address taken from its AIA and a hash compare before every download.
Verifying by `.sig` and `.ocsp` is cryptographically the same check (same signer, same
anchor, same OCSP, the same TSL bytes) but not the method the requirement names. The
maintainer decided (2026-11-01) to take the simplification: XMLDSig leaves the trust path
(TASK-166, high), the deviation is recorded in the spec, and if the pre-release TI 2.0
internet requirements exclude the detached signature, a request for change goes to
gematik's PKI team (TASK-167, doc-3).

**Consequence for every stack.** The core every binding and helper embeds loses
`ti-xmldsig`, the canonicalization code and the second XML parser (TASK-57); what remains
on the TSL trust path is an ASN.1 parse of three fields, one ECDSA verification over the
file, the compiled anchors, one OCSP check and the existing update rules. The TSL XML is
read for its CA list by one hardened reader without canonicalization.

## 7. OPA

The PDP's authorization decisions move to Open Policy Agent (TASK-169).

- OPA runs as a sidecar container in the PDP's pod, its server on a Unix socket in a
  shared `emptyDir`, never on the network. The PDP's client is the standard library over
  that socket. A compose or VM deployment runs the same container next to the PDP.
- The policy input is what the PDP has verified: the client, scopes, the DPoP binding,
  and from the SMC-B verdict the Telematik-ID and profession OIDs. Never raw certificates
  or tokens.
- Policies and data are configuration: mounted at start, hashed and reported, never
  loaded at run time and never fetched from a bundle server, as
  [servers](../../docs/design/servers.md) rule 7 demands of everything that runs.
- Rejected: embedding the OPA Go module (a dependency tree far beyond the Go profile's
  zero-dependency aim), and OPA compiled to Wasm (needs a runtime in the process, which
  decision-10 rejects). An unreachable OPA denies.

## 8. The HSM

The PDP's signing and sealing keys live in a (cloud) HSM (TASK-170). Without cgo the
vendor's PKCS#11 library cannot be in the image, which leaves two channels and one rule:

- **Channels.** A cloud KMS HTTPS API, where a signing request carries a digest and the
  standard library is enough; or a provider sidecar that holds the vendor library behind
  a small signing API over a Unix socket, the pattern Kubernetes uses for its KMS plugin.
  A remoted PKCS#11 (p11-kit) is a variant of the sidecar.
- **Mutual binding.** The HSM and its channel are part of the PDP's trusted base, and the
  HSM's key policy admits only this workload, proven by attestation and a workload
  identity, never by a credential in a file. Only digests cross the channel; the key never
  exists in the workload. The workload identity comes from the platform (the SPIFFE
  Workload API socket when mounted); the repository consumes it and does not implement it.
- In Go the key is a `crypto.Signer` (TASK-88); the random fallback key the PDP has today
  is a start-up failure from now on.

## 9. Helpers for servers

The helper is the shape of the process boundary for servers (decision-10, replacing
`ti serve` of TASK-26 and the state model TASK-120 recorded on 2026-10-20):

- one static binary per group (`ti-pki-helper`, `ti-idpd-helper`), shipped in the
  product's image under `libexec/telematik`, found by the lookup order of TASK-120.6;
- **stateless**: no profile, no configuration directory, no store, no cache database, no
  key file; configuration by flags and environment only (environment, listen socket,
  limits); nothing written to disk;
- trust material **supplied** by the host from a mounted directory, verified by the
  helper and kept in memory; the helper owns the renewal policy and tells the host when a
  re-fetch is due; OCSP for end entities goes through the host's transport, the helper
  builds the request and verifies the response;
- two modes, same protocol and client: a child over stdio inside one container (the
  default for compose, local runs and VMs), or a sidecar container started from the same
  image with the helper as its command, over a Unix socket in a shared `emptyDir`;
- the socket rules of [servers](../../docs/design/servers.md): peer checks, no network
  listener, bounded frames, versioned handshake, no secrets across the socket, fail
  closed, restart and fail only the calls in flight;
- platform services are consumed through their standard interfaces (the SPIFFE Workload
  API, a mesh's mTLS, the platform's attestation) and never provided here. This is a
  compatible architecture, not a re-implementation of SPIFFE or Istio (maintainer,
  2026-11-01).

The `ti` CLI keeps its profiles, caches and store for humans and for the producer job
below. The Caddy plugin carries none of this.

## 10. Trust material in Docker and Kubernetes

Fetching and renewing trust material is separate from the consumers. Three kinds of
state, treated differently:

| State | Where | Rule |
|---|---|---|
| trust material (TSL, `.sig`, `.ocsp`, roots.json) | supplied: a mounted ConfigMap or volume | verified on every load, whatever delivered it; never cached writably by a consumer |
| short-lived caches (end-entity OCSP responses, parsed context) | memory, an `emptyDir` at most | bounded, rebuilt on restart |
| application state (sessions, sealed tokens) | a real store under the server rules | not what "stateless" forbids |

**What exists.** `ti-pki`'s file transport was written for a mounted ConfigMap (it
follows the `..data` symlink swap and asks for roots.json and the TSL in one ConfigMap);
`StaticLoader` and `Bundle` carry offline material keyed by the anchor hash; the
`Reloader`'s policy reloads hourly with jitter, serves stale after six hours of failures,
refuses material older than 24 hours in production and reloads before `NextUpdate`.

**What is added** (TASK-173):

- **Producer.** A command that fetches `.xml`, `.sig`, `.ocsp` and roots.json as a
  consistent set, verifies it and writes it with a manifest (fetch time, anchor hash,
  environment). In Kubernetes a CronJob from the product image runs it hourly (the
  `.ocsp` renews hourly; the hash compare before download of A_30044 keeps it cheap) and
  writes a ConfigMap or a volume. The set is about 600 KB today, under the ConfigMap limit
  of 1 MiB; a volume is the fallback.
- **Air-gapped.** The same export on a connected machine, imported by the operator.
  Consumers verify on load and age it out by the hard expiry, so a stale import fails
  closed; [architecture](../../docs/architecture.md#offline-and-air-gapped-operation)
  already requires a daily import.
- **Consumers.** epa in Docker (through `ti` today) and the PDP's helper mount the
  directory read-only and poll through the reloader; nothing on disk. Compose and VM
  deployments use the same export into a shared directory from a cron on the host or a
  second container of the same image.

## 11. Risk reduction for anything implemented twice

The rules exist and are cited, not restated: a specification with rule IDs and result
codes in `spec/<topic>` ([interop](../../docs/interop.md#a-concise-shared-specification)),
a corpus both implementations run, tests named after the rule they prove, a traceability
table, an interop run in `just check` of both workspaces, fuzz targets on both sides, and
a disagreement fixed in the specification first. Today this applies to PKCS#12 and the
store; it applies to DPoP as soon as `spec/dpop` exists; it does not apply to the SMC-B
check, because Go does not implement it.

## 12. Consequences

Tasks: TASK-166 (detached signature, high), TASK-167 (request for change, conditional),
TASK-168 (token exchange), TASK-169 (OPA), TASK-170 (HSM), TASK-171 (gemidp certificate
verification, high), TASK-172 (.NET profile), TASK-173 (trust-material producer);
TASK-88 raised to high with the random-key finding; TASK-97 extended; TASK-120 and its
subtasks rewritten for stateless helpers; TASK-26, TASK-57, TASK-65, TASK-66 annotated.
Rules changed: architecture, languages, interop, servers, naming and configuration, git
and releases, both profiles.

Open:

- framing for bulk data on the helper protocol (JSON lines decided for the first helpers;
  the spike measured a tighter tail for length-prefixed binary; CBOR open, TASK-65);
- the maturity of `uniffi-bindgen-cs` (TASK-172);
- the pre-release TI 2.0 internet requirements and, depending on them, the PKI team's
  answer (TASK-166, TASK-167);
- whether epa in Docker moves to the helpers (TASK-120.7).

## Sources

gemSpec_TSL V1.25.0 section 6.3.1.3 (A_21175 to A_21182); gemSpec_PKI V2.28.0 section
8.2.6 (A_30044), TUC_PKI_001, TUC_PKI_011, TUC_PKI_012, TUC_PKI_020; the download points
probed on 2026-11-01 (`curl`, `openssl asn1parse`, `openssl ocsp`); TASK-116's spike on
branch `spike/go-rust-bridge`; doc-1; Istio's sidecar and ambient architectures, the SPIFFE
Workload API and the Kubernetes KMS plugin v2 as the practice the server rules follow.
