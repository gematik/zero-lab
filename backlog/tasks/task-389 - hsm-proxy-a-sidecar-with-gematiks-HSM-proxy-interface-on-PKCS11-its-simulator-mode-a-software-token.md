---
id: TASK-389
title: >-
  ti-hsm: a sidecar with gematik's HSM proxy interface on PKCS#11, its simulator
  mode a software token
status: In Progress
assignee: []
created_date: '2026-11-19 07:17'
updated_date: '2026-11-19 14:13'
labels:
  - rust
  - security
  - keys
  - architecture
dependencies: []
references:
  - docs/design/servers.md
  - docs/design/keys.md
  - zeta-backlog TASK-18
priority: medium
ordinal: 402000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A workload that keeps a key in an HSM reaches it through a key provider sidecar over a Unix socket; the vendor's native library is never in the workload's image (docs/design/servers.md rule 6, docs/design/keys.md). ZETA Guard has the interface for it, the gRPC service `gematik.zetaguard.hsmproxy.v1.HsmProxyService` (`hsm-proxy.proto` in ngx_pep: Sign, GetPublicKey, GetCertificate, Encrypt, Decrypt, HealthCheck), and one implementation, `hsm_sim` in ngx_pep, which derives every key from its `key_id` by HKDF, listens on TCP only and has no backend behind it. Nothing speaks PKCS#11. The first consumer is zeta-pdp-go (its TASK-141): the token signing key, and the key-encryption key that unwraps its keychain (`kv.Unwrapper`, the Decrypt of this interface).

To build: one sidecar, `hsm-proxy`, that serves that gRPC interface unchanged, on a Unix domain socket and optionally on TCP for the clients there are, and has PKCS#11 as its one way to a key. It loads the PKCS#11 module it is told at start. **Simulator mode is the same code with a software token**: the sidecar brings an open-source token and provisions it, so that development and tests go through C_Sign, C_Encrypt and C_Decrypt exactly as production does, and the only thing a real HSM changes is the module path and its configuration.

Licences and availability, researched 2026-11-19 (sources in the notes; each claim is the vendor's or project's own page):

- **Utimaco** u.trust GP HSM simulator: free of charge, but the EULA allows "test and evaluation purposes only", forbids making the software "available to third parties for payment or for free" and asks to "retain Software in strict confidence"; download after registration at the support portal with a review of up to 48 hours; the simulator is a 32-bit x86 Linux binary. So: usable by a registered developer and on a private runner, not in a public image, not in public CI, and on Apple Silicon only under emulation.
- **Thales** Luna: no simulator found; the client is behind the support portal, its EULA was not found; a 30-day trial of the cloud HSM needs an account.
- **Entrust** nShield: no simulator found; software for customers under maintenance; the container option pack is "licensed for internal Customer use only".
- No vendor publishes a simulator image that can be pulled without credentials. Nitrokey publishes a NetHSM test image; its licence was not found.
- Open source: **SoftHSM2** (BSD-2-Clause; CKM_ECDSA_SHA256 only from 2.7.0, which distributions do not all have; brainpool not confirmed), **Kryoptic** (Apache-2.0 since after 1.5.2, GPL-3.0+ before; Rust on OpenSSL; lists brainpoolP256r1), NSS softokn (MPL-2.0). OpenSC's pkcs11-tool is LGPL-2.1, a tool beside, not linked.
- Libraries: Rust `cryptoki` (Apache-2.0, prebuilt bindings for Linux and macOS on x86_64 and aarch64); Go `miekg/pkcs11` (BSD-3-Clause, cgo) and `ThalesGroup/crypto11` (MIT). The OASIS PKCS#11 headers are under the OASIS IPR policy, not an OSI licence: whichever binding is taken, where its headers come from has to be checked.
- EUPL-1.2: BSD, MIT and Apache-2.0 code can be part of the work; a proprietary PKCS#11 module cannot be distributed with it and is mounted by the operator at run time.

What differs between HSMs and the interface has to survive: several generate the AES-GCM IV themselves (AWS CloudHSM, Luna in FIPS mode, nShield for an empty IV), which the interface allows, since Encrypt returns the IV; raw CKM_ECDSA is single-part on some; CKM_ECDSA_SHA256, associated data with AES-GCM and brainpool curves are not everywhere, and what a certified firmware offers can be less than its simulator (a SECDSA wallet on u.trust reported in November 2026 waits for ECIES in the certified firmware).

Developer experience is a requirement, not an afterthought, since everybody works against the simulator mode most of the time: it starts with one command and no account, natively on Linux and macOS, x86_64 and arm64; a key that is asked for and not there is made (as hsm_sim does by derivation), or the sidecar is told the keys to have, so that a test needs no provisioning step; keys can be deterministic for tests that compare output; errors name the PKCS#11 return code and the key; and the same conformance suite runs against the bundled token in public CI and against a vendor's simulator or device where someone has one.

Decided by the maintainer on 2026-11-19:

- **Rust**, as new `ti-hsm` crates in the Rust workspace, beside the others.
- **How a vendor's HSM is connected is what matters**, and it needs tests: the simulator token is still open. The first step is a spike with SoftHSM2, which is also the first measure of how far plain PKCS#11 carries.
- **The sidecar does not ask who calls.** It is reached over a Unix socket inside the pod, in the same trust domain as the workload: there is no caller to tell apart.
- **Decrypt returns what it decrypts.** Rule 6 says that only digests cross the channel; for a key-encryption key that cannot hold, and inside one trust domain it need not. The rule's wording is to be corrected with this work.
- **Rule 7 holds with the vendor's module** when what is loaded is a static library pinned by its SHA-256: the measured image then contains what runs.

Still open: which token the simulator mode brings, and whether ngx_pep's `hsm_sim` is replaced by this or stays beside it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The sidecar serves gematik.zetaguard.hsmproxy.v1.HsmProxyService and grpc.health.v1 on a Unix domain socket, and the clients there are (ngx_pep, the notification service's keychain generator, zeta-pdp-go) work against it unchanged
- [ ] #2 Every operation reaches its key through PKCS#11 alone: with another module path and no other change the same binary works against the bundled software token and against a vendor's module
- [ ] #3 Simulator mode starts with one command, without an account, natively on Linux and macOS on x86_64 and arm64, and a test needs no provisioning step; keys can be made deterministic
- [x] #4 Keys are created not extractable and with the one use they have: a signing key signs, a key-encryption key encrypts for the generator and decrypts for the workload
- [ ] #5 A conformance suite of the interface runs against the bundled token in public CI and can be pointed at a vendor's simulator or device; it covers an IV the HSM generates, associated data, signing a digest and signing a message, and the curves asked for
- [ ] #6 The image holds no vendor software and only components whose licences allow redistribution with EUPL-1.2; a document says how an operator mounts a vendor's module, and what was verified of each vendor's terms
- [x] #7 A spike drives SoftHSM2 through the sidecar's PKCS#11 path and records what worked as specified and what did not: the mechanisms, associated data, who makes the IV, key attributes
- [ ] #8 Tests that connect a vendor's module exist and say how they are run where the vendor's software may be used, with what was found for each vendor that was tried
- [ ] #9 docs/design/servers.md rule 6 says what crosses the channel to a key provider in the workload's own trust domain, and the vendor's module is loaded as a library pinned by its SHA-256 (rule 7)
- [ ] #10 It is recorded which token the simulator mode brings and what becomes of ngx_pep's hsm_sim
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Step 1, the spike (AC #7), on branch feat/ti-hsm-spike:
1. New crate rust/ti-hsm (publish = false, forbid(unsafe_code)) with a PKCS#11 adapter on cryptoki 0.12.1 (approved by the maintainer 2026-11-19): load a module by path, open a session on a token, find or make a key by label (EC P-256/P-384 signing key, AES-256 key-encryption key), sign a digest (CKM_ECDSA) and a message (CKM_ECDSA_SHA256/384), encrypt and decrypt with CKM_AES_GCM with and without associated data, IV given or made by the token.
2. Spike tests against SoftHSM2 (installed with Homebrew), each operation recording what the token did: return code, signature length and form, IV length, whether the token makes the IV, the attributes it keeps (CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_SIGN/ENCRYPT/DECRYPT and that a forbidden use is refused). Results go into a document under rust/ti-hsm/docs.
3. Cross-check with pkcs11-tool (OpenSC) where it can: the key exists, is not extractable, a signature verifies with an independent library.
Not in step 1: gRPC (decided after the spike, maintainer 2026-11-19), the sidecar, other tokens, vendor modules.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sources of the licence research of 2026-11-19. Utimaco: https://utimaco.com/data-protection/simulators-and-trials, EULA https://utimaco.com/sites/default/files/2024-02/Utimaco_IS_GmbH_EULA_2024_EN.pdf (sections 2, 3, 7), Docker guide https://integration-guides.utimaco.com/docker-container-and-cryptoserver-hsm/1.0.0/online/creating-the-dockerfile. Thales: https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_install_overview-and-prep.htm, mechanisms https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/mechanism_summary_7-7-0.htm, trial https://cpl.thalesgroup.com/encryption/data-protection-on-demand/luna-cloud-hsm-trial. Entrust: https://nshielddocs.entrust.com/ncop-docs/ncop-licensing.html, mechanisms https://nshielddocs.entrust.com/security-world-docs/api-pkcs11/mechanisms.html. SoftHSM2: https://github.com/softhsm/SoftHSMv2 (LICENSE, releases). Kryoptic: https://github.com/latchset/kryoptic. cryptoki: https://github.com/parallaxsecond/rust-cryptoki. miekg/pkcs11: https://github.com/miekg/pkcs11. crypto11: https://github.com/ThalesGroup/crypto11. OASIS headers: https://github.com/oasis-tcs/pkcs11 (LICENSE.md). AWS CloudHSM mechanisms: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html. EUPL-1.2 and its matrix of compatible licences: https://interoperable-europe.ec.europa.eu/collection/eupl/matrix-eupl-compatible-open-source-licences. NetHSM test image: https://docs.nitrokey.com/nethsm/container/test-image. The SECDSA report: a post of Eric Verheul on LinkedIn, November 2026. Not verified, and to be before a vendor is named as supported: Utimaco's PKCS#11 mechanism list, brainpool and arm64 or macOS builds; the Luna EULA and whether its client needs a contract; Entrust's Security World EULA and any emulator (the statements on customers under maintenance and on the image come from search summaries); brainpool in SoftHSM2; AES-GCM with associated data and macOS in Kryoptic; the key attributes each module honours.

2026-11-19, step 1 done on feat/ti-hsm-spike. New crate rust/ti-hsm (publish = false, an adapter in the Rust profile's diagram) with a PKCS#11 adapter on cryptoki 0.12.1 (approved; vet exemptions for cryptoki, cryptoki-sys, libloading 0.8.9, secrecy, with notes, as ureq's). Spike suite tests/spike_softhsm2.rs, 11 tests, gated (#[ignore], TI_HSM_PKCS11_MODULE_PATH), run by just hsm-spike with a fresh token directory; row in rust/docs/development.md. Findings in rust/ti-hsm/docs/spike-softhsm2.md, SoftHSM2 2.7.0 on macOS arm64: every mechanism the interface needs is listed; keys made sensitive, never extractable, one use, a misuse refused with CKR_KEY_FUNCTION_NOT_PERMITTED; ECDSA over a digest and over a message (SHA-256/384/512) on P-256 and P-384 verified with RustCrypto; brainpoolP256r1 works (open question answered for this build); AES-GCM single-part with AAD, tamper refused with CKR_ENCRYPTED_DATA_INVALID; CKA_EC_POINT DER-wrapped. Differences: SoftHSM2 does not make the GCM IV (it encrypts under the zero IV it is given), so the adapter takes Iv::Random from C_GenerateRandom and refuses Iv::FromToken when the IV comes back unchanged; cryptoki 0.12 reports CKA_VALUE of a sensitive key as absent, not as CKR_ATTRIBUTE_SENSITIVE; SoftHSM2 does not report CKA_ENCRYPT/CKA_WRAP of a private EC key. Not covered: gRPC and the sidecar (maintainer: after the spike), multi-part operations, Linux/x86_64, deterministic keys (SoftHSM2 makes keys from its own random source), other tokens. Next decisions: the gRPC server (tonic etc., 46 new crates, or generated code committed), the simulator token (SoftHSM2 vs Kryoptic), how keys are deterministic for tests (#3).

2026-11-19, session pool and benchmark on feat/ti-hsm-spike. ti_hsm::Pool (Module::pool): a fixed number of logged-in sessions, lent one per caller, a bounded wait refused with Error::Busy; a key found through one session is used through every other. Two gated tests in the spike suite. benches/softhsm2.rs (just hsm-bench, no harness, dev-dependencies serde_json and base64ct from the workspace): direct, and JSON-RPC 2.0 multiplexed over one Unix-socket connection. M3 Pro, SoftHSM2 2.7.0: ECDSA P-256 15.7k/s on one session, and SoftHSM2 stops at 25-35k/s from 2 to 8 sessions, whatever the operation and also with a key per caller, so the limit is in the module; JSON-RPC adds about 20 µs per call and matches direct from 4 calls in flight; ping without the token carries 86k-287k/s on one connection. Results in rust/ti-hsm/docs/spike-softhsm2.md. Open: reopening a broken session and logging in again after the token logs out.

2026-11-19, transport compared (rust/ti-hsm/docs/spike-softhsm2.md, Transport: JSON-RPC against gRPC). gemSpec_ZETA V2.0.0_CC settles AC #1: A_28829 requires hsm-proxy.proto (gRPC), A_28830 requires that calling components can be authenticated with mTLS, A_28816 a minimal TCB. A_28830 conflicts with the maintainer's decision that the sidecar does not ask who calls; to be decided. SBOM of a sidecar on ti-hsm, without TLS: JSON-RPC 17 crates at run time (0 new) and 6 at build time; gRPC (tonic 0.14, prost, tonic-health, tokio) 61 at run time (36 new) and 38 at build time (28 new), plus protoc. Measured on M3 Pro against SoftHSM2, one connection: Sign is bound by the token for both protocols (about 25k/s from 4 calls in flight); one call in flight 82 µs JSON-RPC against 99 µs gRPC at p50; transport alone 277k/s against 82k/s; gRPC takes about 15 µs more server CPU time per call. The scratch harness and the CycloneDX files are not committed. The question whether a lighter local transport is allowed went to zeta-backlog TASK-18 (2026-11-19).

2026-11-19, step 2 on feat/ti-hsm-spike: the sidecar. The maintainer decided one crate, ti-hsm-proxy (ti-hsm merged into it), with gRPC behind the feature grpc, on by default: a deliberate exception to decision-13 for this host, whose library layer is used by no other crate. The code is generated from proto/ (hsm-proxy.proto of gematik/zeta 49f10d8 and googleapis 984d837, Apache-2.0) by a generator outside the workspace (codegen/, tonic-prost-build on protox, no protoc) and committed; just check runs hsm-proxy-codegen-check. Layers: the PKCS#11 adapter (find-only keys, certificate objects, a session check added), HsmProxy (the six operations without transport, keys from a stated list, Failure kinds), grpc (HsmProxyService and grpc.health.v1 on a Unix socket, spawn_blocking, 34 KiB message limit). Binary hsm-proxy, configured by HSM_PROXY_* (README): vendor mode requires the module's SHA-256 (rule 7), a PIN file and the IV source; the simulator mode provisions a TEST-ONLY token and makes missing keys. Health: grpc.health.v1 follows the token every HSM_PROXY_HEALTH_INTERVAL_MS (busy sessions count as SERVING), and hsm-proxy health ready|live serves exec probes, since kubelet probes do not reach a Unix socket. Dependencies approved by the maintainer: tonic 0.14.9 (server, router, codegen, channel for the probe), prost, tonic-prost, tonic-health, tokio, tokio-stream, hyper-util, tower; vet exemptions with notes for 48 crates, async-trait raised to safe-to-deploy; libc raised to 0.2.191 on the maintainer's request (unsafe diff reviewed, docs/unsafe-exceptions.md). Tests: 7 gated gRPC tests (A_28829, A_28820, health) and 5 config tests. Open: mTLS and ABAC (A_28830, which conflicts with the decision that the sidecar does not ask who calls), TCP listener, socket peer check and permissions (rule 8), reopening broken sessions, metrics, certificate chains, P-521, whether the clients there are work unchanged (AC #1), JSON-RPC (zeta-backlog TASK-18).

2026-11-19, tidied for review: the crate is the sidecar, not a spike. Removed: benches/softhsm2.rs and just hsm-bench (the JSON-RPC comparison; its numbers stay in docs/softhsm2.md with the commit 2ef3a115). Renamed: tests/spike_softhsm2.rs to tests/token_softhsm2.rs (the adapter's conformance suite), docs/spike-softhsm2.md to docs/softhsm2.md, just hsm-spike to just hsm-proxy-softhsm2. Rule 17: test probes (misuse_*, read_secret_value, ec_point_is_wrapped, key facts, Iv::Given) behind the feature conformance, which the token suite requires; the simulator mode and its TEST-ONLY PINs behind the feature simulator (HSM_PROXY_SIMULATOR=true stops the start without it), checked by just nonprod-absent on the binary both ways; the generated gRPC client goes to tests/generated, the sidecar compiles the server only. tokio's macros feature declared, since main uses select!. 13 token and 8 gRPC tests pass against SoftHSM2 2.7.0; just check-changed green in rust/.
<!-- SECTION:NOTES:END -->
