---
id: TASK-389
title: >-
  hsm-proxy: a sidecar with gematik's HSM proxy interface on PKCS#11, its
  simulator mode a software token
status: To Do
assignee: []
created_date: '2026-11-19 07:17'
updated_date: '2026-11-19 07:17'
labels:
  - security
  - keys
  - architecture
dependencies: []
references:
  - docs/design/servers.md
  - docs/design/keys.md
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

To decide in the task: the language (Rust with `cryptoki`, or Go with cgo, which the Go profile rules out for workloads); which token simulator mode brings (SoftHSM2 from 2.7.0 or Kryoptic); how the sidecar knows its caller (rule 6: a workload identity, not a credential in a file; a Unix socket shared in a pod is the least); what "only digests cross the channel" means for Encrypt and Decrypt, which carry key material by design; how rule 7 (sidecars rebuilt reproducibly from source) holds when the vendor's module is a binary the operator mounts; and whether ngx_pep's `hsm_sim` is replaced by this or stays beside it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The sidecar serves gematik.zetaguard.hsmproxy.v1.HsmProxyService and grpc.health.v1 on a Unix domain socket, and the clients there are (ngx_pep, the notification service's keychain generator, zeta-pdp-go) work against it unchanged
- [ ] #2 Every operation reaches its key through PKCS#11 alone: with another module path and no other change the same binary works against the bundled software token and against a vendor's module
- [ ] #3 Simulator mode starts with one command, without an account, natively on Linux and macOS on x86_64 and arm64, and a test needs no provisioning step; keys can be made deterministic
- [ ] #4 Keys are created not extractable and with the one use they have: a signing key signs, a key-encryption key encrypts for the generator and decrypts for the workload
- [ ] #5 A conformance suite of the interface runs against the bundled token in public CI and can be pointed at a vendor's simulator or device; it covers an IV the HSM generates, associated data, signing a digest and signing a message, and the curves asked for
- [ ] #6 The image holds no vendor software and only components whose licences allow redistribution with EUPL-1.2; a document says how an operator mounts a vendor's module, and what was verified of each vendor's terms
- [ ] #7 The decisions named in the description are recorded: language, token, caller's identity, what crosses the channel, reproducible build, and the future of hsm_sim
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Sources of the licence research of 2026-11-19. Utimaco: https://utimaco.com/data-protection/simulators-and-trials, EULA https://utimaco.com/sites/default/files/2024-02/Utimaco_IS_GmbH_EULA_2024_EN.pdf (sections 2, 3, 7), Docker guide https://integration-guides.utimaco.com/docker-container-and-cryptoserver-hsm/1.0.0/online/creating-the-dockerfile. Thales: https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_install_overview-and-prep.htm, mechanisms https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/mechanisms/mechanism_summary_7-7-0.htm, trial https://cpl.thalesgroup.com/encryption/data-protection-on-demand/luna-cloud-hsm-trial. Entrust: https://nshielddocs.entrust.com/ncop-docs/ncop-licensing.html, mechanisms https://nshielddocs.entrust.com/security-world-docs/api-pkcs11/mechanisms.html. SoftHSM2: https://github.com/softhsm/SoftHSMv2 (LICENSE, releases). Kryoptic: https://github.com/latchset/kryoptic. cryptoki: https://github.com/parallaxsecond/rust-cryptoki. miekg/pkcs11: https://github.com/miekg/pkcs11. crypto11: https://github.com/ThalesGroup/crypto11. OASIS headers: https://github.com/oasis-tcs/pkcs11 (LICENSE.md). AWS CloudHSM mechanisms: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html. EUPL-1.2 and its matrix of compatible licences: https://interoperable-europe.ec.europa.eu/collection/eupl/matrix-eupl-compatible-open-source-licences. NetHSM test image: https://docs.nitrokey.com/nethsm/container/test-image. The SECDSA report: a post of Eric Verheul on LinkedIn, November 2026. Not verified, and to be before a vendor is named as supported: Utimaco's PKCS#11 mechanism list, brainpool and arm64 or macOS builds; the Luna EULA and whether its client needs a contract; Entrust's Security World EULA and any emulator (the statements on customers under maintenance and on the image come from search summaries); brainpool in SoftHSM2; AES-GCM with associated data and macOS in Kryoptic; the key attributes each module honours.
<!-- SECTION:NOTES:END -->
