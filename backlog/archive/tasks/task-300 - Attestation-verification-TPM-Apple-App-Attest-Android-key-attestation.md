---
id: TASK-300
title: >-
  Attestation verification: TPM; Apple App Attest and Android key attestation
  are in zeta-pdp-go
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-22 16:14'
labels: []
dependencies: []
ordinal: 316000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No language in this repository verifies a device attestation: TPM (EK certificate chain, quote, MakeCredential and ActivateCredential), Apple App Attest (attestation object and assertions), Android key attestation (chain, challenge, boot state, revocation status list). docs/design/keys.md asks that attestation is verified, not believed. By docs/architecture.md a new protocol core starts in Rust; zeta-pdp-go needs it from Go (its TASK-50, TASK-51). Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A decision where the cores live and how Go reaches them; verification of each of the three with test vectors
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14, from zeta-pdp-go: the maintainer decided that Apple App Attest and Android key attestation are built in zeta-pdp-go and not here. They are vendor formats and not TI-specific, nothing existed here, and no second consumer is in sight. They are there since its commit 8318555 (packages pdp/attest/apple and pdp/attest/android, Apache-2.0, behind an interface of its core, tested with registrations of real devices; the App Attest object is read without a CBOR library). The assertion side (Apple) and the runtime signature (Android) are its TASK-84. If a second server here needs them, they can be moved here: gematik holds both repositories.

What is left of this task is TPM (EK certificate chain, quote, MakeCredential and ActivateCredential), which zeta-pdp-go has not started (its TASK-51) and for which no decision is made where it lives. The Apple attestation and assertion vectors of the removed go/libzero/attestation/dcappattest (before 9b4054a3) are real devices' and worth keeping in mind for either place.

2026-11-22: archived by the maintainer's decision.
<!-- SECTION:NOTES:END -->
