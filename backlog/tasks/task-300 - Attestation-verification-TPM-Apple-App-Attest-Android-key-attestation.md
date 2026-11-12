---
id: TASK-300
title: 'Attestation verification: TPM, Apple App Attest, Android key attestation'
status: To Do
assignee: []
created_date: '2026-11-12T21:08:00Z'
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
