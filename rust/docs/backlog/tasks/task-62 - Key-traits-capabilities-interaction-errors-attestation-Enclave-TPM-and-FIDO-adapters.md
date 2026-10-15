---
id: TASK-62
title: >-
  Key traits: capabilities, interaction errors, attestation; Enclave, TPM and
  FIDO adapters
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - jwz
  - keys
dependencies: []
references:
  - docs/design/keys.md
priority: medium
ordinal: 60000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Private-key rules 2 to 7 and 10: keys state algorithms, digest or message, signable structures and user interaction; errors tell cancelled, absent, PIN blocked and not permitted apart; attestation is verified.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 capability and attestation traits next to Signer/KeyAgreement, the error kinds, and a plan with dependency review for Secure Enclave, TPM 2.0 and FIDO adapter crates
<!-- AC:END -->
