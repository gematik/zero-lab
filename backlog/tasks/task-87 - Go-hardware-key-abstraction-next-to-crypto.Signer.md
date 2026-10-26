---
id: TASK-87
title: 'Go: hardware-key abstraction next to crypto.Signer'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - keys
dependencies: []
references:
  - docs/design/keys.md
  - go/docs/design.md
priority: medium
ordinal: 85000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No capability, interaction or attestation interface and no Enclave, TPM or FIDO adapters (private-key rules).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a small interface for context-aware signing, capabilities and attestation; adapter plan with the dependency decision on a pure-Go TSS
<!-- AC:END -->
