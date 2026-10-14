---
id: TASK-60
title: 'ti-idpd: take an AsyncSigner so a card can sign through the Konnektor'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - ti-idpd
  - keys
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 58000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti-idpd takes a synchronous Signer; a card signs through the Konnektor's async AuthSignatureService (private-key rule 6).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 authenticator takes an AsyncSigner; ti idpd works with a Konnektor-backed card signer as well as a software key
<!-- AC:END -->
