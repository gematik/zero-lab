---
id: TASK-60
title: 'ti-idpd: take an AsyncSigner so a card can sign through the Konnektor'
status: Done
assignee: []
created_date: '2026-10-14 20:43'
updated_date: '2026-10-20 19:32'
labels:
  - ti-idpd
  - keys
dependencies: []
references:
  - docs/design/keys.md
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
- [x] #1 authenticator takes an AsyncSigner; ti idpd works with a Konnektor-backed card signer as well as a software key
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented: authenticator::Identity::signer is a jwz AsyncSigner, authenticate and challenge::respond are async (only the signature is awaited, the transport stays synchronous); ti-directory owner::login async; ti-cli ConnectorSigner implements AsyncSigner and awaits ExternalAuthenticate (no block_on inside the signer), software keys through SoftSigner; ti-cli drops its direct signature dependency. Tests: an_asynchronous_signer_answers_the_challenge (a signer pending once), the existing flow tests through a one-poll helper. HITL open: ti idpd authenticate --card against a real Konnektor (maintainer).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-idpd: authenticator::Identity::signer is a jwz AsyncSigner; authenticate and challenge::respond are async, awaiting only the signature (the transport stays synchronous). ti-directory: owner::login async. ti-cli: the Konnektor signer implements AsyncSigner and awaits ExternalAuthenticate; software keys through SoftSigner; the direct signature dependency is gone. Tests: an_asynchronous_signer_answers_the_challenge and the flow tests; HITL passed (maintainer, 2026-10-20): idpd authenticate and directory login owner with an SMC-B at a real Konnektor.
<!-- SECTION:FINAL_SUMMARY:END -->
