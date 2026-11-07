---
id: TASK-258
title: 'jwz: RFC 8725 (JWT BCP) traced in full'
status: To Do
assignee: []
created_date: '2026-11-07T18:04:00Z'
labels:
  - jwz
  - spec
  - security
dependencies: []
references:
  - rust/jwz/docs/traceability.md
  - https://www.rfc-editor.org/rfc/rfc8725
priority: medium
type: task
ordinal: 274000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz's README cites RFC 8725 (JSON Web Token Best Current Practices) only for §3.4 (cryptographic inputs validated). The rest of §2 and §3 is not traced as requirements: algorithm verification (§3.1, §3.2), JWE and key-management cautions (§3.3, §3.5, §3.6), UTF-8 (§3.7), issuer and subject validation (§3.8, §3.10), audience (§3.9), explicit typing (§3.11), mutually exclusive validation rules (§3.12). The IETF is revising the document (draft-ietf-oauth-rfc8725bis); its current state is to be checked.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each requirement of RFC 8725 §3 is traced in jwz's traceability table to the code and tests that meet it, or recorded as the caller's duty (ClaimsPolicy, profile) with where jwz helps
- [ ] #2 the state of draft-ietf-oauth-rfc8725bis is checked and its new requirements are traced the same way, or a watch task records why not yet
- [ ] #3 a gap found becomes its own task
<!-- AC:END -->
