---
id: TASK-257
title: 'ti-tls / go titls: a weak certificate whose issuer the server did not send'
status: To Do
assignee: []
created_date: '2026-11-07T17:19:00Z'
labels:
  - ti-tls
  - go
  - spec
dependencies: []
references:
  - spec/pki-validation/README.md
priority: low
ordinal: 273000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Under the web profile, a certificate signed with SHA-1, MD5 or SHA-224 whose issuer is not among the certificates the server sent is chain_incomplete in go/tipki/titls (crypto/x509's pool cannot say whether that issuer is an anchor, and it refuses the weak signature itself) but signature_algorithm_not_allowed in ti-tls when the issuer is an anchor (rustls-webpki tries the anchors). Both refuse; the codes differ. Found in TASK-233.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a corpus case pins the code and ti-tls and go/tipki agree, or the spec says the code may differ here
<!-- AC:END -->
