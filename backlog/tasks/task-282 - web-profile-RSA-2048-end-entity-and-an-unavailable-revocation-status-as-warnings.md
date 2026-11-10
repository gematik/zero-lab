---
id: TASK-282
title: >-
  web profile: RSA-2048 end entity and an unavailable revocation status as
  warnings
status: To Do
assignee: []
created_date: '2026-11-10T18:40:00Z'
labels:
  - rust
  - go
  - tls
  - security
dependencies: []
priority: high
ordinal: 298000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback (2026-11-10). The web profile refuses an RSA-2048 server certificate (TLSV-041, gemSpec_Krypt A_28976) and a server whose revocation status no source gives (TLSV-044, A_27857-02). Maintainer: both become warnings, the exception documented: the Web-PKI's CAs (Let's Encrypt ended OCSP) and flaky responders (idp-ref.app.ti-dienste.de staples nothing, lists no CRL, and GlobalSign's responder failed once). Revoked still refuses. Rust and Go alike through spec/pki-validation and its corpus.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pki-validation TLSV-041 and TLSV-044 give the warnings key_phased_out and revocation_unavailable, with a documented deviation from A_28976 and A_27857-02; revoked still refuses
- [ ] #2 the corpus pins the new behaviour and both rust/ti-tls and go/tipki/titls pass it
- [ ] #3 ti probe shows such a server with a yellow ! and the warning; the web transports accept it
<!-- AC:END -->
