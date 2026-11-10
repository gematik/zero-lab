---
id: TASK-282
title: >-
  web profile: RSA-2048 end entity and an unavailable revocation status as
  warnings
status: In Progress
assignee: []
created_date: '2026-11-10T18:40:00Z'
updated_date: '2026-11-10T19:20:00Z'
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
- [x] #1 spec/pki-validation TLSV-041 and TLSV-044 give the warnings key_phased_out and revocation_unavailable, with a documented deviation from A_28976 and A_27857-02; revoked still refuses
- [x] #2 the corpus pins the new behaviour and both rust/ti-tls and go/tipki/titls pass it
- [x] #3 ti probe shows such a server with a yellow ! and the warning; the web transports accept it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decisions (implementation): a web verdict accepted without a revocation status is not reused (TLSV-050: it rests on no status; the next connection asks the sources again), so reusable_until is None for it; a reused verdict keeps its warnings (Rust Verdicts and Go verdictCache store them). Warnings carry in step order (key_phased_out before revocation_unavailable) and also on a refusal after the key check. Verdict::status_source (Rust only) names the source for ti pki verify. WebVerifier::with_warning_observer tells the host each accepted server's warnings, since rustls only accepts or refuses; the probe keeps them by host. The strict rule is not an option: a host judges with verify()/Verify and refuses on the warnings itself (documented). Code::RevocationUnavailable / RevocationUnavailable kept but no longer returned. Corpus: no new certificates (generate.sh not rerun, so no re-keying); manifest.py changed web-rsa2048, web-no-status-source, web-sources-down to valid + warning and added web-unknown-only, web-revoked-by-responder, web-revoked-staple-before-crl, web-rsa2048-no-status (both warnings). RSA below 2048 is proven by unit tests in both languages (no RSA-1024 leaf in the corpus). Go release notes: none, Go adds a section per module when tagged. Live: ti probe ref showed catalog (RSA-2048) as warn: key_phased_out.
<!-- SECTION:NOTES:END -->
