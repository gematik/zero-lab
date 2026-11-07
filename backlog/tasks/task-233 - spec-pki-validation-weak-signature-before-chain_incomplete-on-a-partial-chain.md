---
id: TASK-233
title: 'spec/pki-validation: weak signature before chain_incomplete on a partial chain'
status: Done
assignee: []
created_date: '2026-11-06T14:09:00Z'
updated_date: '2026-11-07T17:19:00Z'
labels:
  - spec
  - security
dependencies: []
priority: low
ordinal: 249000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-98.1 review: when the validator builds a partial chain of two or more certificates that does not reach an anchor, ti_pki::tls (and go/tipki, following it) reports signature_algorithm_not_allowed for a SHA-1/MD5/SHA-224 link before chain_incomplete, while the spec's check order puts the path (TLSV-020) first. Both refuse; only the code differs. Decide the order in the spec, add a corpus case, align Rust and Go.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the spec states the order and a corpus case pins it
- [x] #2 ti-pki and go/tipki agree with it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TLSV-020 states the order; corpus cases ti-partial-path-weak-link (web-sha1 + web-ca under ti) and web-partial-path-weak-link (ti-sha1 + ti-ca under web). ti_pki::tls and go/tipki tls.go refuse with chain_incomplete when the validator reports it, before the weak-signature check. go titls web: the walk over sent certificates records the first weak link and reports it only when the first non-weak certificate above it reaches an anchor (x509 Verify); rustls already returned UnknownIssuer. Edge left: under web, a weak certificate whose issuer the server did not send is chain_incomplete in Go (crypto/x509's pool cannot say whether that issuer is an anchor) but signature_algorithm_not_allowed in ti-tls when the issuer is an anchor; both refuse, no corpus case.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
TLSV-020 states that the path is judged before its links. Corpus cases ti-partial-path-weak-link and web-partial-path-weak-link. ti_pki::tls and go/tipki refuse with chain_incomplete before the weak-signature check; go titls's web walk reports a weak link only when the path above it reaches an anchor. Verified by both corpora and full just check (Rust, Go). Left: a weak certificate whose issuer the server did not send differs between Go and ti-tls under web (own task).
<!-- SECTION:FINAL_SUMMARY:END -->
