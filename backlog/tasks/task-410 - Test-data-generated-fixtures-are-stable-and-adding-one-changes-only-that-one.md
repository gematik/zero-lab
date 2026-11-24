---
id: TASK-410
title: 'Test data: generated fixtures are stable, and adding one changes only that one'
status: Done
assignee: []
created_date: '2026-11-23T20:21:00Z'
updated_date: '2026-11-24T05:49:00Z'
labels:
  - testing
  - rust
  - go
dependencies: []
priority: medium
ordinal: 423000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
rust/ti-pki/tests/pki/generate.sh rebuilds the whole test PKI with fresh keys on every run: its CA keys live only in a temporary directory. Adding one certificate (TASK-409) therefore rewrites ~94 certificates, 11 OCSP responses and the corpora in spec/pki-path and spec/pki-profiles; the dipag-vau-aut profile (268802b4) changed 111 files the same way. A review cannot see what changed, and every addition invalidates the shared Rust/Go corpora. There are eight more generators (ti-pki ocsp.sh and tsl-signer, ti-pkcs12, ti-idpd-client, ti-connector-client tls, ti-cli identity and tls/web, spec/pki-validation, spec/pkcs12 tool). The repo already commits TEST-ONLY private keys (16 files, e.g. rust/ti-cli/tests/fixtures/identity). Decided by the maintainer 2026-11-23: test data first, TASK-409 builds on it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 docs/design/testing.md states the rule once: a generated fixture is reproducible from committed inputs (TEST-ONLY keys, fixed instants, deterministic signatures), its generator writes only what is missing unless a full rebuild is asked for explicitly, and adding a fixture changes that fixture and the corpus entries that describe it, nothing else
- [x] #2 rust/ti-pki/tests/pki (generate.sh, ocsp.sh, tsl-signer/generate.sh) follows it: the TEST-ONLY keys are committed next to the certificates, ECDSA signatures are deterministic (RFC 6979, OpenSSL nonce-type 1), a second run of just test-pki changes no file, and a forced rebuild reproduces the same bytes wherever the algorithm allows (RSA-PSS salts are the documented exception)
- [x] #3 The switch is one commit whose diff is the keys and the regenerated fixtures and corpora, with the Rust and Go corpus tests green on it
- [x] #4 Each other generator is checked against the rule; those that do not follow it get a follow-up task each
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. testing.md: the test data rule (where generated fixtures live, committed inputs, idempotent generators, explicit full rebuild, deterministic signatures, corpus rewrite only on change).
2. generate.sh: keys under tests/pki/keys/ (TEST-ONLY), reused when present; a certificate, OCSP response or TSL piece is written only when missing; FORCE=1 rebuilds everything; ECDSA via -sigopt nonce-type:1 (brainpool and P-256); RSA-PSS documented as not reproducible.
3. ocsp.sh and tsl-signer/generate.sh the same way.
4. One switch commit: keys plus regenerated outputs, TI_PKI_BLESS=1 corpora, Go tipki tests green.
5. Prove it: just test-pki twice leaves git clean; FORCE=1 rebuild diff is empty except the documented RSA-PSS files.
6. Survey the other eight generators; follow-up tasks for those that rebuild everything.
7. Then TASK-409 on top: one new certificate, its corpus entries.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-23, branch feat/ti-pki-oid-3.27, d42cd212. rust/ti-pki/tests/pki/lib.sh: keys committed in keys/ (77) and tsl-signer/keys/ (13), made only when missing; wanted() writes an output only when missing or FORCE=1; serial_of(name) = 0x1 + 15 hex of SHA-256(name); sign_options() adds -sigopt nonce-type:1 for EC keys (OpenSSL >= 3.2; 4.1 here). Proof: a second just test-pki changes no file; FORCE=1 reproduces every byte except ee-rsa-pss.pem (random PSS salt, named in lib.sh). ocsp_002 now derives its byte positions from the DER (first/last ecdsa-with-SHA256 AlgorithmIdentifier), checked against the old fixture (311, 325, 782). Rule in docs/design/testing.md 'Generated fixtures are stable'. Follow-ups TASK-411 to 417, one per other generator. Rust workspace 943 tests and Go tipki green on the switch.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All generators follow docs/design/testing.md 'Generated fixtures are stable' via spec/fixtures.sh (TASK-411 to 417, merged 70f13022). Follow-ups: TASK-419, TASK-420.
<!-- SECTION:FINAL_SUMMARY:END -->
