---
id: TASK-97.2
title: >-
  TLS verification (b): ti profile in ti-pki, web profile and rustls verifiers
  in ti-tls
status: Done
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T12:16:00Z'
labels:
  - ti-pki
  - security
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 236000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (b): the verifier in ti-pki, held to spec/pki-validation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti_pki::tls verifies chain, server name and stapled OCSP under the ti and web profiles over an atomically swapped trust snapshot and a bounded verdict cache; the corpus passes
- [x] #2 feature rustls supplies a ServerCertVerifier; every new parser (CRL) has a fuzz target
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Maintainer, 2026-11-06: ti-pki has nothing to do with hardening the Web-PKI. ti-pki implements the ti profile only; a new adapter-level crate ti-tls holds the web profile (system roots via rustls-native-certs, rustls-webpki paths, the hardening rules), the rustls verifiers for both profiles and the ClientConfig per profile. Dependencies approved for ti-tls: rustls, rustls-webpki, rustls-native-certs (all already in the tree).

On spec/pki-validation (../zero-lab-tls): c7b1927f ti-pki::tls::ServerCheck (ti profile; tls_corpus: all 23 ti cases); 490cbe49 ti-tls::WebCheck (web profile: system roots via rustls-native-certs, rustls-webpki paths with ti-pki's algorithms, key/hash/name/validity/revocation rules; corpus: all 27 web cases; two rules weakened on purpose were caught); 7db59827 TiVerifier/WebVerifier (rustls), client_config (TLS 1.3/1.2, AES-GCM ECDHE, P-256/P-384; handshake.json test), verdict reuse (TLSV-050/051 tests), fuzz target web_server (210k runs clean). Spec changes on the way: TLSV-020 (ti CAs from the TSL), TLSV-042 without P-521 (no verifier for it; the Web-PKI hardly uses it). Deviation for the maintainer: the verdict cache is a Mutex<HashMap>, a lock held for one lookup; a lock-free map needs a new dependency. A snapshot swap needs no lock: a refreshed snapshot is a new verifier and ClientConfig. OCSP for web reuses ti-pki's RFC 6960 verifier (certHash optional, thisUpdate..nextUpdate). futures-lite stayed dev-only: a std block_on avoids two unaudited crates.

Full just check on the branch: green (816 + 128 tests), after the jwz browser stamp rerun (the workspace Cargo.toml is one of its inputs) and the TASK-230 fix it surfaced.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged into main by fast-forward (1f6aa1e6) with TASK-97's branch spec/pki-validation; just check green (820 + 128 tests, deny, vet, stamps).
<!-- SECTION:FINAL_SUMMARY:END -->
