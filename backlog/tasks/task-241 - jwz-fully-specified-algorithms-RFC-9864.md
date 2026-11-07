---
id: TASK-241
title: 'jwz: fully-specified algorithms (RFC 9864)'
status: To Do
assignee: []
created_date: '2026-11-07T10:52:00Z'
labels:
  - jwz
dependencies: []
ordinal: 257000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 9864 (draft-ietf-jose-fully-specified-algorithms-13, https://datatracker.ietf.org/doc/rfc9864/) registers the fully-specified JWS algorithms Ed25519 and Ed448 and deprecates the polymorphic EdDSA (RFC 8037), whose curve comes from the key's crv. jwz has EdDSA over Ed25519 today. Support the new identifiers in the registry, keys and profiles; decide what the strict profile does with the deprecated EdDSA (accept only for verification, or refuse) and whether Ed448 comes now or stays out like P-384/P-521; keep the key the source of the algorithm (a JWK's alg, which RFC 9864 says should be present). JWE is unchanged: ECDH-ES stays as it is, the RFC registers no replacement.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 jwa registers Ed25519 (and Ed448 if decided) with RFC 9864's requirement IDs, signing and verifying through the backend traits, with RFC 9864 named in the README's standards table and the traceability table
- [ ] #2 the strict and rfc7518-interop profiles' handling of the deprecated EdDSA is decided, recorded in ADR 0001, and tested
- [ ] #3 a JWK's alg Ed25519 binds the key to that algorithm; an EdDSA token is not accepted for a key whose alg is Ed25519 and the reverse, unless the profile allows it, with tests
<!-- AC:END -->
