---
id: TASK-241
title: 'jwz: fully-specified algorithms (RFC 9864)'
status: Done
assignee: []
created_date: '2026-11-07T10:52:00Z'
updated_date: '2026-11-08T17:37:00Z'
labels:
  - jwz
milestone: m-1
dependencies:
  - TASK-271
ordinal: 257000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
RFC 9864 (draft-ietf-jose-fully-specified-algorithms-13, https://datatracker.ietf.org/doc/rfc9864/) registers the fully-specified JWS algorithms Ed25519 and Ed448 and deprecates the polymorphic EdDSA (RFC 8037), whose curve comes from the key's crv. jwz has EdDSA over Ed25519 today. Support the new identifiers in the registry, keys and profiles; decide what the strict profile does with the deprecated EdDSA (accept only for verification, or refuse) and whether Ed448 comes now or stays out like P-384/P-521; keep the key the source of the algorithm (a JWK's alg, which RFC 9864 says should be present). JWE is unchanged: ECDH-ES stays as it is, the RFC registers no replacement.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 jwa registers Ed25519 (and Ed448 if decided) with RFC 9864's requirement IDs, signing and verifying through the backend traits, with RFC 9864 named in the README's standards table and the traceability table
- [x] #2 a JWK's alg Ed25519 binds the key to that algorithm; an EdDSA token is not accepted for a key whose alg is Ed25519 and the reverse, unless the profile allows it, with tests
- [x] #3 strict accepts ES256 and Ed25519; the polymorphic EdDSA stays only in rfc7518_interop, so the lists bind signing and verifying alike; Ed448 stays out (rare, a new dependency); recorded in ADR 0001 and tested
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Plan for jwz 0.2.0 (2026-11-08): Ed25519 per RFC 9864 is the name new tokens carry; EdDSA stays relevant worldwide (DPoP, FAPI 2.0, DID/VC, and as a component of ML-DSA composite signatures in the PQC transition) but not in the TI (gemSpec_Krypt V2.50.0 names no EdDSA). strict = ES256 + Ed25519, EdDSA only in rfc7518_interop, no Ed448.

Ed25519 registered (OKP, curve Ed25519, available), Ed448 reserved. SoftwareKey binds a fully specified EdDSA algorithm to its curve (from_jwk and generate). strict = ECDSA_NIST + ED25519 (constant profile::ED25519); profile::EDDSA stays for older peers and rfc7518-interop lists both. Existing EdDSA tests (RFC 8037 vectors, curve binding) run under strict().with(&EDDSA); the browser and JSON tests use Ed25519. ADR 0001 has a TASK-241 section; README standards table names RFC 9864.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Ed25519 (RFC 9864) registered and bound to its curve, Ed448 reserved; a JWK's alg binds it to Ed25519 or EdDSA; strict lists ES256 and Ed25519, the deprecated EdDSA stays as a constant and in rfc7518-interop.
<!-- SECTION:FINAL_SUMMARY:END -->
