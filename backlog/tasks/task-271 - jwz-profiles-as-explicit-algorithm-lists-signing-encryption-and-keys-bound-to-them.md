---
id: TASK-271
title: >-
  jwz: profiles as explicit algorithm lists; signing, encryption and keys bound
  to them
status: To Do
assignee: []
created_date: '2026-11-08T12:06:00Z'
labels:
  - jwz
  - security
  - architecture
milestone: m-1
dependencies:
  - TASK-243
priority: high
ordinal: 287000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A profile must state exactly what it accepts: no RSA, ECC only, ECC and brainpool, later ML-DSA (TASK-242). jwz's Policy already holds lists of JWS alg, JWE alg/enc and ECDH curves, but jws::sign and jwe::encrypt take no policy (jwz can produce what its own profile refuses), nothing binds a JWK's kty and crv to the profile, and ti() accepts ES256 on any curve its key has (ePA's ES256 on brainpoolP256r1 passes as a side effect, tests/profiles.rs epa_es256_with_a_brainpool_key_passes_ti). Maintainer's design (2026-11-08): a profile is the explicit lists that result from its construction; building blocks are constants with slices of algorithms (jwz: e.g. ECDSA_NIST; ti-jwz: BRAINPOOL; later ML_DSA), composed with Profile::with; no families, no only/without. The signing-key curves are a list of their own, as key_agreement_curves is for JWE: strict has ES256 on P-256 only (RFC 7518), ti() has ES256 on P-256 and brainpoolP256r1 (ePA, stated instead of implied), ti_legacy() is ti() with BP256R1 (the IDP-Dienst).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a Profile holds explicit lists of signature, key-encryption and content-encryption algorithms, key-agreement curves and signing-key curves; jwz and ti-jwz offer them as constant slices, and Profile::with composes them
- [ ] #2 jws::sign and jwe::encrypt (compact and JSON) take the profile and refuse an algorithm or key outside it
- [ ] #3 verification refuses a key whose kty or crv the profile does not list, including keys from a KeyResolver (TASK-243), which are skipped
- [ ] #4 strict, rfc7518_interop, ti and ti_legacy are built from the constants; ti states ES256 on P-256 and brainpoolP256r1
- [ ] #5 negative tests per binding: an RSA token, an RSA key and RSA signing against a profile without RSA, a curve the profile does not list; traceability and ADR 0001 updated
<!-- AC:END -->
