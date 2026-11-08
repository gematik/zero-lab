---
id: TASK-271
title: >-
  jwz: profiles as explicit algorithm lists; signing, encryption and keys bound
  to them
status: In Progress
assignee: []
created_date: '2026-11-08T12:06:00Z'
updated_date: '2026-11-08T13:23:00Z'
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
- [x] #1 a Profile holds explicit lists of signature, key-encryption and content-encryption algorithms, key-agreement curves and signing-key curves; jwz and ti-jwz offer them as constant slices, and Profile::with composes them
- [x] #2 jws::sign and jwe::encrypt (compact and JSON) take the profile and refuse an algorithm or key outside it
- [x] #3 verification refuses a key whose kty or crv the profile does not list, including keys from a KeyResolver (TASK-243), which are skipped
- [x] #4 strict, rfc7518_interop, ti and ti_legacy are built from the constants; ti states ES256 on P-256 and brainpoolP256r1
- [x] #5 negative tests per binding: an RSA token, an RSA key and RSA signing against a profile without RSA, a curve the profile does not list; traceability and ADR 0001 updated
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented on feat/jwz-0.2.0. Constants (jwz::profile): ECDSA_NIST (ES256+P-256), EDDSA (EdDSA+Ed25519), HMAC (HS256/384/512), ECDH_ES_P256 (ECDH-ES, +A128KW, +A256KW, P-256), ECDH_ES_DIRECT_P256 (ECDH-ES, P-256; ti), AES_KW, DIRECT, AES_GCM, AES_128_GCM, AES_256_GCM, Algorithms::NONE; Profile::new(name, version). ti-jwz: BP_256 (now ungated name, re-exported by brainpool), EPA_BRAINPOOL_KEYS, BRAINPOOL_SIGNATURES (legacy), BRAINPOOL_KEY_AGREEMENT (legacy). Error code for a key on an unlisted curve (verify and sign) and for unlisted alg/enc/recipient curve when producing: PolicyViolation (the key fits its algorithm; the profile refuses it). Decision taken: ti_legacy() does not list BP-256 for key agreement (would open untested brainpool decryption); ti-idpd-client encrypts under ti_legacy().with(&BRAINPOOL_KEY_AGREEMENT). rfc7518_interop keeps registry-derived lists (needed for ti-jwz brainpool registry). Profile versions bumped to 2 (strict, rfc7518-interop, ti). jwe::encrypt/json::encrypt allow clippy::too_many_arguments (8 params) with a reason. Kani harnesses key_reference_union_is_the_or and claims_policy_union_only_widens removed with the unions; stamps restamped in TASK-272. AC5 RSA: RS256 token, RSA key and RS256 signer are refused (UnsupportedAlgorithm, reserved in every profile).

Review follow-up: the too_many_arguments allows are gone. jwe::Recipient (alg, key, header; re-exported from jwe::json) and jwe::json::Shared (enc, protected, aad) split per-recipient from shared parameters as RFC 7516 §7.2.1 does; jwe::encrypt and jwe::json::encrypt take six parameters.

Maintainer confirmed (2026-11-08): BRAINPOOL_KEY_AGREEMENT as a separate constant only ti-idpd-client uses; profile versions 2; rfc7518_interop's lists from the registry.
<!-- SECTION:NOTES:END -->
