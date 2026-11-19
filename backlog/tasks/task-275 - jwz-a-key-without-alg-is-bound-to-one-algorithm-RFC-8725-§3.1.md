---
id: TASK-275
title: 'jwz: a key without alg is bound to one algorithm (RFC 8725 §3.1)'
status: Done
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-19 08:55'
labels:
  - jwz
  - security
dependencies: []
priority: medium
ordinal: 291000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258. RFC 8725 §3.1 (and RFC 9864 §7: one key, one algorithm): a JWK without alg verifies HS256, HS384 and HS512 alike; a SymmetricKey without alg serves both dir and AES key wrap; a KeyAgreement key serves every ECDH-ES variant. A key that names its algorithm is bound already (RFC 7517 §4.4).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a JWE key (SymmetricKey, KeyAgreement) is made for one algorithm and refuses another
- [x] #2 verify_with refuses a JWK without alg when the profile lists more than one algorithm its key type could serve, or the binding is stated otherwise, decided and recorded in ADR 0001
- [x] #3 tests named after RFC 8725 §3.1 prove each case
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. JWE keys carry their algorithm. SymmetricKey::new(bytes, alg) and from_jwk(jwk, alg, registry): the key is for one KeyEncryptionAlgorithm; a JWK alg that names another is refused (for dir the enc name stays accepted, RFC 7520 §5.6). KeyAgreement and AsyncKeyAgreement get algorithm(); SoftwareAgreementKey::from_jwk and generate take it. Decryption and encryption refuse a key whose algorithm is not the token's (KeyMismatch).
2. verify_with: a resolved JWK without alg is passed over when the profile lists more than one signature algorithm it could serve (it can be made a key for it and the profile's curve rule accepts it); parsing records the listed algorithms with the key rule, so verification still needs no policy. If no other key verifies, the error says a key was ambiguous.
3. Tests named after RFC 8725 §3.1 for each case; ADR 0001 records the decision; callers in ti-jwz, ti-client, ti-idpd-client, ti-cli and the fuzz targets follow.
4. Breaking for jwz (0.3.0): release notes in the Unreleased block; stamps and traceability regenerated.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Design question before building (maintainer, 2026-11-08; not in jwz 0.2.0): a blanket refusal of JWKs without alg would break common issuers (alg is optional, RFC 7517). jwz already rules out cross-type confusion (key type and curve must fit). Decide which remaining ambiguities are dangerous (HMAC hash sizes, oct for dir vs key wrap) and which are names of one primitive (EdDSA/Ed25519; ES256 on brainpoolP256r1 vs BP256R1 under ti_legacy, which a gematik IDP key without alg would hit). Check real JWKs (IDP-Dienst, TASK-251's issuers) first.

Decision (maintainer, 2026-11-17): RFC conform. A key is bound to one algorithm (RFC 8725 §3.1, RFC 9864 §7); starts after TASK-279 leaves jwz.

Built as planned. Decided along the way, recorded in ADR 0001 ('Decisions taken for jwz 0.3'): (1) 'could serve' means SoftwareKey::from_jwk succeeds for the algorithm and the profile's curve rule accepts the key, so an oct key counts for every HMAC its length allows (32 bytes: HS256 only; 48: HS256 and HS384) and a P-256 or brainpool key has one algorithm in every shipped profile. (2) An ambiguous key is passed over; if nothing else verifies the error is KeyMismatch, not VerificationFailed. (3) SoftwareAgreementKey::public_jwk names its alg; a recipient JWK without alg (PuK_IDP_ENC) is still encrypted to, the sender stating the algorithm. (4) SymmetricKey keeps the RFC 7520 §5.6 case as a dir key bound to the enc its JWK names. Tests: rfc_8725_3_1_a_jwe_key_is_made_for_one_algorithm_and_refuses_another, rfc_8725_3_1_a_resolved_key_without_alg_is_used_only_where_one_algorithm_fits. No source of another crate changed, only tests (ti-jwz, ti-idpd-client, ti-cli) and jwz's two JWE fuzz targets, which now hold one key per algorithm so every decryption path stays reachable. Breaking for jwz: 0.3.0, not bumped, tagged or published here; rust/ReleaseNotes.md has the Unreleased block.

The JWE test is two, for clippy's limit on a function's length: rfc_8725_3_1_a_shared_jwe_key_is_made_for_one_algorithm_and_refuses_another and rfc_8725_3_1_a_key_agreement_key_is_made_for_one_algorithm_and_refuses_another.

2026-11-19, maintainer: keep it simple, one key one algorithm, everything explicit. verify_with now passes over every resolved JWK that names no alg (KeyMismatch if nothing else verifies), not only one that fits several listed algorithms; the counting (serves_several, SigningKeyRule::listed) is removed. A host that knows the algorithm of such a key sets alg on the JWK its resolver returns, or makes the key itself and calls verify. Test renamed rfc_8725_3_1_a_resolved_key_that_names_no_alg_is_not_used (HS256, Ed25519, ES256 each: bare refused, named and stated verify). rfc_7515_5_2_step_8's Ed25519 decoy now names its alg, so the test still shows a key of another type being passed over. ADR 0001, guide and release notes rewritten.
<!-- SECTION:NOTES:END -->
