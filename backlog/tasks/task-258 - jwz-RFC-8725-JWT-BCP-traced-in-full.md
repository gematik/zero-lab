---
id: TASK-258
title: 'jwz: RFC 8725 (JWT BCP) traced in full'
status: In Progress
assignee: []
created_date: '2026-11-07T18:04:00Z'
updated_date: '2026-11-08T15:19:00Z'
labels:
  - jwz
  - spec
  - security
milestone: m-1
dependencies: []
references:
  - rust/jwz/docs/traceability.md
  - https://www.rfc-editor.org/rfc/rfc8725
priority: medium
type: task
ordinal: 274000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
jwz's README cites RFC 8725 (JSON Web Token Best Current Practices) only for §3.4 (cryptographic inputs validated). The rest of §2 and §3 is not traced as requirements: algorithm verification (§3.1, §3.2), JWE and key-management cautions (§3.3, §3.5, §3.6), UTF-8 (§3.7), issuer and subject validation (§3.8, §3.10), audience (§3.9), explicit typing (§3.11), mutually exclusive validation rules (§3.12). The IETF is revising the document (draft-ietf-oauth-rfc8725bis); its current state is to be checked.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each requirement of RFC 8725 §3 is traced in jwz's traceability table to the code and tests that meet it, or recorded as the caller's duty (ClaimsPolicy, profile) with where jwz helps
- [x] #2 the state of draft-ietf-oauth-rfc8725bis is checked and its new requirements are traced the same way, or a watch task records why not yet
- [ ] #3 a gap found becomes its own task
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
In jwz 0.2.0 (TASK-272). §3.1/3.2 (algorithm verification) are met by TASK-271's explicit lists; a gap in explicit typing (§3.11) would also serve TASK-269 (client-authentication+jwt).

Traced (tests/rfc8725.rs, guide section "RFC 8725: what jwz does and what is yours", README standards table):
- Met by jwz, cited in source and proven by rfc_8725_3_<n> tests: §3.1 (allowlist, alg from the accepted header, JWS key bound to one alg), §3.2 (none never, strict current only, RSA1_5 absent, RFC 6979 ECDSA), §3.3 (type-state; Nested JWT layer by layer), §3.4 (epk on the curve), §3.6 (zip neither produced nor accepted), §3.7 (UTF-8 only: invalid bytes, BOM, lone surrogates refused).
- Caller's duty, with jwz's part cited and tested: §3.2 algorithm choice and agility (Profile), §3.5 key provenance (HMAC key length, generated keys random), §3.8 issuer keys and sub (KeyResolver, ClaimsPolicy::issuer, Claims::sub), §3.9 audience (ClaimsPolicy::audience), §3.10 kid/jku/x5u (KeyReferences opt-in, no fetching, exact kid match), §3.11 explicit typing (Policy::typ, HeaderParams::typ), §3.12 exclusive rules (a Profile per kind).
- draft-ietf-oauth-rfc8725bis-10 (document dated 2026-08-21, expires 2027-02-22) followed and pinned; a later revision is a watch item. The traceability generator reads RFC and NIST ids only, so the draft is cited in prose and traced in the guide's second table; its tests are named draft_ietf_oauth_rfc8725bis_10_3_<n>_… (§3.1 allowlist, §3.3 told apart, §3.13 no PBES2, §3.14 base64url only, §3.15 no zip).
- Gaps for AC 3 (not implemented here): keys without alg are not bound to one algorithm (JWK without alg under several HS*, SymmetricKey without alg for dir and A*KW, KeyAgreement keys for every ECDH-ES variant); signing and encryption do not hold the header to Policy::typ, require_kid or key_references (a profile with typ signs a token it refuses; serves TASK-269); Policy::typ has no if-present rule or set of types (draft §3.11); same_media_type drops application/ also when another / follows.
<!-- SECTION:NOTES:END -->
