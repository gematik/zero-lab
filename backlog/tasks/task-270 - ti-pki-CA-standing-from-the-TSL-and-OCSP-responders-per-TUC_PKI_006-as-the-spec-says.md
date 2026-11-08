---
id: TASK-270
title: >-
  ti-pki: CA standing from the TSL and OCSP responders per TUC_PKI_006, as the
  spec says
status: In Progress
assignee: []
created_date: '2026-11-08T09:52:00Z'
updated_date: '2026-11-08T10:35:00Z'
labels:
  - rust
  - ti-pki
  - security
dependencies: []
ordinal: 286000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A ref SMC-B (GEM.SMCB-CA9 TEST-ONLY, expired 2025-08-28) failed ti pki verify with ocsp_responder_untrusted: ti checked the sub-CA by OCSP at its root, and the CA names the production root responder, certified by the production GEM.RCA11. gemSpec_PKI TUC_PKI_018 takes a CA's standing from its TSL ServiceStatus (step 5, Tab_PKI_271; the status also covers expired HBA/SMC-B CAs under the Kompromissmodell) and queries OCSP for the checked certificate only (step 7). TUC_PKI_006 step 5 authorizes a responder by its certificate among the TSL's OCSP services; RFC 6960 option 2 is a duty of the TSPs for new responder certificates (A_23142-01), not of the relying party. Maintainer's decision: follow the spec, remove the sub-CA OCSP check, and make a responder outside RFC 6960 a warning when the TSL lists it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the Validator checks revocation for the end entity only; skip_sub_ca_revocation is gone
- [x] #2 a responder that is the issuing CA or its delegate (RFC 6960) is accepted silently; one the verified TSL lists as an OCSP service is accepted with the warning ocsp_responder_not_rfc6960; any other is ocsp_responder_untrusted
- [x] #3 design docs, the GemLibPki comparison and the release notes say so; the stale row on expired CAs is corrected
- [x] #4 the ref SMC-B under GEM.SMCB-CA9 TEST-ONLY verifies
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented on release/ti-cli-0.6.0-rc.1 (Rust and Go alike, pinned by spec/pki-path).

Decisions:
- Validity of a TSL-listed responder (maintainer's decision, relayed during the work): a listed responder that is not an RFC 6960 delegate must carry id-kp-OCSPSigning and be valid now within the clock tolerance, exactly as a delegate; expired or not yet valid is ocsp_responder_untrusted, although the Tab_PKI_271 remark lets in-accord status cover the OCSP signers of expired HBA/SMC-B CAs. Recorded in OCSP-001 and pinned in ocsp.json (store listed: expired-responder at NOW and foreign-responder 25 h before NOW are untrusted).
- Order of routes: issuer, then RFC 6960 delegate (silent), then the TSL listing (tsl_listed + ocsp_responder_not_rfc6960), then untrusted. A direct delegate that fails RFC 6960 (e.g. lacks EKU) falls through to the listing, which asks the same, so the outcome matches.
- ResponderAuthorization::TslListed keeps only tsp (the provider the listing names, first match); ca went, the listing does not certify a CA. Go's ResponderAuthorization dropped CA likewise.
- The listing binds a responder to no CA: listed under any TSP it may answer for any CA (TUC_PKI_006 step 5).
- tests/real_world.rs: live_prod_sub_ca_at_its_root removed, nothing queries a CA any more; live_smcb_end_to_end now expects the end entity alone, TslListed, the responder certified by GEM.KOMP-CA51 and the ocsp_responder_not_rfc6960 warning.
- ti-pki TLS (tls.rs) and Go titls were end-entity only already; their verdicts still carry no not_rfc6960 warning (spec/pki-validation has no such code), unchanged.
- validate.json verdicts record whom the scripted responder was asked (asked); new scripts tsl_listed, ca_untrusted, ca_unavailable; new section compromise (sub-ca-short expired in 2028, in accord with types: SMC-B and HBA valid with issued_before_ca_expiry and asked only about the end entity; the component expired). The skip_sub_ca cases went.
- Go release notes: the convention adds a section per module when tagged, so none was written now.

Sanity: ti pki verify of the maintainer's test SMC-B (GEM.SMCB-CA9 TEST-ONLY) is valid with issued_before_ca_expiry and ocsp_responder_not_rfc6960 (ehca OCSP Signer 51, tsl_listed).

Maintainer's additions:
- issued_before_ca_expiry is renamed ca_expired (Rust ErrorCode::CaExpired, Go CodeCAExpired, spec/pki-path, corpora regenerated, ti-cli schema; schema change noted in the release notes for ti-pki and ti-cli). The message says why the CA is still accepted: expired (notAfter=…); "<below>", which it issued, is accepted under the Kompromissmodell for HBA and SMC-B, as the CA was valid when it issued it.
- ti-cli trust tree: ✗ for a certificate an error concerns, a yellow ! for one only warnings concern, ✓ otherwise. The Kompromissmodell CA row reads 'CA · expired <date>, accepted under the Kompromissmodell' and is not dimmed. The ! applies to any certificate with only warnings, so an end entity carrying ocsp_responder_not_rfc6960 shows ! too. Pinned by ca_expired_is_rendered_as_a_warning_not_a_failure.
<!-- SECTION:NOTES:END -->
