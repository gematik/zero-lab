---
id: TASK-247
title: 'ti-pki: offline certificate check and certificate formatting from ti-report'
status: Done
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-08T08:54:00Z'
labels:
  - ti-pki
  - ti-report
  - architecture
dependencies: []
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 263000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: ti-report goes; its projections become ti_pki::model (TASK-248), and the logic in it moves to the crate it belongs to. ti-report/src/check.rs (CheckContext) is a use case of its own: it loads trust material (a supplied roots.json only if the TSL verifies with it, else the embedded roots, with a warning), selects the profile for the certificate (or checks the chain only, with a warning) and validates with revocation disabled. ti-wasm uses it directly (ti-wasm/src/api.rs), so it cannot live in a host library. fingerprint and pem in ti-report/src/lib.rs format a certificate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-pki offers the offline check as API returning Rust types: the source of the roots and its warning, the profile chosen and why, and the ValidationResult
- [x] #2 the check is tested in ti-pki without JSON, under the requirement IDs the ti-report tests carry
- [x] #3 Certificate has methods for the SHA-256 fingerprint and PEM; ti-report and ti-cli call them
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti_pki::offline (feature load): Check::new(env, config, supplied_roots, xml, sig, now) verifies once; material() -> Material { roots_source: RootsSource (Supplied/Embedded), roots_warning, tsl: Result<VerifiedTsl, VerifyError> }; check(certs, now) -> Outcome::Untrusted | Validated { profile: ProfileChoice::Detected{profile, cert_type, reason, detail} | ChainOnly{detail}, result: Result<ValidationResult, Error> }. No serde. Tests in ti-pki/tests/offline.rs under the ti-report test names, plus usable_supplied_roots_are_used. Certificate::fingerprint_sha256() and to_pem(); ti-report (describe, CertSummary) and ti-cli (roots, bundle, documents, identity, verify-signature, tsl, verify, connector) call them; ti-cli keeps its own hex for serials and file digests. ti-report's CheckContext maps offline::Check; ti-cli and ti-wasm output compared byte for byte with the build before the change (47 CLI invocations in three formats, the ti-wasm API over every fixture, TSL and environment).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Offline use cases in ti_pki::offline; fingerprint and PEM as Certificate methods.
<!-- SECTION:FINAL_SUMMARY:END -->
