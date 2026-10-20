---
id: TASK-1
title: 'ti pki verify --at: anchor OCSP at the given time'
status: Done
assignee: []
created_date: '2026-10-09 13:54'
updated_date: '2026-10-20 18:53'
labels:
  - ti-cli
  - ti-pki
  - ocsp
dependencies: []
references:
  - ti-cli/src/commands/verify.rs
priority: medium
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
With --at, path validation runs at the given instant, but the OCSP request and the response's validity window are still judged against the current time, so a historical check mixes two instants. Source: Obsidian note C_12791 (follow-ups).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 pki verify --at T judges the OCSP status at T (gemSpec_PKI TUC_PKI_006 8a/8b): revoked after T is valid with the warning revoked_after_reference_time, at or before T (or without revocationTime) revoked; freshness stays against the time of the query
- [x] #2 the report says that OCSP answered now and was judged at --at
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The original criterion (thisUpdate/nextUpdate against T) would reject every live answer for a past T; TUC_PKI_006 judges freshness against the system time (OCSP graceperiod) and the status at the reference time (8a, 8b). ti-pki: revocation::apply_revocation takes the reference time; ErrorCode::RevokedAfterReferenceTime (revoked_after_reference_time, warning); tests tuc_pki_006_8a_*, tuc_pki_006_8b_* and validate::tests::validator::tuc_pki_006_revocation_is_judged_at_the_reference_time. ti-cli: the revocation line says "OCSP answered now, judged at --at" and "revoked after the reference time (valid then)"; schema pki-verify lists the code.
<!-- SECTION:FINAL_SUMMARY:END -->
