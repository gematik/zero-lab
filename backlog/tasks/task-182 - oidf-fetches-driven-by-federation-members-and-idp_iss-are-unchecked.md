---
id: TASK-182
title: 'oidf: fetches driven by federation members and idp_iss are unchecked'
status: Done
assignee: []
created_date: '2026-11-02T15:42:00Z'
updated_date: '2026-11-02T23:09:00Z'
labels:
  - go
  - security
dependencies: []
priority: high
ordinal: 192000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
fetchAndVerify takes iss from idp_iss in a request and never compares fromMaster.Subject or the self-signed statement's issuer and subject with it. FetchSignedJwks fetches signed_jwks_uri from the OP's own statement with no scheme or host check and follows redirects, as do the PAR and token endpoints in client.go on the mTLS client. Found by gosec G704 (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 iss is compared with the statements, fetched URLs are https with no redirect to elsewhere, tests prove both, and the nolint lines naming this task are gone
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed with requirement-named tests in the consolidation.
<!-- SECTION:FINAL_SUMMARY:END -->
