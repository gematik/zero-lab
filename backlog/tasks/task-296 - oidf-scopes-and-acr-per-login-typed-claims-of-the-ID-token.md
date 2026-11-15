---
id: TASK-296
title: 'oidf: scopes and acr per login, typed claims of the ID token'
status: Done
assignee: []
created_date: '2026-11-12T21:08:00Z'
updated_date: '2026-11-15T09:05:00Z'
labels: []
dependencies: []
ordinal: 312000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
AuthenticationURL sends fixed scopes and a hard-coded acr_values (client.go); Exchange returns the raw claims. A caller cannot ask for another acr or scope, and nothing checks the acr of the ID token or extracts the KVNR (urn:telematik:claims:id), the display name, acr and amr into a type. Found by zeta-pdp-go, which needs it for the login of insured persons at a sektoral IDP (its TASK-54) or as named.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Scopes and acr are parameters of a login; the result is a typed identity; an ID token with a lower acr than asked is refused
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-14: done as part of TASK-315 on feat/oidf-rp (per-login scope, acr_values, claims; typed Identity; lower acr refused).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Done with TASK-315 (merged at 1fc214c7): openid.Login carries Scopes, ACRValues, Claims; oidf checks them against registration, the gematik LoA set and the IDP's claims_supported before PAR; ExchangeIdentity returns a typed Identity (personal claims redacted in fmt/slog) and refuses a lower acr than asked, a missing amr, and missing essential claims.
<!-- SECTION:FINAL_SUMMARY:END -->
