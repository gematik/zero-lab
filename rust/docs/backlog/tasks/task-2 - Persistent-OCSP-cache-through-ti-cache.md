---
id: TASK-2
title: Persistent OCSP cache through ti-cache
status: Done
assignee: []
created_date: '2026-10-09 13:55'
updated_date: '2026-10-11 07:38'
labels:
  - ti-pki
  - ti-cli
  - ocsp
dependencies: []
references:
  - ti-pki/src/ocsp.rs
  - ti-cache/src
priority: medium
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OcspChecker caches results in memory only (HashMap, until nextUpdate, capped by the TTL), so every separate ti invocation asks the responder again. Persist results in ti-cache so repeated ti calls benefit. A_23225 suggests 1 h as the caching default (wording still to confirm, see the C_12791 task). Source: Obsidian note C_12791 (follow-ups).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a second ti pki verify within the TTL answers revocation from the cache, and the report says so
- [x] #2 unknown results and errors are never cached; nextUpdate and the TTL bound every entry
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Done 2026-10-11. ti-pki OcspChecker::with_store persists good/revoked DER responses under ti-pki/v1/ocsp/<sha256 of the request>, bounded by OCSP_CACHE_TTL (1 h) and nextUpdate; read back, a response is verified again as of its fetch time (signature, responder authorization, cert binding), so a planted entry is passed over. RevocationResult::from_cache; pki verify reports chain[].revocation.cached. Used by pki verify, the TSL signer status (trust load and tsl verify) and the IDP certificate check. HITL: pki verify --connect epa-as-1.ref twice (second cached), directory login twice (second from the cache), cache clear.
<!-- SECTION:NOTES:END -->
