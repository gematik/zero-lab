---
id: TASK-386
title: 'pep/proxy: DATABASE_URL carries the component''s prefix'
status: Done
assignee: []
created_date: '2026-11-18 21:34'
updated_date: '2026-11-22 15:09'
labels:
  - pep-proxy
  - go
  - config
dependencies: []
references:
  - docs/conventions/naming-and-config.md
priority: low
ordinal: 400000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zero-pep-proxy (go/pep/proxy/cmd/zero-pep-proxy/main.go:134, 160) and zero-pdp (go/pdp/cmd/zero-pdp/start.go:136) read their Postgres peer from DATABASE_URL. naming-and-config.md asks every variable to carry the prefix of the component that reads it, and the transport scheme (TASK-382) names a peer <COMPONENT>_<NAME>_URL. Found while writing TASK-382. go/pdp is frozen (decision-19), so this concerns zero-pep-proxy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 zero-pep-proxy reads its store peer from a variable with its prefix, and its documentation says so
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: retitled from 'Go: …'. zero-pdp reads DATABASE_URL too, but go/pdp is frozen (decision-19) and keeps it.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy reads its Postgres peer (session store and revocation bus) from PEP_DATABASE_URL; the retired DATABASE_URL stops the start with the new name. CONFIG.md, DOCKERHUB.md, .env.example, the compose files, the e2e guide, at-rest-encryption.md and stateless-session-validation.md use it. Test: TestNamingAndConfig_TheStorePeerCarriesThePrefix. Breaking at the next release (zero-lab-k8s sets no DATABASE_URL for zerobin today). go/pdp, frozen, keeps DATABASE_URL.
<!-- SECTION:FINAL_SUMMARY:END -->
