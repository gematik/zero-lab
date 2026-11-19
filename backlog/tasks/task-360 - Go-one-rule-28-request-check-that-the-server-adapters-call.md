---
id: TASK-360
title: 'Go: one rule 28 request check that the server adapters call'
status: In Progress
assignee: []
created_date: '2026-11-16T22:52:00Z'
updated_date: '2026-11-19 08:36'
labels: []
dependencies: []
priority: medium
ordinal: 375000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/docs/design.md section 10 names a helper that refuses a repeated `url.Values` key and `RawPath`/`EscapedPath` checks, yet no module has one (only `oidf/oidftest/idp.go:328-335`, a test IdP); pep/proxy, epa and zaddy each would write their own. servers.md rule 28, "One implementation, fuzzed". Found by the rule 28 audit of TASK-321 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 one package offers the single-value parameter read, the canonical-path check and the Host check, each with a `Fuzz…` target seeded with the rule's hostile inputs; the profile names it.
- [ ] #2 tasks 1, 2, 5, 7, 8 and 10 use it.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-18: the maintainer chose a new stdlib-only module go/httpguard, which will also host the shared rate limiter (TASK-301).
Branch fix/rule28-gaps, 73c4560f. New stdlib-only module go/httpguard: CheckPath/Path (as received; refuses encoded / \ % NUL controls and unreserved, literal \ ? #, dot and empty segments), HasPrefix (segment boundary), Value/Single (repeated parameter, ParameterError), Host (byte-equal to configured names). Fuzz targets FuzzCheckPath, FuzzHasPrefix, FuzzValue, FuzzHost, 1 min each; FuzzCheckPath found a literal '?' accepted, fixed, seed kept. go/docs/design.md §10 names it. AC #2: TASK-350 uses it; 351, 354, 356, 357, 359 adopt it in their own changes. Not tagged yet: modules that import it need go/httpguard v0.1.0 tagged and just sync before their own tags.

2026-11-19: pep/proxy's remaining users are in: TASK-351 (httpguard.Single for /oauth2/start, /oauth2/sign_in and the callback) and TASK-354 (httpguard.Host for every request). pep itself cannot import httpguard (mod-check: pep carries only pep and dpop), so TASK-353's checks live in pep and dpop. Still open for criterion 2: epa (TASK-356, TASK-357) and zaddy (TASK-359).
<!-- SECTION:NOTES:END -->
