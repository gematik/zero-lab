---
id: TASK-380
title: 'pdp: development of go/pdp is frozen, zeta-pdp-go replaces it'
status: Done
assignee: []
created_date: '2026-11-18 15:40'
updated_date: '2026-11-18 15:41'
labels:
  - pdp
  - go
  - chore
dependencies: []
ordinal: 395000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The maintainer froze the development of zero-lab's PDP (go/pdp, zero-pdp) on 2026-11-18. zeta-pdp-go replaces it, and go/pdp was already left out of encoding/json/v2 (TASK-323), the rule 28 audit (TASK-321) and the RFC 9700 check (TASK-259). The freeze is so far only in task notes and one clause of go/docs/design.md; a reader of the repository or of the image's description cannot tell.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A decision records the freeze and what it means for fixes, checks, pins and releases
- [x] #2 README.md, the Go profile and the image description of zero-pdp say that go/pdp is frozen and name the decision
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
decision-19 records the freeze; its Decision section holds what the maintainer said, the Consequences are drafted from what TASK-323, TASK-321 and TASK-259 already did with go/pdp and are for the maintainer to confirm in review. Notes in README.md, go/docs/design.md (rule 28, encoding/json) and go/pdp/cmd/zero-pdp/DOCKERHUB.md. No code changed; just check-changed in go/ passed. Left out: pushing the new description to Docker Hub, and removing go/pdp, which the decision names as a later one.
<!-- SECTION:NOTES:END -->
