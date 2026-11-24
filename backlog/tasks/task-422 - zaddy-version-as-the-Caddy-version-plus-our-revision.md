---
id: TASK-422
title: 'zaddy: version as the Caddy version plus our revision'
status: In Progress
assignee: []
created_date: '2026-11-24T06:04:00Z'
updated_date: '2026-11-24T06:04:00Z'
labels:
  - go
  - zaddy
dependencies: []
ordinal: 435000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zaddy and its zero-caddy image carry the Caddy version first and our revision after it: tag go/zaddy/v2.11.9-zero.1, module path go/zaddy/v2, image zero-caddy:2.11.9-zero.1, binary 'zero-caddy 2.11.9-zero.1'. The revision counts from 1 for each Caddy version. Requested by the maintainer on 2026-11-24.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Module path github.com/gematik/zero-lab/go/zaddy/v2
- [ ] #2 just tag zaddy refuses a version whose Caddy part differs from zaddy/go.mod or lacks -zero.N
- [ ] #3 Image tag and binary version are the module version alone
- [ ] #4 git-and-releases.md and the Go development guide state the scheme
<!-- AC:END -->
