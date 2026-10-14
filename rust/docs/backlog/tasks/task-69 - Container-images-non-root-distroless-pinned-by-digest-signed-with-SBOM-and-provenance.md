---
id: TASK-69
title: >-
  Container images: non-root, distroless, pinned by digest, signed with SBOM and
  provenance
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - go
  - release
dependencies:
  - TASK-7
references:
  - go/docs/design.md
priority: medium
ordinal: 67000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zero-pdp and zero-epa run as root; zero-caddy runs on alpine; base images by tag; nothing signed (server rules 4, 7, 25).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 all images non-root on scratch or distroless, base images by digest, signed with provenance and SBOM
<!-- AC:END -->
