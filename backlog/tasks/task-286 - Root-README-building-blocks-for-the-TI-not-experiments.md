---
id: TASK-286
title: 'Root README: building blocks for the TI, not experiments'
status: To Do
assignee: []
created_date: '2026-11-10T18:40:00Z'
updated_date: '2026-11-10T18:42:00Z'
labels:
  - docs
dependencies: []
priority: low
ordinal: 302000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: the repository is no longer only for experimenting. The name zero-lab stays; the README's title and introduction become 'zero-lab: building blocks for the Telematikinfrastruktur' (maintainer's choice, 2026-11-10). Experimenting wording goes from the READMEs and docs; the GitHub description only with the maintainer's go-ahead.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the root README's title and introduction as chosen; the DSR PoC note kept as provenance
- [x] #2 no README or doc describes the repository as experimental
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Title and introduction as chosen; the long Zero Trust quote removed; the DSR PoC note kept as where the work started. A grep found no other README or doc calling the repository experimental. The GitHub description still says 'experimental': changing it with gh repo edit waits for the maintainer's go-ahead.
<!-- SECTION:NOTES:END -->
