---
id: TASK-240
title: 'ti-cli: Homebrew formula in gematik/tap, passing brew style and audit'
status: In Progress
assignee: []
created_date: '2026-11-07T10:45:00Z'
updated_date: '2026-11-07T10:50:00Z'
labels:
  - ti-cli
  - release
  - chore
dependencies: []
priority: medium
ordinal: 256000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti releases publish their formula to spilikin/homebrew-tap (TAP_OWNER in rust/Justfile), a personal tap. gematik/homebrew-tap now exists and carries the earlier ti formula history, so releases should go there. The formula template rust/ti-cli/Formula/ti.rb fails brew style (FormulaAudit/ComponentsOrder: url and sha256 directly under on_macos/on_linux) and brew audit --strict (version redundant with the URL).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just publish defaults to the gematik tap, and the README, the ti-cli README and the development guide say brew install gematik/tap/ti
- [ ] #2 The rendered formula passes brew style and brew audit --strict, and loads on every OS and architecture, refusing the unsupported ones by its arch requirement
<!-- AC:END -->
