---
id: TASK-29
title: GEM.RCA10 unreachable without brainpool
status: To Do
assignee: []
created_date: '2026-10-10 17:08'
labels:
  - ti-pki
dependencies: []
priority: low
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From the GEM.RCA7 anchor the A_28419 cross-certificate walk under algorithms::NIST stops at the first brainpool signature: it keeps GEM.RCA7 and GEM.RCA6 only. GEM.RCA10 is a P-256 root a NIST-only client could use, but the walk reaches the newer roots only through RCA8's brainpool cross signature, so --nist-only never reaches RCA9 (RSA) or RCA10.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided whether NIST-only trust needs RCA9/RCA10 (e.g. a pinned anchor, or a brainpool-checked walk that exports non-brainpool roots), and implemented or closed with the reason
<!-- AC:END -->
