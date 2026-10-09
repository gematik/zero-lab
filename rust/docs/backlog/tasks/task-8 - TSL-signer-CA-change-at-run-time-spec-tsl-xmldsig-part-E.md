---
id: TASK-8
title: TSL signer CA change at run time (spec/tsl-xmldsig part E)
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - ti-pki
  - tsl
  - parked
dependencies: []
references:
  - ../spec/tsl-xmldsig
priority: low
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TSLSIG-061 – 068: an anchor announced in the TSL becomes active at its StatusStartingTime, with the roots.json fallback. Simplified on 2026-10-03 (see decisions): tsl_signer_anchors is a list, an announcement is the warning tsl_anchor_announced, and a release adds the new CA. GEM.TSL-CA3 runs until 2028-05-25. Revisit only if an installation must follow an anchor change without a release.
<!-- SECTION:DESCRIPTION:END -->
