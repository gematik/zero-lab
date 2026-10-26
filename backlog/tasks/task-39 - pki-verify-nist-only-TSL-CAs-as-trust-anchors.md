---
id: TASK-39
title: 'pki verify --nist-only: TSL CAs as trust anchors'
status: To Do
assignee: []
created_date: '2026-10-11 11:48'
updated_date: '2026-10-20 18:15'
labels:
  - ti-pki
  - nist
dependencies: []
priority: low
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
--nist-only narrows trust to the roots and TSL CAs whose own key is not brainpool (decision TASK-29). Bundles hand such CAs to curl and Java as anchors, and they validate there even when their root is brainpool. ti pki verify --nist-only still needs a path to a non-brainpool root, so a chain under a NIST CA whose root is brainpool (e.g. under GEM.RCA8) fails in ti but works in curl/Java with the same bundle. Let the NIST subset's TSL CAs act as anchors in that mode, or document the difference.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pki verify --nist-only and tsl bundle --nist-only agree on what validates (test with a NIST CA under a brainpool root)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Documented (2026-10-20): the --nist-only help of pki verify, ti-cli/README.md, ti-cli/AGENTS.md and ReleaseNotes say that ti needs a path to a non-brainpool root while curl and Java take a TSL CA of tsl bundle --nist-only as an anchor. The behaviour is unchanged, so the criterion (both agree) stays open.
<!-- SECTION:NOTES:END -->
