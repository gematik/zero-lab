---
id: TASK-267
title: 'ti-client: messages free of CLI flags'
status: In Progress
assignee: []
created_date: '2026-11-08T06:34:00Z'
updated_date: '2026-11-08T09:27:00Z'
labels:
  - rust
dependencies: []
ordinal: 283000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Two ti-client messages name CLI flags (--validation-profile, --offline) and stayed so the ti CLI's JSON did not change. The Tauri app needs its own wording: ti-client reports a typed reason, each front end words it. Found during TASK-250.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 no ti-client message names a CLI flag; the ti CLI's output is unchanged
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
ti-client reports TslUncached, ProxyUnsupported, ComfortUserIdInvalid, and the profile warning ends at the fact; ti-cli adds its flags. Pinned by error::tests::client_reasons_are_worded_with_the_cli_flags and cli::verify_names_the_option_when_no_profile_is_detected.
<!-- SECTION:NOTES:END -->
