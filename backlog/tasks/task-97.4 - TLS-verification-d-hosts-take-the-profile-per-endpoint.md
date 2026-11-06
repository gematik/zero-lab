---
id: TASK-97.4
title: 'TLS verification (d): hosts take the profile per endpoint'
status: To Do
assignee: []
created_date: '2026-11-06T07:36:00Z'
labels:
  - ti-cli
  - security
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 238000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (d): ti-cli and the ureq adapters verify TI endpoints with the ti profile and internet endpoints with the web profile.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-cli takes the profile per endpoint from configuration, with no system-store fallback for ti; the Konnektor's .kon pinning stays as it is
- [ ] #2 a rustls ClientConfig per profile for other rustls clients
<!-- AC:END -->
