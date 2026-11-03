---
id: TASK-197
title: zero-epa image runs as root
status: To Do
assignee: []
created_date: '2026-11-03T09:20:00Z'
labels:
  - security
  - go
dependencies: []
priority: medium
ordinal: 207000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/epa/cmd/zero-epa/Dockerfile has no USER, so the scratch image runs zero-epa and the ti it starts as root, unlike zero-pep-proxy (65532). A non-root user needs a passwd entry and write access to what ti and zero-epa use: the VOLUME /var/cache/ti, /tmp and HOME=/app. Mounted identity files must stay readable for that user.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The image runs as a non-root user with a fixed UID
- [ ] #2 ti can write its trust cache and temporary files as that user, proven by just epa-connect-test against the image
- [ ] #3 An identity mounted from a Secret is readable, and the deployment documentation says which UID it needs
<!-- AC:END -->
