---
id: TASK-445
title: Examples and images follow the container locations of TASK-444
status: To Do
assignee: []
created_date: '2026-11-27T06:20:00Z'
labels: []
dependencies: []
ordinal: 454000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Compose files, .env.example, CONFIG.md, DOCKERHUB.md and e2e examples of zero-pep-proxy, hsm-proxy, zaddy and the trust producer still mount at /tls, /config, /secrets, /keys and /trust. Move them to the locations naming-and-config.md defines. zero-pdp is frozen and keeps /etc/pdp. zaddy keeps Caddy's /config and /data only where Caddy requires them, stated in its README.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every example outside go/pdp uses the defined locations
- [ ] #2 Each image's list of written paths (rule 27) uses them
<!-- AC:END -->
