---
id: TASK-444
title: >-
  Conventions: where a container finds its configuration, secrets and writable
  paths, and their permissions under OpenShift
status: In Progress
assignee: []
created_date: '2026-11-27T06:20:00Z'
updated_date: '2026-11-27T06:20:00Z'
labels: []
dependencies: []
ordinal: 453000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The repository's examples mount configuration and secrets at /etc/pdp, /tls, /config, /secrets, /keys, /trust and /run/secrets with no rule. Define one set of locations for ConfigMaps, Secrets, TLS material, TI trust material, sockets and writable paths, and the permissions they carry under OpenShift restricted-v2 and Pod Security restricted, in docs/conventions/naming-and-config.md and servers.md rule 27.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 naming-and-config.md names the locations for configuration, secrets, TLS, trust material, PKCS#11 modules, sockets, state, cache and temporary files
- [ ] #2 servers.md rule 27 gives the permissions and mount settings for Secrets and ConfigMaps, and why each is so under restricted-v2
- [ ] #3 zeta-authserver-go is told the result
<!-- AC:END -->
