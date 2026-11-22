---
id: TASK-373
title: 'idpd: the trust bundle is read once at start (rule 8)'
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-22 14:21'
labels:
  - pep-proxy
  - idpd
  - go
dependencies: []
priority: medium
ordinal: 388000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Since TASK-289 idpd's BundleTrust rereads its mounted bundle in the background and logs a failed reload to ClientConfig.Logger; zero-pep-proxy sets no logger, so a bad replacement goes unseen. servers.md rule 8 (TASK-395, 2026-11-22) has files read at start and changed by a rollout, with the TI's trust material refreshed at run time only by a verified background download (idpd's trust_fetch), not by following a mounted file. So BundleTrust reads its file once at start and follows it no more; a changed bundle takes effect with a rollout. Reframed by the maintainer from 'hand idpd a logger'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 idpd's BundleTrust reads its mounted bundle once at start and does not reread it; a test proves a changed file changes nothing; zero-pep-proxy's docs say a new bundle takes effect with a rollout
<!-- AC:END -->
