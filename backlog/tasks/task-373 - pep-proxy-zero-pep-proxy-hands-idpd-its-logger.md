---
id: TASK-373
title: 'pep/proxy: zero-pep-proxy hands idpd its logger'
status: Done
assignee: []
created_date: '2026-11-17T06:45:00Z'
updated_date: '2026-11-22 15:07'
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
Since TASK-289 idpd's BundleTrust rereads its mounted bundle in the background and logs a failed reload to ClientConfig.Logger (nil logs nothing, go/docs/design.md section 2). zero-pep-proxy set no logger, so a bad bundle replacement there went unseen. servers.md rule 8 allows exactly this: the TI's trust material is the one exception to read-at-start and may come from mounted files a producer writes, refreshed outside the request path. (Reframed to 'read once' by mistake on 2026-11-22 and set back the same day.)
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 zero-pep-proxy hands idpd its logger in both idpd configurations (providers file and environment), so a failed bundle reload or trust download is logged
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy sets idpd.ClientConfig.Logger to its default logger in the idpd Kind adjust (openid-providers.yaml) and in the environment configuration; idpd passes it to BundleTrust and, via the new idpd.WithTrustLogger, to the fetching trust (TASK-374). No test of its own: the wiring is two assignments, and idpd's and tipki's tests prove what is logged.
<!-- SECTION:FINAL_SUMMARY:END -->
