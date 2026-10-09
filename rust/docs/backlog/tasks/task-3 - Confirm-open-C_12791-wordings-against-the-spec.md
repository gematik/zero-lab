---
id: TASK-3
title: Confirm open C_12791 wordings against the spec
status: To Do
assignee: []
created_date: '2026-10-09 13:55'
labels:
  - spec
  - ti-pki
dependencies: []
priority: low
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Choices ti-pki made where the wording was not available or is open (Obsidian note C_12791 Internet-Prüfung): (1) OCSP validity at the reference time uses thisUpdate <= t <= nextUpdate and ignores producedAt; (2) the FQDN check takes the first word of the commonName (test certificates append ' TEST-ONLY') and does not check the SAN; (3) A_23225's 1 h OCSP caching default comes from a spec comment. Also open in the comments: what 'im Internet' means, who the Afos apply to, how the anchor is provided on the Internet, and whether PointersToOtherTSL gets Internet links.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each of the three choices is confirmed or changed, with the Afo text quoted in the code or docs
<!-- AC:END -->
