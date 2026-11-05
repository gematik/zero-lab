---
id: TASK-197
title: zero-epa image runs as root
status: Done
assignee: []
created_date: '2026-11-03T09:20:00Z'
updated_date: '2026-11-05T19:19:00Z'
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
- [x] #1 The image runs as a non-root user with a fixed UID
- [x] #2 ti can write its trust cache and temporary files as that user, proven by just epa-connect-test against the image
- [x] #3 An identity mounted from a Secret is readable, and the deployment documentation says which UID it needs
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Prepared, not committed: the image runs as 65532:65532 with a passwd entry; /var/cache/ti and HOME=/var/lib/zero-epa belong to that user, /tmp stays 1777. Checked 2026-11-05 with docker: ti 0.5.0 in the image, as that user, fetched the ref TSL into a fresh volume and read it back with --offline. The Dockerfile names the UID and fsGroup 65532 for a mounted cache. Waiting for the maintainer's run of the image against the real environment (AC 2, 3).

Maintainer, 2026-11-05, image built from the branch: zero-epa probe patient against dev as 65532 with the identity mounted read-only: VAU certificates and host keys verified (chain and signature valid), authorized, entitled, consent read. The run was the image itself rather than just epa-connect-test, which tests the host's build. A first run showed /tmp not writable; /tmp now belongs to the user too. The UID and fsGroup are in the Dockerfile; the deployment manifests live outside this repository.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The zero-epa image runs as 65532 with its cache, home and /tmp; proven against dev with the image.
<!-- SECTION:FINAL_SUMMARY:END -->
