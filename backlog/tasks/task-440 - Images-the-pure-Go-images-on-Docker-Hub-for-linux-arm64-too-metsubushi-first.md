---
id: TASK-440
title: 'Images: the pure Go images on Docker Hub for linux/arm64 too, metsubushi first'
status: To Do
assignee: []
created_date: '2026-11-26 14:26'
labels: []
dependencies: []
ordinal: 449000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by zeta-authserver-go TASK-201 (2026-11-26): its chart brings metsubushi as the demo resource behind the PEP (docker.io/spilikin/metsubushi:0.3.1), and on a node of arm64 (kiri's k3s on Apple silicon) the pull fails: 'no match for platform in manifest'. The image is an OCI index with linux/amd64 and an attestation alone, since just docker-build builds --platform linux/amd64. metsubushi, zero-pdp and zero-pep-proxy are static Go on scratch and build for any platform without cost; a local quickstart of a Guard on a Mac needs arm64. zeta-authserver-go builds metsubushi from this checkout in its chart suite meanwhile.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 just docker-push publishes metsubushi as an index of linux/amd64 and linux/arm64 (docker buildx), and the other pure Go images the same where nothing ties them to amd64
- [ ] #2 A tag of metsubushi with both platforms is on Docker Hub, and zeta-authserver-go's chart names it
<!-- AC:END -->
