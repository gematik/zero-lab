---
id: TASK-170
title: >-
  pdp: HSM binding through a provider sidecar or a KMS API; key release gated on
  attestation
status: To Do
assignee: []
created_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - pdp
  - keys
  - security
dependencies:
  - TASK-88
priority: medium
ordinal: 180000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The PDP's signing and sealing keys must live in a (cloud) HSM (maintainer, 2026-11-01). Without cgo the vendor's PKCS#11 library cannot be in the Go image, so the channel is either a cloud KMS HTTPS API (signing requests carry a digest, standard library client) or a provider sidecar that holds the vendor library behind a small signing API over a Unix socket, the pattern of Kubernetes KMS plugin v2. The binding is mutual: the HSM and its channel are part of the PDP's trusted base, and the HSM's key policy admits only this workload, proven by attestation and a workload identity (SPIFFE Workload API consumed when mounted, never implemented here), not by a credential in a file. Only digests cross the channel; the key never exists in the workload. Rules: docs/design/keys.md 1, 2, 9, 10; docs/design/servers.md 6, 8; decision-10.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the PDP signs through a crypto.Signer backed by a KMS API or the provider sidecar; no key bytes in the process (TASK-88 first)
- [ ] #2 the key policy on the HSM admits the PDP by attestation or workload identity, documented with the provider's mechanism; a copy of the image without the attested identity cannot sign
- [ ] #3 the provider sidecar, where used, listens on a Unix socket in a shared emptyDir only and is pinned by digest in the same manifest
<!-- AC:END -->
