---
id: TASK-324
title: 'pdp, pep/proxy: one shared kv store for oidf''s federation documents'
status: Done
assignee: []
created_date: '2026-11-15T08:28:00Z'
updated_date: '2026-11-15T09:10:00Z'
labels:
  - go
  - pdp
  - pep
dependencies: []
ordinal: 339000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/pdp/cmd/zero-pdp/documents.go and go/pep/proxy/cmd/zero-pep-proxy/documents.go (TASK-315, step 7) are byte-identical kvDocuments implementations of oidf.Documents, and so are their tests. One shared host-side package (not in oidf or kv, which stay generic) would remove the copy. Found by the final review of feat/oidf-rp.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One kvDocuments implementation and its tests, used by both hosts
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed by the maintainer's decision (2026-11-15), no code: the module-store pattern puts the wiring in the host, and the two kvDocuments of zero-pdp and zero-pep-proxy (about 40 lines each) are cheaper than a shared module for them, as zaddy loads its own nonce key file.
<!-- SECTION:FINAL_SUMMARY:END -->
