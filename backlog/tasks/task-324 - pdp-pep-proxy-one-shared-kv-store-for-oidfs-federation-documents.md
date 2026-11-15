---
id: TASK-324
title: 'pdp, pep/proxy: one shared kv store for oidf''s federation documents'
status: To Do
assignee: []
created_date: '2026-11-15T08:28:00Z'
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
