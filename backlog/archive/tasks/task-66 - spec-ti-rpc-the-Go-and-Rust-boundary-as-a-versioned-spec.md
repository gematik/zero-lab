---
id: TASK-66
title: 'spec/ti-rpc: the Go and Rust boundary as a versioned spec'
status: To Do
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T16:11:00Z'
labels:
  - go
  - spec
  - rpc
dependencies: []
references:
  - docs/interop.md
  - go/docs/design.md
priority: medium
ordinal: 64000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
epa parses ti --format json, whose schema the CLI publishes (ti schema), but there is no spec in spec/ with a corpus both sides test against.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/ti-rpc with methods, schemas, result codes, limits and a corpus; the CLI and the Go client conform
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01: the spec covers the stateless helpers of decision-10 (stdio child and Unix socket sidecar, handshake, bounded frames, peer checks); TASK-120.2 writes it.
<!-- SECTION:NOTES:END -->
