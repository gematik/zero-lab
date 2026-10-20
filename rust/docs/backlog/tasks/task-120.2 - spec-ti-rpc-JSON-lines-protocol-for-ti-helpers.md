---
id: TASK-120.2
title: 'spec/ti-rpc: JSON-lines protocol for ti helpers'
status: To Do
assignee: []
created_date: '2026-10-20 14:07'
labels:
  - spec
  - interop
dependencies: []
parent_task_id: TASK-120
priority: high
ordinal: 127000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
spec/ti-rpc/README.md: framing (one JSON object per line, UTF-8, a maximum line length); the handshake ({"hello": {capability, protocol, version, build}} first from the helper); request {id, method, params} and answer {id, result} or {id, error: {kind, message, hint}} with ti's error kinds; limits, timeouts, cancellation (closing stdin, killing the process); stdio by default and an optional --listen unix:PATH with peer checks (socket in a 0700 directory, peer uid; on Linux the peer's executable through a pidfd). spec/ti-rpc/pki.md and idpd.md: methods named after the ti subcommands, params and results by their --format json schemas. A corpus of request and answer lines that the Rust server and the Go client both test against, as spec/store does.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 README with framing, handshake, errors, limits, transports
- [ ] #2 pki.md and idpd.md with methods and schemas
- [ ] #3 corpus run by the Rust server and the Go client
<!-- AC:END -->
